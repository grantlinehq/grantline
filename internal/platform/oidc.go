package platform

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oidcState struct{ Verifier, Nonce, Invitation, LinkUser string }

func (s *Server) registerOIDC() {
	s.mux.HandleFunc("POST /api/v1/auth/oidc/start", s.authBound(s.startOIDC))
	s.mux.HandleFunc("POST /api/v1/auth/oidc/link", s.auth(s.authBound(s.startOIDC), false))
	s.mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.authBound(s.finishOIDC))
}
func (s *Server) oidcProvider(ctx context.Context) (context.Context, *oidc.Provider, *oauth2.Config, error) {
	stored, e := s.ssoConfig(ctx)
	if e != nil || !stored.Enabled {
		return ctx, nil, nil, errors.New("OIDC is not configured")
	}
	u, e := url.Parse(stored.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || stored.ClientID == "" {
		return ctx, nil, nil, errors.New("OIDC is not configured")
	}
	client, e := s.client()
	if e != nil {
		return ctx, nil, nil, e
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, e := oidc.NewProvider(ctx, stored.Issuer)
	if e != nil {
		return ctx, nil, nil, errors.New("OIDC discovery unavailable")
	}
	endpoint := provider.Endpoint()
	for _, address := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		p, e := url.Parse(address)
		if e != nil || p.Scheme != "https" || p.Host == "" || p.User != nil {
			return ctx, nil, nil, errors.New("OIDC endpoint invalid")
		}
	}
	cfg := &oauth2.Config{ClientID: stored.ClientID, ClientSecret: stored.ClientSecret, Endpoint: endpoint, RedirectURL: s.cfg.PublicURL + "/api/v1/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return ctx, provider, cfg, nil
}
func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request) {
	var in struct{ Invitation string }
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, _, cfg, e := s.oidcProvider(ctx)
	if e != nil {
		fail(w, 503, "sso_unavailable")
		return
	}
	state := randomID()
	value := oidcState{Verifier: oauth2.GenerateVerifier(), Nonce: randomID(), Invitation: in.Invitation, LinkUser: actor(r).ID}
	b, _ := json.Marshal(value)
	encrypted, e := seal(s.cfg.EncryptionKey, "oidc:"+digest(state), b)
	if e != nil {
		fail(w, 500, "sso_unavailable")
		return
	}
	if _, e = s.db.ExecContext(ctx, "INSERT INTO tickets(digest,kind,email,payload,expires_at) VALUES($1,'oidc','',$2,now()+interval '10 minutes')", digest(state), encrypted); e != nil {
		fail(w, 500, "sso_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "grantline_oidc", Value: state, Path: "/api/v1/auth/oidc", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	send(w, 200, map[string]string{"url": cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(value.Verifier), oidc.Nonce(value.Nonce))})
}
func (s *Server) finishOIDC(w http.ResponseWriter, r *http.Request) {
	cookie, e := r.Cookie("grantline_oidc")
	state := r.URL.Query().Get("state")
	if e != nil || len(state) > 128 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		fail(w, 400, "sso_state_invalid")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "grantline_oidc", Value: "", Path: "/api/v1/auth/oidc", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	var encrypted []byte
	if s.db.QueryRowContext(r.Context(), "DELETE FROM tickets WHERE digest=$1 AND kind='oidc' AND expires_at>now() RETURNING payload", digest(state)).Scan(&encrypted) != nil {
		fail(w, 400, "sso_expired")
		return
	}
	clear, e := unseal(s.cfg.EncryptionKey, "oidc:"+digest(state), encrypted)
	var saved oidcState
	if e != nil || json.Unmarshal(clear, &saved) != nil {
		fail(w, 400, "sso_invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ctx, provider, cfg, e := s.oidcProvider(ctx)
	if e != nil {
		fail(w, 503, "sso_unavailable")
		return
	}
	token, e := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(saved.Verifier))
	if e != nil {
		fail(w, 401, "sso_exchange_failed")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		fail(w, 401, "sso_token_missing")
		return
	}
	identity, e := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if e != nil || identity.Nonce != saved.Nonce {
		fail(w, 401, "sso_token_invalid")
		return
	}
	var claims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Name     string   `json:"name"`
		AMR      []string `json:"amr"`
	}
	if identity.Claims(&claims) != nil {
		fail(w, 401, "sso_claims_invalid")
		return
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var id, role string
	if saved.LinkUser != "" {
		// Linking requires the same still-active local session that initiated it.
		local, e := r.Cookie("grantline_session")
		var current string
		if e != nil || tx.QueryRowContext(ctx, "SELECT user_id FROM sessions WHERE digest=$1 AND expires_at>now() AND NOT mfa_pending", digest(local.Value)).Scan(&current) != nil || current != saved.LinkUser {
			fail(w, 403, "sign_in_again_to_link")
			return
		}
		id = current
		if tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id=$1 AND NOT disabled", id).Scan(&role) != nil {
			fail(w, 403, "account_unavailable")
			return
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO oidc_links(issuer,subject,user_id) VALUES($1,$2,$3)", identity.Issuer, identity.Subject, id); e != nil {
			fail(w, 409, "sso_identity_already_linked")
			return
		}
	} else {
		e = tx.QueryRowContext(ctx, "SELECT u.id,u.role FROM oidc_links l JOIN users u ON u.id=l.user_id WHERE issuer=$1 AND subject=$2 AND NOT u.disabled", identity.Issuer, identity.Subject).Scan(&id, &role)
		if e == sql.ErrNoRows && saved.Invitation != "" && claims.Verified && validEmail(claims.Email) {
			var email string
			e = tx.QueryRowContext(ctx, "DELETE FROM tickets WHERE digest=$1 AND kind='invite' AND expires_at>now() RETURNING email,role", digest(saved.Invitation)).Scan(&email, &role)
			if e != nil || email != strings.ToLower(claims.Email) {
				fail(w, 403, "invitation_does_not_match")
				return
			}
			id = randomID()
			name := claims.Name
			if name == "" || len(name) > 100 {
				name = email
			}
			_, e = tx.ExecContext(ctx, "INSERT INTO users(id,email,name,role) VALUES($1,$2,$3,$4)", id, email, name, role)
			if e == nil {
				_, e = tx.ExecContext(ctx, "INSERT INTO oidc_links(issuer,subject,user_id) VALUES($1,$2,$3)", identity.Issuer, identity.Subject, id)
			}
		}
		if e != nil {
			fail(w, 403, "invitation_or_explicit_account_link_required")
			return
		}
	}
	mfa := false
	for _, method := range claims.AMR {
		if method == "mfa" {
			mfa = true
		}
	}
	if privileged(role) && !mfa {
		fail(w, 403, "identity_provider_mfa_claim_required")
		return
	}
	if audit(ctx, tx, id, "session.sso", id) != nil || tx.Commit() != nil {
		fail(w, 500, "sso_failed")
		return
	}
	if s.issueSession(w, r, id, false) != nil {
		fail(w, 500, "session_unavailable")
		return
	}
	http.Redirect(w, r, s.cfg.PublicURL+"/#overview", http.StatusSeeOther)
}
