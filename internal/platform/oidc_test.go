package platform

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatabaseOIDCInvitationLinkMFAAndPKCE(t *testing.T) {
	db := testDatabase(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	var issuer, nonce, challenge string
	subject, email, mfa, wrongNonce := "viewer-subject", "viewer@example.test", false, false
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "acceptance", "use": "sig", "alg": "RS256", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		proof := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		client, password, ok := r.BasicAuth()
		if !ok || client != "acceptance" || password != "acceptance-secret" || enc(proof[:]) != challenge || r.Form.Get("code") != "test-code" {
			fail(w, 401, "invalid_test_exchange")
			return
		}
		amr := []string{"pwd"}
		if mfa {
			amr = append(amr, "mfa")
		}
		n := nonce
		if wrongNonce {
			n = "unrelated-sign-in"
		}
		head, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "acceptance", "typ": "JWT"})
		body, _ := json.Marshal(map[string]any{"iss": issuer, "sub": subject, "aud": "acceptance", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": n, "email": email, "email_verified": true, "name": "Acceptance user", "amr": amr})
		unsigned := enc(head) + "." + enc(body)
		hash := sha256.Sum256([]byte(unsigned))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			fail(w, 500, "test_signing_failed")
			return
		}
		send(w, 200, map[string]any{"access_token": "synthetic-access-token", "token_type": "Bearer", "expires_in": 60, "id_token": unsigned + "." + enc(sig)})
	})
	idp := httptest.NewTLSServer(mux)
	defer idp.Close()
	issuer = idp.URL
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32), OIDCIssuer: issuer, OIDCClientID: "acceptance", OIDCClientSecret: "acceptance-secret", CustomCA: ca})
	if e != nil {
		t.Fatal(e)
	}
	owner := databaseBrowser(t, s, "owner")
	anonymous := &testBrowser{t: t, s: s, ip: "192.0.2.40"}
	signIn := func(browser *testBrowser, path, invitation string, want int) {
		start := browser.request("POST", path, map[string]string{"Invitation": invitation}, 200)
		var out struct{ URL string }
		json.Unmarshal(start.Body.Bytes(), &out)
		u, _ := url.Parse(out.URL)
		nonce, challenge = u.Query().Get("nonce"), u.Query().Get("code_challenge")
		if nonce == "" || challenge == "" || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("missing nonce/PKCE")
		}
		r := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/v1/auth/oidc/callback?state="+url.QueryEscape(u.Query().Get("state"))+"&code=test-code", nil)
		r.RemoteAddr = "192.0.2.41:1234"
		for _, c := range start.Result().Cookies() {
			r.AddCookie(c)
		}
		if browser.cookie != nil {
			r.AddCookie(browser.cookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("callback: %d want %d: %s", w.Code, want, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "grantline_session" {
				browser.cookie = c
				browser.csrf = digest("csrf:" + c.Value)
			}
		}
		repeated := httptest.NewRecorder()
		s.ServeHTTP(repeated, r)
		if repeated.Code != 400 {
			t.Fatal("OIDC state reused")
		}
	}
	signIn(anonymous, "/auth/oidc/start", "", 403) // No open self-registration.
	var ticket struct{ URL string }
	json.Unmarshal(owner.request("POST", "/invitations", map[string]string{"Email": email, "Role": "viewer"}, 201).Body.Bytes(), &ticket)
	signIn(anonymous, "/auth/oidc/start", strings.Split(ticket.URL, "/#accept/")[1], 303)
	anonymous.request("GET", "/overview", nil, 200)
	wrongNonce = true
	signIn(anonymous, "/auth/oidc/start", "", 401)
	wrongNonce = false
	signIn(anonymous, "/auth/oidc/start", "", 303)
	var current struct{ User User }
	json.Unmarshal(owner.request("GET", "/auth/session", nil, 200).Body.Bytes(), &current)
	subject, email = "owner-subject", current.User.Email
	signIn(anonymous, "/auth/oidc/start", "", 403) // Matching email must not merge accounts.
	signIn(owner, "/auth/oidc/link", "", 403)      // Privileged SSO requires IdP MFA.
	mfa = true
	signIn(owner, "/auth/oidc/link", "", 303)
	signIn(anonymous, "/auth/oidc/start", "", 303)
	anonymous.request("GET", "/settings/sso", nil, 200)
}
