package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

type SSOConfiguration struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Enabled      bool   `json:"enabled"`
	Revision     int    `json:"revision"`
}

func (s *Server) registerAdministration() {
	s.mux.HandleFunc("GET /api/v1/settings/sso", s.require("owner", s.getSSO))
	s.mux.HandleFunc("PUT /api/v1/settings/sso", s.require("owner", s.saveSSO))
	s.mux.HandleFunc("GET /api/v1/settings/versions", s.require("admin", s.versions))
	s.mux.HandleFunc("GET /api/v1/auth/sessions", s.auth(s.sessions, false))
	s.mux.HandleFunc("POST /api/v1/auth/sessions/revoke", s.auth(s.revokeSessions, false))
	s.mux.HandleFunc("POST /api/v1/users/{id}/sessions/revoke", s.require("admin", s.revokeUserSessions))
}
func (s *Server) checkEncryptionKey(ctx context.Context) error {
	cipher, e := seal(s.cfg.EncryptionKey, "settings:key_check", []byte("grantline-encryption-key-v1"))
	if e != nil {
		return e
	}
	if _, e = s.db.ExecContext(ctx, "INSERT INTO system_settings(name,encrypted) VALUES('key_check',$1) ON CONFLICT DO NOTHING", cipher); e != nil {
		return errors.New("encryption state unavailable; run migrate")
	}
	if e = s.db.QueryRowContext(ctx, "SELECT encrypted FROM system_settings WHERE name='key_check'").Scan(&cipher); e != nil {
		return errors.New("encryption state unavailable")
	}
	clear, e := unseal(s.cfg.EncryptionKey, "settings:key_check", cipher)
	if e != nil || string(clear) != "grantline-encryption-key-v1" {
		return errors.New("encryption key does not match this database")
	}
	return nil
}
func (s *Server) ssoConfig(ctx context.Context) (SSOConfiguration, error) {
	var cipher []byte
	var revision int
	e := s.db.QueryRowContext(ctx, "SELECT encrypted,revision FROM system_settings WHERE name='oidc'").Scan(&cipher, &revision)
	if e == sql.ErrNoRows {
		return SSOConfiguration{Issuer: s.cfg.OIDCIssuer, ClientID: s.cfg.OIDCClientID, ClientSecret: s.cfg.OIDCClientSecret, Enabled: s.cfg.OIDCIssuer != ""}, nil
	}
	if e != nil {
		return SSOConfiguration{}, e
	}
	clear, e := unseal(s.cfg.EncryptionKey, "settings:oidc", cipher)
	var cfg SSOConfiguration
	if e != nil || json.Unmarshal(clear, &cfg) != nil {
		return cfg, errors.New("SSO configuration unavailable")
	}
	cfg.Revision = revision
	return cfg, nil
}
func (s *Server) getSSO(w http.ResponseWriter, r *http.Request) {
	cfg, e := s.ssoConfig(r.Context())
	if e != nil {
		fail(w, 503, "sso_configuration_unavailable")
		return
	}
	send(w, 200, map[string]any{"issuer": cfg.Issuer, "client_id": cfg.ClientID, "enabled": cfg.Enabled, "secret_configured": cfg.ClientSecret != "", "revision": cfg.Revision, "redirect_uri": s.cfg.PublicURL + "/api/v1/auth/oidc/callback"})
}
func (s *Server) saveSSO(w http.ResponseWriter, r *http.Request) {
	var in SSOConfiguration
	if decode(r, &in) != nil || len(in.Issuer) > 1000 || len(in.ClientID) > 256 || len(in.ClientSecret) > 8192 {
		fail(w, 400, "invalid_sso_configuration")
		return
	}
	if in.Enabled {
		u, e := url.Parse(in.Issuer)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || in.ClientID == "" {
			fail(w, 400, "https_issuer_and_client_id_required")
			return
		}
	}
	current, e := s.ssoConfig(r.Context())
	if e != nil {
		fail(w, 503, "sso_configuration_unavailable")
		return
	}
	if in.ClientSecret == "" && in.Enabled {
		if in.Issuer != current.Issuer || in.ClientID != current.ClientID {
			fail(w, 400, "new_provider_requires_client_secret")
			return
		}
		in.ClientSecret = current.ClientSecret
	}
	if in.Enabled && in.ClientSecret == "" {
		fail(w, 400, "client_secret_required")
		return
	}
	if !in.Enabled {
		in.ClientSecret = ""
	}
	raw, _ := json.Marshal(in)
	cipher, e := seal(s.cfg.EncryptionKey, "settings:oidc", raw)
	if e != nil {
		fail(w, 500, "sso_save_failed")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	if in.Revision == 0 {
		result, e = tx.ExecContext(r.Context(), "INSERT INTO system_settings(name,encrypted) VALUES('oidc',$1) ON CONFLICT DO NOTHING", cipher)
	} else {
		result, e = tx.ExecContext(r.Context(), "UPDATE system_settings SET encrypted=$1,revision=revision+1,updated_at=now() WHERE name='oidc' AND revision=$2", cipher, in.Revision)
	}
	if e != nil {
		fail(w, 500, "sso_save_failed")
		return
	}
	if n, _ := result.RowsAffected(); n == 0 {
		fail(w, 409, "sso_changed_reload")
		return
	}
	if _, e = tx.ExecContext(r.Context(), "DELETE FROM tickets WHERE kind='oidc'"); e != nil {
		fail(w, 500, "sso_save_failed")
		return
	}
	if audit(r.Context(), tx, actor(r).ID, "sso.updated", in.Issuer) != nil || tx.Commit() != nil {
		fail(w, 500, "sso_save_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	out, e := jsonRows(r.Context(), s.db, "SELECT to_jsonb(v) FROM configuration_versions v ORDER BY id DESC LIMIT 100")
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, out)
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("grantline_session")
	out, e := jsonRows(r.Context(), s.db, "SELECT jsonb_build_object('created_at',created_at,'expires_at',expires_at,'current',digest=$2,'mfa_pending',mfa_pending) FROM sessions WHERE user_id=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 100", actor(r).ID, digest(c.Value))
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, out)
}
func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) {
	s.revoke(w, r, actor(r).ID, true)
}
func (s *Server) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	s.revoke(w, r, r.PathValue("id"), false)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, id string, self bool) {
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var role string
	if tx.QueryRowContext(r.Context(), "SELECT role FROM users WHERE id=$1", id).Scan(&role) != nil {
		fail(w, 404, "user_not_found")
		return
	}
	if !self && role == "owner" && actor(r).Role != "owner" {
		fail(w, 403, "owner_required")
		return
	}
	keep := ""
	if self {
		c, _ := r.Cookie("grantline_session")
		keep = digest(c.Value)
	}
	if _, e = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=$1 AND digest<>$2", id, keep); e != nil || audit(r.Context(), tx, actor(r).ID, "sessions.revoked", id) != nil || tx.Commit() != nil {
		fail(w, 500, "session_revocation_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func recordVersion(ctx context.Context, tx *sql.Tx, kind, subject string, revision int, value any, actor string) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO configuration_versions(kind,subject,revision,configuration,actor_id) VALUES($1,$2,$3,$4,NULLIF($5,''))", kind, subject, revision, b, actor)
	return e
}

// RotateKey runs while the server is stopped. The caller supplies independently
// persisted old and new key files, then switches the deployment after commit.
func RotateKey(ctx context.Context, db *sql.DB, oldKey, newKey []byte) error {
	if len(oldKey) != 32 || len(newKey) != 32 {
		return errors.New("32-byte keys required")
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var acquired bool
	if e = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(714290005)").Scan(&acquired); e != nil || !acquired {
		return errors.New("stop the server before rotating the key")
	}
	for _, spec := range []struct{ table, id, column, label string }{{"integrations", "id", "credentials", "connection:"}, {"users", "id", "totp_secret", "totp:"}, {"system_settings", "name", "encrypted", "settings:"}, {"email_jobs", "id", "encrypted", "mail:"}} {
		rows, e := tx.QueryContext(ctx, "SELECT "+spec.id+","+spec.column+" FROM "+spec.table+" WHERE "+spec.column+" IS NOT NULL")
		if e != nil {
			return e
		}
		type entry struct {
			id     string
			cipher []byte
		}
		entries := []entry{}
		for rows.Next() {
			var v entry
			if e = rows.Scan(&v.id, &v.cipher); e != nil {
				rows.Close()
				return e
			}
			entries = append(entries, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, v := range entries {
			clear, e := unseal(oldKey, spec.label+v.id, v.cipher)
			if e != nil {
				return errors.New("old key cannot decrypt database; transaction aborted")
			}
			cipher, e := seal(newKey, spec.label+v.id, clear)
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE "+spec.table+" SET "+spec.column+"=$2 WHERE "+spec.id+"=$1", v.id, cipher); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM tickets WHERE kind='oidc'; DELETE FROM sessions"); e != nil {
		return e
	}
	if e = audit(ctx, tx, "", "encryption_key.rotated", ""); e != nil {
		return e
	}
	return tx.Commit()
}
