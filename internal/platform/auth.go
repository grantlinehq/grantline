package platform

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

func validEmail(s string) bool {
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && len(s) < 255
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token, Organization, Email, Name, Password string }
	if decode(r, &in) != nil || !validEmail(in.Email) || len(in.Organization) < 1 || len(in.Organization) > 100 || len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, 400, "invalid_setup")
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.Token), []byte(s.cfg.SetupToken)) != 1 {
		fail(w, 403, "setup_token_rejected")
		return
	}
	hash, e := passwordHash(in.Password)
	if e != nil {
		fail(w, 400, "password_requires_15_to_256_bytes")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(714290002)"); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	var n int
	if e = tx.QueryRowContext(r.Context(), "SELECT count(*) FROM workspace").Scan(&n); e != nil || n != 0 {
		fail(w, 409, "setup_complete")
		return
	}
	id := randomID()
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO workspace(id,name) VALUES(1,$1)", in.Organization); e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO users(id,email,name,role,password) VALUES($1,$2,$3,'owner',$4)", id, strings.ToLower(in.Email), in.Name, hash)
	}
	if e == nil {
		e = audit(r.Context(), tx, id, "workspace.created", "")
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "setup_failed")
		return
	}
	if e = s.issueSession(w, r, id, true); e != nil {
		fail(w, 500, "session_failed")
		return
	}
	send(w, 201, map[string]bool{"mfa_pending": true})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	var id, hash, role string
	var enabled bool
	e := s.db.QueryRowContext(r.Context(), "SELECT id,password,role,totp_enabled FROM users WHERE email=$1 AND NOT disabled", strings.ToLower(in.Email)).Scan(&id, &hash, &role, &enabled)
	if e != nil {
		hash = s.dummyHash
	}
	ok := passwordMatches(hash, in.Password)
	if e != nil || !ok {
		fail(w, 401, "credentials_not_accepted")
		return
	}
	pending := enabled || privileged(role)
	if e = s.issueSession(w, r, id, pending); e != nil {
		fail(w, 503, "session_unavailable")
		return
	}
	send(w, 200, map[string]bool{"mfa_pending": pending})
}
func (s *Server) enrollMFA(w http.ResponseWriter, r *http.Request) {
	u := actor(r)
	var encrypted []byte
	var enabled bool
	if e := s.db.QueryRowContext(r.Context(), "SELECT totp_secret,totp_enabled FROM users WHERE id=$1", u.ID).Scan(&encrypted, &enabled); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	if enabled {
		send(w, 200, map[string]bool{"enrolled": true})
		return
	}
	if len(encrypted) == 0 {
		cipher, e := seal(s.cfg.EncryptionKey, "totp:"+u.ID, []byte(newTOTP()))
		if e != nil {
			fail(w, 500, "mfa_unavailable")
			return
		}
		if _, e = s.db.ExecContext(r.Context(), "UPDATE users SET totp_secret=$2 WHERE id=$1 AND totp_secret IS NULL", u.ID, cipher); e != nil {
			fail(w, 500, "mfa_unavailable")
			return
		}
		if e = s.db.QueryRowContext(r.Context(), "SELECT totp_secret FROM users WHERE id=$1", u.ID).Scan(&encrypted); e != nil {
			fail(w, 500, "mfa_unavailable")
			return
		}
	}
	secret, e := unseal(s.cfg.EncryptionKey, "totp:"+u.ID, encrypted)
	if e != nil {
		fail(w, 503, "mfa_unavailable")
		return
	}
	send(w, 200, map[string]any{"enrolled": false, "secret": string(secret), "uri": "otpauth://totp/" + url.PathEscape("Grantline:"+u.Email) + "?secret=" + string(secret) + "&issuer=Grantline&algorithm=SHA1&digits=6&period=30"})
}
func (s *Server) verifyMFA(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	u := actor(r)
	var b []byte
	if e := s.db.QueryRowContext(r.Context(), "SELECT totp_secret FROM users WHERE id=$1", u.ID).Scan(&b); e != nil {
		fail(w, 401, "code_not_accepted")
		return
	}
	secret, e := unseal(s.cfg.EncryptionKey, "totp:"+u.ID, b)
	if e != nil {
		fail(w, 401, "code_not_accepted")
		return
	}
	step := totpStep(string(secret), in.Code, time.Now())
	if step == 0 {
		fail(w, 401, "code_not_accepted")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(r.Context(), "UPDATE users SET totp_enabled=true,totp_step=$2 WHERE id=$1 AND totp_step<$2", u.ID, step)
	if e != nil {
		fail(w, 500, "mfa_unavailable")
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		fail(w, 401, "code_already_used")
		return
	}
	c, _ := r.Cookie("grantline_session")
	if _, e = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE digest=$1", digest(c.Value)); e != nil {
		fail(w, 500, "mfa_unavailable")
		return
	}
	if e = audit(r.Context(), tx, u.ID, "session.mfa_verified", u.ID); e != nil || tx.Commit() != nil {
		fail(w, 500, "mfa_unavailable")
		return
	}
	if e = s.issueSession(w, r, u.ID, false); e != nil {
		fail(w, 500, "session_unavailable")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	out, e := jsonRows(r.Context(), s.db, "SELECT jsonb_build_object('id',id,'email',email,'name',name,'role',role,'disabled',disabled,'mfa_enabled',totp_enabled) FROM users ORDER BY name LIMIT 200")
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	send(w, 200, out)
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role     string
		Disabled bool
	}
	if decode(r, &in) != nil || !validRole(in.Role) {
		fail(w, 400, "invalid_role")
		return
	}
	u := actor(r)
	id := r.PathValue("id")
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(714290003)"); e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	var role string
	if e = tx.QueryRowContext(r.Context(), "SELECT role FROM users WHERE id=$1 FOR UPDATE", id).Scan(&role); e != nil {
		fail(w, 404, "user_not_found")
		return
	}
	if (role == "owner" || in.Role == "owner") && u.Role != "owner" {
		fail(w, 403, "owner_required")
		return
	}
	if role == "owner" && (in.Disabled || in.Role != "owner") {
		var n int
		if e = tx.QueryRowContext(r.Context(), "SELECT count(*) FROM users WHERE role='owner' AND NOT disabled AND id<>$1", id).Scan(&n); e != nil || n == 0 {
			fail(w, 409, "last_owner")
			return
		}
	}
	_, e = tx.ExecContext(r.Context(), "UPDATE users SET role=$2,disabled=$3 WHERE id=$1", id, in.Role, in.Disabled)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=$1", id)
	}
	if e == nil {
		e = audit(r.Context(), tx, u.ID, "user.updated", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "user_update_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func validRole(role string) bool {
	return role == "owner" || role == "admin" || role == "analyst" || role == "viewer"
}
func (s *Server) invite(w http.ResponseWriter, r *http.Request)   { s.ticket(w, r, "invite") }
func (s *Server) recovery(w http.ResponseWriter, r *http.Request) { s.ticket(w, r, "recovery") }
func (s *Server) ticket(w http.ResponseWriter, r *http.Request, kind string) {
	var in struct {
		Email, Role string
		SendEmail   bool `json:"send_email"`
	}
	if decode(r, &in) != nil || !validEmail(in.Email) {
		fail(w, 400, "invalid_email")
		return
	}
	in.Email = strings.ToLower(in.Email)
	if in.SendEmail && s.cfg.SMTPAddress == "" {
		fail(w, 400, "email_not_configured_use_a_link")
		return
	}
	u := actor(r)
	if kind == "invite" && (!validRole(in.Role) || in.Role == "owner") {
		fail(w, 400, "invite_role_must_be_admin_analyst_or_viewer")
		return
	}
	var existingRole string
	e := s.db.QueryRowContext(r.Context(), "SELECT role FROM users WHERE email=$1", in.Email).Scan(&existingRole)
	if kind == "invite" && e != sql.ErrNoRows {
		fail(w, 409, "account_exists")
		return
	}
	if kind == "recovery" && (e != nil || (existingRole == "owner" && u.Role != "owner")) {
		fail(w, 403, "recovery_unavailable")
		return
	}
	if kind == "recovery" {
		in.Role = existingRole
	}
	token := randomID()
	expiry := time.Now().Add(24 * time.Hour)
	if kind == "recovery" {
		expiry = time.Now().Add(30 * time.Minute)
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), "DELETE FROM tickets WHERE kind=$1 AND email=$2", kind, in.Email)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO tickets(digest,kind,email,role,expires_at) VALUES($1,$2,$3,$4,$5)", digest(token), kind, in.Email, in.Role, expiry)
	}
	if e == nil {
		e = audit(r.Context(), tx, u.ID, kind+".created", in.Email)
	}
	if e == nil && in.SendEmail {
		e = s.queueAccountEmail(r.Context(), tx, in.Email, kind, s.cfg.PublicURL+"/#accept/"+token)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "ticket_failed")
		return
	}
	link := s.cfg.PublicURL + "/#accept/" + token
	send(w, 201, map[string]any{"url": link, "expires_at": expiry, "email_queued": in.SendEmail})
}
func (s *Server) acceptTicket(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token, Name, Password string }
	if decode(r, &in) != nil || len(in.Name) < 1 || len(in.Name) > 100 {
		fail(w, 400, "invalid_request")
		return
	}
	hash, e := passwordHash(in.Password)
	if e != nil {
		fail(w, 400, "password_requires_15_to_256_bytes")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	var kind, email, role string
	if e = tx.QueryRowContext(r.Context(), "DELETE FROM tickets WHERE digest=$1 AND expires_at>now() AND kind IN ('invite','recovery') RETURNING kind,email,role", digest(in.Token)).Scan(&kind, &email, &role); e != nil {
		fail(w, 400, "link_expired_or_used")
		return
	}
	id := randomID()
	if kind == "invite" {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO users(id,email,name,role,password) VALUES($1,$2,$3,$4,$5)", id, email, in.Name, role, hash)
	} else {
		e = tx.QueryRowContext(r.Context(), "UPDATE users SET password=$2 WHERE email=$1 AND NOT disabled RETURNING id", email, hash).Scan(&id)
		if e == nil {
			_, e = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=$1", id)
		}
	}
	if e == nil {
		e = audit(r.Context(), tx, id, kind+".accepted", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 409, "account_update_failed")
		return
	}
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, Password string }
	if decode(r, &in) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	u := actor(r)
	var hash string
	if e := s.db.QueryRowContext(r.Context(), "SELECT password FROM users WHERE id=$1", u.ID).Scan(&hash); e != nil || !passwordMatches(hash, in.Current) {
		fail(w, 403, "credentials_not_accepted")
		return
	}
	next, e := passwordHash(in.Password)
	if e != nil {
		fail(w, 400, "password_requires_15_to_256_bytes")
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), "UPDATE users SET password=$2 WHERE id=$1", u.ID, next)
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=$1", u.ID)
	}
	if e == nil {
		e = audit(r.Context(), tx, u.ID, "password.changed", u.ID)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "password_change_failed")
		return
	}
	s.cookie(w, "", -1)
	send(w, 200, json.RawMessage(`{"ok":true}`))
}
