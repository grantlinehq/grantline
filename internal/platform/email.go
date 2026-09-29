package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// SMTP uses implicit verified TLS (normally port 465); plaintext mail is not supported.
func (s *Server) sendAccountEmail(ctx context.Context, email, kind, link string) error {
	host, _, e := net.SplitHostPort(s.cfg.SMTPAddress)
	if e != nil || !validEmail(s.cfg.SMTPFrom) || !validEmail(email) {
		return errors.New("email configuration invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	raw, e := s.dial(ctx, "tcp", s.cfg.SMTPAddress)
	if e != nil {
		return errors.New("email unavailable")
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if s.cfg.CustomCA != "" {
		b, e := os.ReadFile(s.cfg.CustomCA)
		if e != nil || !roots.AppendCertsFromPEM(b) {
			return errors.New("email CA unavailable")
		}
	}
	connection := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if connection.HandshakeContext(ctx) != nil {
		return errors.New("email TLS unavailable")
	}
	client, e := smtp.NewClient(connection, host)
	if e != nil {
		return errors.New("email unavailable")
	}
	defer client.Close()
	if s.cfg.SMTPUsername != "" && client.Auth(smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, host)) != nil {
		return errors.New("email authentication unavailable")
	}
	subject := "Your Grantline invitation"
	if kind == "recovery" {
		subject = "Reset your Grantline password"
	}
	if client.Mail(s.cfg.SMTPFrom) != nil || client.Rcpt(email) != nil {
		return errors.New("email recipient unavailable")
	}
	body, e := client.Data()
	if e != nil {
		return errors.New("email delivery unavailable")
	}
	_, e = body.Write([]byte("From: Grantline <" + s.cfg.SMTPFrom + ">\r\nTo: " + email + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nOpen this single-use account link in your browser:\r\n\r\n" + link + "\r\n\r\nIf you did not expect this message, contact your workspace administrator.\r\n"))
	closeErr := body.Close()
	if e != nil || closeErr != nil || client.Quit() != nil {
		return errors.New("email delivery unavailable")
	}
	return nil
}
func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email string }
	if decode(r, &in) != nil || !validEmail(in.Email) {
		fail(w, 400, "invalid_email")
		return
	}
	email := strings.ToLower(in.Email)
	// Identical public responses prevent disclosing account membership.
	respond := func() { send(w, 202, map[string]bool{"ok": true}) }
	if s.cfg.SMTPAddress == "" {
		respond()
		return
	}
	var exists bool
	if s.db.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND NOT disabled)", email).Scan(&exists) != nil || !exists {
		respond()
		return
	}
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		respond()
		return
	}
	defer tx.Rollback()
	// A single outstanding recovery link limits unsolicited mail and preserves a valid link.
	if _, e = tx.ExecContext(r.Context(), "SELECT pg_advisory_xact_lock(hashtextextended($1,714290006))", email); e != nil {
		respond()
		return
	}
	var pending bool
	if tx.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM tickets WHERE email=$1 AND kind='recovery' AND expires_at>now())", email).Scan(&pending) != nil || pending {
		respond()
		return
	}
	token := randomID()
	if _, e = tx.ExecContext(r.Context(), "INSERT INTO tickets(digest,kind,email,expires_at) VALUES($1,'recovery',$2,now()+interval '30 minutes')", digest(token), email); e != nil || s.queueAccountEmail(r.Context(), tx, email, "recovery", s.cfg.PublicURL+"/#accept/"+token) != nil || audit(r.Context(), tx, "", "recovery.requested", email) != nil || tx.Commit() != nil {
		respond()
		return
	}
	respond()
}

type accountMail struct{ Email, Kind, Link string }

func (s *Server) queueAccountEmail(ctx context.Context, tx *sql.Tx, email, kind, link string) error {
	id := randomID()
	b, _ := json.Marshal(accountMail{email, kind, link})
	cipher, e := seal(s.cfg.EncryptionKey, "mail:"+id, b)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO email_jobs(id,encrypted) VALUES($1,$2)", id, cipher)
	return e
}
func (s *Server) deliverEmail(ctx context.Context) {
	var id string
	var cipher []byte
	var attempts int
	if s.db.QueryRowContext(ctx, "SELECT id,encrypted,attempts FROM email_jobs WHERE state='queued' AND next_attempt<=now() ORDER BY created_at LIMIT 1").Scan(&id, &cipher, &attempts) != nil {
		return
	}
	clear, e := unseal(s.cfg.EncryptionKey, "mail:"+id, cipher)
	var value accountMail
	state := "sent"
	if e != nil || json.Unmarshal(clear, &value) != nil || s.sendAccountEmail(ctx, value.Email, value.Kind, value.Link) != nil {
		state = "queued"
		if attempts >= 2 {
			state = "failed"
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "UPDATE email_jobs SET state=$2,attempts=attempts+1,next_attempt=now()+interval '1 minute',finished_at=CASE WHEN $2='queued' THEN NULL ELSE now() END WHERE id=$1", id, state); e != nil {
		return
	}
	if state != "queued" {
		if audit(ctx, tx, "", "email."+state, id) != nil {
			return
		}
	}
	tx.Commit()
}
