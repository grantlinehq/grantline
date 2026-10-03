package platform

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/grantlinehq/grantline/web"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

type Config struct {
	Version                                           string
	PublicURL                                         string
	DatabaseURL                                       string
	EncryptionKey                                     []byte
	SetupToken                                        string
	SecretDir                                         string
	OIDCIssuer, OIDCClientID, OIDCClientSecret        string
	CustomCA                                          string
	TrustedProxies                                    []netip.Prefix
	SMTPAddress, SMTPUsername, SMTPPassword, SMTPFrom string
}
type Server struct {
	db            *sql.DB
	cfg           Config
	mux           *http.ServeMux
	dummyHash     string
	authSlots     chan struct{}
	previewSlots  chan struct{}
	workerHealthy atomic.Bool
}
type User struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	MFAPending bool   `json:"mfa_pending"`
	Disabled   bool   `json:"disabled"`
}
type actorKey struct{}

//go:embed openapi.json
var openAPI []byte

func actor(r *http.Request) User  { u, _ := r.Context().Value(actorKey{}).(User); return u }
func privileged(role string) bool { return role == "owner" || role == "admin" }
func New(db *sql.DB, cfg Config) (*Server, error) {
	u, e := url.Parse(cfg.PublicURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("public URL must be an origin")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost")) {
		return nil, errors.New("HTTPS is required except for loopback development")
	}
	if len(cfg.EncryptionKey) != 32 || len(cfg.SetupToken) < 32 {
		return nil, errors.New("32-byte encryption key and setup token required")
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if cfg.Version == "" {
		cfg.Version = "v0.1.0-dev"
	}
	s := &Server{db: db, cfg: cfg, mux: http.NewServeMux(), authSlots: make(chan struct{}, 4), previewSlots: make(chan struct{}, 1)}
	check, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := s.checkEncryptionKey(check)
	cancel()
	if err != nil {
		return nil, err
	}
	s.dummyHash, _ = passwordHash(randomID())
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { send(w, 200, map[string]string{"status": "ok"}) })
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var version int
		if e := db.QueryRowContext(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); e != nil || version != databaseVersion || !s.workerHealthy.Load() {
			fail(w, 503, "not_ready")
			return
		}
		send(w, 200, map[string]string{"status": "ready"})
	})
	s.mux.HandleFunc("GET /api/v1/status", s.status)
	s.mux.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) { send(w, 200, json.RawMessage(openAPI)) })
	s.mux.HandleFunc("POST /api/v1/auth/setup", s.authBound(s.setup))
	s.mux.HandleFunc("POST /api/v1/auth/login", s.authBound(s.login))
	s.mux.HandleFunc("POST /api/v1/auth/accept", s.authBound(s.acceptTicket))
	s.mux.HandleFunc("POST /api/v1/auth/forgot", s.authBound(s.forgotPassword))
	s.mux.HandleFunc("GET /api/v1/auth/session", s.auth(s.session, true))
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.auth(s.logout, true))
	s.mux.HandleFunc("GET /api/v1/auth/mfa", s.auth(s.enrollMFA, true))
	s.mux.HandleFunc("POST /api/v1/auth/mfa", s.auth(s.authBound(s.verifyMFA), true))
	s.mux.HandleFunc("POST /api/v1/auth/password", s.auth(s.authBound(s.changePassword), false))
	s.mux.HandleFunc("GET /api/v1/users", s.auth(s.users, false))
	s.mux.HandleFunc("PATCH /api/v1/users/{id}", s.require("admin", s.updateUser))
	s.mux.HandleFunc("POST /api/v1/invitations", s.require("admin", s.invite))
	s.mux.HandleFunc("POST /api/v1/recovery", s.require("admin", s.recovery))
	s.registerData()
	s.registerIntegrations()
	s.registerOIDC()
	s.registerAdministration()
	assets, _ := fs.Sub(web.Assets, "dist")
	files := http.FileServer(http.FS(assets))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fail(w, 404, "not_found")
			return
		}
		if r.URL.Path == "/docs" {
			http.Redirect(w, r, "/docs/", http.StatusPermanentRedirect)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/docs/") {
			name := strings.TrimPrefix(r.URL.Path, "/")
			if strings.HasSuffix(name, "/") {
				name += "index.html"
			}
			if !fs.ValidPath(name) {
				fail(w, 404, "not_found")
				return
			}
			b, err := fs.ReadFile(assets, name)
			if err != nil {
				fail(w, 404, "documentation_not_found")
				return
			}
			if strings.HasSuffix(name, ".html") {
				// Hash only trusted, compiled documentation scripts; no unsafe-inline scripts.
				csp := w.Header().Get("Content-Security-Policy")
				hashes := ""
				for _, script := range regexp.MustCompile(`(?s)<script(?:\s[^>]*)?>(.*?)</script>`).FindAllSubmatch(b, -1) {
					if len(script[1]) > 0 {
						hash := sha256.Sum256(script[1])
						hashes += " 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
					}
				}
				csp = strings.Replace(csp, "script-src 'self'", "script-src 'self'"+hashes, 1)
				// VitePress renders trusted theme style attributes for syntax highlighting.
				csp = strings.Replace(csp, "style-src 'self'", "style-src 'self' 'unsafe-inline'", 1)
				w.Header().Set("Content-Security-Policy", csp)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(b)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			fail(w, 404, "not_found")
			return
		}
		if v, err := fs.Stat(assets, name); err != nil || v.IsDir() {
			clone := r.Clone(r.Context())
			clone.URL.Path = "/"
			files.ServeHTTP(w, clone)
			return
		}
		files.ServeHTTP(w, r)
	})
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if strings.HasPrefix(s.cfg.PublicURL, "https:") {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
		origin, _ := url.Parse(s.cfg.PublicURL)
		if r.Host != origin.Host {
			fail(w, 403, "host_rejected")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && (r.Header.Get("Origin") != s.cfg.PublicURL || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
			fail(w, 403, "origin_rejected")
			return
		}
	}
	limit := int64(2 << 20)
	if r.URL.Path == "/api/v1/reports/import" {
		limit = 64 << 20
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/integrations") {
		limit = 12 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	s.mux.ServeHTTP(w, r)
}
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string) {
	send(w, status, map[string]string{"error": code})
}
func decode(r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return errors.New("JSON required")
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}
func (s *Server) auth(next http.HandlerFunc, pending bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("grantline_session")
		if e != nil {
			fail(w, 401, "sign_in_required")
			return
		}
		var u User
		e = s.db.QueryRowContext(r.Context(), "SELECT u.id,u.email,u.name,u.role,s.mfa_pending FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.digest=$1 AND s.expires_at>now() AND NOT u.disabled", digest(c.Value)).Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.MFAPending)
		if e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				fail(w, 401, "sign_in_required")
			} else {
				fail(w, 503, "database_unavailable")
			}
			return
		}
		if u.MFAPending && !pending {
			fail(w, 403, "mfa_required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-Grantline-CSRF") != digest("csrf:"+c.Value) {
			fail(w, 403, "csrf_rejected")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, u)))
	}
}
func (s *Server) require(role string, next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		u := actor(r)
		allowed := u.Role == "owner" || u.Role == role || (role == "analyst" && u.Role == "admin")
		if !allowed {
			fail(w, 403, "role_required")
			return
		}
		next(w, r)
	}, false)
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	var name string
	e := s.db.QueryRowContext(r.Context(), "SELECT name FROM workspace WHERE id=1").Scan(&name)
	if e != nil && e != sql.ErrNoRows {
		fail(w, 503, "database_unavailable")
		return
	}
	sso, err := s.ssoConfig(r.Context())
	if err != nil {
		fail(w, 503, "configuration_unavailable")
		return
	}
	send(w, 200, map[string]any{"mode": "server", "setup_required": e == sql.ErrNoRows, "organization": name, "oidc_enabled": sso.Enabled, "email_enabled": s.cfg.SMTPAddress != "", "version": s.cfg.Version})
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("grantline_session")
	send(w, 200, map[string]any{"user": actor(r), "csrf": digest("csrf:" + c.Value)})
}
func (s *Server) cookie(w http.ResponseWriter, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{Name: "grantline_session", Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.PublicURL, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, id string, pending bool) error {
	token := randomID()
	duration := 8 * time.Hour
	if pending {
		duration = 10 * time.Minute
	}
	if _, e := s.db.ExecContext(r.Context(), "INSERT INTO sessions(digest,user_id,mfa_pending,expires_at) VALUES($1,$2,$3,$4)", digest(token), id, pending, time.Now().Add(duration)); e != nil {
		return e
	}
	s.cookie(w, token, int(duration.Seconds()))
	return nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("grantline_session")
	if _, e := s.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE digest=$1", digest(c.Value)); e != nil {
		fail(w, 500, "logout_failed")
		return
	}
	s.cookie(w, "", -1)
	send(w, 200, map[string]bool{"ok": true})
}
func (s *Server) authBound(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.authSlots <- struct{}{}:
			defer func() { <-s.authSlots }()
		default:
			fail(w, 429, "try_again_later")
			return
		}
		host := s.clientAddress(r)
		bucket := digest("auth:" + host)
		var count int
		e := s.db.QueryRowContext(r.Context(), `INSERT INTO auth_attempts(bucket,failures,until_at) VALUES($1,1,now()+interval '5 minutes') ON CONFLICT(bucket) DO UPDATE SET failures=CASE WHEN auth_attempts.until_at<now() THEN 1 ELSE auth_attempts.failures+1 END,until_at=CASE WHEN auth_attempts.until_at<now() THEN now()+interval '5 minutes' ELSE auth_attempts.until_at END RETURNING failures`, bucket).Scan(&count)
		if e != nil {
			fail(w, 503, "authentication_unavailable")
			return
		}
		if count > 60 {
			w.Header().Set("Retry-After", "300")
			fail(w, 429, "try_again_later")
			return
		}
		next(w, r)
	}
}
func (s *Server) secretReference(name string) ([]byte, error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." || s.cfg.SecretDir == "" {
		return nil, errors.New("invalid secret reference")
	}
	root, e := os.OpenRoot(s.cfg.SecretDir)
	if e != nil {
		return nil, errors.New("secret reference unavailable")
	}
	defer root.Close()
	f, e := root.Open(name)
	if e != nil {
		return nil, errors.New("secret reference unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (12<<20)+1))
	if e != nil || len(b) > 12<<20 {
		return nil, errors.New("secret reference exceeds limit")
	}
	return b, nil
}

// Ignore forwarding headers unless the immediate peer and each proxy hop are trusted.
func (s *Server) clientAddress(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	trusted := func(value string) bool {
		ip, e := netip.ParseAddr(value)
		if e != nil {
			return false
		}
		for _, p := range s.cfg.TrustedProxies {
			if p.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if !trusted(host) {
		return host
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(chain) > 16 {
		return host
	}
	for i := len(chain) - 1; i >= 0; i-- {
		value := strings.TrimSpace(chain[i])
		if _, e := netip.ParseAddr(value); e != nil {
			return host
		}
		host = value
		if !trusted(value) {
			break
		}
	}
	return host
}
