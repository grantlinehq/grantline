package viewer

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/web"
	"io"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const CookieName = "grantline_session"

func Token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Address(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("viewer must bind to literal 127.0.0.1")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid viewer port")
	}
	return nil
}
func strictJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func sortEdges(edges []model.Relationship) {
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
}

type Server struct {
	report      model.Report
	host, token string
	mu          sync.Mutex
	sessions    map[string]time.Time
	failures    int
	retryAt     time.Time
	assets      http.Handler
}

func New(r model.Report, host, token string) (http.Handler, error) {
	if err := Address(host); err != nil {
		return nil, err
	}
	if len(token) < 43 {
		return nil, fmt.Errorf("access code requires at least 256 bits")
	}
	if err := Validate(r); err != nil {
		return nil, err
	}
	assets, err := fs.Sub(web.Assets, "dist")
	if err != nil {
		return nil, err
	}
	return &Server{report: r, host: host, token: token, sessions: map[string]time.Time{}, assets: http.FileServer(http.FS(assets))}, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if r.Host != s.host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+s.host) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Origin or host rejected", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" && r.URL.Path != "/api/graph" {
		http.Error(w, "Unexpected query", 400)
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Origin") != "http://"+s.host {
			http.Error(w, "Origin required", 403)
			return
		}
		if r.URL.Path == "/api/session" {
			s.login(w, r)
			return
		}
		if r.URL.Path == "/api/logout" {
			s.logout(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	// The shared frontend probes this endpoint to distinguish the persistent
	// workspace from the local report viewer before showing its unlock form.
	if r.URL.Path == "/api/v1/status" {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if !s.authorized(r) {
			http.Error(w, "Unlock this local report to continue", 401)
			return
		}
		switch r.URL.Path {
		case "/api/session":
			s.json(w, map[string]bool{"authenticated": true})
		case "/api/report", "/api/report/download":
			if r.URL.Path == "/api/report/download" {
				h.Set("Content-Disposition", `attachment; filename="grantline-report.json"`)
			}
			s.json(w, s.report)
		case "/api/graph":
			q := r.URL.Query()
			for k, v := range q {
				if (k != "entity" && k != "depth" && k != "assertion" && k != "type") || len(v) != 1 {
					http.Error(w, "Invalid graph filter", 400)
					return
				}
			}
			depth := 1
			if q.Get("depth") != "" {
				n, err := strconv.Atoi(q.Get("depth"))
				if err != nil || n < 1 || n > 2 {
					http.Error(w, "Depth must be 1 or 2", 400)
					return
				}
				depth = n
			}
			s.json(w, Graph(s.report.Snapshot, q.Get("entity"), q.Get("assertion"), q.Get("type"), depth))
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" {
		name := "dist" + r.URL.Path
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(web.Assets, name)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
	}
	s.assets.ServeHTTP(w, r)
}
func (s *Server) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
func (s *Server) authorized(r *http.Request) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if !time.Now().Before(until) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "JSON required", 415)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	var input struct {
		Token string `json:"token"`
	}
	if err != nil || strictJSON(body, &input) != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Before(s.retryAt) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Please wait before trying again", 429)
		return
	}
	if subtle.ConstantTimeCompare([]byte(input.Token), []byte(s.token)) != 1 {
		s.failures++
		if s.failures >= 5 {
			s.retryAt = now.Add(30 * time.Second)
			s.failures = 0
		}
		http.Error(w, "Access code not accepted", 401)
		return
	}
	session, err := Token()
	if err != nil {
		http.Error(w, "Session unavailable", 500)
		return
	}
	for id, until := range s.sessions {
		if now.After(until) {
			delete(s.sessions, id)
		}
	}
	if len(s.sessions) >= 32 {
		http.Error(w, "Session limit reached", 429)
		return
	}
	s.sessions[session] = now.Add(8 * time.Hour)
	s.failures = 0
	// This legacy viewer only accepts literal 127.0.0.1 over HTTP (Address and
	// ServeHTTP enforce it). Secure would break that supported local-only flow.
	// Network deployments use grantline server with HTTPS and Secure cookies.
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 60 * 60})
	s.json(w, map[string]bool{"authenticated": true})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "Session required", 401)
		return
	}
	c, _ := r.Cookie(CookieName)
	s.mu.Lock()
	delete(s.sessions, c.Value)
	s.mu.Unlock()
	// Match the loopback-only login cookie; see the documented viewer exception.
	http.SetCookie(w, &http.Cookie{Name: CookieName, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
