package platform

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Database tests create and remove only their own random schema. They never use public.
func testDatabase(t *testing.T) *sql.DB {
	return prepareTestDatabase(t, false)
}
func prepareTestDatabase(t *testing.T, retain bool) *sql.DB {
	t.Helper()
	dsn := os.Getenv("GRANTLINE_TEST_DATABASE_URL")
	if file := os.Getenv("GRANTLINE_TEST_DATABASE_URL_FILE"); file != "" {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal("test database file unavailable")
		}
		dsn = strings.TrimSpace(string(b))
	}
	if dsn == "" {
		t.Skip("set GRANTLINE_TEST_DATABASE_URL to run PostgreSQL acceptance")
	}
	root, e := Open(context.Background(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "acceptance_" + digest(randomID())[:16]
	if _, e = root.Exec("CREATE SCHEMA " + schema); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal("test URL invalid")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, e := Open(context.Background(), u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		db.Close()
		if !retain {
			root.Exec("DROP SCHEMA " + schema + " CASCADE")
		}
		root.Close()
	})
	if e = Migrate(context.Background(), db); e != nil {
		t.Fatal(e)
	}
	if e = Migrate(context.Background(), db); e != nil {
		t.Fatal("idempotent migration:", e)
	}
	return db
}

type testBrowser struct {
	t      *testing.T
	s      *Server
	cookie *http.Cookie
	csrf   string
	ip     string
}

func (b *testBrowser) request(method, path string, body any, want int) *httptest.ResponseRecorder {
	b.t.Helper()
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "http://127.0.0.1:8080/api/v1"+path, bytes.NewReader(data))
	r.RemoteAddr = b.ip + ":12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("X-Grantline-CSRF", b.csrf)
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	w := httptest.NewRecorder()
	b.s.ServeHTTP(w, r)
	if w.Code != want {
		b.t.Fatalf("%s %s: %d, want %d (%s)", method, path, w.Code, want, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "grantline_session" {
			b.cookie = c
			b.csrf = digest("csrf:" + c.Value)
		}
	}
	return w
}
func TestDatabaseAccountLifecycleAndRBAC(t *testing.T) {
	db := testDatabase(t)
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)}
	s, e := New(db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	owner := &testBrowser{t: t, s: s, ip: "192.0.2.1"}
	anonymous := &testBrowser{t: t, s: s, ip: "192.0.2.2"}
	anonymous.request("GET", "/overview", nil, 401)
	setup := map[string]any{"Token": cfg.SetupToken, "Organization": "Acceptance", "Email": "owner@example.test", "Name": "Owner", "Password": "an acceptance password phrase"}
	owner.request("POST", "/auth/setup", setup, 201)
	owner.request("GET", "/overview", nil, 403)
	var enrollment struct{ Secret string }
	json.Unmarshal(owner.request("GET", "/auth/mfa", nil, 200).Body.Bytes(), &enrollment)
	code := totpCode(enrollment.Secret, time.Now().Unix()/30)
	owner.request("POST", "/auth/mfa", map[string]string{"Code": code}, 200)
	owner.request("GET", "/overview", nil, 200)
	owner.request("POST", "/auth/mfa", map[string]string{"Code": code}, 401)
	anonymous.request("POST", "/auth/setup", setup, 409)
	var session struct{ User User }
	json.Unmarshal(owner.request("GET", "/auth/session", nil, 200).Body.Bytes(), &session)
	owner.request("PATCH", "/users/"+session.User.ID, map[string]any{"Role": "viewer", "Disabled": false}, 409)
	csrf := owner.csrf
	owner.csrf = "wrong"
	owner.request("POST", "/invitations", map[string]string{"Email": "v@example.test", "Role": "viewer"}, 403)
	owner.csrf = csrf
	var ticket struct{ URL string }
	json.Unmarshal(owner.request("POST", "/invitations", map[string]string{"Email": "v@example.test", "Role": "viewer"}, 201).Body.Bytes(), &ticket)
	token := strings.Split(ticket.URL, "/#accept/")[1]
	viewer := &testBrowser{t: t, s: s, ip: "192.0.2.3"}
	accept := map[string]string{"Token": token, "Name": "Viewer", "Password": "another acceptance password"}
	viewer.request("POST", "/auth/accept", accept, 200)
	viewer.request("POST", "/auth/accept", accept, 400)
	viewer.request("POST", "/auth/login", map[string]string{"Email": "v@example.test", "Password": "another acceptance password"}, 200)
	viewer.request("GET", "/overview", nil, 200)
	for _, path := range []string{"/invitations", "/recovery", "/integrations", "/runs", "/reports/import"} {
		viewer.request("POST", path, map[string]any{}, 403)
	}
	viewer.request("GET", "/settings", nil, 403)
	var v struct{ User User }
	json.Unmarshal(viewer.request("GET", "/auth/session", nil, 200).Body.Bytes(), &v)
	owner.request("PATCH", "/users/"+v.User.ID, map[string]any{"Role": "viewer", "Disabled": true}, 200)
	viewer.request("GET", "/overview", nil, 401)
	viewer.request("POST", "/auth/login", map[string]string{"Email": "v@example.test", "Password": "another acceptance password"}, 401)
	owner.request("POST", "/auth/logout", nil, 200)
	owner.request("GET", "/overview", nil, 401)
}

func TestDatabaseSingleWorkerAndRestartRecovery(t *testing.T) {
	db := testDatabase(t)
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)}
	s, e := New(db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO runs(id,kind,state,attempts) VALUES('interrupted-job','collection','running',1)"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, e := s.StartWorker(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var state string
	db.QueryRow("SELECT state FROM runs WHERE id='interrupted-job'").Scan(&state)
	if state != "queued" {
		t.Fatal("unfinished job not recovered")
	}
	other, _ := New(db, cfg)
	if _, e = other.StartWorker(ctx); e == nil {
		t.Fatal("two workers acquired lease")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker shutdown timed out")
	}
	if s.workerHealthy.Load() {
		t.Fatal("stopped worker marked ready")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2, e := other.StartWorker(ctx2)
	if e != nil {
		t.Fatal("lease not released")
	}
	cancel2()
	<-done2
}

func TestDatabaseEncryptedConnectionAndRevision(t *testing.T) {
	db := testDatabase(t)
	s, _ := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	db.Exec("INSERT INTO users(id,email,name,role) VALUES('owner','owner@example.test','Owner','owner')")
	token := randomID()
	db.Exec("INSERT INTO sessions(digest,user_id,expires_at) VALUES($1,'owner',now()+interval '1 hour')", digest(token))
	b := &testBrowser{t: t, s: s, ip: "192.0.2.1", cookie: &http.Cookie{Name: "grantline_session", Value: token}, csrf: digest("csrf:" + token)}
	body := map[string]any{"name": "Vault", "config": map[string]any{"auth_mode": "token", "source": map[string]any{"kind": "vault", "scope": "vault/test", "address": "https://vault.example.test", "policies": []string{"observer"}}}, "credentials": map[string]string{"token": "PRIVATE-TEST-CREDENTIAL"}, "enabled": false}
	var created struct{ ID string }
	json.Unmarshal(b.request("POST", "/integrations", body, 201).Body.Bytes(), &created)
	if strings.Contains(b.request("GET", "/integrations", nil, 200).Body.String(), "PRIVATE-TEST-CREDENTIAL") {
		t.Fatal("credential returned in API")
	}
	var cipher []byte
	db.QueryRow("SELECT credentials FROM integrations WHERE id=$1", created.ID).Scan(&cipher)
	if bytes.Contains(cipher, []byte("PRIVATE-TEST-CREDENTIAL")) {
		t.Fatal("plaintext stored")
	}
	_, creds, revision, e := s.connection(context.Background(), created.ID)
	if e != nil || creds["token"] != "PRIVATE-TEST-CREDENTIAL" || revision != 1 {
		t.Fatal("credential unavailable to collection")
	}
	delete(body, "credentials")
	body["revision"] = 1
	body["enabled"] = true
	b.request("PUT", "/integrations/"+created.ID, body, 201)
	b.request("PUT", "/integrations/"+created.ID, body, 409)
	b.request("POST", "/runs", map[string]any{}, 202)
	b.request("POST", "/runs", map[string]any{}, 409)
	// A failed access test must replace an older healthy test, without leaking credentials.
	if _, e := db.Exec("UPDATE integrations SET tested_at=now(),test_result='[{\"status\":\"ok\",\"complete\":true}]'"); e != nil {
		t.Fatal(e)
	}
	s.cfg.CustomCA = "/nonexistent-grantline-acceptance-ca.pem"
	b.request("POST", "/integrations/"+created.ID+"/test", map[string]any{}, 422)
	var outcome string
	if e := db.QueryRow("SELECT test_result->0->>'status' FROM integrations WHERE id=$1", created.ID).Scan(&outcome); e != nil || outcome != "error" {
		t.Fatal("failed test left a stale healthy result")
	}
	b.request("DELETE", "/integrations/"+created.ID, nil, 200)
	if _, _, _, e = s.connection(context.Background(), created.ID); e == nil {
		t.Fatal("deleted credentials still usable")
	}
}
