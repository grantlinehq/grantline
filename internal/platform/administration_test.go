package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Seed only the disposable acceptance schema; normal setup/MFA is covered separately.
func databaseBrowser(t *testing.T, s *Server, role string) *testBrowser {
	t.Helper()
	id, token := randomID(), randomID()
	if _, e := s.db.Exec("INSERT INTO users(id,email,name,role) VALUES($1,$2,'Acceptance',$3)", id, strings.ToLower(id)+"@example.test", role); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("INSERT INTO sessions(digest,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')", digest(token), id); e != nil {
		t.Fatal(e)
	}
	return &testBrowser{t: t, s: s, ip: "192.0.2.10", cookie: &http.Cookie{Name: "grantline_session", Value: token}, csrf: digest("csrf:" + token)}
}

func TestDatabaseSSORolesRevisionAndKeyRotation(t *testing.T) {
	db := testDatabase(t)
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)}
	s, e := New(db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	owner, admin := databaseBrowser(t, s, "owner"), databaseBrowser(t, s, "admin")
	body := map[string]any{"issuer": "https://id.example.test", "client_id": "grantline", "client_secret": "acceptance-client-secret", "enabled": true, "revision": 0}
	admin.request("PUT", "/settings/sso", body, 403)
	owner.request("PUT", "/settings/sso", body, 200)
	owner.request("PUT", "/settings/sso", body, 409)
	if strings.Contains(owner.request("GET", "/settings/sso", nil, 200).Body.String(), "acceptance-client-secret") {
		t.Fatal("SSO secret returned")
	}
	body["revision"] = 1
	delete(body, "client_secret")
	owner.request("PUT", "/settings/sso", body, 200)
	before, e := s.ssoConfig(context.Background())
	if e != nil || before.ClientSecret != "acceptance-client-secret" || before.Revision != 2 {
		t.Fatal("secret/revision not retained")
	}
	bad := cfg
	bad.EncryptionKey = randomBytes(32)
	if _, e = New(db, bad); e == nil {
		t.Fatal("wrong key accepted at startup")
	}
	if e = RotateKey(context.Background(), db, bad.EncryptionKey, randomBytes(32)); e == nil {
		t.Fatal("rotation accepted wrong old key")
	}
	if e = s.checkEncryptionKey(context.Background()); e != nil {
		t.Fatal("failed rotation changed data")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, e := s.StartWorker(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = RotateKey(context.Background(), db, cfg.EncryptionKey, bad.EncryptionKey); e == nil {
		t.Fatal("rotated while server active")
	}
	cancel()
	<-done
	if e = RotateKey(context.Background(), db, cfg.EncryptionKey, bad.EncryptionKey); e != nil {
		t.Fatal(e)
	}
	if _, e = New(db, cfg); e == nil {
		t.Fatal("old key still accepted")
	}
	rotated, e := New(db, bad)
	if e != nil {
		t.Fatal(e)
	}
	after, e := rotated.ssoConfig(context.Background())
	if e != nil || after != before {
		t.Fatal("SSO configuration changed on rotation")
	}
	owner.request("GET", "/overview", nil, 401)
}

func TestDatabaseWorkspaceRolesAndRecoveryQueue(t *testing.T) {
	db := testDatabase(t)
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32), SMTPAddress: "mail.example.test:465", SMTPFrom: "grantline@example.test"}
	s, e := New(db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	owner, admin := databaseBrowser(t, s, "owner"), databaseBrowser(t, s, "admin")
	if _, e = db.Exec("INSERT INTO workspace(id,name) VALUES(1,'Acceptance')"); e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"Name": "Changed", "schedule_minutes": 60, "retention_days": 30, "Revision": 1}
	admin.request("PUT", "/settings", body, 403)
	body["Name"] = "Acceptance"
	admin.request("PUT", "/settings", body, 200)
	owner.request("PUT", "/settings", body, 409)
	if bytes.Equal(owner.request("GET", "/settings/versions", nil, 200).Body.Bytes(), []byte("[]\n")) {
		t.Fatal("no configuration version recorded")
	}
	var current struct{ User User }
	json.Unmarshal(owner.request("GET", "/auth/session", nil, 200).Body.Bytes(), &current)
	anonymous := &testBrowser{t: t, s: s, ip: "192.0.2.30"}
	unknown := anonymous.request("POST", "/auth/forgot", map[string]string{"Email": "absent@example.test"}, 202).Body.String()
	known := anonymous.request("POST", "/auth/forgot", map[string]string{"Email": current.User.Email}, 202).Body.String()
	if known != unknown {
		t.Fatal("recovery exposes account membership")
	}
	anonymous.request("POST", "/auth/forgot", map[string]string{"Email": current.User.Email}, 202)
	var count int
	db.QueryRow("SELECT count(*) FROM email_jobs").Scan(&count)
	if count != 1 {
		t.Fatalf("recovery queue count %d", count)
	}
	var id string
	var cipher []byte
	db.QueryRow("SELECT id,encrypted FROM email_jobs").Scan(&id, &cipher)
	if bytes.Contains(cipher, []byte(current.User.Email)) {
		t.Fatal("mail stored as plaintext")
	}
	plain, e := unseal(cfg.EncryptionKey, "mail:"+id, cipher)
	if e != nil {
		t.Fatal(e)
	}
	var mail accountMail
	json.Unmarshal(plain, &mail)
	token := strings.Split(mail.Link, "/#accept/")[1]
	anonymous.request("POST", "/auth/accept", map[string]string{"Token": token, "Name": "Owner", "Password": "new recovery acceptance phrase"}, 200)
	owner.request("GET", "/overview", nil, 401)
	anonymous.request("POST", "/auth/login", map[string]string{"Email": current.User.Email, "Password": "new recovery acceptance phrase"}, 200)
	anonymous.request("GET", "/overview", nil, 403) // Owner still requires MFA after recovery.
}

func TestDatabaseTriageIndependentOfCollectionCoverage(t *testing.T) {
	db := testDatabase(t)
	s, e := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if e != nil {
		t.Fatal(e)
	}
	analyst, viewer := databaseBrowser(t, s, "analyst"), databaseBrowser(t, s, "viewer")
	// Minimal indexed fixture deliberately isolates triage from report serialization.
	if _, e = db.Exec(`INSERT INTO runs(id,kind,state) VALUES('first','import','completed'); INSERT INTO reports(run_id,report) VALUES('first','{}'); INSERT INTO objects(run_id,category,id,body) VALUES('first','findings','finding','{"id":"finding"}')`); e != nil {
		t.Fatal(e)
	}
	review := map[string]any{"State": "accepted_risk", "Revision": 0}
	viewer.request("PUT", "/triage/finding", review, 403)
	analyst.request("PUT", "/triage/finding", review, 400)
	review["Reason"] = "Compensating control, reviewed in ticket SEC-42"
	review["expires_at"] = time.Now().Add(time.Hour).UTC()
	analyst.request("PUT", "/triage/finding", review, 200)
	analyst.request("PUT", "/triage/finding", review, 409)
	analyst.request("POST", "/comments/finding", map[string]string{"Body": "Review retained independently from source availability."}, 201)
	if _, e = db.Exec(`INSERT INTO runs(id,kind,state) VALUES('incomplete','collection','partial'); INSERT INTO reports(run_id,report) VALUES('incomplete','{}')`); e != nil {
		t.Fatal(e)
	}
	var state string
	db.QueryRow("SELECT state FROM triage WHERE finding_id='finding'").Scan(&state)
	if state != "accepted_risk" {
		t.Fatal("incomplete collection changed triage")
	}
	var detail struct{ Comments []any }
	json.Unmarshal(analyst.request("GET", "/objects/findings/finding?run=first", nil, 200).Body.Bytes(), &detail)
	if len(detail.Comments) != 1 {
		t.Fatal("comment missing")
	}
}
