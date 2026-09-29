package platform

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in restore rehearsal. The harness retains only a disposable random schema
// and an independently mounted key file, then verifies a pg_dump/pg_restore copy.
type backupFixture struct {
	Schema string
	Key    []byte
}

func TestDatabaseBackupSeed(t *testing.T) {
	dir := os.Getenv("GRANTLINE_TEST_BACKUP_DIR")
	if dir == "" {
		t.Skip("opt-in backup rehearsal")
	}
	db := prepareTestDatabase(t, true)
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)}
	s, e := New(db, cfg)
	if e != nil {
		t.Fatal(e)
	}
	b := databaseBrowser(t, s, "owner")
	hash, e := passwordHash("backup rehearsal password phrase")
	if e != nil {
		t.Fatal(e)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // Public RFC 6238 test vector. gitleaks:allow
	var id string
	db.QueryRow("SELECT id FROM users LIMIT 1").Scan(&id)
	encrypted, e := seal(cfg.EncryptionKey, "totp:"+id, []byte(secret))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("UPDATE users SET email='restore-owner@example.test',password=$1,totp_secret=$2,totp_enabled=true", hash, encrypted); e != nil {
		t.Fatal(e)
	}
	b.request("POST", "/integrations", map[string]any{"name": "Restore fixture", "config": map[string]any{"auth_mode": "token", "source": map[string]any{"kind": "vault", "scope": "vault/restore-fixture", "address": "https://vault.example.test", "policies": []string{"observer"}}}, "credentials": map[string]string{"token": "restore-fixture-not-a-provider-token"}, "enabled": false}, 201)
	if _, e = db.Exec(`INSERT INTO workspace(id,name) VALUES(1,'Restore acceptance'); INSERT INTO runs(id,kind,state) VALUES('preserved-report','import','completed'); INSERT INTO reports(run_id,report) VALUES('preserved-report','{"sentinel":"immutable-evidence"}'); INSERT INTO triage(finding_id,state,reason,expires_at) VALUES('preserved-review','accepted_risk','Restore acceptance',now()+interval '1 day')`); e != nil {
		t.Fatal(e)
	}
	var schema string
	db.QueryRow("SELECT current_schema()").Scan(&schema)
	data, _ := json.Marshal(backupFixture{schema, cfg.EncryptionKey})
	if e = os.WriteFile(filepath.Join(dir, "fixture.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("Seeded a disposable schema with password, TOTP, encrypted connection, report, triage and audit.")
}

func TestDatabaseBackupRestored(t *testing.T) {
	dir := os.Getenv("GRANTLINE_TEST_BACKUP_DIR")
	if dir == "" {
		t.Skip("opt-in backup rehearsal")
	}
	data, e := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if e != nil {
		t.Fatal(e)
	}
	var fixture backupFixture
	if json.Unmarshal(data, &fixture) != nil {
		t.Fatal("fixture state unavailable")
	}
	if !strings.HasPrefix(fixture.Schema, "acceptance_") {
		t.Fatal("not an acceptance schema")
	}
	dsn := os.Getenv("GRANTLINE_TEST_DATABASE_URL")
	if file := os.Getenv("GRANTLINE_TEST_DATABASE_URL_FILE"); file != "" {
		v, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		dsn = strings.TrimSpace(string(v))
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", fixture.Schema)
	u.RawQuery = q.Encode()
	db, e := Open(context.Background(), u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = Migrate(context.Background(), db); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: fixture.Key})
	if e != nil {
		t.Fatal(e)
	}
	b := &testBrowser{t: t, s: s, ip: "192.0.2.44"}
	b.request("POST", "/auth/login", map[string]string{"Email": "restore-owner@example.test", "Password": "backup rehearsal password phrase"}, 200)
	b.request("GET", "/overview", nil, 403)
	b.request("POST", "/auth/mfa", map[string]string{"Code": totpCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Now().Unix()/30)}, 200)
	var id string
	db.QueryRow("SELECT id FROM integrations LIMIT 1").Scan(&id)
	_, credentials, _, e := s.connection(context.Background(), id)
	if e != nil || credentials["token"] != "restore-fixture-not-a-provider-token" {
		t.Fatal("restored connection cannot decrypt")
	}
	var sentinel, state string
	db.QueryRow("SELECT report->>'sentinel' FROM reports WHERE run_id='preserved-report'").Scan(&sentinel)
	db.QueryRow("SELECT state FROM triage WHERE finding_id='preserved-review'").Scan(&state)
	if sentinel != "immutable-evidence" || state != "accepted_risk" {
		t.Fatal("report/review not restored")
	}
	t.Log("Restored password+TOTP sign-in, connection decryption, report and review verified with the separately retained key.")
}
