package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
)

func TestDatabaseCollectionCallsProviderAndRecordsFailure(t *testing.T) {
	db := testDatabase(t)
	var calls atomic.Int32
	var denied atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Vault-Token") != "private-observer-token" {
			t.Error("missing observer credential")
		}
		if denied.Load() {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/sys/policies/acl/metadata-only" {
			t.Error("unexpected provider request", r.URL.Path)
		}
		w.Write([]byte(`{"data":{"name":"metadata-only","policy":"path \"*\" { capabilities=[\"deny\"] }"}}`))
	}))
	defer provider.Close()
	cfg := Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)}
	s, err := New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO workspace(id,name) VALUES(1,'Collection acceptance')"); err != nil {
		t.Fatal(err)
	}
	connection, _ := json.Marshal(Connection{Source: config.Source{ID: "vault-test", Kind: "vault", Scope: "vault/local", Address: provider.URL, TokenEnv: "GRANTLINE_TOKEN", Policies: []string{"metadata-only"}}, AuthMode: "token"})
	cipher, err := seal(cfg.EncryptionKey, "connection:vault-test", []byte(`{"token":"private-observer-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO integrations(id,name,kind,config,credentials) VALUES('vault-test','Vault','vault',$1,$2)", connection, cipher); err != nil {
		t.Fatal(err)
	}
	browser := databaseBrowser(t, s, "owner")
	for _, blocked := range []bool{false, true} {
		denied.Store(blocked)
		before := calls.Load()
		var job struct {
			RunID string `json:"run_id"`
		}
		if err = json.Unmarshal(browser.request("POST", "/runs", map[string]any{}, 202).Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		s.run(context.Background(), job.RunID)
		if calls.Load() != before+1 {
			t.Fatal("worker did not call the actual collector HTTP path")
		}
		var state string
		var raw, progressRaw []byte
		if err = db.QueryRow("SELECT state,configuration->'collection' FROM runs WHERE id=$1", job.RunID).Scan(&state, &progressRaw); err != nil {
			t.Fatal(err)
		}
		var progress collectionProgress
		if err = json.Unmarshal(progressRaw, &progress); err != nil {
			t.Fatal(err)
		}
		if progress.Phase != "finished" || len(progress.Sources) != 1 || progress.Sources[0].Method != "live_api" {
			t.Fatal("missing provider timing", progress)
		}
		expected := "completed"
		if blocked {
			expected = "partial"
		}
		if state != expected || progress.Sources[0].State != expected {
			t.Fatalf("state=%s, progress=%+v", state, progress)
		}
		if err = db.QueryRow("SELECT report FROM reports WHERE run_id=$1", job.RunID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var report model.Report
		if err = json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		if report.FixtureNotice != "" || report.Snapshot.Sources[0].Provenance != model.ProvenanceLiveAPI {
			t.Fatal("collection substituted generated input")
		}
		if blocked && report.Completeness.Complete {
			t.Fatal("provider failure reported as complete")
		}
		public := browser.request("GET", "/runs", nil, 200).Body.String()
		if strings.Contains(public, "private-observer-token") || strings.Contains(public, "configuration") || strings.Contains(public, provider.URL) {
			t.Fatal("run timing API exposed credentials/configuration")
		}
	}
}
