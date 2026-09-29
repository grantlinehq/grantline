package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/viewer"
)

func TestDatabaseCapacityAndReportRoundTrip(t *testing.T) {
	if os.Getenv("GRANTLINE_TEST_CAPACITY") != "1" {
		t.Skip("set GRANTLINE_TEST_CAPACITY=1 for the 10,000-identity acceptance")
	}
	db := testDatabase(t)
	s, e := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if e != nil {
		t.Fatal(e)
	}
	users := make([]*testBrowser, 50)
	for i := range users {
		role := "viewer"
		if i == 0 {
			role = "owner"
		}
		users[i] = databaseBrowser(t, s, role)
	}
	snap := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: time.Now().UTC(), Entities: []model.Entity{}, Evidence: []model.Evidence{}, Relationships: []model.Relationship{}, Sources: []model.Source{}}
	sources := []config.Source{}
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("capacity-%02d", i)
		source := config.Source{ID: id, Kind: "kubernetes", Scope: "cluster/" + id}
		sources = append(sources, source)
		snap.Sources = append(snap.Sources, model.Source{ID: id, Kind: "kubernetes", Scope: source.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceSyntheticFixture, Warnings: []string{}, PermissionsObserved: []string{}})
		cfg, _ := json.Marshal(Connection{Source: source})
		if _, e = db.Exec("INSERT INTO integrations(id,name,kind,config,enabled) VALUES($1,$1,'kubernetes',$2,false)", id, cfg); e != nil {
			t.Fatal(e)
		}
		for n := 0; n < 500; n++ {
			native := fmt.Sprintf("account-%02d-%04d", i, n)
			snap.Entities = append(snap.Entities, model.Entity{ID: model.EntityID(id, "service_account", native), Kind: "service_account", SourceID: id, NativeID: native, Name: native, Scope: source.Scope, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: snap.CollectedAt, Provenance: model.ProvenanceSyntheticFixture})
		}
	}
	report, e := (analyze.Analyzer{}).Analyze(snap, defaultPolicy(sources))
	if e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	users[0].request("POST", "/reports/import", report, 201)
	t.Logf("10,000 identities import: %s", time.Since(started))
	var exported model.Report
	json.Unmarshal(users[0].request("GET", "/report", nil, 200).Body.Bytes(), &exported)
	if !sameReport(report, exported) {
		t.Fatal("report contract changed in PostgreSQL round trip")
	}
	server := httptest.NewServer(s)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	samples := make(chan time.Duration, 1000)
	errs := make(chan string, 1000)
	var wg sync.WaitGroup
	for user := 0; user < 10; user++ {
		wg.Add(1)
		go func(b *testBrowser) {
			defer wg.Done()
			for request := 0; request < 100; request++ {
				path := "/api/v1/objects/identities?native=true&page=0"
				if request%2 == 1 {
					path = "/api/v1/objects/identities?native=true&q=account-09&page=2"
				}
				req, _ := http.NewRequest("GET", server.URL+path, nil)
				req.AddCookie(b.cookie)
				req.Host = "127.0.0.1:8080"
				start := time.Now()
				res, e := client.Do(req)
				if e != nil {
					errs <- "request failed"
					continue
				}
				body, e := io.ReadAll(res.Body)
				res.Body.Close()
				samples <- time.Since(start)
				if e != nil || res.StatusCode != 200 {
					errs <- fmt.Sprintf("HTTP %d", res.StatusCode)
					continue
				}
				var page struct {
					Items []model.Entity
					Total int
				}
				json.Unmarshal(body, &page)
				expected := 10000
				if request%2 == 1 {
					expected = 500
				}
				if len(page.Items) != 50 || page.Total != expected {
					errs <- "incorrect pagination/search"
				}
			}
		}(users[user])
	}
	wg.Wait()
	close(samples)
	close(errs)
	for problem := range errs {
		t.Error(problem)
	}
	times := []time.Duration{}
	for sample := range samples {
		times = append(times, sample)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	if len(times) != 1000 {
		t.Fatalf("expected 1000 responses; got %d", len(times))
	}
	p95 := times[len(times)*95/100]
	t.Logf("50 users / 20 connections / 10000 identities / 10 concurrent / 1000 requests: p50=%s p95=%s max=%s", times[len(times)/2], p95, times[len(times)-1])
	if p95 > 500*time.Millisecond {
		t.Errorf("p95 exceeded 500ms")
	}
}

func TestDatabaseHistoricalReportUnchanged(t *testing.T) {
	file := os.Getenv("GRANTLINE_TEST_REPORT_FILE")
	if file == "" {
		t.Skip("optional private report contract acceptance")
	}
	report, e := viewer.Load(file)
	if e != nil {
		t.Fatal("private report unavailable or invalid")
	}
	db := testDatabase(t)
	s, e := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if e != nil {
		t.Fatal(e)
	}
	b := databaseBrowser(t, s, "owner")
	b.request("POST", "/reports/import", report, 201)
	var roundTrip model.Report
	json.Unmarshal(b.request("GET", "/report", nil, 200).Body.Bytes(), &roundTrip)
	if !sameReport(report, roundTrip) {
		t.Fatal("historical report identity/evidence/outcome contract changed")
	}
	var connections int
	db.QueryRow("SELECT count(*) FROM integrations").Scan(&connections)
	if connections != 0 {
		t.Fatal("historical import created live integrations")
	}
	unknown := 0
	for _, r := range roundTrip.RuleResults {
		if r.Outcome == model.OutcomeUnknown {
			unknown++
		}
	}
	t.Logf("Historical round trip preserved: %d entities, %d relationships, %d evidence, %d findings, %d UNKNOWN results", len(report.Snapshot.Entities), len(report.Snapshot.Relationships), len(report.Snapshot.Evidence), len(report.Findings), unknown)
}

// PostgreSQL JSONB normalizes insignificant whitespace and object key order inside
// RawMessage attributes. Compare full JSON values, retaining exact number text.
func sameReport(first, second model.Report) bool {
	normalize := func(report model.Report) any {
		data, _ := json.Marshal(report)
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return nil
		}
		return value
	}
	return reflect.DeepEqual(normalize(first), normalize(second))
}
