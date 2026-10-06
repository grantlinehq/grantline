package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestDatabaseCapacityRelatedWorkflowFindings(t *testing.T) {
	if os.Getenv("GRANTLINE_TEST_CAPACITY") != "1" {
		t.Skip("set GRANTLINE_TEST_CAPACITY=1 for related-finding capacity acceptance")
	}
	db := testDatabase(t)
	s, err := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if err != nil {
		t.Fatal(err)
	}
	viewer := databaseBrowser(t, s, "viewer")
	run := randomID()
	if _, err = db.Exec("INSERT INTO runs(id,kind,state) VALUES($1,'import','completed')", run); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO reports(run_id,report) VALUES($1,'{"rule_results":[]}')`, run); err != nil {
		t.Fatal(err)
	}
	// Stored-object fixture: 1,000 distinct Entra application findings, each
	// connected to the same collected workflow through an exact federation edge.
	// These projection fixtures never reach a real workspace or provider.
	if _, err = db.Exec(`INSERT INTO objects(run_id,category,id,source_id,name,kind,body)
	 SELECT $1,'identities','workflow','github','Deploy','workflow',
	 jsonb_build_object('id','workflow','source_id','github','kind','workflow','name','Deploy','attributes','{}'::jsonb,'field_status','{}'::jsonb)
	 UNION ALL
	 SELECT $1,'identities','app-'||n,'entra','Application '||n,'application_registration',
	 jsonb_build_object('id','app-'||n,'source_id','entra','kind','application_registration','name','Application '||n,'attributes',jsonb_build_object('object_id','object-'||n,'owner_count',0),'field_status',jsonb_build_object('object_id','known','owner_count','known')) FROM generate_series(1,1000) n
	 UNION ALL
	 SELECT $1,'identities','fic-'||n,'entra','Federation '||n,'federated_credential',
	 jsonb_build_object('id','fic-'||n,'source_id','entra','kind','federated_credential','attributes',jsonb_build_object('parent_object_id','object-'||n),'field_status',jsonb_build_object('parent_object_id','known')) FROM generate_series(1,1000) n
	 UNION ALL
	 SELECT $1,'relationships','edge-'||n,'','Federation','trusts_subject',
	 jsonb_build_object('id','edge-'||n,'from','fic-'||n,'to','workflow','type','trusts_subject','assertion_kind','declared','evidence_ids',jsonb_build_array('fixture-proof')) FROM generate_series(1,1000) n
	 UNION ALL
	 SELECT $1,'findings','finding-'||n,'','Missing application owners','IL004',
	 jsonb_build_object('id','finding-'||n,'rule_id','IL004','affected_entity_ids',jsonb_build_array('app-'||n)) FROM generate_series(1,1000) n`, run); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("ANALYZE objects"); err != nil {
		t.Fatal(err)
	}
	var plan []byte
	if err = db.QueryRow("EXPLAIN (ANALYZE,FORMAT JSON) SELECT count(*)"+objectListWhere("findings", "github", ""), run, "findings", "", "github", "", false, "").Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var timing []struct {
		Execution float64 `json:"Execution Time"`
		JIT       struct {
			Timing struct{ Total float64 }
		}
	}
	if err = json.Unmarshal(plan, &timing); err != nil {
		t.Fatal(err)
	}
	t.Logf("related count query execution: %.2f ms, JIT: %.2f ms", timing[0].Execution, timing[0].JIT.Timing.Total)
	server := httptest.NewServer(s)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	samples := make(chan time.Duration, 200)
	var wg sync.WaitGroup
	for user := 0; user < 10; user++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for request := 0; request < 20; request++ {
				req, _ := http.NewRequest("GET", server.URL+"/api/v1/objects/findings?source=github&run="+run, nil)
				req.Host = "127.0.0.1:8080"
				req.AddCookie(viewer.cookie)
				started := time.Now()
				response, e := client.Do(req)
				if e != nil {
					t.Error("related findings request failed", e)
					return
				}
				var page struct {
					Total int
					Items []struct{ Context findingContext }
				}
				e = json.NewDecoder(response.Body).Decode(&page)
				response.Body.Close()
				samples <- time.Since(started)
				if e != nil || response.StatusCode != 200 || page.Total != 1000 || len(page.Items) != 50 {
					t.Error("incorrect related findings response")
					return
				}
				for _, item := range page.Items {
					if len(item.Context.RelatedSources) != 1 || len(item.Context.SourceIDs) != 1 || item.Context.SourceIDs[0] != "entra" {
						t.Error("related projection lost root cause")
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(samples)
	var times []time.Duration
	for sample := range samples {
		times = append(times, sample)
	}
	if len(times) != 200 {
		t.Fatalf("expected 200 related responses; got %d", len(times))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	p95 := times[len(times)*95/100]
	t.Logf("1000 related findings / 10 concurrent / 200 requests: p95=%s max=%s", p95, times[len(times)-1])
	if p95 > 500*time.Millisecond {
		t.Errorf("related findings p95 exceeded 500ms")
	}
}
