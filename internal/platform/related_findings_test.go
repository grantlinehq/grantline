package platform

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/grantlinehq/grantline/internal/model"
)

// Exercise the stored-object projection independently of provider ingestion.
// All values belong to a disposable test schema, never a real workspace.
func TestDatabaseRelatedWorkflowFilterKeepsRootCauseAndExactSource(t *testing.T) {
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
	original := `{"rule_results":[],"snapshot_collected_at":"2026-10-01T00:00:00Z"}`
	if _, err = db.Exec("INSERT INTO reports(run_id,report) VALUES($1,$2)", run, original); err != nil {
		t.Fatal(err)
	}
	app := contextEntity("app", "application_registration", map[string]any{"object_id": "app-object"})
	app.SourceID = "entra"
	fic := contextEntity("fic", "federated_credential", map[string]any{"parent_object_id": "app-object"})
	fic.SourceID = "entra"
	workflow := contextEntity("workflow", "workflow", nil)
	workflow.SourceID = "github"
	workflow.Name = "Deploy workflow"
	edge := model.Relationship{ID: "trust", From: fic.ID, To: workflow.ID, Type: "trusts_subject", AssertionKind: model.AssertionConfigured, EvidenceIDs: []string{"fic-proof", "workflow-proof"}}
	f := model.Finding{ID: "finding", RuleID: "IL004", Severity: model.SeverityMedium, AffectedEntityIDs: []string{app.ID}, EvidenceIDs: []string{"owner-proof"}}
	put := func(category, id, source, kind string, value any) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if _, e := db.Exec("INSERT INTO objects(run_id,category,id,source_id,name,kind,body) VALUES($1,$2,$3,$4,$3,$5,$6) ON CONFLICT(run_id,category,id) DO UPDATE SET source_id=EXCLUDED.source_id,body=EXCLUDED.body", run, category, id, source, kind, raw); e != nil {
			t.Fatal(e)
		}
	}
	for _, e := range []model.Entity{app, fic, workflow} {
		put("identities", e.ID, e.SourceID, e.Kind, e)
	}
	put("relationships", edge.ID, "", edge.Type, edge)
	put("findings", f.ID, "", f.RuleID, f)
	var page struct {
		Total int
		Items []struct{ Context findingContext }
	}
	json.Unmarshal(viewer.request("GET", "/objects/findings?source=github&run="+run, nil, 200).Body.Bytes(), &page)
	if page.Total != 1 || len(page.Items[0].Context.RelatedSources) != 1 || page.Items[0].Context.SourceIDs[0] != "entra" {
		t.Fatalf("lost exact federation context: %+v", page)
	}
	if page.Items[0].Context.RelatedSources[0].RelationshipIDs[0] != edge.ID {
		t.Fatal("related workflow has no inspectable edge")
	}
	var emptyPage struct {
		Total int
		Items []json.RawMessage
	}
	json.Unmarshal(viewer.request("GET", "/objects/findings?source=github&run="+run+"&page=3", nil, 200).Body.Bytes(), &emptyPage)
	if emptyPage.Total != 1 || len(emptyPage.Items) != 0 {
		t.Fatal("empty page lost the filtered total")
	}
	for _, scenario := range []string{"inferred edge", "missing evidence", "different source", "unknown parent"} {
		t.Run(scenario, func(t *testing.T) {
			changedApp, changedFic, changedEdge := app, fic, edge
			switch scenario {
			case "inferred edge":
				changedEdge.AssertionKind = model.AssertionInferred
			case "missing evidence":
				changedEdge.EvidenceIDs = []string{}
			case "different source":
				changedApp.SourceID = "other-entra"
			case "unknown parent":
				changedFic = contextEntity("fic", "federated_credential", map[string]any{"parent_object_id": "app-object"})
				changedFic.SourceID = "entra"
				changedFic.FieldStatus["parent_object_id"] = model.FieldUnknown
			}
			put("identities", app.ID, changedApp.SourceID, app.Kind, changedApp)
			put("identities", fic.ID, changedFic.SourceID, fic.Kind, changedFic)
			put("relationships", edge.ID, "", edge.Type, changedEdge)
			var result struct{ Total int }
			json.Unmarshal(viewer.request("GET", "/objects/findings?source=github&run="+run, nil, 200).Body.Bytes(), &result)
			if result.Total != 0 {
				t.Fatal("invented or cross-source relationship")
			}
			contexts, e := s.findingContexts(context.Background(), run, []model.Finding{f})
			if e != nil || len(contexts[f.ID].RelatedSources) != 0 {
				t.Fatal("detail contradicted filtered list")
			}
			put("identities", app.ID, app.SourceID, app.Kind, app)
			put("identities", fic.ID, fic.SourceID, fic.Kind, fic)
			put("relationships", edge.ID, "", edge.Type, edge)
		})
	}
	var after string
	if db.QueryRow("SELECT report::text FROM reports WHERE run_id=$1", run).Scan(&after) != nil {
		t.Fatal("report missing")
	}
	var a, b any
	json.Unmarshal([]byte(original), &a)
	json.Unmarshal([]byte(after), &b)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatal("presentation changed immutable report")
	}
}
