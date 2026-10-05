package platform

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"os"
)

func contextEntity(id, kind string, attributes map[string]any) model.Entity {
	e := model.Entity{ID: id, Kind: kind, SourceID: "source", Name: id, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}}
	for key, value := range attributes {
		e.Attributes[key], _ = json.Marshal(value)
		e.FieldStatus[key] = model.FieldKnown
	}
	return e
}
func TestFindingContextCountsAndUnknownFields(t *testing.T) {
	role := contextEntity("role", "role", map[string]any{"rbac_rules": []model.RBACRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}}})
	f := model.Finding{RuleID: "IL001", AffectedEntityIDs: []string{"role", "binding", "principal", "missing"}}
	entities := map[string]model.Entity{"role": role, "binding": contextEntity("binding", "role_binding", nil), "principal": contextEntity("principal", "service_account", nil)}
	c := describeFinding(f, entities, findingRunContext{Rules: []model.RuleResult{{RuleID: "IL001", Outcome: model.OutcomeUnknown, Limitations: []string{"Unresolved binding"}}}})
	if c.Subject != "principal" || c.IdentityCount != 1 || c.ConfigurationCount != 2 || c.UnresolvedCount != 1 || c.RuleOutcome != "UNKNOWN" || len(c.RuleLimitations) != 1 || len(c.Facts) != 1 || !strings.Contains(c.Facts[0].Observed, "core") {
		t.Fatalf("Incorrect investigation context: %#v", c)
	}
	role.FieldStatus["rbac_rules"] = model.FieldPermissionDenied
	entities["role"] = role
	if c = describeFinding(f, entities, findingRunContext{}); len(c.Facts) != 0 {
		t.Fatal("Denied fields were presented as known")
	}
}
func TestFindingContextParentAndRecordedThreshold(t *testing.T) {
	e := contextEntity("credential", "credential_metadata", map[string]any{"parent_object_id": "app-id", "parent_kind": "application_registration", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-06-30T00:00:00Z"})
	wrong := contextEntity("wrong", "application_registration", map[string]any{"object_id": "app-id"})
	wrong.SourceID = "other"
	parent := contextEntity("reviewed-app", "application_registration", map[string]any{"object_id": "app-id"})
	entities := map[string]model.Entity{e.ID: e, wrong.ID: wrong, parent.ID: parent}
	f := model.Finding{RuleID: "IL003", AffectedEntityIDs: []string{e.ID}}
	c := describeFinding(f, entities, findingRunContext{HasPolicy: true, Policy: policy.Policy{MaxClientSecretValidity: 720 * time.Hour}})
	if c.Subject != "reviewed-app" || c.Facts[0].Observed != "180 days" || c.Facts[0].Expected != "Maximum 30 days" {
		t.Fatalf("Wrong parent/threshold: %#v", c)
	}
	delete(entities, parent.ID)
	if c = describeFinding(f, entities, findingRunContext{}); c.Subject == "wrong" || c.Facts[0].Expected != "" || c.PolicyAvailable {
		t.Fatal("Invented cross-source parent or historical policy")
	}
}
func TestFindingContextEnvironmentOrderingAndTTL(t *testing.T) {
	p := policy.Policy{Rules: map[string]policy.Rule{"IL008": {SeparatedEnvironments: []policy.EnvironmentPair{{First: "production", Second: "development"}}}}, MaxJWTSVIDTTL: 15 * time.Minute}
	e := contextEntity("sa", "service_account", nil)
	f := model.Finding{ID: model.FindingID("IL008", "1", e.ID, "development", "production"), RuleID: "IL008", RuleVersion: "1", AffectedEntityIDs: []string{e.ID}}
	c := describeFinding(f, map[string]model.Entity{e.ID: e}, findingRunContext{HasPolicy: true, Policy: p})
	if len(c.Facts) != 1 {
		t.Fatal("Declaration was not matched with sorted environment IDs")
	}
	entry := contextEntity("entry", "spire_entry", map[string]any{"spiffe_id": "spiffe://example.test/worker", "jwt_ttl_mode": "explicit", "jwt_svid_ttl_seconds": 1800, "x509_ttl_mode": "inherited", "x509_svid_ttl_seconds": 7200})
	f = model.Finding{ID: model.FindingID("IL007", "1", entry.ID, "jwt"), RuleID: "IL007", RuleVersion: "1", AffectedEntityIDs: []string{entry.ID}}
	c = describeFinding(f, map[string]model.Entity{entry.ID: entry}, findingRunContext{HasPolicy: true, Policy: p})
	if c.Subject != "spiffe://example.test/worker" || len(c.Facts) != 1 || c.Facts[0].Expected != "Maximum 15m0s" {
		t.Fatalf("Wrong TTL projection: %#v", c)
	}
}
func TestDatabaseFindingContextSearchAndHistory(t *testing.T) {
	db := testDatabase(t)
	s, err := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if err != nil {
		t.Fatal(err)
	}
	owner, viewer := databaseBrowser(t, s, "owner"), databaseBrowser(t, s, "viewer")
	data, err := os.ReadFile("../../testdata/synthetic/wildcard-rbac.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap model.Snapshot
	if err = json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	report, err := analyze.Analyze(snap, defaultPolicy([]config.Source{{ID: "k8s-lab", Kind: "kubernetes", Scope: "cluster/kind-grantline"}}))
	if err != nil {
		t.Fatal(err)
	}
	var imported struct {
		RunID string `json:"run_id"`
	}
	json.Unmarshal(owner.request("POST", "/reports/import", report, 201).Body.Bytes(), &imported)
	f := report.Findings[0]
	var detail struct{ Context findingContext }
	json.Unmarshal(viewer.request("GET", "/objects/findings/"+f.ID+"?run="+imported.RunID, nil, 200).Body.Bytes(), &detail)
	if detail.Context.PolicyAvailable || detail.Context.PolicyRevision != nil {
		t.Fatal("Imported report pretended to have recorded policy")
	}
	var principal model.Entity
	for _, e := range snap.Entities {
		if nativePrincipal(e.Kind) {
			principal = e
			break
		}
	}
	var page struct {
		Items []struct{ Context findingContext }
		Total int
	}
	json.Unmarshal(viewer.request("GET", "/objects/findings?run="+imported.RunID+"&q="+url.QueryEscape(principal.Name), nil, 200).Body.Bytes(), &page)
	if page.Total == 0 || page.Items[0].Context.Subject == "" {
		t.Fatal("Finding search failed to resolve the named subject")
	}
	recorded := `schema_version: 1
required_sources:
  - k8s-lab
limits:
  max_client_secret_validity: 720h
rules:
  IL001:
    severity: high
`
	cfg, _ := json.Marshal(map[string]any{"policy": recorded, "connections": []Connection{}})
	if _, err = db.Exec("UPDATE runs SET kind='collection',config_revision=7,configuration=$1 WHERE id=$2", cfg, imported.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO workspace(id,name,policy) VALUES(1,'Different current policy','')"); err != nil {
		t.Fatal(err)
	}
	contexts, err := s.findingContexts(context.Background(), imported.RunID, report.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if !contexts[f.ID].PolicyAvailable || *contexts[f.ID].PolicyRevision != 7 {
		t.Fatal("Recorded configuration not used")
	}
	// An Entra credential indexes its parent name only in the exact source/kind.
	credential := contextEntity("credential", "credential_metadata", map[string]any{"parent_object_id": "object-id", "parent_kind": "application_registration", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-06-30T00:00:00Z"})
	app := contextEntity("application", "application_registration", map[string]any{"object_id": "object-id"})
	app.Name = "A discoverable application"
	cf := model.Finding{ID: "credential-finding", RuleID: "IL003", AffectedEntityIDs: []string{credential.ID}}
	for _, v := range []struct {
		ID, Category, Kind, Name, Source string
		Body                             any
	}{{credential.ID, "identities", credential.Kind, "", credential.SourceID, credential}, {app.ID, "identities", app.Kind, app.Name, app.SourceID, app}, {cf.ID, "findings", cf.RuleID, "condition", "", cf}} {
		raw, _ := json.Marshal(v.Body)
		if _, err = db.Exec("INSERT INTO objects(run_id,category,id,source_id,name,kind,severity,body) VALUES($1,$2,$3,$4,$5,$6,0,$7)", imported.RunID, v.Category, v.ID, v.Source, v.Name, v.Kind, raw); err != nil {
			t.Fatal(err)
		}
	}
	json.Unmarshal(viewer.request("GET", "/objects/findings?run="+imported.RunID+"&q=discoverable", nil, 200).Body.Bytes(), &page)
	if page.Total != 1 || page.Items[0].Context.Subject != app.Name {
		t.Fatal("Credential parent search/display mismatch")
	}
	json.Unmarshal(viewer.request("GET", "/objects/findings/"+cf.ID+"?run="+imported.RunID, nil, 200).Body.Bytes(), &detail)
	if len(detail.Context.Facts) < 1 || detail.Context.Facts[0].Expected != "Maximum 30 days" {
		t.Fatal("Historical limit was replaced with current/default limit")
	}
	var exported model.Report
	json.Unmarshal(viewer.request("GET", "/report?run="+imported.RunID, nil, 200).Body.Bytes(), &exported)
	if !sameReport(report, exported) {
		t.Fatal("Investigation projection changed the immutable report")
	}
}
