package platform

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"os"
	"strings"
	"testing"
)

func TestDatabasePolicyPreviewAcknowledgementAndImmutability(t *testing.T) {
	db := testDatabase(t)
	s, err := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32)})
	if err != nil {
		t.Fatal(err)
	}
	owner := databaseBrowser(t, s, "owner")
	if _, err = db.Exec("INSERT INTO workspace(id,name) VALUES(1,'Policy acceptance')"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "analyst"} {
		b := databaseBrowser(t, s, role)
		b.request("GET", "/settings/policy", nil, 403)
		b.request("POST", "/settings/policy/validate", map[string]any{}, 403)
	}
	empty := ""
	var result struct {
		Valid     bool
		Policy    string
		YAML      string   `json:"yaml"`
		Requires  bool     `json:"requires_acknowledgement"`
		Disabled  []string `json:"disabled_rules"`
		Effective policyForm
		Preview   struct {
			Available bool
			Kind      string `json:"run_kind"`
			Notice    string `json:"fixture_notice"`
			Before    int
			After     int
			Rules     []struct {
				ID    string
				After string `json:"after_outcome"`
			}
		}
	}
	raw := owner.request("POST", "/settings/policy/validate", policyCandidate{Policy: &empty, Revision: 1, Preview: true}, 200)
	if err = json.Unmarshal(raw.Body.Bytes(), &result); err != nil || !result.Valid || result.Preview.Available {
		t.Fatal("empty workspace preview")
	}
	source := config.Source{ID: "k8s-lab", Kind: "kubernetes", Scope: "cluster/kind-grantline"}
	connection, _ := json.Marshal(Connection{Source: source, AuthMode: "kubeconfig"})
	if _, err = db.Exec("INSERT INTO integrations(id,name,kind,config,enabled) VALUES('k8s-lab','Cluster','kubernetes',$1,true)", connection); err != nil {
		t.Fatal(err)
	}
	var editor struct{ Effective policyForm }
	json.Unmarshal(owner.request("GET", "/settings/policy", nil, 200).Body.Bytes(), &editor)
	if len(editor.Effective.Rules) != 9 || len(editor.Effective.RequiredSources) != 1 {
		t.Fatal("effective defaults missing")
	}
	if _, ok := editor.Effective.Rules["IL009"]; !ok {
		t.Fatal("Jenkins shared Vault role default missing")
	}
	data, err := os.ReadFile("../../testdata/synthetic/wildcard-rbac.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot model.Snapshot
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	report, err := analyze.Analyze(snapshot, defaultPolicy([]config.Source{source}))
	if err != nil {
		t.Fatal(err)
	}
	owner.request("POST", "/reports/import", report, 201)
	beforeReport := owner.request("GET", "/report", nil, 200).Body.String()
	var beforeRuns, beforeAudit, beforeVersions int
	db.QueryRow("SELECT count(*) FROM runs").Scan(&beforeRuns)
	db.QueryRow("SELECT count(*) FROM audit").Scan(&beforeAudit)
	db.QueryRow("SELECT count(*) FROM configuration_versions").Scan(&beforeVersions)
	candidate := editor.Effective
	delete(candidate.Rules, "IL001")
	raw = owner.request("POST", "/settings/policy/validate", policyCandidate{Form: &candidate, Revision: 1, Preview: true}, 200)
	if err = json.Unmarshal(raw.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || !result.Requires || len(result.Disabled) != 1 || result.Disabled[0] != "IL001" || !result.Preview.Available || result.Preview.Kind != "import" || result.Preview.Notice == "" || result.Preview.Before <= result.Preview.After {
		t.Fatalf("preview did not show removed detection: %s", raw.Body.String())
	}
	unknown := false
	for _, r := range result.Preview.Rules {
		if r.After == "UNKNOWN" {
			unknown = true
		}
	}
	if !unknown {
		t.Fatal("preview concealed missing-source UNKNOWN")
	}
	if result.YAML == "" || result.Policy == "" {
		t.Fatal("canonical policy missing")
	}
	if got := owner.request("GET", "/report", nil, 200).Body.String(); got != beforeReport {
		t.Fatal("preview mutated report")
	}
	var n int
	for _, check := range []struct {
		table string
		count int
	}{{"runs", beforeRuns}, {"audit", beforeAudit}, {"configuration_versions", beforeVersions}, {"triage", 0}} {
		if err = db.QueryRow("SELECT count(*) FROM " + check.table).Scan(&n); err != nil || n != check.count {
			t.Fatal("preview mutated "+check.table, err)
		}
	}
	s.previewSlots <- struct{}{}
	owner.request("POST", "/settings/policy/validate", policyCandidate{Form: &candidate, Revision: 1, Preview: true}, 429)
	<-s.previewSlots
	owner.request("POST", "/settings/policy/validate", policyCandidate{Form: &candidate, Revision: 99}, 409)
	save := map[string]any{"Name": "Policy acceptance", "schedule_minutes": 60, "retention_days": 30, "Policy": result.Policy, "Bindings": "", "Revision": 1}
	blocked := owner.request("PUT", "/settings", save, 409)
	if !strings.Contains(blocked.Body.String(), "coverage_acknowledgement_required") {
		t.Fatal("coverage reduction was not guarded")
	}
	save["acknowledge_coverage_reduction"] = true
	owner.request("PUT", "/settings", save, 200)
	owner.request("PUT", "/settings", save, 409)
	editor.Effective.Rules = nil
	json.Unmarshal(owner.request("GET", "/settings/policy", nil, 200).Body.Bytes(), &editor)
	if _, enabled := editor.Effective.Rules["IL001"]; enabled {
		t.Fatal("disabled rule restored")
	}
}

func TestConfigurationDiagnosticsDoNotEchoValues(t *testing.T) {
	issues := configurationIssues("schema_version: 1\ncredential: PRIVATE_SENTINEL\n", "private_field: PRIVATE_SENTINEL\n", nil)
	raw, _ := json.Marshal(issues)
	if len(issues) != 2 || strings.Contains(string(raw), "PRIVATE_SENTINEL") || issues[0].Line != 2 {
		t.Fatalf("unsafe or missing diagnostics: %s", raw)
	}
	f := policyForm{Limits: map[string]string{"max_client_secret_validity": "PRIVATE_SENTINEL"}}
	_, issues = f.parsed()
	if len(issues) != 1 || issues[0].Field != "limits.max_client_secret_validity" {
		t.Fatal("duration field diagnostic missing")
	}
	for _, c := range []Connection{
		{Source: config.Source{Kind: "entra", TenantID: "PRIVATE_SENTINEL", Scope: "entra/production"}, AuthMode: "client_secret", ClientID: "PRIVATE_SENTINEL"},
		{Source: config.Source{Kind: "github", Scope: "github/production"}, AuthMode: "github_app", AppID: "PRIVATE_SENTINEL"},
		{Source: config.Source{Kind: "vault", Scope: "vault/prod", Address: "https://user:PRIVATE_SENTINEL@vault.example.test"}, AuthMode: "token"},
	} {
		issues = integrationIssues(c)
		raw, _ = json.Marshal(issues)
		if len(issues) == 0 || strings.Contains(string(raw), "PRIVATE_SENTINEL") {
			t.Fatal("integration diagnostics unsafe")
		}
	}
}

func TestPreviewRemovesOnlyContextDerivedRelationships(t *testing.T) {
	snapshot := model.Snapshot{Evidence: []model.Evidence{
		{ID: "declared", AssertionKind: model.AssertionDeclared, Locator: "bindings/vault/0"},
		{ID: "workflow", AssertionKind: model.AssertionDeclared, Locator: "github/workflow"},
		{ID: "provider", AssertionKind: model.AssertionObserved, Locator: "bindings/provider-is-not-a-declaration"},
	}, Relationships: []model.Relationship{{ID: "old-context", EvidenceIDs: []string{"declared"}}, {ID: "workflow-edge", EvidenceIDs: []string{"workflow"}}, {ID: "provider-edge", EvidenceIDs: []string{"provider"}}}}
	got, err := previewSnapshot(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, edge := range got.Relationships {
		ids[edge.ID] = true
	}
	if len(got.Evidence) != 2 || len(got.Relationships) != 2 || !ids["workflow-edge"] || !ids["provider-edge"] {
		t.Fatal("preview changed provider provenance or retained old bindings")
	}
}
