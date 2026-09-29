package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

func TestIL002ExactConfiguredBindingPasses(t *testing.T) {
	t.Parallel()
	input, configuredPolicy := il002Snapshot(t, []string{"payments"}, []string{"demo-dev"})
	configuredPolicy.Rules["IL002"] = policy.Rule{Severity: model.SeverityMedium, AllowedVaultKubernetesBindings: []policy.AllowedVaultKubernetesBinding{{VaultSourceID: "vault-lab", RoleNativeID: "kubernetes/payments-kubernetes", KubernetesSourceID: "k8s-lab", ServiceAccountID: "sa-uid"}}}
	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if resultByID(t, report, "IL002").Outcome != model.OutcomePass {
		t.Fatalf("result=%#v", resultByID(t, report, "IL002"))
	}
}

func TestIL002WildcardBindingFails(t *testing.T) {
	t.Parallel()
	input, configuredPolicy := il002Snapshot(t, []string{"*"}, []string{"demo-dev"})
	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if resultByID(t, report, "IL002").Outcome != model.OutcomeFail {
		t.Fatalf("result=%#v", resultByID(t, report, "IL002"))
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "IL002" {
		t.Fatalf("findings=%#v", report.Findings)
	}
}

func TestIL002IncompleteCoverageIsUnknown(t *testing.T) {
	t.Parallel()
	input, configuredPolicy := il002Snapshot(t, []string{"*"}, []string{"demo-dev"})
	input.Sources[1].Status = model.SourcePartial
	input.Sources[1].Complete = false
	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if resultByID(t, report, "IL002").Outcome != model.OutcomeUnknown {
		t.Fatalf("result=%#v", resultByID(t, report, "IL002"))
	}
}

func il002Snapshot(t *testing.T, names, namespaces []string) (model.Snapshot, policy.Policy) {
	t.Helper()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	sa := model.Entity{ID: model.EntityID("k8s-lab", "service_account", "sa-uid"), Kind: "service_account", SourceID: "k8s-lab", NativeID: "sa-uid", Scope: "cluster/lab/namespaces/demo-dev", Name: "payments", Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: now, Provenance: model.ProvenanceLiveAPI}
	attrs := map[string]json.RawMessage{"auth_mount": raw("kubernetes"), "auth_type": raw("kubernetes"), "bound_service_account_names": raw(names), "bound_service_account_namespaces": raw(namespaces), "policy_names": raw([]string{"payments-read"})}
	role := model.Entity{ID: model.EntityID("vault-lab", "vault_auth_role", "kubernetes/payments-kubernetes"), Kind: "vault_auth_role", SourceID: "vault-lab", NativeID: "kubernetes/payments-kubernetes", Scope: "vault/local/auth/kubernetes", Name: "payments-kubernetes", Attributes: attrs, FieldStatus: map[string]model.FieldStatus{"auth_mount": model.FieldKnown, "auth_type": model.FieldKnown, "bound_service_account_names": model.FieldKnown, "bound_service_account_namespaces": model.FieldKnown, "policy_names": model.FieldKnown}, ObservedAt: now, Provenance: model.ProvenanceLiveAPI}
	evSA := model.Evidence{ID: "e-sa", SourceID: "k8s-lab", NativeID: "sa-uid", Locator: "kubernetes://k8s-lab/sa", Fields: []string{"metadata.uid"}, ObservedAt: now, AssertionKind: model.AssertionObserved}
	evRole := model.Evidence{ID: "e-role", SourceID: "vault-lab", NativeID: role.NativeID, Locator: "vault://vault-lab/role", Fields: []string{"bound_service_account_names"}, ObservedAt: now, AssertionKind: model.AssertionObserved}
	edge := model.Relationship{ID: model.RelationshipID(role.ID, sa.ID, "trusts_subject", sa.Scope), From: role.ID, To: sa.ID, Type: "trusts_subject", AssertionKind: model.AssertionConfigured, EvidenceIDs: []string{evRole.ID, evSA.ID}, Scope: sa.Scope, ObservedAt: now}
	return model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: now, Entities: []model.Entity{sa, role}, Relationships: []model.Relationship{edge}, Evidence: []model.Evidence{evSA, evRole}, Sources: []model.Source{{ID: "k8s-lab", Kind: "kubernetes", Scope: "cluster/lab", Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}, {ID: "vault-lab", Kind: "vault", Scope: "vault/local", Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}}}, policy.Policy{SchemaVersion: 1, RequiredSources: []string{"k8s-lab", "vault-lab"}, Rules: map[string]policy.Rule{"IL002": {Severity: model.SeverityMedium}}}
}
func raw(value any) json.RawMessage { encoded, _ := json.Marshal(value); return encoded }
func resultByID(t *testing.T, report model.Report, id string) model.RuleResult {
	t.Helper()
	for _, result := range report.RuleResults {
		if result.RuleID == id {
			return result
		}
	}
	t.Fatalf("missing %s", id)
	return model.RuleResult{}
}
