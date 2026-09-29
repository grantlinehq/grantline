package analyze

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"github.com/grantlinehq/grantline/internal/snapshot"
)

func TestIL001WildcardGrantFailsWithEvidence(t *testing.T) {
	t.Parallel()

	input, configuredPolicy := loadAnalysisInputs(t, "wildcard-rbac.snapshot.json")
	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if report.FixtureNotice == "" {
		t.Fatal("synthetic input must remain visibly labeled in the report")
	}
	if !reflect.DeepEqual(report.InputProvenances, []model.Provenance{model.ProvenanceSyntheticFixture}) {
		t.Fatalf("input provenances = %#v", report.InputProvenances)
	}
	if len(report.RuleResults) != 1 || report.RuleResults[0].Outcome != model.OutcomeFail {
		t.Fatalf("IL001 outcome = %#v, want FAIL", report.RuleResults)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}

	evidenceIDs := make(map[string]struct{}, len(report.Evidence))
	for _, evidence := range report.Evidence {
		evidenceIDs[evidence.ID] = struct{}{}
	}
	for _, evidenceID := range report.Findings[0].EvidenceIDs {
		if _, exists := evidenceIDs[evidenceID]; !exists {
			t.Fatalf("finding references absent evidence %q", evidenceID)
		}
	}
}

func TestIL001RestrictedGrantPasses(t *testing.T) {
	t.Parallel()

	input, configuredPolicy := loadAnalysisInputs(t, "restricted-rbac.snapshot.json")
	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if report.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("IL001 outcome = %s, want PASS", report.RuleResults[0].Outcome)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

func TestIL001ExactAllowlistSuppressesWildcardFinding(t *testing.T) {
	t.Parallel()

	input, configuredPolicy := loadAnalysisInputs(t, "wildcard-rbac.snapshot.json")
	rule := configuredPolicy.Rules["IL001"]
	rule.AllowedGrants = []policy.AllowedGrant{{
		SourceID:               "k8s-lab",
		RoleNativeID:           "cluster-role-read-config",
		ServiceAccountNativeID: "sa-uid-payments-runner",
		Scope:                  "cluster/kind-grantline/namespaces/payments",
	}}
	configuredPolicy.Rules["IL001"] = rule

	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if report.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("IL001 outcome = %s, want PASS", report.RuleResults[0].Outcome)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
}

func TestIL001IncompleteRequiredSourceIsUnknown(t *testing.T) {
	t.Parallel()

	input, configuredPolicy := loadAnalysisInputs(t, "wildcard-rbac.snapshot.json")
	input.Sources[0].Status = model.SourcePartial
	input.Sources[0].Complete = false
	input.Sources[0].PaginationComplete = false

	report, err := (Analyzer{Now: fixedNow}).Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if report.Completeness.Complete {
		t.Fatal("incomplete source must make report completeness false")
	}
	if report.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatalf("IL001 outcome = %s, want UNKNOWN", report.RuleResults[0].Outcome)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("incomplete coverage should not emit findings, got %d", len(report.Findings))
	}
}

func TestAnalysisIsDeterministicForSameInputs(t *testing.T) {
	t.Parallel()

	input, configuredPolicy := loadAnalysisInputs(t, "wildcard-rbac.snapshot.json")
	analyzer := Analyzer{Now: fixedNow}
	first, err := analyzer.Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("first analyze: %v", err)
	}
	second, err := analyzer.Analyze(input, configuredPolicy)
	if err != nil {
		t.Fatalf("second analyze: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first report: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second report: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("same snapshot and policy produced different reports")
	}
}

func loadAnalysisInputs(t *testing.T, snapshotName string) (model.Snapshot, policy.Policy) {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "synthetic")
	input, err := snapshot.Load(filepath.Join(root, snapshotName))
	if err != nil {
		t.Fatalf("load snapshot fixture: %v", err)
	}
	configuredPolicy, err := policy.Load(filepath.Join(root, "grantline.policy.yaml"))
	if err != nil {
		t.Fatalf("load policy fixture: %v", err)
	}
	return input, configuredPolicy
}

func fixedNow() time.Time {
	return time.Date(2026, time.September, 20, 1, 2, 3, 0, time.UTC)
}
