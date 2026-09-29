package analyze

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"reflect"
	"testing"
)

func environmentFixture(t *testing.T) (model.Snapshot, policy.Policy, bindings.Config) {
	t.Helper()
	s, _ := loadAnalysisInputs(t, "restricted-rbac.snapshot.json")
	var sa model.Entity
	for _, e := range s.Entities {
		if e.Kind == "service_account" {
			sa = e
			break
		}
	}
	p := policy.Policy{SchemaVersion: 1, RequiredSources: []string{sa.SourceID}, Rules: map[string]policy.Rule{"IL008": {Severity: model.SeverityMedium, SeparatedEnvironments: []policy.EnvironmentPair{{First: "dev", Second: "prod"}}}}}
	s.Evidence = append(s.Evidence, model.Evidence{ID: model.EvidenceID(sa.SourceID, sa.NativeID, "api/serviceaccounts/fixture"), SourceID: sa.SourceID, NativeID: sa.NativeID, Locator: "api/serviceaccounts/fixture", Fields: []string{"metadata.uid"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionObserved})
	members := []bindings.Member{}
	for _, env := range []string{"dev", "prod"} {
		members = append(members, bindings.Member{Reference: bindings.Reference{SourceID: sa.SourceID, Kind: sa.Kind, NativeID: sa.NativeID}, Environment: env})
	}
	b := bindings.Config{SchemaVersion: 1, Applications: []bindings.Application{{ID: "payments", Name: "Payments", Members: members}}}
	return s, p, b
}
func TestEnvironmentConflictUsesExactIdentityAndPreservesInput(t *testing.T) {
	s, p, b := environmentFixture(t)
	before, _ := json.Marshal(s)
	r, err := (Analyzer{Bindings: &b, Now: fixedNow}).Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.RuleResults[0].Outcome != model.OutcomeFail || len(r.Contexts) != 2 || r.Snapshot == nil {
		t.Fatalf("unexpected result: %+v", r.RuleResults)
	}
	after, _ := json.Marshal(s)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("analysis mutated input")
	}
	again, err := (Analyzer{Bindings: &b, Now: fixedNow}).Analyze(s, p)
	if err != nil || !reflect.DeepEqual(r, again) {
		t.Fatal("analysis not deterministic")
	}
}
func TestSameNameDoesNotMergeNativePrincipals(t *testing.T) {
	s, p, b := environmentFixture(t)
	id := model.EntityID(b.Applications[0].Members[0].SourceID, "service_account", b.Applications[0].Members[0].NativeID)
	var other model.Entity
	for _, e := range s.Entities {
		if e.ID == id {
			other = e
		}
	}
	other.NativeID = "different-native-uid"
	other.ID = model.EntityID(other.SourceID, other.Kind, other.NativeID)
	s.Entities = append(s.Entities, other)
	s.Evidence = append(s.Evidence, model.Evidence{ID: model.EvidenceID(other.SourceID, other.NativeID, "api/serviceaccounts/other"), SourceID: other.SourceID, NativeID: other.NativeID, Locator: "api/serviceaccounts/other", Fields: []string{"metadata.uid"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionObserved})
	b.Applications[0].Members[1].NativeID = other.NativeID
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || r.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatal("same display name merged")
	}
}
func TestEnvironmentExceptionAndUnknownPrecedence(t *testing.T) {
	s, p, b := environmentFixture(t)
	m := b.Applications[0].Members[0]
	rule := p.Rules["IL008"]
	rule.AllowedSharedIdentities = []policy.SharedIdentity{{EnvironmentPair: rule.SeparatedEnvironments[0], SourceID: m.SourceID, Kind: m.Kind, NativeID: m.NativeID, Reason: "Reviewed shared demo service"}}
	p.Rules["IL008"] = rule
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || len(r.Findings) != 0 || len(r.PolicyExceptions) != 1 || r.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("exception: %v %+v", err, r.RuleResults)
	}
	b.Applications[0].Members = append(b.Applications[0].Members, bindings.Member{Reference: bindings.Reference{SourceID: m.SourceID, Kind: m.Kind, NativeID: "absent-native-id"}, Environment: "prod"})
	r, err = (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || r.RuleResults[0].Outcome != model.OutcomeUnknown || len(r.PolicyExceptions) != 1 || len(r.BindingIssues) != 1 {
		t.Fatal("exception hid unresolved coverage")
	}
	rule.AllowedSharedIdentities = nil
	p.Rules["IL008"] = rule
	r, err = (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || len(r.Findings) != 1 || r.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal("unknown dropped established conflict")
	}
}
func TestNoEnvironmentBindingsIsUnknown(t *testing.T) {
	s, p, _ := environmentFixture(t)
	r, err := Analyze(s, p)
	if err != nil || r.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal("absent business context passed")
	}
}
func TestDeclarationAloneCannotProveNativeIdentity(t *testing.T) {
	s, p, b := environmentFixture(t)
	m := b.Applications[0].Members[0]
	for i := range s.Evidence {
		if s.Evidence[i].SourceID == m.SourceID && s.Evidence[i].NativeID == m.NativeID {
			s.Evidence[i].AssertionKind = model.AssertionDeclared
		}
	}
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || r.RuleResults[0].Outcome != model.OutcomeUnknown || len(r.Findings) != 0 {
		t.Fatal("declaration manufactured native identity evidence")
	}
}
