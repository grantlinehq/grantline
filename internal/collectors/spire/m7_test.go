package spire_test

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"testing"
)

func TestIL008SharedSPIFFEIdentityAcrossRegistrations(t *testing.T) {
	s := collect(t, entries())
	b := bindings.Config{SchemaVersion: 1, Applications: []bindings.Application{{ID: "demo", Name: "Demo", Members: []bindings.Member{
		{Reference: bindings.Reference{SourceID: "spire-lab", Kind: "spire_entry", NativeID: "entry/00000000-0000-0000-0000-000000000002"}, Environment: "dev"},
		{Reference: bindings.Reference{SourceID: "spire-lab", Kind: "spire_entry", NativeID: "entry/00000000-0000-0000-0000-000000000003"}, Environment: "prod"},
	}}}}
	p := policy.Policy{SchemaVersion: 1, RequiredSources: []string{"spire-lab"}, Rules: map[string]policy.Rule{"IL008": {Severity: model.SeverityMedium, SeparatedEnvironments: []policy.EnvironmentPair{{First: "dev", Second: "prod"}}}}}
	r, err := (analyze.Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.RuleResults[0].Outcome != model.OutcomeFail || len(r.Findings[0].AffectedRelationshipIDs) != 2 {
		t.Fatalf("shared identity result: %+v", r.RuleResults)
	}
}
func TestSpireKubernetesScopeAndDeclarationEvidence(t *testing.T) {
	makeSnapshot := func() model.Snapshot {
		s := collect(t, entries())
		s.Sources = append(s.Sources, model.Source{ID: "k8s", Kind: "kubernetes", Scope: "cluster/kind-lab", Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceSyntheticFixture})
		sa := model.Entity{ID: model.EntityID("k8s", "service_account", "native-sa"), Kind: "service_account", SourceID: "k8s", NativeID: "native-sa", Name: "restricted", Scope: "cluster/kind-lab/namespaces/demo", ObservedAt: s.CollectedAt, Provenance: model.ProvenanceSyntheticFixture}
		s.Entities = append(s.Entities, sa)
		s.Evidence = append(s.Evidence, model.Evidence{ID: model.EvidenceID("k8s", "native-sa", "api/serviceaccounts/restricted"), SourceID: "k8s", NativeID: "native-sa", Locator: "api/serviceaccounts/restricted", Fields: []string{"metadata.uid"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionObserved})
		return s
	}
	mapping := []bindings.SpireKubernetes{{SpireSourceID: "spire-lab", ParentID: parent, KubernetesSourceID: "k8s", Cluster: "lab"}}
	s := makeSnapshot()
	issues := correlate.AddSpireKubernetesMatches(&s, mapping)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	matches := 0
	for _, e := range s.Relationships {
		if e.Type == "selector_matches" {
			matches++
			if e.AssertionKind != model.AssertionDeclared || len(e.EvidenceIDs) < 4 {
				t.Fatal("missing declaration or provider evidence")
			}
		}
	}
	if matches != 2 {
		t.Fatalf("matches=%d", matches)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"wrong-cluster", "unknown-parent", "unsupported-selector", "missing-subject"} {
		s = makeSnapshot()
		m := append([]bindings.SpireKubernetes(nil), mapping...)
		switch mode {
		case "wrong-cluster":
			m[0].Cluster = "other"
		case "unknown-parent":
			for i := range s.Entities {
				if s.Entities[i].Kind == "spire_entry" && s.Entities[i].NativeID == "entry/00000000-0000-0000-0000-000000000001" {
					s.Entities[i].FieldStatus["selectors"] = model.FieldUnknown
				}
			}
		case "unsupported-selector":
			for i := range s.Entities {
				if s.Entities[i].NativeID == "entry/00000000-0000-0000-0000-000000000002" {
					s.Entities[i].Attributes["selectors"] = json.RawMessage(`[{"type":"unix","value":"uid:123"}]`)
				}
			}
		case "missing-subject":
			s.Entities = s.Entities[:len(s.Entities)-1]
		}
		issues = correlate.AddSpireKubernetesMatches(&s, m)
		if len(issues) == 0 {
			t.Fatalf("%s silently passed", mode)
		}
	}
}
