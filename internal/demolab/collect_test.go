package demolab

import (
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/viewer"
)

func demoConnections() []config.Source {
	sources := []config.Source{}
	for _, kind := range []string{"kubernetes", "vault", "jenkins", "entra", "github", "spire"} {
		sources = append(sources, config.Source{ID: "local-" + kind, Kind: kind})
	}
	return sources
}

func TestCollectUsesConfiguredSourceIDs(t *testing.T) {
	sources := demoConnections()
	inputs, err := Collect(time.Now().UTC(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if err = inputs.Bindings.Validate(sources); err != nil {
		t.Fatal(err)
	}
	report, err := (analyze.Analyzer{Bindings: &inputs.Bindings}).Analyze(inputs.Snapshot, inputs.Policy)
	if err != nil {
		t.Fatal(err)
	}
	report.FixtureNotice = Notice
	if err = viewer.Validate(report); err != nil {
		t.Fatal(err)
	}
	if !report.Completeness.Complete || len(report.Findings) != 128 || len(report.BindingIssues) != 0 {
		t.Fatalf("unexpected demo analysis: findings=%d, issues=%v", len(report.Findings), report.BindingIssues)
	}
	ids := map[string]bool{}
	for _, s := range sources {
		ids[s.ID] = true
	}
	for _, s := range report.Snapshot.Sources {
		if !ids[s.ID] || s.Provenance != model.ProvenanceSyntheticFixture {
			t.Fatalf("unmapped source: %+v", s)
		}
	}
	for _, e := range report.Snapshot.Entities {
		if !ids[e.SourceID] {
			t.Fatal("unmapped entity", e.ID)
		}
	}
	for _, e := range report.Evidence {
		if !ids[e.SourceID] {
			t.Fatal("unmapped evidence", e.ID)
		}
	}
	for severity, count := range severityCounts(report) {
		if count != 32 {
			t.Fatalf("%s=%d, want 32", severity, count)
		}
	}
}

func TestCollectRequiresSixDistinctSourceKinds(t *testing.T) {
	for _, scenario := range []string{"missing", "duplicate-kind", "duplicate-id", "unknown-kind", "empty-id"} {
		t.Run(scenario, func(t *testing.T) {
			sources := demoConnections()
			switch scenario {
			case "missing":
				sources = sources[:5]
			case "duplicate-kind":
				sources[0].Kind = sources[1].Kind
			case "duplicate-id":
				sources[0].ID = sources[1].ID
			case "unknown-kind":
				sources[0].Kind = "unknown"
			case "empty-id":
				sources[0].ID = ""
			}
			if _, err := Collect(time.Now(), sources); err == nil {
				t.Fatal("invalid demo connections accepted")
			}
		})
	}
}
