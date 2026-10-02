package demolab

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

func TestCatalogEvaluatesAllRulesAndHealthyControls(t *testing.T) {
	c := buildCatalog(time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
	report, err := c.analyze()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Completeness.Complete || len(report.Snapshot.Sources) != 6 || len(report.BindingIssues) != 0 {
		t.Fatal("demo evidence must be complete across all six sources", report.BindingIssues)
	}
	expected := map[string]int{"IL001": 20, "IL002": 18, "IL003": 20, "IL004": 20, "IL005": 12, "IL006": 14, "IL007": 12, "IL008": 12}
	actual := map[string]int{}
	for _, f := range report.Findings {
		actual[f.RuleID]++
		if len(f.EvidenceIDs) == 0 {
			t.Fatal("finding without evidence", f.ID)
		}
		for _, healthy := range c.controls[f.RuleID] {
			for _, affected := range f.AffectedEntityIDs {
				if affected == healthy {
					t.Fatalf("%s flagged a healthy control", f.RuleID)
				}
			}
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("rule distribution: got %v, want %v", actual, expected)
	}
	for _, level := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if severityCounts(report)[level] != 32 {
			t.Fatalf("%s distribution: %v", level, severityCounts(report))
		}
	}
	for _, r := range report.RuleResults {
		if r.Outcome != model.OutcomeFail || len(c.controls[r.RuleID]) == 0 {
			t.Fatalf("rule must have established findings and healthy controls: %+v", r)
		}
	}
	for _, e := range report.Snapshot.Entities {
		if e.Provenance != model.ProvenanceSyntheticFixture {
			t.Fatal("demo entity must not claim live provenance")
		}
	}
	for _, s := range report.Snapshot.Sources {
		if s.Provenance != model.ProvenanceSyntheticFixture {
			t.Fatal("demo source must not claim live provenance")
		}
	}
	// The exported policy must recreate the same analysis, not just look readable.
	loaded, err := policy.Parse([]byte(c.policyYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, c.policy) {
		t.Fatal("exported policy changes semantics")
	}
	again := buildCatalog(c.snapshot.CollectedAt)
	again.policy = loaded
	next, err := again.analyze()
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(report)
	nextJSON, _ := json.Marshal(next)
	if string(firstJSON) != string(nextJSON) {
		t.Fatal("fixed-time catalog output is not deterministic")
	}
}

func TestCatalogFindingIDsSurviveRefresh(t *testing.T) {
	a := buildCatalog(time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
	b := buildCatalog(a.snapshot.CollectedAt.Add(time.Hour))
	first, err := a.analyze()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.analyze()
	if err != nil {
		t.Fatal(err)
	}
	// Identity-based scenarios remain stable. IL003 includes actual validity dates
	// in its identity, so those dates must be fixed across regenerated fixtures.
	for i, f := range first.Findings {
		if f.ID != second.Findings[i].ID {
			t.Fatalf("refresh changed finding identity for %s", f.RuleID)
		}
	}
}
