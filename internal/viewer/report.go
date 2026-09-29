package viewer

import (
	"github.com/grantlinehq/grantline/internal/model"
	"fmt"
	"io"
	"os"
	"reflect"
)

const MaxReportBytes = 32 << 20

func Load(path string) (model.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.Report{}, fmt.Errorf("report unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxReportBytes+1))
	if err != nil || len(data) > MaxReportBytes {
		return model.Report{}, fmt.Errorf("report exceeds limit or cannot be read")
	}
	return Parse(data)
}
func Parse(data []byte) (model.Report, error) {
	var r model.Report
	if len(data) > MaxReportBytes {
		return r, fmt.Errorf("report exceeds size limit")
	}
	if err := strictJSON(data, &r); err != nil {
		return r, fmt.Errorf("invalid report JSON")
	}
	if err := Validate(r); err != nil {
		return model.Report{}, err
	}
	return r, nil
}
func Validate(r model.Report) error {
	if r.SchemaVersion != model.ReportSchemaVersion || r.GeneratedAt.IsZero() || r.Snapshot == nil {
		return fmt.Errorf("viewer requires a self-contained M7 report; run analyze again")
	}
	s := r.Snapshot
	if err := s.Validate(); err != nil {
		return fmt.Errorf("invalid embedded snapshot: %w", err)
	}
	if !s.CollectedAt.Equal(r.SnapshotCollectedAt) {
		return fmt.Errorf("report snapshot timestamp mismatch")
	}
	provenance := map[model.Provenance]bool{}
	sources := map[string]model.Source{}
	for _, source := range s.Sources {
		provenance[source.Provenance] = true
		sources[source.ID] = source
	}
	for _, e := range s.Entities {
		provenance[e.Provenance] = true
	}
	if provenance[model.ProvenanceSyntheticFixture] && r.FixtureNotice == "" {
		return fmt.Errorf("synthetic reports require a visible fixture notice")
	}
	seenProvenance := map[model.Provenance]bool{}
	for _, p := range r.InputProvenances {
		if !provenance[p] || seenProvenance[p] {
			return fmt.Errorf("report provenance mismatch")
		}
		seenProvenance[p] = true
	}
	if len(provenance) != len(seenProvenance) {
		return fmt.Errorf("report provenance is incomplete")
	}
	seenSource := map[string]bool{}
	complete := true
	for _, a := range r.Completeness.RequiredSources {
		source, present := sources[a.SourceID]
		satisfies := present && source.Status == model.SourceOK && source.Complete && source.PaginationComplete
		if seenSource[a.SourceID] || a.Present != present || a.SatisfiesRequiredCoverage != satisfies || a.Complete != source.Complete || a.PaginationComplete != source.PaginationComplete {
			return fmt.Errorf("source assessment mismatch")
		}
		seenSource[a.SourceID] = true
		complete = complete && satisfies
	}
	if len(seenSource) == 0 || r.Completeness.Complete != complete {
		return fmt.Errorf("required coverage mismatch")
	}
	entities := map[string]bool{}
	edges := map[string]bool{}
	evidence := map[string]model.Evidence{}
	for _, e := range s.Entities {
		entities[e.ID] = true
	}
	for _, e := range s.Relationships {
		edges[e.ID] = true
	}
	for _, v := range s.Evidence {
		evidence[v.ID] = v
	}
	if len(r.Evidence) != len(s.Evidence) {
		return fmt.Errorf("report evidence mismatch")
	}
	seenEvidence := map[string]bool{}
	for _, v := range r.Evidence {
		if seenEvidence[v.ID] || !reflect.DeepEqual(evidence[v.ID], v) {
			return fmt.Errorf("report evidence mismatch")
		}
		seenEvidence[v.ID] = true
	}
	validEvidence := func(ids []string) bool {
		if len(ids) == 0 {
			return false
		}
		for _, id := range ids {
			if _, ok := evidence[id]; !ok {
				return false
			}
		}
		return true
	}
	findings := map[string]bool{}
	for _, f := range r.Findings {
		if f.ID == "" || findings[f.ID] || model.SeverityRank(f.Severity) == 0 || !validEvidence(f.EvidenceIDs) || len(f.AffectedEntityIDs) == 0 {
			return fmt.Errorf("invalid finding")
		}
		findings[f.ID] = true
		for _, id := range f.AffectedEntityIDs {
			if !entities[id] {
				return fmt.Errorf("dangling finding entity")
			}
		}
		for _, id := range f.AffectedRelationshipIDs {
			if !edges[id] {
				return fmt.Errorf("dangling finding relationship")
			}
		}
	}
	for _, c := range r.Contexts {
		if !entities[c.EntityID] || c.ApplicationID == "" || c.Environment == "" || !validEvidence(c.EvidenceIDs) {
			return fmt.Errorf("invalid business context")
		}
		for _, id := range c.EvidenceIDs {
			if evidence[id].AssertionKind != model.AssertionDeclared {
				return fmt.Errorf("business context requires declared evidence")
			}
		}
	}
	for _, e := range r.PolicyExceptions {
		if !entities[e.EntityID] || e.RuleID != "IL008" || len(e.Environments) != 2 || e.Reason == "" {
			return fmt.Errorf("invalid policy exception")
		}
	}
	rules := map[string]bool{}
	referencedFindings := map[string]bool{}
	for _, result := range r.RuleResults {
		if rules[result.RuleID] || result.RuleVersion == "" {
			return fmt.Errorf("duplicate or invalid rule result")
		}
		rules[result.RuleID] = true
		switch result.Outcome {
		case model.OutcomePass, model.OutcomeFail, model.OutcomeUnknown, model.OutcomeNotApplicable:
		default:
			return fmt.Errorf("invalid rule outcome")
		}
		for _, id := range result.FindingIDs {
			if !findings[id] {
				return fmt.Errorf("dangling rule finding")
			}
			if referencedFindings[id] {
				return fmt.Errorf("duplicate rule finding reference")
			}
			referencedFindings[id] = true
			for _, f := range r.Findings {
				if f.ID == id && (f.RuleID != result.RuleID || f.RuleVersion != result.RuleVersion) {
					return fmt.Errorf("finding rule mismatch")
				}
			}
		}
	}
	if len(referencedFindings) != len(findings) {
		return fmt.Errorf("unreferenced report finding")
	}
	return nil
}

type Neighborhood struct {
	Nodes     []model.Entity       `json:"nodes"`
	Edges     []model.Relationship `json:"edges"`
	Truncated bool                 `json:"truncated"`
	Limit     int                  `json:"limit"`
}

// Neighborhood returns a deterministic bounded undirected neighborhood. Edges
// retain their original direction and assertions; no new relationships arise.
func Graph(s *model.Snapshot, root, assertion, typ string, depth int) Neighborhood {
	result := Neighborhood{Nodes: []model.Entity{}, Edges: []model.Relationship{}, Limit: 75}
	entities := map[string]model.Entity{}
	for _, e := range s.Entities {
		entities[e.ID] = e
	}
	if _, ok := entities[root]; !ok {
		return result
	}
	selected := map[string]bool{root: true}
	frontier := []string{root}
	result.Nodes = append(result.Nodes, entities[root])
	relationships := append([]model.Relationship(nil), s.Relationships...)
	sortEdges(relationships)
	for d := 0; d < depth; d++ {
		next := []string{}
		for _, id := range frontier {
			for _, edge := range relationships {
				if assertion != "" && string(edge.AssertionKind) != assertion || typ != "" && edge.Type != typ {
					continue
				}
				neighbor := ""
				if edge.From == id {
					neighbor = edge.To
				} else if edge.To == id {
					neighbor = edge.From
				}
				if neighbor == "" || selected[neighbor] {
					continue
				}
				if len(selected) >= 75 {
					result.Truncated = true
					continue
				}
				selected[neighbor] = true
				next = append(next, neighbor)
				result.Nodes = append(result.Nodes, entities[neighbor])
			}
		}
		frontier = next
	}
	for _, edge := range relationships {
		if selected[edge.From] && selected[edge.To] && (assertion == "" || string(edge.AssertionKind) == assertion) && (typ == "" || edge.Type == typ) {
			result.Edges = append(result.Edges, edge)
		}
	}
	return result
}
