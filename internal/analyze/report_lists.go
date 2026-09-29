package analyze

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/model"
)

// Required JSON arrays/objects stay arrays/objects even when an earlier collector
// used nil slices. Normalize an owned copy; source evidence and status do not change.
func normalizeReportLists(r *model.Report) {
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	if r.RuleResults == nil {
		r.RuleResults = []model.RuleResult{}
	}
	if r.Evidence == nil {
		r.Evidence = []model.Evidence{}
	}
	if r.InputProvenances == nil {
		r.InputProvenances = []model.Provenance{}
	}
	for i := range r.RuleResults {
		if r.RuleResults[i].FindingIDs == nil {
			r.RuleResults[i].FindingIDs = []string{}
		}
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.AffectedRelationshipIDs == nil {
			f.AffectedRelationshipIDs = []string{}
		}
		if f.Limitations == nil {
			f.Limitations = []string{}
		}
	}
	if r.Snapshot == nil {
		return
	}
	s := *r.Snapshot
	s.Entities = append([]model.Entity{}, s.Entities...)
	s.Sources = append([]model.Source{}, s.Sources...)
	s.Relationships = append([]model.Relationship{}, s.Relationships...)
	s.Evidence = append([]model.Evidence{}, s.Evidence...)
	for i := range s.Entities {
		if s.Entities[i].Attributes == nil {
			s.Entities[i].Attributes = map[string]json.RawMessage{}
		}
		if s.Entities[i].FieldStatus == nil {
			s.Entities[i].FieldStatus = map[string]model.FieldStatus{}
		}
	}
	for i := range s.Sources {
		if s.Sources[i].Warnings == nil {
			s.Sources[i].Warnings = []string{}
		}
		if s.Sources[i].PermissionsObserved == nil {
			s.Sources[i].PermissionsObserved = []string{}
		}
	}
	r.Snapshot = &s
}
