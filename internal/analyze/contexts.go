package analyze

import (
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/graph"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"fmt"
	"sort"
)

func applyContexts(s *model.Snapshot, b *bindings.Config) ([]model.EntityContext, []string, error) {
	if b == nil {
		return nil, nil, nil
	}
	var sources []config.Source
	for _, source := range s.Sources {
		sources = append(sources, config.Source{ID: source.ID, Kind: source.Kind, Scope: source.Scope})
	}
	if err := b.Validate(sources); err != nil {
		return nil, nil, err
	}
	// The analyzer owns the extended slices; callers' snapshots remain unchanged.
	s.Evidence = append([]model.Evidence(nil), s.Evidence...)
	s.Relationships = append([]model.Relationship(nil), s.Relationships...)
	s.Sources = append([]model.Source(nil), s.Sources...)
	for i := range s.Sources {
		s.Sources[i].Warnings = append([]string(nil), s.Sources[i].Warnings...)
	}
	correlate.AddJenkinsVaultBindings(s, b.JenkinsVault)
	issues := correlate.AddSpireKubernetesMatches(s, b.SpireKubernetes)
	issues = append(issues, correlate.AddDeclaredVaultMounts(s, b.VaultKubernetes)...)
	entities := map[string]model.Entity{}
	for _, e := range s.Entities {
		entities[e.ID] = e
	}
	var contexts []model.EntityContext
	for _, app := range b.Applications {
		for _, m := range app.Members {
			id := model.EntityID(m.SourceID, m.Kind, m.NativeID)
			e, ok := entities[id]
			if !ok {
				issues = append(issues, fmt.Sprintf("Application %s has an unresolved %s native reference in source %s.", app.ID, m.Kind, m.SourceID))
				continue
			}
			locator := "bindings/applications/" + app.ID + "/" + m.Environment + "/" + e.ID
			v := model.Evidence{ID: model.EvidenceID(e.SourceID, e.NativeID, locator), SourceID: e.SourceID, NativeID: e.NativeID, Locator: locator, Fields: []string{"business_application", "environment", "owner_hint"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionDeclared}
			found := false
			for _, old := range s.Evidence {
				if old.ID == v.ID {
					found = true
					break
				}
			}
			if !found {
				s.Evidence = append(s.Evidence, v)
			}
			contexts = append(contexts, model.EntityContext{EntityID: e.ID, ApplicationID: app.ID, ApplicationName: app.Name, Environment: m.Environment, OwnerHint: app.OwnerHint, EvidenceIDs: []string{v.ID}})
		}
	}
	sort.Slice(contexts, func(i, j int) bool {
		a, b := contexts[i], contexts[j]
		return a.EntityID+a.ApplicationID+a.Environment < b.EntityID+b.ApplicationID+b.Environment
	})
	return contexts, sortedUnique(issues), nil
}

// Only explicit identity-bearing edges are traversed. This is an environment
// separation check, not a transitive permission or authentication calculation.
func evaluateIL008(g graph.Graph, s model.Snapshot, contexts []model.EntityContext, issues []string, rule policy.Rule, coverage model.Completeness) (model.RuleResult, []model.Finding, []model.PolicyException) {
	result := model.RuleResult{RuleID: "IL008", RuleVersion: "1", Limitations: append([]string(nil), issues...)}
	if !coverage.Complete {
		result.Limitations = append(result.Limitations, "Required source coverage is incomplete; known environment conflicts are retained.")
	}
	type association struct{ evidence, edges []string }
	associations := map[string]map[string]association{}
	for _, c := range contexts {
		e := g.Entities[c.EntityID]
		targets := []model.Entity{}
		evidence := append([]string(nil), c.EvidenceIDs...)
		edges := []string{}
		if policy.PrincipalKind(e.Kind) {
			targets = append(targets, e)
		} else {
			typ := ""
			switch e.Kind {
			case "workload":
				typ = "runs_as"
			case "spire_entry":
				typ = "assigned_spiffe_id"
			case "application_registration":
				typ = "registered_as"
			}
			if typ == "" {
				continue
			}
			for _, edge := range g.Outgoing(e.ID, typ) {
				target := g.Entities[edge.To]
				if policy.PrincipalKind(target.Kind) && edge.AssertionKind != model.AssertionInferred && len(edge.EvidenceIDs) > 0 {
					targets = append(targets, target)
					evidence = append(evidence, edge.EvidenceIDs...)
					edges = append(edges, edge.ID)
				}
			}
		}
		if len(targets) == 0 {
			result.Limitations = append(result.Limitations, "A declared environment member has no resolved native principal.")
		}
		for _, target := range targets {
			native := []string{}
			for _, v := range s.Evidence {
				if v.SourceID == target.SourceID && v.NativeID == target.NativeID && (v.AssertionKind == model.AssertionConfigured || v.AssertionKind == model.AssertionObserved) {
					native = append(native, v.ID)
				}
			}
			if target.Kind == "spiffe_identity" {
				for _, edge := range s.Relationships {
					if edge.Type == "assigned_spiffe_id" && edge.To == target.ID && edge.AssertionKind == model.AssertionConfigured {
						native = append(native, edge.EvidenceIDs...)
					}
				}
			}
			if len(native) == 0 {
				result.Limitations = append(result.Limitations, "A principal lacks native identity evidence.")
				continue
			}
			if associations[target.ID] == nil {
				associations[target.ID] = map[string]association{}
			}
			a := associations[target.ID][c.Environment]
			a.evidence = append(a.evidence, append(evidence, native...)...)
			a.edges = append(a.edges, edges...)
			associations[target.ID][c.Environment] = a
		}
	}
	var findings []model.Finding
	var exceptions []model.PolicyException
	ids := []string{}
	for id := range associations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		envs := associations[id]
		e := g.Entities[id]
		for _, pair := range rule.SeparatedEnvironments {
			a, aOK := envs[pair.First]
			b, bOK := envs[pair.Second]
			if !aOK || !bOK {
				continue
			}
			exempt := false
			for _, exception := range rule.AllowedSharedIdentities {
				if exception.SourceID == e.SourceID && exception.Kind == e.Kind && exception.NativeID == e.NativeID && ((exception.First == pair.First && exception.Second == pair.Second) || (exception.Second == pair.First && exception.First == pair.Second)) {
					exceptions = append(exceptions, model.PolicyException{RuleID: "IL008", EntityID: id, Environments: []string{pair.First, pair.Second}, Reason: exception.Reason})
					exempt = true
					break
				}
			}
			if exempt {
				continue
			}
			environments := []string{pair.First, pair.Second}
			sort.Strings(environments)
			findings = append(findings, model.Finding{ID: model.FindingID("IL008", "1", id, environments[0], environments[1]), RuleID: "IL008", RuleVersion: "1", Severity: rule.Severity, AffectedEntityIDs: []string{id}, AffectedRelationshipIDs: sortedUnique(append(a.edges, b.edges...)), EvidenceIDs: sortedUnique(append(a.evidence, b.evidence...)), Condition: "The same native principal is associated with environments that policy separates.", Description: fmt.Sprintf("%s is associated with both %s and %s.", e.Name, pair.First, pair.Second), Recommendation: "Use separate native principals for these environments, or document an exact shared-service exception with its reason.", Limitations: []string{"Environment membership is operator-declared; identity links are collected metadata. This does not prove runtime use or effective access."}})
		}
	}
	for _, f := range findings {
		result.FindingIDs = append(result.FindingIDs, f.ID)
	}
	if len(contexts) == 0 {
		result.Limitations = append(result.Limitations, "No explicit environment bindings were supplied.")
	}
	result.Limitations = sortedUnique(result.Limitations)
	switch {
	case len(result.Limitations) > 0:
		result.Outcome = model.OutcomeUnknown
	case len(findings) > 0:
		result.Outcome = model.OutcomeFail
	case len(associations) == 0:
		result.Outcome = model.OutcomeNotApplicable
	default:
		result.Outcome = model.OutcomePass
	}
	result.Limitations = sortedUnique(append(result.Limitations, "This check covers explicit environment members; unassigned inventory is outside its scope."))
	return result, findings, exceptions
}
