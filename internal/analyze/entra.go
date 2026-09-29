package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/grantlinehq/grantline/internal/graph"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

func evaluateEntra(ruleID string, g graph.Graph, s model.Snapshot, p policy.Policy) (model.RuleResult, []model.Finding) {
	rule := p.Rules[ruleID]
	result := model.RuleResult{RuleID: ruleID, RuleVersion: "1"}
	var findings []model.Finding
	assessed := false
	sources := map[string]model.Source{}
	for _, source := range s.Sources {
		sources[source.ID] = source
	}
	for _, required := range p.RequiredSources {
		source, ok := sources[required]
		if !ok || source.Kind == "entra" && (!source.Complete || !source.PaginationComplete || source.Status != model.SourceOK) {
			result.Limitations = append(result.Limitations, "Required Entra source coverage is incomplete.")
		}
	}
	selected := func(e model.Entity) bool {
		role, ok := vaultString(e, "collection_role")
		return ok && role == "selected" && (e.Kind == "application_registration" || e.Kind == "service_principal") && sources[e.SourceID].Kind == "entra"
	}
	unknown := func(text string) { result.Limitations = append(result.Limitations, text) }
	add := func(e model.Entity, relationships []string, evidence []string, condition, description, recommendation, limitation string, stable ...string) {
		if len(evidence) == 0 {
			unknown("Required Entra evidence is missing.")
			return
		}
		findings = append(findings, model.Finding{ID: model.FindingID(ruleID, "1", append([]string{e.ID}, stable...)...), RuleID: ruleID, RuleVersion: "1", Severity: rule.Severity, AffectedEntityIDs: []string{e.ID}, AffectedRelationshipIDs: sortedUnique(relationships), EvidenceIDs: sortedUnique(evidence), Condition: condition, Description: description, Recommendation: recommendation, Limitations: []string{limitation}})
	}
	switch ruleID {
	case "IL003":
		for _, parent := range g.Entities {
			if !selected(parent) {
				continue
			}
			count, known := entraCount(parent, "client_credentials_count")
			if known && len(fieldEvidence(s, parent, "client_credentials_count")) == 0 {
				known = false
			}
			if !known {
				unknown("Client credential collection is incomplete.")
			}
			found := 0
			for _, edge := range g.Outgoing(parent.ID, "references_credential") {
				credential := g.Entities[edge.To]
				typ, typed := vaultString(credential, "credential_type")
				if credential.Kind != "credential_metadata" || credential.SourceID != parent.SourceID {
					continue
				}
				if !typed {
					unknown("Credential type is unresolved.")
					continue
				}
				if typ != "client_secret" {
					continue
				}
				parentID, _ := vaultString(parent, "object_id")
				credentialParent, parentOK := vaultString(credential, "parent_object_id")
				parentKind, kindOK := vaultString(credential, "parent_kind")
				if !parentOK || !kindOK || credentialParent != parentID || parentKind != parent.Kind {
					unknown("Credential reference parent identity is inconsistent.")
					continue
				}
				found++
				start, startOK := entraTime(credential, "start_time")
				end, endOK := entraTime(credential, "end_time")
				if !startOK || !endOK || end.Before(start) {
					unknown("Client credential validity dates are incomplete or invalid.")
					continue
				}
				assessed = true
				if !end.After(start.Add(p.MaxClientSecretValidity)) {
					continue
				}
				add(credential, []string{edge.ID}, append(entityEvidence(s, credential.SourceID, credential.NativeID), edge.EvidenceIDs...), "Client credential record validity exceeds the configured policy duration.", fmt.Sprintf("Credential metadata %q has configured validity %s, exceeding %s.", credential.NativeID, end.Sub(start), p.MaxClientSecretValidity), "Review the allowed credential validity and use a shorter lifetime or supported federation.", "Configured start/end metadata only; no credential value, last rotation, current use or successful authentication is inferred.", start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
			}
			if known && count != found {
				unknown("Client credential count and collected references disagree.")
			} else if known && count == 0 {
				assessed = true
			}
		}
	case "IL004":
		for _, target := range rule.RequireOwnersFor {
			var e model.Entity
			found := false
			for _, candidate := range g.Entities {
				object, ok := vaultString(candidate, "object_id")
				if selected(candidate) && candidate.SourceID == target.SourceID && candidate.Kind == target.ObjectKind && ok && object == target.ObjectID {
					e = candidate
					found = true
					break
				}
			}
			if !found {
				unknown("An IL004 target is missing or was not selected for full collection.")
				continue
			}
			count, known := entraCount(e, "owners_count")
			if !known {
				unknown("Required owner collection is incomplete or permission denied.")
				continue
			}
			edges := g.Outgoing(e.ID, "owned_by")
			validOwners := true
			for _, edge := range edges {
				owner := g.Entities[edge.To]
				if owner.Kind != "owner" || owner.SourceID != e.SourceID || (edge.AssertionKind != model.AssertionConfigured && edge.AssertionKind != model.AssertionObserved) {
					validOwners = false
				}
			}
			if !validOwners {
				unknown("Directory owner references have inconsistent source or assertion provenance.")
				continue
			}
			if count != len(edges) {
				unknown("Owner count and collected owner references disagree.")
				continue
			}
			assessed = true
			if count != 0 {
				continue
			}
			// A successful, complete owners endpoint is required as negative evidence.
			evidence := fieldEvidence(s, e, "owners_count")
			if len(evidence) == 0 {
				unknown("Complete empty owners evidence is unavailable.")
				continue
			}
			add(e, nil, evidence, "A policy-required application or service principal has a complete empty owners collection.", fmt.Sprintf("The selected %s %q has no directory owners.", e.Kind, e.NativeID), "Assign an accountable directory owner through the normal approval process.", "Application and service principal owners are separate; business owner hints are not directory owners.")
		}
	case "IL005":
		for _, principal := range g.Entities {
			if !selected(principal) || principal.Kind != "service_principal" {
				continue
			}
			count, known := entraCount(principal, "app_role_assignments_count")
			if known && len(fieldEvidence(s, principal, "app_role_assignments_count")) == 0 {
				known = false
			}
			if !known {
				unknown("Granted app-role collection or role resolution is incomplete.")
			}
			found := 0
			for _, binding := range g.Entities {
				if binding.Kind != "role_binding" || binding.SourceID != principal.SourceID {
					continue
				}
				kind, ok := vaultString(binding, "binding_kind")
				if !ok || kind != "entra_app_role_assignment" {
					continue
				}
				bound := g.Outgoing(binding.ID, "bound_to")
				if len(bound) != 1 || bound[0].To != principal.ID {
					continue
				}
				found++
				grants := g.Outgoing(binding.ID, "grants_role")
				definition, knownDefinition := vaultString(binding, "role_definition_id")
				if len(grants) != 1 || !knownDefinition {
					unknown("A granted app role has no complete resource role definition.")
					continue
				}
				role := g.Entities[grants[0].To]
				if role.NativeID != definition || role.Kind != "role" || role.SourceID != binding.SourceID {
					unknown("Resource role definition does not match the assignment.")
					continue
				}
				principalID, pOK := vaultString(binding, "principal_object_id")
				resourceID, rOK := vaultString(binding, "resource_object_id")
				roleID, aOK := vaultString(binding, "app_role_id")
				definitionResource, dROK := vaultString(role, "resource_object_id")
				definitionRole, dAOK := vaultString(role, "app_role_id")
				objectID, _ := vaultString(principal, "object_id")
				if !pOK || !rOK || !aOK || !dROK || !dAOK || principalID != objectID || resourceID != definitionResource || roleID != definitionRole {
					unknown("Assignment and definition IDs are inconsistent.")
					continue
				}
				assessed = true
				if rule.AllowsAppRole(binding.SourceID, principalID, resourceID, roleID) {
					continue
				}
				evidence := append(append([]string{}, bound[0].EvidenceIDs...), grants[0].EvidenceIDs...)
				add(binding, []string{bound[0].ID, grants[0].ID}, evidence, "A granted Entra application role is outside the explicit policy allowlist.", fmt.Sprintf("Service principal %q is assigned role %q on resource service principal %q.", principalID, roleID, resourceID), "Review the actual app-role assignment and add an exact exception only when approved.", "This is a configured Graph app-role assignment, not requested permissions, delegated grants, Azure ARM RBAC or proof of effective access.")
			}
			if known && count != found {
				unknown("Granted app-role count and assignment records disagree.")
			} else if known && count == 0 {
				assessed = true
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	for _, finding := range findings {
		result.FindingIDs = append(result.FindingIDs, finding.ID)
	}
	result.Limitations = sortedUnique(result.Limitations)
	switch {
	case len(result.Limitations) > 0:
		result.Outcome = model.OutcomeUnknown
	case len(findings) > 0:
		result.Outcome = model.OutcomeFail
	case assessed:
		result.Outcome = model.OutcomePass
	default:
		result.Outcome = model.OutcomeNotApplicable
	}
	return result, findings
}
func entraCount(e model.Entity, key string) (int, bool) {
	var count int
	raw, exists := e.Attributes[key]
	return count, exists && e.FieldStatus[key] == model.FieldKnown && json.Unmarshal(raw, &count) == nil && count >= 0
}
func entraTime(e model.Entity, key string) (time.Time, bool) {
	value, ok := vaultString(e, key)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	return t, err == nil
}
func fieldEvidence(s model.Snapshot, e model.Entity, field string) []string {
	var result []string
	for _, item := range s.Evidence {
		if item.SourceID != e.SourceID || item.NativeID != e.NativeID {
			continue
		}
		for _, name := range item.Fields {
			if name == field {
				result = append(result, item.ID)
				break
			}
		}
	}
	return result
}
