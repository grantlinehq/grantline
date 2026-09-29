package analyze

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/graph"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"fmt"
	"sort"
	"strings"
	"time"
)

func evaluateSpire(ruleID string, g graph.Graph, s model.Snapshot, p policy.Policy) (model.RuleResult, []model.Finding) {
	result := model.RuleResult{RuleID: ruleID, RuleVersion: "1"}
	findings := []model.Finding{}
	assessed := false
	sources := map[string]model.Source{}
	unknown := func(text string) { result.Limitations = append(result.Limitations, text) }
	for _, source := range s.Sources {
		sources[source.ID] = source
		if source.Kind == "spire" && (!source.Complete || !source.PaginationComplete || source.Status != model.SourceOK) {
			unknown("SPIRE source coverage is incomplete; known findings are retained.")
		}
	}
	for _, required := range p.RequiredSources {
		if _, ok := sources[required]; !ok {
			unknown("A required source is missing.")
		}
	}
	add := func(e model.Entity, evidence []string, condition, description, recommendation, stable string) {
		findings = append(findings, model.Finding{ID: model.FindingID(ruleID, "1", e.ID, stable), RuleID: ruleID, RuleVersion: "1", Severity: p.Rules[ruleID].Severity, AffectedEntityIDs: []string{e.ID}, EvidenceIDs: sortedUnique(evidence), Condition: condition, Description: description, Recommendation: recommendation, Limitations: []string{"Registration configuration only; selector matches and configured TTL do not prove runtime issuance or effective access. Observed certificate expiry is separate evidence."}})
	}
	for _, e := range g.Entities {
		if e.Kind != "spire_entry" || sources[e.SourceID].Kind != "spire" {
			continue
		}
		kind, _ := vaultString(e, "entry_kind")
		if kind != "workload" {
			continue
		}
		switch ruleID {
		case "IL006":
			var selectors []model.SpireSelector
			if e.FieldStatus["selectors"] != model.FieldKnown || json.Unmarshal(e.Attributes["selectors"], &selectors) != nil || len(spireEvidence(s, e, "selectors")) == 0 {
				unknown("Workload selectors lack configured evidence.")
				continue
			}
			if !*p.Rules[ruleID].ForbidNamespaceOnly {
				assessed = true
				continue
			}
			// This rule is specifically about Kubernetes namespace-only registrations.
			supported := true
			for _, selector := range selectors {
				if selector.Type != "k8s" {
					supported = false
				}
			}
			evidence, parentOK := spireParentEvidence(g, s, e)
			if !supported || !parentOK {
				unknown("Workload parent alias or Kubernetes attestor context is unresolved or unsupported.")
				continue
			}
			assessed = true
			if len(selectors) == 1 && strings.HasPrefix(selectors[0].Value, "ns:") && len(selectors[0].Value) > 3 {
				evidence = append(evidence, spireEvidence(s, e, "selectors")...)
				add(e, evidence, "Policy forbids a namespace-only Kubernetes workload selector.", fmt.Sprintf("Registration %q selects only Kubernetes namespace %q within its configured parent alias.", e.NativeID, strings.TrimPrefix(selectors[0].Value, "ns:")), "Constrain the workload entry with the intended ServiceAccount or another verified workload selector.", "namespace-only")
			}
		case "IL007":
			for _, typ := range []string{"x509", "jwt"} {
				key := typ + "_svid_ttl_seconds"
				mode, _ := vaultString(e, typ+"_ttl_mode")
				var seconds int64
				evidence := spireEvidence(s, e, key)
				if mode != "explicit" || e.FieldStatus[key] != model.FieldKnown || json.Unmarshal(e.Attributes[key], &seconds) != nil || len(evidence) == 0 {
					unknown("A workload " + typ + " TTL is inherited or lacks explicit configured evidence; server defaults are unresolved.")
					continue
				}
				assessed = true
				limit := p.MaxX509SVIDTTL
				if typ == "jwt" {
					limit = p.MaxJWTSVIDTTL
				}
				if seconds <= int64(limit/time.Second) {
					continue
				}
				add(e, evidence, "Configured workload SVID TTL exceeds the policy limit.", fmt.Sprintf("Registration %q configures %s SVID TTL %ds, exceeding %s.", e.NativeID, typ, seconds, limit), "Review this registration and configure a lifetime within the approved policy limit.", typ)
			}
		}
	}
	result.Limitations = sortedUnique(result.Limitations)
	for _, f := range findings {
		result.FindingIDs = append(result.FindingIDs, f.ID)
	}
	sort.Strings(result.FindingIDs)
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
func spireEvidence(s model.Snapshot, e model.Entity, field string) []string {
	var ids []string
	for _, v := range s.Evidence {
		if v.SourceID != e.SourceID || v.NativeID != e.NativeID || v.AssertionKind != model.AssertionConfigured {
			continue
		}
		for _, f := range v.Fields {
			if f == field {
				ids = append(ids, v.ID)
				break
			}
		}
	}
	return ids
}
func spireParentEvidence(g graph.Graph, s model.Snapshot, e model.Entity) ([]string, bool) {
	parent, ok := vaultString(e, "parent_spiffe_id")
	if !ok || len(spireEvidence(s, e, "parent_spiffe_id")) == 0 {
		return nil, false
	}
	ids, known := vaultStringList(e, "parent_entry_ids")
	if !known || len(ids) == 0 {
		return nil, false
	}
	evidence := spireEvidence(s, e, "parent_spiffe_id")
	for _, id := range ids {
		alias, ok := g.Entities[model.EntityID(e.SourceID, "spire_entry", "entry/"+id)]
		if !ok {
			return nil, false
		}
		kind, _ := vaultString(alias, "entry_kind")
		uri, _ := vaultString(alias, "spiffe_id")
		if kind != "node_alias" || uri != parent || alias.Scope != e.Scope {
			return nil, false
		}
		var selectors []model.SpireSelector
		if alias.FieldStatus["selectors"] != model.FieldKnown || json.Unmarshal(alias.Attributes["selectors"], &selectors) != nil || len(selectors) == 0 {
			return nil, false
		}
		for _, selector := range selectors {
			if selector.Type != "k8s_psat" && selector.Type != "k8s_sat" {
				return nil, false
			}
		}
		aliasEvidence := spireEvidence(s, alias, "selectors")
		if len(aliasEvidence) == 0 {
			return nil, false
		}
		evidence = append(evidence, aliasEvidence...)
	}
	return evidence, true
}
