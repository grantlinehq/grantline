package correlate

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"sort"
	"strings"
)

// Parent-to-cluster is an explicit operator declaration. Selector matches remain
// declared/configured evidence, never proof that a workload received an SVID.
func AddSpireKubernetesMatches(s *model.Snapshot, mappings []bindings.SpireKubernetes) []string {
	var issues []string
	for _, mapping := range mappings {
		aliases := []model.Entity{}
		sourceOK := false
		clusterScope := ""
		for _, source := range s.Sources {
			if source.ID == mapping.KubernetesSourceID && source.Kind == "kubernetes" {
				sourceOK = true
				clusterScope = source.Scope
			}
		}
		for _, e := range s.Entities {
			kind, _ := stringAttribute(e, "entry_kind")
			id, _ := stringAttribute(e, "spiffe_id")
			if e.SourceID == mapping.SpireSourceID && e.Kind == "spire_entry" && kind == "node_alias" && id == mapping.ParentID {
				aliases = append(aliases, e)
			}
		}
		if !sourceOK || len(aliases) == 0 {
			issues = append(issues, "SPIRE parent/cluster declaration has unresolved collected endpoints.")
			continue
		}
		parentEvidence := []string{}
		validParent := true
		for _, alias := range aliases {
			if alias.FieldStatus["selectors"] != model.FieldKnown {
				validParent = false
			}
			var selectors []model.SpireSelector
			json.Unmarshal(alias.Attributes["selectors"], &selectors)
			clusterFound := false
			for _, selector := range selectors {
				if selector.Type != "k8s_psat" {
					validParent = false
				}
				switch {
				case selector.Value == "cluster:"+mapping.Cluster:
					clusterFound = true
				case strings.HasPrefix(selector.Value, "agent_ns:") || strings.HasPrefix(selector.Value, "agent_sa:"):
				default:
					validParent = false
				}
			}
			if !clusterFound {
				validParent = false
			}
			parentEvidence = append(parentEvidence, configuredEvidence(*s, alias)...)
		}
		if !validParent || len(parentEvidence) == 0 {
			issues = append(issues, "SPIRE parent attestor constraints do not establish the declared cluster scope.")
			continue
		}
		for _, entry := range s.Entities {
			parent, _ := stringAttribute(entry, "parent_spiffe_id")
			kind, _ := stringAttribute(entry, "entry_kind")
			if entry.SourceID != mapping.SpireSourceID || entry.Kind != "spire_entry" || kind != "workload" || parent != mapping.ParentID {
				continue
			}
			var selectors []model.SpireSelector
			json.Unmarshal(entry.Attributes["selectors"], &selectors)
			namespace, account := "", ""
			supported := len(selectors) > 0 && entry.FieldStatus["selectors"] == model.FieldKnown
			for _, selector := range selectors {
				if selector.Type != "k8s" {
					supported = false
				}
				switch {
				case strings.HasPrefix(selector.Value, "ns:") && namespace == "":
					namespace = strings.TrimPrefix(selector.Value, "ns:")
				case strings.HasPrefix(selector.Value, "sa:") && account == "":
					account = strings.TrimPrefix(selector.Value, "sa:")
				default:
					supported = false
				}
			}
			entryEvidence := configuredEvidence(*s, entry)
			if !supported || namespace == "" || len(entryEvidence) == 0 {
				issues = append(issues, "A SPIRE workload selector conjunction is unsupported for exact Kubernetes matching.")
				continue
			}
			matched := false
			for _, sa := range s.Entities {
				if sa.SourceID != mapping.KubernetesSourceID || sa.Kind != "service_account" || sa.Scope != clusterScope+"/namespaces/"+namespace || account != "" && sa.Name != account {
					continue
				}
				observed := nativeEvidence(*s, sa)
				if len(observed) == 0 {
					continue
				}
				id := model.RelationshipID(entry.ID, sa.ID, "selector_matches", entry.Scope)
				matched = true
				if hasRelationship(s.Relationships, id) {
					continue
				}
				declaration := model.Evidence{ID: model.EvidenceID(entry.SourceID, entry.NativeID, "bindings/spire-kubernetes/"+id), SourceID: entry.SourceID, NativeID: entry.NativeID, Locator: "bindings/spire-kubernetes/" + id, Fields: []string{"parent_spiffe_id", "cluster_scope", "selectors"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionDeclared}
				s.Evidence = append(s.Evidence, declaration)
				ids := append(append(append([]string{declaration.ID}, entryEvidence...), parentEvidence...), observed...)
				sort.Strings(ids)
				s.Relationships = append(s.Relationships, model.Relationship{ID: id, From: entry.ID, To: sa.ID, Type: "selector_matches", Scope: entry.Scope, AssertionKind: model.AssertionDeclared, EvidenceIDs: unique(ids), ObservedAt: s.CollectedAt})
			}
			if !matched {
				issues = append(issues, "A SPIRE workload selector has no collected Kubernetes subject in the declared cluster.")
			}
		}
	}
	sort.Strings(issues)
	return unique(issues)
}
func nativeEvidence(s model.Snapshot, e model.Entity) []string {
	var ids []string
	for _, v := range s.Evidence {
		if v.SourceID == e.SourceID && v.NativeID == e.NativeID && (v.AssertionKind == model.AssertionObserved || v.AssertionKind == model.AssertionConfigured) {
			ids = append(ids, v.ID)
		}
	}
	return ids
}
func configuredEvidence(s model.Snapshot, e model.Entity) []string {
	var ids []string
	for _, v := range s.Evidence {
		if v.SourceID == e.SourceID && v.NativeID == e.NativeID && v.AssertionKind == model.AssertionConfigured {
			ids = append(ids, v.ID)
		}
	}
	return ids
}
