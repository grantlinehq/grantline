package correlate

import (
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"sort"
)

// AddDeclaredVaultMounts scopes each explicit mapping to one collected mount.
func AddDeclaredVaultMounts(s *model.Snapshot, mappings []bindings.VaultKubernetes) []string {
	var issues []string
	for _, b := range mappings {
		found := false
		clusterScope := ""
		for _, source := range s.Sources {
			if source.ID == b.KubernetesSourceID && source.Kind == "kubernetes" {
				clusterScope = source.Scope
			}
		}
		for _, role := range s.Entities {
			mount, _ := stringAttribute(role, "auth_mount")
			typ, _ := stringAttribute(role, "auth_type")
			if role.SourceID != b.VaultSourceID || role.Kind != "vault_auth_role" || mount != b.Mount || typ != "kubernetes" {
				continue
			}
			found = true
			names, nOK := stringListAttribute(role, "bound_service_account_names")
			namespaces, nsOK := stringListAttribute(role, "bound_service_account_namespaces")
			roleEvidence := nativeEvidence(*s, role)
			if clusterScope == "" || !nOK || !nsOK || len(roleEvidence) == 0 {
				issues = append(issues, "A Vault mount declaration lacks collected role, cluster or subject evidence.")
				continue
			}
			for _, ns := range namespaces {
				for _, name := range names {
					if ns == "*" || name == "*" {
						issues = append(issues, "A Vault mount has wildcard subjects; exact subject correlation is unresolved.")
						continue
					}
					sa, ok := serviceAccountForNamespace(s.Entities, b.KubernetesSourceID, ns, name)
					if !ok || sa.Scope != clusterScope+"/namespaces/"+ns || len(nativeEvidence(*s, sa)) == 0 {
						issues = append(issues, "A declared Vault mount subject does not resolve to a collected Kubernetes native identity.")
						continue
					}
					id := model.RelationshipID(role.ID, sa.ID, "trusts_subject", sa.Scope)
					locator := "bindings/vault-kubernetes/" + id
					v := model.Evidence{ID: model.EvidenceID(role.SourceID, role.NativeID, locator), SourceID: role.SourceID, NativeID: role.NativeID, Locator: locator, Fields: []string{"auth_mount", "kubernetes_source_id"}, ObservedAt: s.CollectedAt, AssertionKind: model.AssertionDeclared}
					exists := false
					for _, old := range s.Evidence {
						if old.ID == v.ID {
							exists = true
						}
					}
					if !exists {
						s.Evidence = append(s.Evidence, v)
					}
					ids := append(append([]string{v.ID}, roleEvidence...), nativeEvidence(*s, sa)...)
					sort.Strings(ids)
					edge := model.Relationship{ID: id, From: role.ID, To: sa.ID, Type: "trusts_subject", Scope: sa.Scope, AssertionKind: model.AssertionDeclared, EvidenceIDs: unique(ids), ObservedAt: s.CollectedAt}
					replaced := false
					for i, old := range s.Relationships {
						if old.ID == id {
							s.Relationships[i] = edge
							replaced = true
							break
						}
					}
					if !replaced {
						s.Relationships = append(s.Relationships, edge)
					}
				}
			}
		}
		if !found {
			issues = append(issues, "A Vault mount declaration does not resolve to any collected Kubernetes auth role.")
		}
	}
	sort.Strings(issues)
	return unique(issues)
}
