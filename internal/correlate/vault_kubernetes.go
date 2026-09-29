package correlate

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/grantlinehq/grantline/internal/model"
)

type VaultKubernetesBinding struct {
	VaultSourceID      string
	KubernetesSourceID string
}

func AddVaultKubernetesTrusts(snapshot *model.Snapshot, bindings []VaultKubernetesBinding) error {
	evidenceBySourceNative := make(map[string][]string)
	for _, item := range snapshot.Evidence {
		key := item.SourceID + "\x00" + item.NativeID
		evidenceBySourceNative[key] = append(evidenceBySourceNative[key], item.ID)
	}
	for _, binding := range bindings {
		for _, entity := range snapshot.Entities {
			if entity.Kind != "vault_auth_role" || entity.SourceID != binding.VaultSourceID {
				continue
			}
			authType, known := stringAttribute(entity, "auth_type")
			if !known || authType != "kubernetes" {
				continue
			}
			names, namesKnown := stringListAttribute(entity, "bound_service_account_names")
			namespaces, namespacesKnown := stringListAttribute(entity, "bound_service_account_namespaces")
			if !namesKnown || !namespacesKnown {
				continue
			}
			for _, namespace := range namespaces {
				if namespace == "*" {
					continue
				}
				for _, name := range names {
					if name == "*" {
						continue
					}
					subject, ok := serviceAccountForNamespace(snapshot.Entities, binding.KubernetesSourceID, namespace, name)
					if !ok {
						continue
					}
					evidenceIDs := append([]string(nil), evidenceBySourceNative[binding.VaultSourceID+"\x00"+entity.NativeID]...)
					evidenceIDs = append(evidenceIDs, evidenceBySourceNative[binding.KubernetesSourceID+"\x00"+subject.NativeID]...)
					if len(evidenceIDs) == 0 {
						return fmt.Errorf("missing evidence for Vault/Kubernetes trust correlation")
					}
					sort.Strings(evidenceIDs)
					relationship := model.Relationship{ID: model.RelationshipID(entity.ID, subject.ID, "trusts_subject", subject.Scope), From: entity.ID, To: subject.ID, Type: "trusts_subject", AssertionKind: model.AssertionConfigured, EvidenceIDs: unique(evidenceIDs), Scope: subject.Scope, ObservedAt: entity.ObservedAt}
					if !hasRelationship(snapshot.Relationships, relationship.ID) {
						snapshot.Relationships = append(snapshot.Relationships, relationship)
					}
				}
			}
		}
	}
	sort.Slice(snapshot.Relationships, func(i, j int) bool { return snapshot.Relationships[i].ID < snapshot.Relationships[j].ID })
	return nil
}

func serviceAccountForNamespace(entities []model.Entity, sourceID, namespace, name string) (model.Entity, bool) {
	suffix := "/namespaces/" + namespace
	for _, entity := range entities {
		if entity.Kind == "service_account" && entity.SourceID == sourceID && entity.Name == name && len(entity.Scope) >= len(suffix) && entity.Scope[len(entity.Scope)-len(suffix):] == suffix {
			return entity, true
		}
	}
	return model.Entity{}, false
}
func hasRelationship(items []model.Relationship, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}
func stringAttribute(entity model.Entity, key string) (string, bool) {
	raw, ok := entity.Attributes[key]
	if !ok || entity.FieldStatus[key] != model.FieldKnown {
		return "", false
	}
	var value string
	return value, json.Unmarshal(raw, &value) == nil
}
func stringListAttribute(entity model.Entity, key string) ([]string, bool) {
	raw, ok := entity.Attributes[key]
	if !ok || entity.FieldStatus[key] != model.FieldKnown {
		return nil, false
	}
	var value []string
	return value, json.Unmarshal(raw, &value) == nil
}
func unique(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	output := items[:1]
	for _, item := range items[1:] {
		if item != output[len(output)-1] {
			output = append(output, item)
		}
	}
	return output
}
