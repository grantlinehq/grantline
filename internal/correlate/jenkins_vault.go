package correlate

import (
	"fmt"
	"sort"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
)

// AddJenkinsVaultBindings joins only collected endpoints with evidence. The
// declaration is not proof of authentication, credential contents or role use.
func AddJenkinsVaultBindings(snapshot *model.Snapshot, declarations []bindings.JenkinsVault) {
	entities := map[string]model.Entity{}
	evidence := map[string][]string{}
	for _, entity := range snapshot.Entities {
		entities[entity.ID] = entity
	}
	for _, item := range snapshot.Evidence {
		key := item.SourceID + "\x00" + item.NativeID
		evidence[key] = append(evidence[key], item.ID)
	}
	for index, binding := range declarations {
		from, foundFrom := entities[model.EntityID(binding.JenkinsSourceID, "credential_reference", binding.CredentialNativeID)]
		to, foundTo := entities[model.EntityID(binding.VaultSourceID, "vault_auth_role", binding.RoleNativeID)]
		typ, known := stringAttribute(to, "auth_type")
		fromEvidence := evidence[from.SourceID+"\x00"+from.NativeID]
		toEvidence := evidence[to.SourceID+"\x00"+to.NativeID]
		if !foundFrom || !foundTo || !known || typ != "approle" || len(fromEvidence) == 0 || len(toEvidence) == 0 {
			for i := range snapshot.Sources {
				source := &snapshot.Sources[i]
				if source.ID != binding.JenkinsSourceID {
					continue
				}
				source.Complete = false
				source.Status = model.SourcePartial
				if source.ErrorCode == "" {
					source.ErrorCode = "unresolved_declared_binding"
				}
				warning := fmt.Sprintf("Jenkins/Vault binding %d: collected endpoints or evidence unavailable", index+1)
				present := false
				for _, existing := range source.Warnings {
					if existing == warning {
						present = true
					}
				}
				if !present {
					source.Warnings = append(source.Warnings, warning)
				}
			}
			continue
		}
		scope := from.Scope
		id := model.RelationshipID(from.ID, to.ID, "bound_to", scope)
		if hasRelationship(snapshot.Relationships, id) {
			continue
		}
		locator := "bindings/jenkins-vault/" + id
		declarationID := model.EvidenceID(from.SourceID, from.NativeID, locator)
		snapshot.Evidence = append(snapshot.Evidence, model.Evidence{ID: declarationID, SourceID: from.SourceID, NativeID: from.NativeID, Locator: locator, Fields: []string{"jenkins_source_id", "credential_native_id", "vault_source_id", "role_native_id"}, AssertionKind: model.AssertionDeclared, ObservedAt: snapshot.CollectedAt})
		ids := append(append([]string{}, fromEvidence...), toEvidence...)
		ids = append(ids, declarationID)
		sort.Strings(ids)
		snapshot.Relationships = append(snapshot.Relationships, model.Relationship{ID: id, From: from.ID, To: to.ID, Type: "bound_to", Scope: scope, AssertionKind: model.AssertionDeclared, EvidenceIDs: unique(ids), ObservedAt: snapshot.CollectedAt})
	}
	sort.Slice(snapshot.Relationships, func(i, j int) bool { return snapshot.Relationships[i].ID < snapshot.Relationships[j].ID })
	sort.Slice(snapshot.Evidence, func(i, j int) bool { return snapshot.Evidence[i].ID < snapshot.Evidence[j].ID })
}
