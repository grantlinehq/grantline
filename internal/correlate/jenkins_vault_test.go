package correlate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
)

func bindingFixture() (model.Snapshot, bindings.JenkinsVault) {
	at := time.Unix(100, 0).UTC()
	s := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at}
	for _, source := range []model.Source{{ID: "j", Kind: "jenkins", Scope: "jenkins/j"}, {ID: "v", Kind: "vault", Scope: "vault/v"}, {ID: "other", Kind: "vault", Scope: "vault/other"}} {
		source.Status = model.SourceOK
		source.Complete = true
		source.PaginationComplete = true
		source.Provenance = model.ProvenanceLiveAPI
		s.Sources = append(s.Sources, source)
	}
	for _, entity := range []model.Entity{
		{SourceID: "j", Kind: "credential_reference", NativeID: "team/build/credentials/id", Scope: "jenkins/j/jobs/team/build"},
		{SourceID: "v", Kind: "vault_auth_role", NativeID: "approle/deploy", Scope: "vault/v", Attributes: map[string]json.RawMessage{"auth_type": json.RawMessage(`"approle"`)}, FieldStatus: map[string]model.FieldStatus{"auth_type": model.FieldKnown}},
		{SourceID: "other", Kind: "vault_auth_role", NativeID: "approle/deploy", Scope: "vault/other", Attributes: map[string]json.RawMessage{"auth_type": json.RawMessage(`"approle"`)}, FieldStatus: map[string]model.FieldStatus{"auth_type": model.FieldKnown}},
	} {
		entity.ID = model.EntityID(entity.SourceID, entity.Kind, entity.NativeID)
		entity.Name = "same-display-name"
		entity.ObservedAt = at
		entity.Provenance = model.ProvenanceLiveAPI
		s.Entities = append(s.Entities, entity)
		locator := "metadata/" + entity.ID
		s.Evidence = append(s.Evidence, model.Evidence{ID: model.EvidenceID(entity.SourceID, entity.NativeID, locator), SourceID: entity.SourceID, NativeID: entity.NativeID, Locator: locator, Fields: []string{"id"}, AssertionKind: model.AssertionObserved, ObservedAt: at})
	}
	return s, bindings.JenkinsVault{JenkinsSourceID: "j", CredentialNativeID: "team/build/credentials/id", VaultSourceID: "v", RoleNativeID: "approle/deploy"}
}

func TestDeclaredBindingUsesExactSourceAndNativeID(t *testing.T) {
	s, b := bindingFixture()
	AddJenkinsVaultBindings(&s, []bindings.JenkinsVault{b})
	AddJenkinsVaultBindings(&s, []bindings.JenkinsVault{b})
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Relationships) != 1 || len(s.Evidence) != 4 {
		t.Fatal("binding not idempotent")
	}
	edge := s.Relationships[0]
	if edge.AssertionKind != model.AssertionDeclared || edge.To != model.EntityID("v", "vault_auth_role", "approle/deploy") || len(edge.EvidenceIDs) != 3 {
		t.Fatal("binding inferred or wrong instance")
	}
}

func TestBindingDoesNotInventMissingEndpoints(t *testing.T) {
	for _, change := range []func(*model.Snapshot, *bindings.JenkinsVault){
		func(s *model.Snapshot, b *bindings.JenkinsVault) { b.CredentialNativeID = "same-display-name" },
		func(s *model.Snapshot, b *bindings.JenkinsVault) { b.RoleNativeID = "same-display-name" },
		func(s *model.Snapshot, b *bindings.JenkinsVault) { s.Evidence = nil },
		func(s *model.Snapshot, b *bindings.JenkinsVault) {
			s.Entities[1].Attributes["auth_type"] = json.RawMessage(`"kubernetes"`)
		},
	} {
		s, b := bindingFixture()
		change(&s, &b)
		AddJenkinsVaultBindings(&s, []bindings.JenkinsVault{b})
		if len(s.Relationships) != 0 || len(s.Entities) != 3 || s.Sources[0].Complete || s.Sources[0].ErrorCode != "unresolved_declared_binding" || !s.Sources[1].Complete {
			t.Fatal("dangling binding hidden or fabricated")
		}
	}
}
