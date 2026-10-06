package analyze

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

func jenkinsEnvironmentFixture(t *testing.T) (model.Snapshot, policy.Policy, bindings.Config) {
	t.Helper()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at, Sources: []model.Source{
		{ID: "jenkins", Kind: "jenkins", Scope: "jenkins/test", Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI},
		{ID: "vault", Kind: "vault", Scope: "vault/test", Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI},
	}}
	entity := func(source, kind, native string, values map[string]any) model.Entity {
		e := model.Entity{ID: model.EntityID(source, kind, native), SourceID: source, Kind: kind, NativeID: native, Name: native, Scope: source + "/test", ObservedAt: at, Provenance: model.ProvenanceLiveAPI, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}}
		for key, value := range values {
			e.Attributes[key], _ = json.Marshal(value)
			e.FieldStatus[key] = model.FieldKnown
		}
		return e
	}
	proof := func(e model.Entity, locator, field string, assertion model.AssertionKind) string {
		v := model.Evidence{ID: model.EvidenceID(e.SourceID, e.NativeID, locator), SourceID: e.SourceID, NativeID: e.NativeID, Locator: locator, Fields: []string{field}, AssertionKind: assertion, ObservedAt: at}
		s.Evidence = append(s.Evidence, v)
		return v.ID
	}
	role := entity("vault", "vault_auth_role", "approle/shared", map[string]any{"auth_mount": "approle", "auth_type": "approle", "policy_names": []string{"payments-read"}})
	s.Entities = append(s.Entities, role)
	proof(role, "vault://vault/v1/auth/approle/role/shared", "policy_names", model.AssertionObserved)
	b := bindings.Config{SchemaVersion: 1, Applications: []bindings.Application{{ID: "payments", Name: "Payments"}}}
	for _, env := range []string{"development", "production"} {
		name := "payments-" + env
		commit := strings.Repeat("a", 40)
		job := entity("jenkins", "job", name, map[string]any{"job_kind": "job", "jenkinsfile_commit": commit, "credential_reference_count": 1})
		ref := entity("jenkins", "credential_reference", name+"/credentials/shared-label", map[string]any{"credential_id": "shared-label", "job_native_id": name})
		s.Entities = append(s.Entities, job, ref)
		jobProof := proof(job, "jenkins/jenkins/job/"+name+"/api/json", "fullName", model.AssertionObserved)
		refProof := proof(ref, "git/"+commit+"/"+name+".groovy#L4", "credential_id", model.AssertionConfigured)
		s.Relationships = append(s.Relationships, model.Relationship{ID: model.RelationshipID(job.ID, ref.ID, "references_credential", job.Scope), From: job.ID, To: ref.ID, Type: "references_credential", Scope: job.Scope, AssertionKind: model.AssertionDeclared, EvidenceIDs: []string{jobProof, refProof}, ObservedAt: at})
		b.JenkinsVault = append(b.JenkinsVault, bindings.JenkinsVault{JenkinsSourceID: "jenkins", CredentialNativeID: ref.NativeID, VaultSourceID: "vault", RoleNativeID: role.NativeID})
		b.Applications[0].Members = append(b.Applications[0].Members, bindings.Member{Reference: bindings.Reference{SourceID: "jenkins", Kind: "job", NativeID: name}, Environment: env})
	}
	p := policy.Policy{SchemaVersion: 1, RequiredSources: []string{"jenkins", "vault"}, Rules: map[string]policy.Rule{"IL009": {Severity: model.SeverityHigh, SeparatedEnvironments: []policy.EnvironmentPair{{First: "production", Second: "development"}}}}}
	return s, p, b
}

func TestJenkinsSharedRoleRequiresEvidenceAndPreservesSnapshot(t *testing.T) {
	s, p, b := jenkinsEnvironmentFixture(t)
	before, _ := json.Marshal(s)
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.RuleResults[0].Outcome != model.OutcomeFail || len(r.Findings[0].AffectedEntityIDs) != 5 || len(r.Findings[0].AffectedRelationshipIDs) != 4 {
		t.Fatalf("unexpected sharing result: %+v", r.RuleResults)
	}
	after, _ := json.Marshal(s)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("mutated provider input")
	}
	rule := p.Rules["IL009"]
	rule.SeparatedEnvironments[0] = policy.EnvironmentPair{First: "development", Second: "production"}
	p.Rules["IL009"] = rule
	again, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || again.Findings[0].ID != r.Findings[0].ID {
		t.Fatal("environment ordering changed finding identity")
	}
}

func TestJenkinsSameCredentialLabelDoesNotEstablishRoleSharing(t *testing.T) {
	s, p, b := jenkinsEnvironmentFixture(t)
	other := s.Entities[0]
	other.NativeID = "approle/other"
	other.ID = model.EntityID(other.SourceID, other.Kind, other.NativeID)
	s.Entities = append(s.Entities, other)
	v := s.Evidence[0]
	v.NativeID = other.NativeID
	v.Locator = "vault://vault/v1/auth/approle/role/other"
	v.ID = model.EvidenceID(v.SourceID, v.NativeID, v.Locator)
	s.Evidence = append(s.Evidence, v)
	b.JenkinsVault[1].RoleNativeID = other.NativeID
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || len(r.Findings) != 0 || r.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("merged same credential labels: %v %+v", err, r.RuleResults)
	}
}

func TestJenkinsSameRoleNameInDifferentVaultSourcesIsNotShared(t *testing.T) {
	s, p, b := jenkinsEnvironmentFixture(t)
	other := s.Entities[0]
	other.SourceID, other.Scope = "other-vault", "vault/other"
	other.ID = model.EntityID(other.SourceID, other.Kind, other.NativeID)
	s.Entities = append(s.Entities, other)
	source := s.Sources[1]
	source.ID, source.Scope = other.SourceID, other.Scope
	s.Sources = append(s.Sources, source)
	v := s.Evidence[0]
	v.SourceID = other.SourceID
	v.ID = model.EvidenceID(v.SourceID, v.NativeID, v.Locator)
	s.Evidence = append(s.Evidence, v)
	b.JenkinsVault[1].VaultSourceID = other.SourceID
	r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || len(r.Findings) != 0 || r.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("merged same role names across Vault sources: %v %+v", err, r.RuleResults)
	}
}

func TestJenkinsMissingMetadataAndPartialCoverageRemainUnknown(t *testing.T) {
	for _, scenario := range []string{"missing pin", "unsupported parser", "missing reference edge", "declared-only file", "unmapped role", "no contexts", "partial source"} {
		t.Run(scenario, func(t *testing.T) {
			s, p, b := jenkinsEnvironmentFixture(t)
			switch scenario {
			case "missing pin":
				delete(s.Entities[1].Attributes, "jenkinsfile_commit")
				delete(s.Entities[1].FieldStatus, "jenkinsfile_commit")
			case "unsupported parser":
				s.Entities[1].FieldStatus["credential_reference_count"] = model.FieldUnsupported
			case "missing reference edge":
				s.Relationships = s.Relationships[1:]
			case "declared-only file":
				s.Evidence[2].AssertionKind = model.AssertionDeclared
			case "unmapped role":
				b.JenkinsVault = b.JenkinsVault[:1]
			case "no contexts":
				b.Applications = nil
			case "partial source":
				s.Sources[0].Complete = false
				s.Sources[0].Status = model.SourcePartial
			}
			r, err := (Analyzer{Bindings: &b}).Analyze(s, p)
			if err != nil || r.RuleResults[0].Outcome != model.OutcomeUnknown {
				t.Fatalf("coverage passed: %v %+v", err, r.RuleResults)
			}
			want := 0
			if scenario == "partial source" {
				want = 1
			}
			if len(r.Findings) != want {
				t.Fatal("invented finding or discarded established conflict")
			}
		})
	}
}

func TestJenkinsExactRoleExceptionIsRecorded(t *testing.T) {
	s, p, b := jenkinsEnvironmentFixture(t)
	rule := p.Rules["IL009"]
	rule.AllowedSharedVaultRoles = []policy.SharedVaultRole{{EnvironmentPair: rule.SeparatedEnvironments[0], VaultSourceID: "vault", RoleNativeID: "approle/shared", Reason: "Reviewed shared lab role"}}
	p.Rules["IL009"] = rule
	encoded, err := policy.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.Parse([]byte(encoded))
	if err != nil || !reflect.DeepEqual(parsed, p) {
		t.Fatal("lost exact exception round-trip")
	}
	r, err := (Analyzer{Bindings: &b}).Analyze(s, parsed)
	if err != nil || len(r.Findings) != 0 || len(r.PolicyExceptions) != 1 || r.PolicyExceptions[0].Reason != rule.AllowedSharedVaultRoles[0].Reason || r.RuleResults[0].Outcome != model.OutcomePass {
		t.Fatalf("exception not recorded: %v %+v", err, r.RuleResults)
	}
	rule.AllowedSharedVaultRoles[0].VaultSourceID = "different-source"
	p.Rules["IL009"] = rule
	r, err = (Analyzer{Bindings: &b}).Analyze(s, p)
	if err != nil || len(r.Findings) != 1 {
		t.Fatal("exception crossed source boundary")
	}
}
