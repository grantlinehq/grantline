package correlate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

	"github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/model"
)

// AddGitHubEntraTrusts joins complete, locally supported configured claims, not
// display names, run success, effective authorization, or unresolved expressions.
// Permission/owner failures elsewhere do not erase an independently proven edge.
func AddGitHubEntraTrusts(snapshot *model.Snapshot) {
	kinds := map[string]string{}
	for _, s := range snapshot.Sources {
		kinds[s.ID] = s.Kind
	}
	evidence := map[string]model.Evidence{}
	for _, e := range snapshot.Evidence {
		evidence[e.SourceID+"\x00"+e.NativeID+"\x00"+e.Locator] = e
	}
	find := func(e model.Entity, locator string, assertion model.AssertionKind, fields ...string) string {
		item, ok := evidence[e.SourceID+"\x00"+e.NativeID+"\x00"+locator]
		if !ok || item.AssertionKind != assertion {
			return ""
		}
		for _, f := range fields {
			found := false
			for _, k := range item.Fields {
				if k == f {
					found = true
				}
			}
			if !found {
				return ""
			}
		}
		return item.ID
	}
	read := func(e model.Entity, key string) string { v, _ := stringAttribute(e, key); return v }
	for _, workflow := range snapshot.Entities {
		if kinds[workflow.SourceID] != "github" || workflow.Kind != "workflow" || read(workflow, "workflow_state") != "active" {
			continue
		}
		repo, path := read(workflow, "repository_id"), read(workflow, "workflow_path")
		repoProof := find(workflow, "github/repositories/"+repo, model.AssertionObserved, "id", "full_name", "owner.id")
		templateProof := find(workflow, github.SubjectLocator(repo), model.AssertionConfigured, "use_default", "use_immutable_subject")
		workflowProof := find(workflow, "github/repositories/"+repo+"/actions/workflows/"+read(workflow, "workflow_id"), model.AssertionObserved, "id", "path", "state")
		if repoProof == "" || templateProof == "" || workflowProof == "" {
			continue
		}
		var revisions []model.GitHubRevision
		if json.Unmarshal(workflow.Attributes["revisions"], &revisions) != nil {
			continue
		}
		for _, revision := range revisions {
			if revision.Status != model.FieldKnown {
				continue
			}
			fileProof := find(workflow, github.ContentLocator(repo, path, revision.CommitSHA, revision.Ref), model.AssertionConfigured, "commit_sha", "jobs.permissions", "jobs.environment", "jobs.steps.uses", "jobs.steps.with.tenant-id", "jobs.steps.with.client-id", "jobs.steps.with.audience")
			if fileProof == "" {
				continue
			}
			for _, job := range revision.Jobs {
				if job.IDTokenPermission != "write" || job.Reusable || job.EnvironmentStatus != model.FieldKnown {
					continue
				}
				for _, login := range job.Logins {
					if login.Status != model.FieldKnown || login.TenantID == "" || login.ClientID == "" || login.Audience == "" || login.Action == "azure/login@unsupported" {
						continue
					}
					proofs := []string{repoProof, templateProof, workflowProof, fileProof}
					resolved := true
					for field, ref := range map[string]string{"tenant_id": login.TenantReference, "client_id": login.ClientReference} {
						if ref == "" {
							continue
						}
						m := github.IdentityMapping{WorkflowPath: path, Ref: revision.Ref, CommitSHA: revision.CommitSHA, JobID: job.ID, Step: login.Step, Field: field}
						proof := find(workflow, github.MappingLocator(repo, m), model.AssertionDeclared, "identity_mapping.reference", "identity_mapping.value")
						if proof == "" || login.IdentityAssertion != model.AssertionDeclared {
							resolved = false
							break
						}
						proofs = append(proofs, proof)
					}
					if !resolved {
						continue
					}
					for _, fic := range snapshot.Entities {
						if kinds[fic.SourceID] != "entra" || fic.Kind != "federated_credential" || read(fic, "tenant_id") != login.TenantID || read(fic, "app_id") != login.ClientID || read(fic, "issuer") != "https://token.actions.githubusercontent.com" {
							continue
						}
						var audiences []string
						if fic.FieldStatus["audiences"] != model.FieldKnown || json.Unmarshal(fic.Attributes["audiences"], &audiences) != nil || len(audiences) != 1 || audiences[0] != login.Audience {
							continue
						}
						parent := read(fic, "parent_object_id")
						var app model.Entity
						for _, e := range snapshot.Entities {
							if e.SourceID == fic.SourceID && e.Kind == "application_registration" && read(e, "tenant_id") == login.TenantID && read(e, "object_id") == parent && read(e, "app_id") == login.ClientID && read(e, "collection_role") == "selected" {
								app = e
								break
							}
						}
						if app.ID == "" {
							continue
						}
						appProof := find(app, "graph/v1.0/applications/"+parent, model.AssertionObserved, "id", "appId")
						ficProof := ""
						for _, e := range snapshot.Evidence {
							if e.SourceID == fic.SourceID && e.NativeID == fic.NativeID && e.AssertionKind == model.AssertionConfigured {
								ficProof = find(fic, e.Locator, model.AssertionConfigured, "issuer", "subject", "audiences")
								if ficProof != "" {
									break
								}
							}
						}
						if appProof == "" || ficProof == "" {
							continue
						}
						for _, context := range job.Contexts {
							if read(fic, "subject") != context.Subject {
								continue
							}
							scope := fmt.Sprintf("%s/workflow/%s/ref/%s/job/%s/step/%d/event/%s", workflow.Scope, read(workflow, "workflow_id"), url.PathEscape(revision.Ref), job.ID, login.Step, context.Event)
							id := model.RelationshipID(fic.ID, workflow.ID, "trusts_subject", scope)
							if hasRelationship(snapshot.Relationships, id) {
								continue
							}
							ids := append(append([]string{}, proofs...), appProof, ficProof)
							sort.Strings(ids)
							snapshot.Relationships = append(snapshot.Relationships, model.Relationship{ID: id, From: fic.ID, To: workflow.ID, Type: "trusts_subject", Scope: scope, AssertionKind: login.IdentityAssertion, EvidenceIDs: unique(ids), ObservedAt: snapshot.CollectedAt})
						}
					}
				}
			}
		}
	}
	sort.Slice(snapshot.Relationships, func(i, j int) bool { return snapshot.Relationships[i].ID < snapshot.Relationships[j].ID })
}
