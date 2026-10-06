package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/grantlinehq/grantline/internal/graph"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

// IL009 compares exact collected Vault AppRoles, never credential display names
// or credential values. Jenkinsfile and role mappings remain declared context.
func evaluateIL009(g graph.Graph, s model.Snapshot, contexts []model.EntityContext, rule policy.Rule, coverage model.Completeness) (model.RuleResult, []model.Finding, []model.PolicyException) {
	r := model.RuleResult{RuleID: "IL009", RuleVersion: "1"}
	type association struct{ jobs, refs, edges, evidence []string }
	roles := map[string]map[string]association{}
	kinds := map[string]string{}
	proofs := map[string][]model.Evidence{}
	for _, source := range s.Sources {
		kinds[source.ID] = source.Kind
	}
	for _, v := range s.Evidence {
		proofs[v.SourceID+"\x00"+v.NativeID] = append(proofs[v.SourceID+"\x00"+v.NativeID], v)
	}
	hasProof := func(e model.Entity, assertion model.AssertionKind, prefix, field string) []string {
		var ids []string
		for _, v := range proofs[e.SourceID+"\x00"+e.NativeID] {
			if v.AssertionKind != assertion || !strings.HasPrefix(v.Locator, prefix) {
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
	declaredJobs, assessed := 0, 0
	for _, context := range contexts {
		job := g.Entities[context.EntityID]
		if kinds[job.SourceID] != "jenkins" || job.Kind != "job" || knownEntityString(job, "job_kind") != "job" {
			continue
		}
		declaredJobs++
		commit := knownEntityString(job, "jenkinsfile_commit")
		jobProof := hasProof(job, model.AssertionObserved, "", "fullName")
		var referenceCount int
		references := g.Outgoing(job.ID, "references_credential")
		if commit == "" || len(jobProof) == 0 || job.FieldStatus["credential_reference_count"] != model.FieldKnown || json.Unmarshal(job.Attributes["credential_reference_count"], &referenceCount) != nil || referenceCount < 0 || referenceCount != len(references) {
			r.Limitations = append(r.Limitations, "A declared Jenkins job lacks complete pinned Jenkinsfile credential metadata.")
			continue
		}
		assessed++
		for _, uses := range references {
			ref := g.Entities[uses.To]
			refProof := hasProof(ref, model.AssertionConfigured, "git/"+commit+"/", "credential_id")
			if uses.AssertionKind == model.AssertionInferred || len(uses.EvidenceIDs) == 0 || ref.SourceID != job.SourceID || ref.Kind != "credential_reference" || knownEntityString(ref, "job_native_id") != job.NativeID || len(refProof) == 0 {
				r.Limitations = append(r.Limitations, "A declared Jenkins credential reference lacks exact pinned-file evidence.")
				continue
			}
			bound := false
			for _, binding := range g.Outgoing(ref.ID, "bound_to") {
				role := g.Entities[binding.To]
				roleProof := hasProof(role, model.AssertionObserved, "vault://", "policy_names")
				if binding.AssertionKind != model.AssertionDeclared || len(binding.EvidenceIDs) == 0 || kinds[role.SourceID] != "vault" || role.Kind != "vault_auth_role" || vaultAuthType(role) != "approle" || len(roleProof) == 0 {
					continue
				}
				bound = true
				if roles[role.ID] == nil {
					roles[role.ID] = map[string]association{}
				}
				a := roles[role.ID][context.Environment]
				a.jobs = append(a.jobs, job.ID)
				a.refs = append(a.refs, ref.ID)
				a.edges = append(a.edges, uses.ID, binding.ID)
				for _, ids := range [][]string{context.EvidenceIDs, jobProof, refProof, roleProof, uses.EvidenceIDs, binding.EvidenceIDs} {
					a.evidence = append(a.evidence, ids...)
				}
				roles[role.ID][context.Environment] = a
			}
			if !bound {
				r.Limitations = append(r.Limitations, "A declared Jenkins credential reference has no evidenced Vault AppRole mapping; other credential providers are outside this check.")
			}
		}
	}
	var findings []model.Finding
	var exceptions []model.PolicyException
	ids := make([]string, 0, len(roles))
	for id := range roles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		role := g.Entities[id]
		for _, pair := range rule.SeparatedEnvironments {
			a, aOK := roles[id][pair.First]
			b, bOK := roles[id][pair.Second]
			if !aOK || !bOK {
				continue
			}
			exempt := false
			for _, e := range rule.AllowedSharedVaultRoles {
				if e.VaultSourceID == role.SourceID && e.RoleNativeID == role.NativeID && (e.First == pair.First && e.Second == pair.Second || e.First == pair.Second && e.Second == pair.First) {
					exempt = true
					exceptions = append(exceptions, model.PolicyException{RuleID: "IL009", EntityID: role.ID, Environments: []string{pair.First, pair.Second}, Reason: e.Reason})
					break
				}
			}
			if exempt {
				continue
			}
			envs := []string{pair.First, pair.Second}
			sort.Strings(envs)
			affected := append([]string{role.ID}, append(a.jobs, b.jobs...)...)
			affected = append(affected, append(a.refs, b.refs...)...)
			findings = append(findings, model.Finding{ID: model.FindingID("IL009", "1", role.ID, envs[0], envs[1]), RuleID: "IL009", RuleVersion: "1", Severity: rule.Severity,
				AffectedEntityIDs: sortedUnique(affected), AffectedRelationshipIDs: sortedUnique(append(a.edges, b.edges...)), EvidenceIDs: sortedUnique(append(a.evidence, b.evidence...)),
				Condition:      "Jenkins jobs in policy-separated environments are explicitly mapped to the same collected Vault AppRole.",
				Description:    fmt.Sprintf("Vault AppRole %q is mapped from pinned Jenkinsfile credential references in both %s and %s.", role.NativeID, pair.First, pair.Second),
				Recommendation: "Use separate Vault AppRoles and job credentials for these environments, or document an exact shared-role exception with its reason.",
				Limitations:    []string{"Environment membership and credential-to-role mappings are operator-declared. Pinned file references do not prove the running job uses that revision, authentication success, identical secret values or effective access."}})
		}
	}
	if !coverage.Complete {
		r.Limitations = append(r.Limitations, "Required source coverage is incomplete; established role-sharing findings are retained.")
	}
	if declaredJobs == 0 {
		r.Limitations = append(r.Limitations, "No exact Jenkins job environment declarations were supplied.")
	}
	for _, f := range findings {
		r.FindingIDs = append(r.FindingIDs, f.ID)
	}
	r.Limitations = sortedUnique(r.Limitations)
	switch {
	case len(r.Limitations) > 0:
		r.Outcome = model.OutcomeUnknown
	case len(findings) > 0:
		r.Outcome = model.OutcomeFail
	case assessed == 0:
		r.Outcome = model.OutcomeNotApplicable
	default:
		r.Outcome = model.OutcomePass
	}
	r.Limitations = append(r.Limitations, "Only explicitly declared Jenkins jobs and evidenced Vault AppRole mappings are assessed; unassigned jobs and other credential providers are outside this check.")
	return r, findings, exceptions
}

func knownEntityString(e model.Entity, key string) string {
	v, ok := vaultString(e, key)
	if !ok {
		return ""
	}
	return v
}
