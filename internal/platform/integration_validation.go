package platform

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/grantlinehq/grantline/internal/model"
)

var connectionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Field diagnostics intentionally contain no submitted values, credentials or
// provider response bodies. normalizeConnection remains the final authority.
func integrationIssues(c Connection) []fieldIssue {
	out := []fieldIssue{}
	add := func(field, message string) { out = append(out, fieldIssue{Field: field, Message: message}) }
	s := c.Source
	prefix := map[string]string{"kubernetes": "cluster/", "vault": "vault/", "jenkins": "jenkins/", "entra": "tenant/", "github": "github/", "spire": "spire/"}[s.Kind]
	if s.Scope == "" {
		add("scope", "Give this source a stable scope name.")
	}
	// Each provider's validator handles its own scope syntax.
	if s.Kind == "vault" || s.Kind == "jenkins" {
		u, e := url.Parse(s.Address)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			add("address", "Use the HTTPS API origin without credentials, query or fragment.")
		}
	}
	switch s.Kind {
	case "entra":
		if s.Scope != "tenant/"+s.TenantID {
			add("tenant_id", "Scope must be tenant/ followed by the Directory (tenant) ID. The guided form derives this automatically.")
		}
		if !connectionUUID.MatchString(s.TenantID) {
			add("tenant_id", "Enter the Directory (tenant) ID from the collector app overview.")
		}
		if c.AuthMode == "client_secret" && !connectionUUID.MatchString(c.ClientID) {
			add("client_id", "Enter the collector Application (client) ID, not an object ID.")
		}
		if len(s.Applications)+len(s.ServicePrincipals) == 0 {
			add("applications", "Select at least one application or service principal object ID to collect.")
		}
		for _, group := range []struct {
			name   string
			values []string
		}{{"applications", s.Applications}, {"service_principals", s.ServicePrincipals}} {
			seen := map[string]bool{}
			for _, id := range group.values {
				if !connectionUUID.MatchString(id) || seen[id] {
					add(group.name, "Use unique object IDs, one per line. These identify the objects to scan, not the collector client.")
					break
				}
				seen[id] = true
			}
		}
	case "github":
		if len(s.Repositories) < 1 || len(s.Repositories) > 25 {
			add("repositories", "Add 1–25 repositories with exact native IDs and refs.")
		}
		if c.AuthMode == "github_app" {
			if !model.GitHubNumericID.MatchString(c.AppID) {
				add("app_id", "Enter the numeric GitHub App ID from its settings.")
			}
			if !model.GitHubNumericID.MatchString(c.InstallationID) {
				add("installation_id", "Enter the numeric installation ID for the selected account.")
			}
		}
		seen := map[string]bool{}
		for i, r := range s.Repositories {
			base := fmt.Sprintf("repositories.%d", i)
			if !model.GitHubRepoName.MatchString(r.Name) {
				add(base+".name", "Use owner/repository, without a URL.")
			}
			if !model.GitHubNumericID.MatchString(r.ID) || seen[r.ID] {
				add(base+".repository_id", "Enter a unique numeric repository ID; the name is not an ID.")
			}
			seen[r.ID] = true
			if len(r.Refs) < 1 || len(r.Refs) > 10 {
				add(base+".refs", "Choose 1–10 full refs, such as refs/heads/main.")
			}
			refs := map[string]bool{}
			for _, ref := range r.Refs {
				if !model.GitHubRef(ref) || refs[ref] {
					add(base+".refs", "Use unique full refs beginning refs/heads/ or refs/tags/.")
					break
				}
				refs[ref] = true
			}
			mappings := map[string]bool{}
			for j, m := range r.IdentityMappings {
				path := fmt.Sprintf("%s.identity_mappings.%d", base, j)
				key := fmt.Sprintf("%s/%s/%s/%s/%d/%s", m.WorkflowPath, m.Ref, m.CommitSHA, m.JobID, m.Step, m.Field)
				if !model.GitHubWorkflowPath(m.WorkflowPath) {
					add(path+".workflow_path", "Use an exact .github/workflows YAML path.")
				}
				if !refs[m.Ref] {
					add(path+".ref", "Select one of this repository's configured full refs.")
				}
				if !model.GitHubSHA.MatchString(m.CommitSHA) {
					add(path+".commit_sha", "Use the full lowercase 40-character commit SHA.")
				}
				if !model.GitHubJobID.MatchString(m.JobID) {
					add(path+".job_id", "Use the workflow job key, not a numeric run job ID.")
				}
				if m.Step < 1 || m.Step > 100 {
					add(path+".step", "Choose a one-based step index from 1 to 100.")
				}
				if m.Field != "tenant_id" && m.Field != "client_id" {
					add(path+".field", "Choose Tenant ID or Client ID.")
				}
				if !model.GitHubReference.MatchString(m.Reference) {
					add(path+".reference", "Use the exact workflow variable reference, such as secrets.AZURE_CLIENT_ID.")
				}
				if !connectionUUID.MatchString(m.Value) {
					add(path+".value", "Enter the lowercase tenant/client UUID; never a secret value.")
				}
				if mappings[key] {
					add(path, "Remove the duplicate pinned identity declaration.")
				}
				mappings[key] = true
			}
			checks := map[string]bool{}
			for j, c := range r.SmokeChecks {
				path := fmt.Sprintf("%s.smoke_checks.%d", base, j)
				key := fmt.Sprintf("%s/%d/%s/%d", c.RunID, c.Attempt, c.JobID, c.LoginStepNumber)
				if !model.GitHubWorkflowPath(c.WorkflowPath) || !model.GitHubNumericID.MatchString(c.RunID) || !model.GitHubNumericID.MatchString(c.JobID) || c.Attempt < 1 || c.Attempt > 100 || c.LoginStepNumber < 1 || c.LoginStepNumber > 1000 || checks[key] {
					add(path, "Use an exact workflow path, unique numeric run/job IDs, attempt 1–100 and step 1–1000.")
				}
				checks[key] = true
			}
		}
	case "vault":
		if len(s.Policies)+len(s.AuthRoles) == 0 {
			add("policies", "Select at least one policy or auth role to read.")
		}
		for i, r := range s.AuthRoles {
			if r.Mount == "" || r.Name == "" || (r.Type != "approle" && r.Type != "kubernetes") {
				add(fmt.Sprintf("auth_roles.%d", i), "Provide the auth mount, exact role name and AppRole or Kubernetes type.")
			}
		}
	case "jenkins":
		if len(s.Jobs) == 0 {
			add("jobs", "Add at least one full job path.")
		}
		for i, m := range c.Jenkinsfiles {
			if m.GitHubSourceID == "" || !model.GitHubRepoName.MatchString(m.Repository) || !model.GitHubNumericID.MatchString(m.RepositoryID) || !model.GitHubSHA.MatchString(m.Commit) || m.Path == "" {
				add(fmt.Sprintf("jenkinsfiles.%d", i), "Choose a GitHub connection, exact repository ID, 40-character commit SHA and Jenkinsfile path.")
			}
		}
	case "spire":
		if s.Spire == nil || s.Spire.TrustDomain == "" {
			add("trust_domain", "Enter the trust domain used by the metadata export.")
		}
		if s.Spire == nil || len(s.Spire.ParentIDs) == 0 {
			add("parent_ids", "Provide the exact parent SPIFFE IDs to include.")
		}
	}
	if len(out) == 0 {
		copy := c
		if err := normalizeConnection(&copy, "validation"); err != nil {
			message := "Review this provider's scope and connection fields using the preparation guide."
			if prefix != "" && !strings.HasPrefix(s.Scope, prefix) {
				message = "Use the provider scope prefix shown in the form and select explicit resources."
			}
			add("config", message)
		}
	}
	return out
}
