package github

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/grantlinehq/grantline/internal/model"
)

const Address = "https://api.github.com"
const APIVersion = "2026-03-10"
const maxResponseBytes = 2 << 20

type Config struct {
	ID, Scope, Address, TokenEnv string
	Repositories                 []Repository
}
type Repository struct {
	Name             string            `json:"name"`
	ID               string            `json:"repository_id"`
	Refs             []string          `json:"refs"`
	IdentityMappings []IdentityMapping `json:"identity_mappings,omitempty"`
	SmokeChecks      []SmokeCheck      `json:"smoke_checks,omitempty"`
}

// A declaration is pinned to a single revision, job, step, and reference. It
// does not grant permission to read secrets and is never provider observation.
type IdentityMapping struct {
	WorkflowPath string `json:"workflow_path"`
	Ref          string `json:"ref"`
	CommitSHA    string `json:"commit_sha"`
	JobID        string `json:"job_id"`
	Step         int    `json:"step"`
	Field        string `json:"field"`
	Reference    string `json:"reference"`
	Value        string `json:"value"`
}
type SmokeCheck struct {
	WorkflowPath    string `json:"workflow_path"`
	RunID           string `json:"run_id"`
	Attempt         int    `json:"attempt"`
	JobID           string `json:"job_id"`
	LoginStepNumber int    `json:"login_step_number"`
}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c Config) Validate() error {
	if c.ID == "" || !strings.HasPrefix(c.Scope, "github/") || len(c.Scope) <= 7 || !model.GitHubText(c.Scope, 240) || !envName.MatchString(c.TokenEnv) || (c.Address != "" && c.Address != Address) {
		return fmt.Errorf("GitHub source requires github scope, token_env and the fixed github.com API origin")
	}
	if len(c.Repositories) < 1 || len(c.Repositories) > 25 {
		return fmt.Errorf("GitHub source requires 1 to 25 allowlisted repositories")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, r := range c.Repositories {
		if !model.GitHubRepoName.MatchString(r.Name) || !model.GitHubNumericID.MatchString(r.ID) || ids[r.ID] || names[strings.ToLower(r.Name)] || len(r.Refs) < 1 || len(r.Refs) > 10 {
			return fmt.Errorf("GitHub repository requires unique name/native ID and 1 to 10 explicit refs")
		}
		ids[r.ID] = true
		names[strings.ToLower(r.Name)] = true
		refs := map[string]bool{}
		for _, ref := range r.Refs {
			if !model.GitHubRef(ref) || refs[ref] {
				return fmt.Errorf("GitHub refs must be unique full branch or tag refs")
			}
			refs[ref] = true
		}
		if len(r.IdentityMappings) > 200 || len(r.SmokeChecks) > 20 {
			return fmt.Errorf("GitHub declaration limit exceeded")
		}
		seen := map[string]bool{}
		for _, m := range r.IdentityMappings {
			key := fmt.Sprintf("%s/%s/%s/%s/%d/%s", m.WorkflowPath, m.Ref, m.CommitSHA, m.JobID, m.Step, m.Field)
			if !model.GitHubWorkflowPath(m.WorkflowPath) || !refs[m.Ref] || !model.GitHubSHA.MatchString(m.CommitSHA) || !model.GitHubJobID.MatchString(m.JobID) || m.Step < 1 || m.Step > 100 || (m.Field != "tenant_id" && m.Field != "client_id") || !model.GitHubReference.MatchString(m.Reference) || !guid.MatchString(m.Value) || seen[key] {
				return fmt.Errorf("GitHub identity mapping requires an unambiguous pinned reference and UUID metadata value")
			}
			seen[key] = true
		}
		seen = map[string]bool{}
		for _, s := range r.SmokeChecks {
			key := fmt.Sprintf("%s/%d/%s/%d", s.RunID, s.Attempt, s.JobID, s.LoginStepNumber)
			if !model.GitHubWorkflowPath(s.WorkflowPath) || !model.GitHubNumericID.MatchString(s.RunID) || !model.GitHubNumericID.MatchString(s.JobID) || s.Attempt < 1 || s.Attempt > 100 || s.LoginStepNumber < 1 || s.LoginStepNumber > 1000 || seen[key] {
				return fmt.Errorf("GitHub smoke check requires explicit workflow, run, attempt, job and step identities")
			}
			seen[key] = true
		}
	}
	return nil
}
