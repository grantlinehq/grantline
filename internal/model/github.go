package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Workflow revisions describe configuration at a commit, never a running identity.
type GitHubRevision struct {
	Ref       string      `json:"ref"`
	CommitSHA string      `json:"commit_sha"`
	Status    FieldStatus `json:"status"`
	Jobs      []GitHubJob `json:"jobs"`
}

type GitHubJob struct {
	ID                string          `json:"id"`
	IDTokenPermission string          `json:"id_token_permission"`
	Environment       string          `json:"environment,omitempty"`
	EnvironmentStatus FieldStatus     `json:"environment_status"`
	Reusable          bool            `json:"reusable"`
	Contexts          []GitHubContext `json:"contexts"`
	Logins            []GitHubLogin   `json:"logins"`
}

type GitHubContext struct {
	Event   string `json:"event"`
	Subject string `json:"subject"`
}

type GitHubLogin struct {
	Step              int           `json:"step"`
	Action            string        `json:"action"`
	TenantID          string        `json:"tenant_id,omitempty"`
	ClientID          string        `json:"client_id,omitempty"`
	TenantReference   string        `json:"tenant_reference,omitempty"`
	ClientReference   string        `json:"client_reference,omitempty"`
	Audience          string        `json:"audience,omitempty"`
	Status            FieldStatus   `json:"status"`
	IdentityAssertion AssertionKind `json:"identity_assertion"`
}

// These are provider-reported run/step outcomes. They never create trust edges
// or prove token claims, tenant authorization, or the current configuration.
type GitHubSmokeResult struct {
	RunID           string `json:"run_id"`
	Attempt         int    `json:"attempt"`
	JobID           string `json:"job_id"`
	LoginStepNumber int    `json:"login_step_number"`
	CommitSHA       string `json:"commit_sha"`
	Event           string `json:"event"`
	RunConclusion   string `json:"run_conclusion"`
	JobConclusion   string `json:"job_conclusion"`
	StepConclusion  string `json:"step_conclusion"`
}

var GitHubNumericID = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var GitHubSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var GitHubRepoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$`)
var GitHubJobID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,99}$`)
var GitHubReference = regexp.MustCompile(`^(secrets|vars)\.[A-Za-z_][A-Za-z0-9_]{0,99}$`)

func GitHubWorkflowPath(s string) bool {
	return GitHubText(s, 240) && strings.HasPrefix(s, ".github/workflows/") &&
		(strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".yaml")) &&
		!strings.Contains(s[len(".github/workflows/"):], "/") &&
		!strings.ContainsAny(s, "\\%@?#\r\n\x00") && !strings.Contains(s, "..")
}

func GitHubRef(s string) bool {
	if !GitHubText(s, 240) || !(strings.HasPrefix(s, "refs/heads/") || strings.HasPrefix(s, "refs/tags/")) {
		return false
	}
	return !strings.HasSuffix(s, "/") && !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ".lock") &&
		!strings.Contains(s, "..") && !strings.Contains(s, "//") && !strings.Contains(s, "@{") &&
		!strings.ContainsAny(s, " ~^:?*[\\%#\t\r\n\x00")
}

func GitHubText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func validateGitHubAttribute(key string, raw json.RawMessage) error {
	bad := fmt.Errorf("attribute %q has an unsupported GitHub metadata shape", key)
	decode := func(v any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(v) == nil && ensureSingleJSONValue(d) == nil
	}
	if key == "revisions" {
		var revisions []GitHubRevision
		if !decode(&revisions) || revisions == nil || len(revisions) > 10 {
			return bad
		}
		seen := map[string]bool{}
		for _, r := range revisions {
			if !GitHubRef(r.Ref) || !GitHubSHA.MatchString(r.CommitSHA) || seen[r.Ref] || !isValidFieldStatus(r.Status) || len(r.Jobs) > 100 {
				return bad
			}
			seen[r.Ref] = true
			jobs := map[string]bool{}
			for _, j := range r.Jobs {
				if !GitHubJobID.MatchString(j.ID) || jobs[j.ID] || !GitHubText(j.Environment, 255) || !isValidFieldStatus(j.EnvironmentStatus) || len(j.Contexts) > 10 || len(j.Logins) > 100 {
					return bad
				}
				jobs[j.ID] = true
				if j.IDTokenPermission != "write" && j.IDTokenPermission != "none" && j.IDTokenPermission != "unknown" {
					return bad
				}
				for _, c := range j.Contexts {
					if c.Event != "push" && c.Event != "workflow_dispatch" && c.Event != "pull_request" {
						return bad
					}
					if !strings.HasPrefix(c.Subject, "repo:") || !GitHubText(c.Subject, 1024) {
						return bad
					}
				}
				steps := map[int]bool{}
				for _, l := range j.Logins {
					if l.Step < 1 || l.Step > 100 || steps[l.Step] || (l.Action != "azure/login@v2" && l.Action != "azure/login@v3" && l.Action != "azure/login@unsupported") || !isValidFieldStatus(l.Status) {
						return bad
					}
					steps[l.Step] = true
					if l.IdentityAssertion != AssertionConfigured && l.IdentityAssertion != AssertionDeclared {
						return bad
					}
					if l.TenantID != "" && !entraUUID.MatchString(l.TenantID) || l.ClientID != "" && !entraUUID.MatchString(l.ClientID) {
						return bad
					}
					if l.TenantReference != "" && !GitHubReference.MatchString(l.TenantReference) || l.ClientReference != "" && !GitHubReference.MatchString(l.ClientReference) {
						return bad
					}
					if !GitHubText(l.Audience, 512) || (l.Status == FieldKnown && (l.TenantID == "" || l.ClientID == "" || l.Audience == "")) {
						return bad
					}
					if l.IdentityAssertion == AssertionConfigured && (l.TenantReference != "" && l.TenantID != "" || l.ClientReference != "" && l.ClientID != "") {
						return bad
					}
				}
			}
		}
		return nil
	}
	if key == "smoke_results" {
		var runs []GitHubSmokeResult
		if !decode(&runs) || runs == nil || len(runs) > 20 {
			return bad
		}
		for _, r := range runs {
			if !GitHubNumericID.MatchString(r.RunID) || !GitHubNumericID.MatchString(r.JobID) || r.Attempt < 1 || r.Attempt > 100 || r.LoginStepNumber < 1 || r.LoginStepNumber > 1000 || !GitHubSHA.MatchString(r.CommitSHA) {
				return bad
			}
			if r.Event != "push" && r.Event != "workflow_dispatch" && r.Event != "pull_request" {
				return bad
			}
			for _, c := range []string{r.RunConclusion, r.JobConclusion, r.StepConclusion} {
				if !GitHubConclusion(c) {
					return bad
				}
			}
		}
		return nil
	}
	var s string
	if !decode(&s) || s == "" || !GitHubText(s, 512) {
		return bad
	}
	switch key {
	case "repository_id", "repository_owner_id", "workflow_id":
		if !GitHubNumericID.MatchString(s) {
			return bad
		}
	case "repository_name":
		if !GitHubRepoName.MatchString(s) {
			return bad
		}
	case "workflow_path":
		if !GitHubWorkflowPath(s) {
			return bad
		}
	case "workflow_state":
		if s != "active" && s != "disabled_manually" && s != "disabled_inactivity" && s != "disabled_fork" && s != "deleted" {
			return bad
		}
	case "subject_format":
		if s != "default_immutable" && s != "default_legacy" {
			return bad
		}
	}
	return nil
}

func GitHubConclusion(s string) bool {
	switch s {
	case "success", "failure", "cancelled", "skipped", "neutral", "timed_out", "action_required", "stale", "startup_failure":
		return true
	}
	return false
}

func validateGitHubIdentity(e Entity, source Source) error {
	read := func(k string) string {
		var s string
		if e.FieldStatus[k] == FieldKnown {
			json.Unmarshal(e.Attributes[k], &s)
		}
		return s
	}
	repo, path := read("repository_id"), read("workflow_path")
	if e.Kind != "workflow" || !GitHubNumericID.MatchString(repo) || !GitHubWorkflowPath(path) || !GitHubNumericID.MatchString(read("repository_owner_id")) || !GitHubRepoName.MatchString(read("repository_name")) || !GitHubNumericID.MatchString(read("workflow_id")) || e.NativeID != repo+"/"+path || e.Scope != source.Scope+"/repo/"+repo {
		return fmt.Errorf("GitHub workflow native identity is inconsistent")
	}
	prefix := ""
	switch read("subject_format") {
	case "default_legacy":
		prefix = "repo:" + read("repository_name")
	case "default_immutable":
		parts := strings.Split(read("repository_name"), "/")
		prefix = "repo:" + parts[0] + "@" + read("repository_owner_id") + "/" + parts[1] + "@" + repo
	}
	var revisions []GitHubRevision
	json.Unmarshal(e.Attributes["revisions"], &revisions)
	for _, r := range revisions {
		for _, j := range r.Jobs {
			for _, c := range j.Contexts {
				expected := prefix + ":ref:" + r.Ref
				if c.Event == "pull_request" {
					expected = prefix + ":pull_request"
				}
				if j.Environment != "" {
					expected = prefix + ":environment:" + strings.ReplaceAll(j.Environment, ":", "%3A")
				}
				if prefix == "" || c.Subject != expected || j.Reusable || j.EnvironmentStatus != FieldKnown {
					return fmt.Errorf("GitHub subject context is inconsistent with repository/ref/environment identity")
				}
			}
		}
	}
	return nil
}
