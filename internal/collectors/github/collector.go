package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

type Collector struct {
	// Credentials are injected per collection by the server; nil preserves CLI environment input.
	Credentials func(string) string
	Config      Config
	Client      *http.Client
	Now         func() time.Time
}
type collection struct {
	config        Config
	client        *http.Client
	token         string
	at            time.Time
	requests      int
	metadataItems int
	exhausted     bool
	snapshot      model.Snapshot
	source        model.Source
	evidence      map[string]bool
}
type repositoryMetadata struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Owner    struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"owner"`
}
type workflowMetadata struct {
	ID    int64  `json:"id"`
	Path  string `json:"path"`
	State string `json:"state"`
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if err := collector.Config.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	client := http.Client{Timeout: 15 * time.Second}
	if collector.Client != nil {
		client = *collector.Client
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	at := now().UTC()
	c := collection{config: collector.Config, client: &client, token: collector.credential(collector.Config.TokenEnv), at: at, evidence: map[string]bool{},
		snapshot: model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at, Entities: []model.Entity{}, Relationships: []model.Relationship{}, Evidence: []model.Evidence{}},
		source:   model.Source{ID: collector.Config.ID, Kind: "github", Scope: collector.Config.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}}
	if c.token == "" || len(c.token) > 32768 || strings.ContainsAny(c.token, " \t\r\n\x00") {
		c.fail("authentication", "credentials_unavailable", false)
	} else {
		for _, r := range c.config.Repositories {
			c.repository(ctx, r)
		}
	}
	sort.Slice(c.snapshot.Entities, func(i, j int) bool { return c.snapshot.Entities[i].ID < c.snapshot.Entities[j].ID })
	sort.Slice(c.snapshot.Evidence, func(i, j int) bool { return c.snapshot.Evidence[i].ID < c.snapshot.Evidence[j].ID })
	sort.Strings(c.source.Warnings)
	sort.Strings(c.source.PermissionsObserved)
	c.snapshot.Sources = []model.Source{c.source}
	return c.snapshot, c.snapshot.Validate()
}

func (c *collection) repository(ctx context.Context, r Repository) {
	base := "/repos/" + r.Name
	var repo repositoryMetadata
	if _, code := c.get(ctx, base, &repo); code != "" {
		c.fail("repository", code, false)
		return
	}
	if strconv.FormatInt(repo.ID, 10) != r.ID || !strings.EqualFold(repo.FullName, r.Name) || !model.GitHubRepoName.MatchString(repo.FullName) || repo.Owner.ID <= 0 || strings.Split(repo.FullName, "/")[0] != repo.Owner.Login {
		c.fail("repository", "repository_identity_mismatch", false)
		return
	}
	c.observed("repository metadata GET")
	prefix, format, oidcCode := c.subjectPrefix(ctx, base, repo)
	if oidcCode != "" {
		c.fail("oidc customization", oidcCode, false)
	}
	workflows := c.workflows(ctx, base)
	commits := map[string]string{}
	for _, ref := range r.Refs {
		var commit struct {
			SHA string `json:"sha"`
		}
		if _, code := c.get(ctx, base+"/commits/"+url.PathEscape(ref), &commit); code != "" {
			c.fail("ref commit", code, false)
			continue
		}
		if !model.GitHubSHA.MatchString(commit.SHA) {
			c.fail("ref commit", "invalid_commit", false)
			continue
		}
		commits[ref] = commit.SHA
		c.observed("contents GET at pinned commit")
	}
	usedMappings := map[int]bool{}
	usedSmoke := map[int]bool{}
	for _, w := range workflows {
		if len(c.snapshot.Entities) >= 2000 {
			c.fail("source inventory", "entity_limit", false)
			return
		}
		native := r.ID + "/" + w.Path
		e := model.Entity{ID: model.EntityID(c.config.ID, "workflow", native), Kind: "workflow", SourceID: c.config.ID, NativeID: native, Scope: c.config.Scope + "/repo/" + r.ID, Name: w.Path, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: c.at, Provenance: model.ProvenanceLiveAPI}
		set(&e, "repository_id", r.ID)
		set(&e, "repository_owner_id", strconv.FormatInt(repo.Owner.ID, 10))
		set(&e, "repository_name", repo.FullName)
		set(&e, "workflow_id", strconv.FormatInt(w.ID, 10))
		set(&e, "workflow_path", w.Path)
		set(&e, "workflow_state", w.State)
		if format != "" {
			set(&e, "subject_format", format)
		} else {
			e.FieldStatus["subject_format"] = fieldStatus(oidcCode)
		}
		c.record(native, "github/repositories/"+r.ID, []string{"id", "full_name", "owner.id"}, model.AssertionObserved)
		c.record(native, "github/repositories/"+r.ID+"/actions/workflows/"+strconv.FormatInt(w.ID, 10), []string{"id", "path", "state"}, model.AssertionObserved)
		if format != "" {
			c.record(native, SubjectLocator(r.ID), []string{"use_default", "use_immutable_subject", "sub_claim_prefix"}, model.AssertionConfigured)
		}
		revisions := []model.GitHubRevision{}
		for _, ref := range r.Refs {
			sha := commits[ref]
			if sha == "" {
				continue
			}
			data, code := c.content(ctx, base, w.Path, sha)
			if code != "" {
				c.fail("workflow content", code, false)
				revisions = append(revisions, model.GitHubRevision{Ref: ref, CommitSHA: sha, Status: fieldStatus(code), Jobs: []model.GitHubJob{}})
				continue
			}
			revision := parseWorkflow(data, ref, sha, prefix)
			items := len(revision.Jobs)
			for _, job := range revision.Jobs {
				items += len(job.Contexts) + len(job.Logins)
			}
			if c.metadataItems+items > 10000 {
				c.fail("workflow metadata", "metadata_limit", false)
				revisions = append(revisions, model.GitHubRevision{Ref: ref, CommitSHA: sha, Status: model.FieldUnknown, Jobs: []model.GitHubJob{}})
				continue
			}
			c.metadataItems += items
			c.record(native, ContentLocator(r.ID, w.Path, sha, ref), []string{"commit_sha", "path", "on", "jobs.permissions", "jobs.environment", "jobs.steps.uses", "jobs.steps.with.tenant-id", "jobs.steps.with.client-id", "jobs.steps.with.audience"}, model.AssertionConfigured)
			before := map[int]bool{}
			for i := range usedMappings {
				before[i] = true
			}
			applyMappings(&revision, w.Path, r.IdentityMappings, usedMappings)
			for i, m := range r.IdentityMappings {
				if usedMappings[i] && !before[i] {
					c.record(native, MappingLocator(r.ID, m), []string{"identity_mapping.reference", "identity_mapping.value", "commit_sha", "job_id", "step"}, model.AssertionDeclared)
				}
			}
			if revision.Status != model.FieldKnown {
				c.fail("workflow configuration", "unsupported_workflow_configuration", false)
			}
			for _, job := range revision.Jobs {
				for _, login := range job.Logins {
					if login.Status != model.FieldKnown {
						c.fail("workflow identity", "unresolved_oidc_login", false)
					}
				}
			}
			revisions = append(revisions, revision)
		}
		set(&e, "revisions", revisions)
		if len(revisions) != len(r.Refs) {
			e.FieldStatus["revisions"] = model.FieldUnknown
		}
		smoke := []model.GitHubSmokeResult{}
		for i, s := range r.SmokeChecks {
			if s.WorkflowPath == w.Path {
				usedSmoke[i] = true
				result, code := c.smoke(ctx, base, r.ID, strconv.FormatInt(w.ID, 10), s, revisions)
				if code != "" {
					c.fail("smoke result", code, false)
					e.FieldStatus["smoke_results"] = fieldStatus(code)
					continue
				}
				smoke = append(smoke, result)
				c.record(native, SmokeLocator(r.ID, s), []string{"run.head_sha", "run.repository.id", "run.workflow_id", "run.conclusion", "job.conclusion", "steps.number", "steps.conclusion"}, model.AssertionObserved)
			}
		}
		if len(smoke) > 0 {
			status := e.FieldStatus["smoke_results"]
			set(&e, "smoke_results", smoke)
			if status != "" {
				e.FieldStatus["smoke_results"] = status
			}
		}
		c.snapshot.Entities = append(c.snapshot.Entities, e)
	}
	if len(usedMappings) != len(r.IdentityMappings) {
		c.fail("identity declarations", "unresolved_identity_mapping", false)
	}
	if len(usedSmoke) != len(r.SmokeChecks) {
		c.fail("smoke declarations", "unresolved_smoke_workflow", false)
	}
}

func (c *collection) subjectPrefix(ctx context.Context, base string, repo repositoryMetadata) (string, string, string) {
	var settings struct {
		Default   *bool    `json:"use_default"`
		Immutable *bool    `json:"use_immutable_subject"`
		Prefix    string   `json:"sub_claim_prefix"`
		Claims    []string `json:"include_claim_keys"`
	}
	if _, code := c.get(ctx, base+"/actions/oidc/customization/sub", &settings); code != "" {
		return "", "", code
	}
	c.observed("Actions OIDC customization GET")
	// Organization/inherited/custom templates require additional evidence and
	// are deliberately unresolved. Do not infer format from repo creation time.
	if settings.Default == nil || !*settings.Default || settings.Immutable == nil {
		return "", "", "unsupported_subject_template"
	}
	prefix := "repo:" + repo.FullName
	format := "default_legacy"
	if *settings.Immutable {
		parts := strings.Split(repo.FullName, "/")
		prefix = "repo:" + parts[0] + "@" + strconv.FormatInt(repo.Owner.ID, 10) + "/" + parts[1] + "@" + strconv.FormatInt(repo.ID, 10)
		format = "default_immutable"
	}
	if settings.Prefix != "" && settings.Prefix != prefix {
		return "", "", "subject_prefix_mismatch"
	}
	return prefix, format, ""
}

func (c *collection) workflows(ctx context.Context, base string) []workflowMetadata {
	result := []workflowMetadata{}
	seenID, seenPath := map[int64]bool{}, map[string]bool{}
	endpoint := base + "/actions/workflows"
	total := -1
	for page := 1; page <= 10; page++ {
		var response struct {
			Total     *int                `json:"total_count"`
			Workflows *[]workflowMetadata `json:"workflows"`
		}
		header, code := c.get(ctx, endpoint+"?per_page=100&page="+strconv.Itoa(page), &response)
		if code != "" {
			c.fail("workflow list", code, true)
			return result
		}
		if response.Total == nil || *response.Total < 0 || *response.Total > 200 || response.Workflows == nil || len(*response.Workflows) > 100 || total >= 0 && total != *response.Total {
			c.fail("workflow list", "invalid_workflow_page", true)
			return result
		}
		total = *response.Total
		for _, w := range *response.Workflows {
			if w.ID <= 0 || !model.GitHubWorkflowPath(w.Path) || seenID[w.ID] || seenPath[w.Path] || !workflowState(w.State) {
				c.fail("workflow list", "invalid_workflow_identity", true)
				return result
			}
			seenID[w.ID] = true
			seenPath[w.Path] = true
			result = append(result, w)
		}
		next, safe := nextPage(header, endpoint, page)
		if !safe || len(result) > total || next && (len(*response.Workflows) == 0 || len(result) >= total) || !next && len(result) != total {
			c.fail("workflow list", "incomplete_or_unsafe_pagination", true)
			return result
		}
		if !next {
			c.observed("Actions workflow list GET")
			return result
		}
	}
	c.fail("workflow list", "page_limit", true)
	return result
}
func workflowState(s string) bool {
	switch s {
	case "active", "disabled_manually", "disabled_inactivity", "disabled_fork", "deleted":
		return true
	}
	return false
}

func (c *collection) content(ctx context.Context, base, path, sha string) ([]byte, string) {
	var file struct {
		Type      string `json:"type"`
		Path      string `json:"path"`
		SHA       string `json:"sha"`
		Encoding  string `json:"encoding"`
		Size      *int   `json:"size"`
		Content   string `json:"content"`
		Target    string `json:"target"`
		Submodule string `json:"submodule_git_url"`
	}
	if _, code := c.get(ctx, base+"/contents/"+path+"?ref="+sha, &file); code != "" {
		return nil, code
	}
	if file.Type != "file" || file.Target != "" || file.Submodule != "" || file.Path != path || !model.GitHubSHA.MatchString(file.SHA) || file.Encoding != "base64" || file.Size == nil || *file.Size < 0 || *file.Size > 256<<10 || len(file.Content) > 400000 {
		return nil, "unsupported_workflow_file"
	}
	data, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil || len(data) != *file.Size {
		return nil, "invalid_workflow_encoding"
	}
	return data, ""
}

func set(e *model.Entity, key string, value any) {
	data, _ := json.Marshal(value)
	e.Attributes[key] = data
	e.FieldStatus[key] = model.FieldKnown
}
func (c *collection) observed(permission string) {
	for _, old := range c.source.PermissionsObserved {
		if old == permission {
			return
		}
	}
	c.source.PermissionsObserved = append(c.source.PermissionsObserved, permission)
}
func (c *collection) fail(part, code string, pagination bool) {
	c.source.Status = model.SourcePartial
	c.source.Complete = false
	if pagination {
		c.source.PaginationComplete = false
	}
	if c.source.ErrorCode == "" {
		c.source.ErrorCode = code
	}
	warning := "GitHub " + part + ": " + code
	for _, old := range c.source.Warnings {
		if old == warning {
			return
		}
	}
	c.source.Warnings = append(c.source.Warnings, warning)
}
func fieldStatus(code string) model.FieldStatus {
	if code == "HTTP_401" || code == "HTTP_403" {
		return model.FieldPermissionDenied
	}
	if strings.HasPrefix(code, "unsupported") {
		return model.FieldUnsupported
	}
	return model.FieldUnknown
}
func (c *collection) record(native, locator string, fields []string, assertion model.AssertionKind) {
	id := model.EvidenceID(c.config.ID, native, locator)
	if c.evidence[id] {
		return
	}
	c.evidence[id] = true
	c.snapshot.Evidence = append(c.snapshot.Evidence, model.Evidence{ID: id, SourceID: c.config.ID, NativeID: native, Locator: locator, Fields: fields, ObservedAt: c.at, AssertionKind: assertion})
}
func SubjectLocator(repo string) string {
	return "github/repositories/" + repo + "/actions/oidc/customization/sub"
}
func ContentLocator(repo, path, sha, ref string) string {
	return "github/repositories/" + repo + "/contents/" + path + "/commit/" + sha + "/ref/" + url.QueryEscape(ref)
}
func MappingLocator(repo string, m IdentityMapping) string {
	return fmt.Sprintf("declarations/github/%s/%s/commit/%s/ref/%s/job/%s/step/%d/%s", repo, m.WorkflowPath, m.CommitSHA, url.QueryEscape(m.Ref), m.JobID, m.Step, m.Field)
}
func SmokeLocator(repo string, s SmokeCheck) string {
	return fmt.Sprintf("github/repositories/%s/actions/runs/%s/attempts/%d/jobs/%s/steps/%d", repo, s.RunID, s.Attempt, s.JobID, s.LoginStepNumber)
}

func (collector Collector) credential(name string) string {
	if collector.Credentials != nil {
		return collector.Credentials(name)
	}
	return os.Getenv(name)
}
