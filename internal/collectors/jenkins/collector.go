package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// PinnedFile loads an explicitly selected immutable blob. Nil preserves CLI file access.
	PinnedFile func(context.Context, Jenkinsfile) ([]byte, error)
	Config     Config
	Client     *http.Client
	Now        func() time.Time
}
type build struct {
	Number    *int64  `json:"number"`
	Result    *string `json:"result"`
	Building  *bool   `json:"building"`
	Timestamp *int64  `json:"timestamp"`
	Duration  *int64  `json:"duration"`
}
type itemResponse struct {
	FullName  string   `json:"fullName"`
	Class     string   `json:"_class"`
	Buildable *bool    `json:"buildable"`
	Builds    *[]build `json:"builds"`
}
type collection struct {
	config          Config
	client          *http.Client
	username, token string
	at              time.Time
	snapshot        model.Snapshot
	source          model.Source
	pinnedFile      func(context.Context, Jenkinsfile) ([]byte, error)
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if err := collector.Config.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	if collector.Config.BuildLimit == 0 {
		collector.Config.BuildLimit = 5
	}
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	at := now().UTC()
	client := http.Client{Timeout: 15 * time.Second}
	if collector.Client != nil {
		client = *collector.Client
	}
	// An injected transport must not accidentally re-enable credential-bearing redirects.
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := collection{config: collector.Config, client: &client, at: at, username: collector.credential(collector.Config.UsernameEnv), token: collector.credential(collector.Config.TokenEnv), pinnedFile: collector.PinnedFile,
		snapshot: model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at},
		source:   model.Source{ID: collector.Config.ID, Kind: "jenkins", Scope: collector.Config.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}}
	if c.username == "" || c.token == "" || strings.ContainsAny(c.username, ":\r\n") || strings.ContainsAny(c.token, "\r\n") {
		c.fail("authentication", "credentials_unavailable", true)
	} else {
		for _, job := range c.config.Jobs {
			c.collectJob(ctx, job)
		}
	}
	sort.Slice(c.snapshot.Entities, func(i, j int) bool { return c.snapshot.Entities[i].ID < c.snapshot.Entities[j].ID })
	sort.Slice(c.snapshot.Evidence, func(i, j int) bool { return c.snapshot.Evidence[i].ID < c.snapshot.Evidence[j].ID })
	sort.Slice(c.snapshot.Relationships, func(i, j int) bool { return c.snapshot.Relationships[i].ID < c.snapshot.Relationships[j].ID })
	sort.Strings(c.source.Warnings)
	sort.Strings(c.source.PermissionsObserved)
	c.snapshot.Sources = []model.Source{c.source}
	return c.snapshot, c.snapshot.Validate()
}

func (c *collection) collectJob(ctx context.Context, job Job) {
	endpoint := jobEndpoint(job.Path)
	tree := "_class,fullName"
	if job.Kind == "job" {
		tree += fmt.Sprintf(",buildable,builds[number,result,building,timestamp,duration]{0,%d}", c.config.BuildLimit)
	}
	var response itemResponse
	if code := c.get(ctx, endpoint, tree, &response); code != "" {
		c.fail(endpoint, code, true)
		return
	}
	if response.FullName != job.Path || response.Class == "" {
		c.fail(endpoint, "unexpected_item_identity", true)
		return
	}
	folder := response.Class == "com.cloudbees.hudson.plugins.folder.Folder" || response.Class == "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" || response.Class == "jenkins.branch.OrganizationFolder"
	if folder != (job.Kind == "folder") {
		c.fail(endpoint, "unexpected_item_kind", true)
		return
	}
	entity := model.Entity{ID: model.EntityID(c.config.ID, "job", job.Path), Kind: "job", SourceID: c.config.ID, NativeID: job.Path, Name: job.Path, Scope: c.config.Scope,
		Attributes: map[string]json.RawMessage{"job_kind": raw(job.Kind)}, FieldStatus: map[string]model.FieldStatus{"job_kind": model.FieldKnown}, ObservedAt: c.at, Provenance: model.ProvenanceLiveAPI}
	fields := []string{"fullName", "job_kind"}
	if job.Kind == "job" {
		entity.FieldStatus["builds"] = model.FieldUnknown
		entity.FieldStatus["buildable"] = model.FieldUnknown
		entity.FieldStatus["credential_reference_count"] = model.FieldUnknown
		if response.Buildable == nil || response.Builds == nil || !validBuilds(*response.Builds, c.config.BuildLimit) {
			c.fail(endpoint, "incomplete_build_metadata", true)
		} else {
			entity.Attributes["buildable"] = raw(*response.Buildable)
			entity.Attributes["builds"] = raw(*response.Builds)
			entity.FieldStatus["buildable"] = model.FieldKnown
			entity.FieldStatus["builds"] = model.FieldKnown
			fields = append(fields, "buildable", "builds.number", "builds.result", "builds.building", "builds.timestamp", "builds.duration")
		}
	}
	jobEvidence := c.evidence(job.Path, "jenkins/"+url.PathEscape(c.config.ID)+endpoint, fields, model.AssertionObserved)
	c.source.PermissionsObserved = append(c.source.PermissionsObserved, "jenkins:"+endpoint+":read")
	if job.Jenkinsfile != nil {
		c.addReferences(ctx, job, &entity, jobEvidence)
	} else if job.Kind == "job" {
		c.source.Warnings = append(c.source.Warnings, "Jenkins "+endpoint+": credential references not requested; no pinned Jenkinsfile supplied")
	}
	c.snapshot.Entities = append(c.snapshot.Entities, entity)
}

func validBuilds(builds []build, limit int) bool {
	if len(builds) > limit {
		return false
	}
	seen := map[int64]bool{}
	for _, b := range builds {
		if b.Number == nil || *b.Number < 1 || seen[*b.Number] || b.Building == nil || b.Timestamp == nil || *b.Timestamp < 0 || b.Duration == nil || *b.Duration < 0 {
			return false
		}
		seen[*b.Number] = true
		if b.Result == nil {
			if !*b.Building {
				return false
			}
			continue
		}
		switch *b.Result {
		case "SUCCESS", "FAILURE", "UNSTABLE", "ABORTED", "NOT_BUILT":
		default:
			return false
		}
	}
	return true
}

func (c *collection) addReferences(ctx context.Context, job Job, entity *model.Entity, jobEvidence string) {
	file := *job.Jenkinsfile
	load := c.pinnedFile
	if load == nil {
		load = readPinnedFile
	}
	data, err := load(ctx, file)
	if len(data) > maxJenkinsfileBytes {
		data = nil
		err = fmt.Errorf("Jenkinsfile exceeds size limit")
	}
	if err != nil {
		c.fail(jobEndpoint(job.Path), "jenkinsfile_unavailable", false)
		return
	}
	parsed := ParseJenkinsfile(data)
	// Keep only validated metadata. Neither file content nor its hash is retained.
	data = nil
	count := map[string]bool{}
	for _, ref := range parsed.References {
		count[ref.ID] = true
	}
	entity.Attributes["jenkinsfile_commit"] = raw(file.Commit)
	entity.FieldStatus["jenkinsfile_commit"] = model.FieldKnown
	entity.Attributes["credential_reference_count"] = raw(len(count))
	entity.FieldStatus["credential_reference_count"] = model.FieldKnown
	if parsed.Unresolved {
		entity.FieldStatus["credential_reference_count"] = model.FieldUnsupported
		c.fail(jobEndpoint(job.Path), "unresolved_jenkinsfile", false)
	}
	fileLocator := "git/" + file.Commit + "/" + strings.ReplaceAll(url.PathEscape(file.Path), "%2F", "/")
	declaration := c.evidence(job.Path, "config/"+url.PathEscape(c.config.ID)+"/jobs/"+url.PathEscape(job.Path)+"/jenkinsfile", []string{"job_native_id", "repository", "commit", "path"}, model.AssertionDeclared)
	refs := map[string][]string{}
	for _, ref := range parsed.References {
		native := CredentialNativeID(job.Path, ref.ID)
		evidence := c.evidence(native, fileLocator+"#L"+strconv.Itoa(ref.Line), []string{"credential_id"}, model.AssertionConfigured)
		refs[ref.ID] = appendUnique(refs[ref.ID], evidence)
	}
	for id, evidenceIDs := range refs {
		native := CredentialNativeID(job.Path, id)
		ref := model.Entity{ID: model.EntityID(c.config.ID, "credential_reference", native), Kind: "credential_reference", SourceID: c.config.ID, NativeID: native, Scope: c.config.Scope + "/jobs/" + job.Path, Name: id,
			Attributes: map[string]json.RawMessage{"credential_id": raw(id), "job_native_id": raw(job.Path)}, FieldStatus: map[string]model.FieldStatus{"credential_id": model.FieldKnown, "job_native_id": model.FieldKnown}, ObservedAt: c.at, Provenance: model.ProvenanceProviderExport}
		c.snapshot.Entities = append(c.snapshot.Entities, ref)
		evidenceIDs = append(evidenceIDs, jobEvidence, declaration)
		sort.Strings(evidenceIDs)
		c.snapshot.Relationships = append(c.snapshot.Relationships, model.Relationship{ID: model.RelationshipID(entity.ID, ref.ID, "references_credential", entity.Scope), From: entity.ID, To: ref.ID, Type: "references_credential", Scope: entity.Scope, AssertionKind: model.AssertionDeclared, EvidenceIDs: evidenceIDs, ObservedAt: c.at})
	}
}

func (c *collection) get(ctx context.Context, endpoint, tree string, target any) string {
	requestURL := strings.TrimRight(c.config.Address, "/") + endpoint + "?" + url.Values{"tree": []string{tree}}.Encode()
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return "invalid_request"
		}
		req.SetBasicAuth(c.username, c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return "transport_error"
		} // Do not retain URLs, credentials or transport diagnostics.
		if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			resp.Body.Close()
			if attempt == 2 {
				return fmt.Sprintf("HTTP_%d", resp.StatusCode)
			}
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			if value := resp.Header.Get("Retry-After"); value != "" {
				seconds, e := strconv.Atoi(value)
				if e != nil || seconds < 0 || seconds > 2 {
					return "rate_limited"
				}
				delay = time.Duration(seconds) * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "cancelled"
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Sprintf("HTTP_%d", resp.StatusCode)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			return "response_read_error"
		}
		if len(body) > maxResponseBytes {
			return "response_too_large"
		}
		if json.Unmarshal(body, target) != nil {
			return "invalid_metadata_json"
		}
		return ""
	}
	return "request_failed"
}

func (c *collection) fail(item, code string, api bool) {
	c.source.Status = model.SourcePartial
	c.source.Complete = false
	if api {
		c.source.PaginationComplete = false
	}
	if c.source.ErrorCode == "" {
		c.source.ErrorCode = code
	}
	c.source.Warnings = append(c.source.Warnings, "Jenkins "+item+": "+code)
}
func (c *collection) evidence(native, locator string, fields []string, kind model.AssertionKind) string {
	id := model.EvidenceID(c.config.ID, native, locator)
	for _, e := range c.snapshot.Evidence {
		if e.ID == id {
			return id
		}
	}
	c.snapshot.Evidence = append(c.snapshot.Evidence, model.Evidence{ID: id, SourceID: c.config.ID, NativeID: native, Locator: locator, Fields: fields, AssertionKind: kind, ObservedAt: c.at})
	return id
}
func raw(value any) json.RawMessage { data, _ := json.Marshal(value); return data }
func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

func (collector Collector) credential(name string) string {
	if collector.Credentials != nil {
		return collector.Credentials(name)
	}
	return os.Getenv(name)
}
