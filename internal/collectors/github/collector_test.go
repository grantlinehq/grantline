package github_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/collectors/entra"
	"github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/model"
)

const tenantID = "11111111-1111-1111-1111-111111111111"
const clientID = "22222222-2222-2222-2222-222222222222"
const objectID = "33333333-3333-3333-3333-333333333333"
const ficID = "44444444-4444-4444-4444-444444444444"
const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const workflowPath = ".github/workflows/demo.yml"
const subject = "repo:owner@12/repo@34:ref:refs/heads/main"
const workflow = `on: workflow_dispatch
permissions: {id-token: write, contents: read}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v3
        with:
          tenant-id: 11111111-1111-1111-1111-111111111111
          client-id: 22222222-2222-2222-2222-222222222222
      - run: echo INLINE_CANARY_DO_NOT_PERSIST
`

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(status int, v any) *http.Response {
	data, _ := json.Marshal(v)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}
}

type fixture struct {
	config   github.Config
	workflow string
	bodies   map[string]any
	calls    []string
	hook     func(*http.Request) *http.Response
}

func newFixture() *fixture {
	f := &fixture{workflow: workflow, config: github.Config{ID: "gh", Scope: "github/test", TokenEnv: "TEST_GITHUB_TOKEN", Repositories: []github.Repository{{Name: "owner/repo", ID: "34", Refs: []string{"refs/heads/main"}}}}, bodies: map[string]any{}}
	f.bodies["/repos/owner/repo"] = map[string]any{"id": 34, "full_name": "owner/repo", "owner": map[string]any{"id": 12, "login": "owner"}, "description": "RESPONSE_CANARY"}
	f.bodies["/repos/owner/repo/actions/oidc/customization/sub"] = map[string]any{"use_default": true, "use_immutable_subject": true, "sub_claim_prefix": "repo:owner@12/repo@34"}
	f.bodies["/repos/owner/repo/actions/workflows"] = map[string]any{"total_count": 1, "workflows": []any{map[string]any{"id": 56, "path": workflowPath, "state": "active", "name": "RESPONSE_CANARY"}}}
	f.bodies["/repos/owner/repo/commits/refs/heads/main"] = map[string]any{"sha": sha, "commit": map[string]any{"message": "RESPONSE_CANARY"}}
	return f
}
func (f *fixture) collect(t *testing.T) model.Snapshot {
	t.Helper()
	t.Setenv("TEST_GITHUB_TOKEN", "AUTH_CANARY")
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		f.calls = append(f.calls, r.URL.RequestURI())
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "api.github.com" || !strings.HasPrefix(r.URL.Path, "/repos/owner/repo") || strings.Contains(r.URL.Path, "/secrets") || strings.Contains(r.URL.Path, "/logs") {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer AUTH_CANARY" || r.Header.Get("X-GitHub-Api-Version") != github.APIVersion {
			t.Fatal("request headers missing")
		}
		if f.hook != nil {
			if response := f.hook(r); response != nil {
				return response, nil
			}
		}
		if strings.HasPrefix(r.URL.Path, "/repos/owner/repo/contents/") {
			if r.URL.Query().Get("ref") != sha {
				t.Fatal("unpinned file request")
			}
			return reply(200, map[string]any{"type": "file", "path": strings.TrimPrefix(r.URL.Path, "/repos/owner/repo/contents/"), "sha": sha, "encoding": "base64", "size": len(f.workflow), "content": base64.StdEncoding.EncodeToString([]byte(f.workflow)), "download_url": "https://evil.invalid/RESPONSE_CANARY"}), nil
		}
		if body, ok := f.bodies[r.URL.Path]; ok {
			return reply(200, body), nil
		}
		t.Fatalf("unexpected endpoint %s", r.URL)
		return nil, nil
	})}
	s, err := (github.Collector{Config: f.config, Client: client, Now: func() time.Time { return time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC) }}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "CANARY") {
		t.Fatal("provider contents or token leaked")
	}
	return s
}
func entraSnapshot(t *testing.T, tenant, sub, audience string, denyOwners bool) model.Snapshot {
	t.Helper()
	t.Setenv("TEST_GRAPH_TOKEN", "GRAPH_AUTH_CANARY")
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" || r.URL.Host != "graph.microsoft.com" {
			t.Fatal("unexpected Graph request")
		}
		switch r.URL.Path {
		case "/v1.0/applications/" + objectID:
			return reply(200, map[string]any{"id": objectID, "appId": clientID, "displayName": "same display name", "passwordCredentials": []any{}, "keyCredentials": []any{}, "requiredResourceAccess": []any{}}), nil
		case "/v1.0/applications/" + objectID + "/owners":
			if denyOwners {
				return reply(403, map[string]any{"error": "ERROR_CANARY"}), nil
			}
			return reply(200, map[string]any{"value": []any{}}), nil
		case "/v1.0/applications/" + objectID + "/federatedIdentityCredentials":
			return reply(200, map[string]any{"value": []any{map[string]any{"id": ficID, "name": "same display name", "issuer": "https://token.actions.githubusercontent.com", "subject": sub, "audiences": []string{audience}}}}), nil
		}
		t.Fatalf("unexpected Graph endpoint %s", r.URL)
		return nil, nil
	})}
	s, err := (entra.Collector{Config: entra.Config{ID: "entra", Scope: "tenant/" + tenant, TenantID: tenant, TokenEnv: "TEST_GRAPH_TOKEN", Applications: []string{objectID}}, Client: client}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func merge(a, b model.Snapshot) model.Snapshot {
	a.Entities = append(a.Entities, b.Entities...)
	a.Evidence = append(a.Evidence, b.Evidence...)
	a.Relationships = append(a.Relationships, b.Relationships...)
	a.Sources = append(a.Sources, b.Sources...)
	return a
}
func trustEdges(s model.Snapshot) []model.Relationship {
	var result []model.Relationship
	for _, r := range s.Relationships {
		if r.Type == "trusts_subject" {
			result = append(result, r)
		}
	}
	return result
}

func TestLiveAPIShapeAndExactFICCorrelation(t *testing.T) {
	for _, name := range []string{"positive", "wrong tenant", "wrong client", "wrong subject", "wrong ref", "wrong repo ID", "wrong audience", "unresolved vars", "job override", "dynamic environment", "unsupported action", "missing file evidence", "missing template evidence", "missing FIC evidence", "denied owners keeps known edge", "declaration", "missing declaration evidence", "legacy", "wrong legacy format", "environment"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			tenant, sub, aud := tenantID, subject, "api://AzureADTokenExchange"
			want := 0
			denied := false
			switch name {
			case "positive":
				want = 1
			case "wrong tenant":
				tenant = "99999999-9999-9999-9999-999999999999"
			case "wrong client":
				f.workflow = strings.Replace(f.workflow, clientID, "99999999-9999-9999-9999-999999999999", 1)
			case "wrong subject":
				sub = "repo:another@12/repo@34:ref:refs/heads/main"
			case "wrong ref":
				sub = strings.Replace(subject, "main", "other", 1)
			case "wrong repo ID":
				sub = strings.Replace(subject, "repo@34", "repo@35", 1)
			case "wrong audience":
				aud = "api://OtherAudience"
			case "unresolved vars":
				f.workflow = strings.Replace(f.workflow, tenantID, "${{ vars.TENANT_ID }}", 1)
			case "job override":
				f.workflow = strings.Replace(f.workflow, "    runs-on:", "    permissions: {contents: read}\n    runs-on:", 1)
			case "dynamic environment":
				f.workflow = strings.Replace(f.workflow, "    runs-on:", "    environment: ${{ inputs.environment }}\n    runs-on:", 1)
			case "unsupported action":
				f.workflow = strings.Replace(f.workflow, "azure/login@v3", "azure/login@main", 1)
			case "denied owners keeps known edge":
				want = 1
				denied = true
			case "declaration", "missing declaration evidence":
				f.workflow = strings.Replace(f.workflow, tenantID, "${{ secrets.TENANT_ID }}", 1)
				f.config.Repositories[0].IdentityMappings = []github.IdentityMapping{{WorkflowPath: workflowPath, Ref: "refs/heads/main", CommitSHA: sha, JobID: "deploy", Step: 1, Field: "tenant_id", Reference: "secrets.TENANT_ID", Value: tenantID}}
				if name == "declaration" {
					want = 1
				}
			case "legacy", "wrong legacy format":
				f.bodies["/repos/owner/repo/actions/oidc/customization/sub"] = map[string]any{"use_default": true, "use_immutable_subject": false, "sub_claim_prefix": "repo:owner/repo"}
				if name == "legacy" {
					sub = "repo:owner/repo:ref:refs/heads/main"
					want = 1
				}
			case "environment":
				f.workflow = strings.Replace(f.workflow, "    runs-on:", "    environment: production\n    runs-on:", 1)
				sub = "repo:owner@12/repo@34:environment:production"
				want = 1
			}
			s := merge(f.collect(t), entraSnapshot(t, tenant, sub, aud, denied))
			filtered := []model.Evidence{}
			for _, e := range s.Evidence {
				if name == "missing file evidence" && strings.Contains(e.Locator, "/contents/") || name == "missing template evidence" && strings.Contains(e.Locator, "customization") || name == "missing FIC evidence" && strings.Contains(e.Locator, "federatedIdentityCredentials/") || name == "missing declaration evidence" && e.AssertionKind == model.AssertionDeclared {
					continue
				}
				filtered = append(filtered, e)
			}
			s.Evidence = filtered
			// Removing FIC evidence also invalidates its parent edge, so remove that
			// unrelated edge before validating the adversarial snapshot below.
			if name == "missing FIC evidence" {
				s.Relationships = nil
			}
			correlate.AddGitHubEntraTrusts(&s)
			edges := trustEdges(s)
			if len(edges) != want {
				t.Fatalf("trust edges=%d want=%d; GitHub source=%+v", len(edges), want, s.Sources[0])
			}
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if want == 1 {
				assertion := model.AssertionConfigured
				if name == "declaration" {
					assertion = model.AssertionDeclared
				}
				if edges[0].AssertionKind != assertion || len(edges[0].EvidenceIDs) < 5 {
					t.Fatal("edge proof/assertion missing")
				}
				correlate.AddGitHubEntraTrusts(&s)
				if len(trustEdges(s)) != 1 {
					t.Fatal("duplicate edge")
				}
			}
			if name == "unresolved vars" && s.Sources[0].Complete {
				t.Fatal("unresolved variables hidden")
			}
			if name == "declaration" && !s.Sources[0].Complete {
				t.Fatal("exact declaration not resolved")
			}
		})
	}
}

func TestHTTPFailuresPaginationLimitsAndIdentity(t *testing.T) {
	for _, name := range []string{"401", "403", "404", "redirect", "oversize", "malformed", "repository mismatch", "duplicate workflow", "custom template", "unknown immutable format", "bad prefix", "missing page", "external link", "extra query", "second page denied", "retry", "rate delay limit", "content denied", "stale declaration"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			retries := 0
			f.hook = func(r *http.Request) *http.Response {
				if r.URL.Path == "/repos/owner/repo" {
					switch name {
					case "401":
						return reply(401, map[string]string{"error": "ERROR_CANARY"})
					case "403":
						return reply(403, map[string]string{"error": "ERROR_CANARY"})
					case "404":
						return reply(404, map[string]string{"error": "ERROR_CANARY"})
					case "redirect":
						resp := reply(302, nil)
						resp.Header.Set("Location", "https://evil.invalid")
						return resp
					case "oversize":
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (2<<20)+1)))}
					case "malformed":
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ERROR_CANARY"))}
					case "retry":
						retries++
						if retries < 3 {
							return reply(503, nil)
						}
					case "rate delay limit":
						resp := reply(429, nil)
						resp.Header.Set("Retry-After", "9223372036854775807")
						return resp
					}
				}
				if r.URL.Path == "/repos/owner/repo/actions/workflows" {
					switch name {
					case "missing page", "external link", "extra query", "second page denied":
						if r.URL.Query().Get("page") == "2" {
							return reply(403, map[string]string{"error": "ERROR_CANARY"})
						}
						resp := reply(200, map[string]any{"total_count": 2, "workflows": []any{map[string]any{"id": 56, "path": workflowPath, "state": "active"}}})
						link := "https://api.github.com/repos/owner/repo/actions/workflows?per_page=100&page=2"
						if name == "external link" {
							link = strings.Replace(link, "api.github.com", "evil.invalid", 1)
						}
						if name == "extra query" {
							link += "&secret=ERROR_CANARY"
						}
						if name != "missing page" {
							resp.Header.Set("Link", "<"+link+">; rel=\"next\"")
						}
						return resp
					}
				}
				if name == "content denied" && strings.Contains(r.URL.Path, "/contents/") {
					return reply(403, map[string]string{"error": "ERROR_CANARY"})
				}
				return nil
			}
			switch name {
			case "repository mismatch":
				f.bodies["/repos/owner/repo"].(map[string]any)["id"] = 35
			case "duplicate workflow":
				f.bodies["/repos/owner/repo/actions/workflows"] = map[string]any{"total_count": 2, "workflows": []any{map[string]any{"id": 56, "path": workflowPath, "state": "active"}, map[string]any{"id": 56, "path": workflowPath, "state": "active"}}}
			case "custom template":
				f.bodies["/repos/owner/repo/actions/oidc/customization/sub"].(map[string]any)["use_default"] = false
			case "unknown immutable format":
				delete(f.bodies["/repos/owner/repo/actions/oidc/customization/sub"].(map[string]any), "use_immutable_subject")
			case "bad prefix":
				f.bodies["/repos/owner/repo/actions/oidc/customization/sub"].(map[string]any)["sub_claim_prefix"] = "repo:owner@12/repo@99"
			case "stale declaration":
				f.config.Repositories[0].IdentityMappings = []github.IdentityMapping{{WorkflowPath: workflowPath, Ref: "refs/heads/main", CommitSHA: strings.Repeat("b", 40), JobID: "deploy", Step: 1, Field: "tenant_id", Reference: "secrets.TENANT_ID", Value: tenantID}}
			}
			s := f.collect(t)
			if name == "retry" {
				if !s.Sources[0].Complete || retries != 3 {
					t.Fatal("bounded retry failed")
				}
				return
			}
			if s.Sources[0].Complete || s.Sources[0].Status != model.SourcePartial {
				t.Fatal("failure hidden as success")
			}
			if name == "401" && len(f.calls) != 1 {
				t.Fatal("token reused after 401")
			}
			if name == "external link" || name == "extra query" {
				for _, call := range f.calls {
					if strings.Contains(call, "page=2") {
						t.Fatal("unsafe pagination followed")
					}
				}
			}
			if name == "second page denied" && (s.Sources[0].PaginationComplete || len(s.Entities) != 1) {
				t.Fatal("partial page evidence lost")
			}
		})
	}
}

func TestObservedSmokeIsSeparateAndCannotCreateTrust(t *testing.T) {
	f := newFixture()
	f.config.Repositories[0].SmokeChecks = []github.SmokeCheck{{WorkflowPath: workflowPath, RunID: "70", Attempt: 1, JobID: "80", LoginStepNumber: 2}}
	f.bodies["/repos/owner/repo/actions/runs/70/attempts/1"] = map[string]any{"id": 70, "run_attempt": 1, "workflow_id": 56, "head_sha": sha, "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "repository": map[string]any{"id": 34}, "head_repository": map[string]any{"id": 34}, "logs_url": "SMOKE_CANARY"}
	f.bodies["/repos/owner/repo/actions/jobs/80"] = map[string]any{"id": 80, "run_id": 70, "run_attempt": 1, "head_sha": sha, "status": "completed", "conclusion": "success", "steps": []any{map[string]any{"number": 2, "name": "STEP_NAME_CANARY", "status": "completed", "conclusion": "success"}}}
	// A successful run does not reveal the current referenced tenant/client ID.
	f.workflow = strings.Replace(f.workflow, tenantID, "${{ secrets.TENANT_ID }}", 1)
	s := merge(f.collect(t), entraSnapshot(t, tenantID, subject, "api://AzureADTokenExchange", false))
	correlate.AddGitHubEntraTrusts(&s)
	if len(trustEdges(s)) != 0 {
		t.Fatal("run success fabricated a trust edge")
	}
	var results []model.GitHubSmokeResult
	json.Unmarshal(s.Entities[0].Attributes["smoke_results"], &results)
	if len(results) != 1 || results[0].StepConclusion != "success" {
		t.Fatal("selected observed result missing")
	}
	f.bodies["/repos/owner/repo/actions/jobs/80"].(map[string]any)["run_attempt"] = 2
	s = f.collect(t)
	if s.Sources[0].Complete {
		t.Fatal("wrong run attempt accepted")
	}
}

func TestConfigRejectsBroadOrAmbiguousScope(t *testing.T) {
	for _, name := range []string{"address", "ref", "repo", "id", "duplicate", "mapping value", "mapping reference"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			switch name {
			case "address":
				f.config.Address = "https://evil.invalid"
			case "ref":
				f.config.Repositories[0].Refs = []string{"main"}
			case "repo":
				f.config.Repositories[0].Name = "owner/repo/../other"
			case "id":
				f.config.Repositories[0].ID = ""
			case "duplicate":
				f.config.Repositories = append(f.config.Repositories, f.config.Repositories[0])
			default:
				m := github.IdentityMapping{WorkflowPath: workflowPath, Ref: "refs/heads/main", CommitSHA: sha, JobID: "deploy", Step: 1, Field: "tenant_id", Reference: "secrets.TENANT", Value: tenantID}
				if name == "mapping value" {
					m.Value = "NOT_A_UUID_SECRET_CANARY"
				} else {
					m.Reference = "${{ secrets.TENANT }}"
				}
				f.config.Repositories[0].IdentityMappings = []github.IdentityMapping{m}
			}
			if err := f.config.Validate(); err == nil || strings.Contains(fmt.Sprint(err), "CANARY") {
				t.Fatal("invalid config accepted or leaked")
			}
		})
	}
}

func TestCompletePaginationAndStableNativeIdentity(t *testing.T) {
	f := newFixture()
	f.hook = func(r *http.Request) *http.Response {
		if r.URL.Path != "/repos/owner/repo/actions/workflows" {
			return nil
		}
		id, path := 56, workflowPath
		if r.URL.Query().Get("page") == "2" {
			id, path = 57, ".github/workflows/second.yml"
		}
		resp := reply(200, map[string]any{"total_count": 2, "workflows": []any{map[string]any{"id": id, "path": path, "state": "active"}}})
		if id == 56 {
			resp.Header.Set("Link", `<https://api.github.com/repos/owner/repo/actions/workflows?per_page=100&page=2>; rel="next"`)
		}
		return resp
	}
	s := f.collect(t)
	if !s.Sources[0].Complete || len(s.Entities) != 2 {
		t.Fatal("successful pagination incomplete")
	}
	for _, e := range s.Entities {
		if e.ID != model.EntityID("gh", "workflow", e.NativeID) || !strings.HasPrefix(e.NativeID, "34/.github/workflows/") {
			t.Fatal("workflow does not use repo-native identity")
		}
	}
	for _, field := range []string{"native", "scope", "subject", "nested secret", "unknown field", "missing identity", "false configured identity"} {
		t.Run(field, func(t *testing.T) {
			data, _ := json.Marshal(s)
			var mutated model.Snapshot
			json.Unmarshal(data, &mutated)
			e := &mutated.Entities[0]
			switch field {
			case "native":
				e.NativeID = "999/" + workflowPath
			case "scope":
				e.Scope = "github/another/repo/34"
			case "missing identity":
				delete(e.Attributes, "repository_owner_id")
				e.FieldStatus["repository_owner_id"] = model.FieldUnknown
			default:
				var revisions []map[string]any
				json.Unmarshal(e.Attributes["revisions"], &revisions)
				job := revisions[0]["jobs"].([]any)[0].(map[string]any)
				login := job["logins"].([]any)[0].(map[string]any)
				switch field {
				case "subject":
					job["contexts"].([]any)[0].(map[string]any)["subject"] = "repo:wrong@99/repo@77:ref:refs/heads/main"
				case "nested secret":
					login["access_token"] = "SECRET_VALUE_CANARY"
				case "unknown field":
					login["untrusted"] = "SECRET_VALUE_CANARY"
				case "false configured identity":
					login["tenant_reference"] = "secrets.TENANT"
				}
				e.Attributes["revisions"], _ = json.Marshal(revisions)
			}
			if err := mutated.Validate(); err == nil || strings.Contains(err.Error(), "SECRET_VALUE_CANARY") {
				t.Fatal("malformed nested metadata accepted or leaked")
			}
		})
	}
}
