package entra_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/collectors/entra"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

const tenant = "11111111-1111-1111-1111-111111111111"
const app = "22222222-2222-2222-2222-222222222222"
const sp = "33333333-3333-3333-3333-333333333333"
const resource = "44444444-4444-4444-4444-444444444444"
const appID = "55555555-5555-5555-5555-555555555555"
const resourceApp = "66666666-6666-6666-6666-666666666666"
const owner = "77777777-7777-7777-7777-777777777777"
const credentialID = "88888888-8888-8888-8888-888888888888"
const certID = "99999999-9999-9999-9999-999999999999"
const roleID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const fic = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
const requestedID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
const authCanary = "AUTH_CANARY_NOT_A_REAL_GRAPH_TOKEN"
const bodyCanary = "BODY_CANARY_DO_NOT_RETAIN"

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixture struct {
	bodies  map[string]map[string]any
	status  map[string]int
	queries []string
	calls   int
	handler func(*http.Request) (*http.Response, error)
}

func baseFixture() *fixture {
	f := &fixture{bodies: map[string]map[string]any{}, status: map[string]int{}}
	f.bodies["/applications/"+app] = map[string]any{"id": app, "appId": appID, "displayName": "same-name", "passwordCredentials": []any{map[string]any{"keyId": credentialID, "startDateTime": "2026-09-01T00:00:00Z", "endDateTime": "2026-10-01T00:00:00Z", "secretText": bodyCanary, "hint": bodyCanary}}, "keyCredentials": []any{map[string]any{"keyId": certID, "type": "AsymmetricX509Cert", "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2027-01-01T00:00:00Z", "key": bodyCanary}}, "requiredResourceAccess": []any{map[string]any{"resourceAppId": resourceApp, "resourceAccess": []any{map[string]any{"id": requestedID, "type": "Role"}}}}, "notes": bodyCanary}
	f.bodies["/applications/"+app+"/owners"] = map[string]any{"value": []any{}}
	f.bodies["/applications/"+app+"/federatedIdentityCredentials"] = map[string]any{"value": []any{map[string]any{"id": fic, "name": "github-main", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:owner/repo:ref:refs/heads/main", "audiences": []string{"api://AzureADTokenExchange"}, "description": bodyCanary}}}
	f.bodies["/servicePrincipals/"+sp] = map[string]any{"id": sp, "appId": appID, "displayName": "same-name", "servicePrincipalType": "Application", "passwordCredentials": []any{}, "keyCredentials": []any{}, "appRoles": []any{}}
	f.bodies["/servicePrincipals/"+sp+"/owners"] = map[string]any{"value": []any{map[string]any{"id": owner, "@odata.type": "#microsoft.graph.user", "displayName": nil, "mail": bodyCanary}}}
	f.bodies["/servicePrincipals/"+sp+"/appRoleAssignments"] = map[string]any{"value": []any{map[string]any{"id": "opaque-assignment_id", "principalId": sp, "principalType": "ServicePrincipal", "resourceId": resource, "appRoleId": roleID, "principalDisplayName": bodyCanary}}}
	f.bodies["/servicePrincipals/"+resource] = map[string]any{"id": resource, "appId": resourceApp, "displayName": "Resource API", "appRoles": []any{map[string]any{"id": roleID, "value": "Records.Read.All", "isEnabled": true, "allowedMemberTypes": []string{"Application"}, "description": bodyCanary}}}
	return f
}
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func (f *fixture) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		f.calls++
		f.queries = append(f.queries, r.URL.String())
		if r.Method != "GET" || r.URL.Host != "graph.microsoft.com" || r.URL.Scheme != "https" || !strings.HasPrefix(r.URL.Path, "/v1.0/") {
			t.Fatalf("out-of-scope request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer "+authCanary {
			t.Fatal("token authentication missing")
		}
		if r.URL.Query().Get("$select") == "" {
			t.Fatal("missing projection")
		}
		if f.handler != nil {
			if resp, err := f.handler(r); resp != nil || err != nil {
				return resp, err
			}
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1.0")
		if code := f.status[path]; code != 0 {
			return response(code, bodyCanary), nil
		}
		body, ok := f.bodies[path]
		if !ok {
			t.Errorf("unexpected endpoint %s", path)
			return response(404, ""), nil
		}
		data, _ := json.Marshal(body)
		return response(200, string(data)), nil
	})}
}
func collect(t *testing.T, f *fixture) model.Snapshot {
	t.Helper()
	t.Setenv("TEST_ENTRA_AUTH", authCanary)
	cfg := entra.Config{ID: "entra", Scope: "tenant/" + tenant, TenantID: tenant, TokenEnv: "TEST_ENTRA_AUTH", Applications: []string{app}, ServicePrincipals: []string{sp}}
	s, err := (entra.Collector{Config: cfg, Client: f.client(t), Now: func() time.Time { return time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC) }}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	for _, canary := range []string{authCanary, bodyCanary, "secretText", "passwordCredentials\":", "hint\":"} {
		if strings.Contains(string(data), canary) {
			t.Fatalf("private response/auth input retained: %s", canary)
		}
	}
	return s
}
func find(t *testing.T, s model.Snapshot, kind, native string) model.Entity {
	t.Helper()
	for _, e := range s.Entities {
		if e.Kind == kind && (native == "" || e.NativeID == native) {
			return e
		}
	}
	t.Fatalf("missing %s %s", kind, native)
	return model.Entity{}
}
func testPolicy() policy.Policy {
	return policy.Policy{SchemaVersion: 1, RequiredSources: []string{"entra"}, MaxClientSecretValidity: 168 * time.Hour, Rules: map[string]policy.Rule{
		"IL003": {Severity: model.SeverityMedium}, "IL004": {Severity: model.SeverityLow, RequireOwnersFor: []policy.EntraOwnerTarget{{SourceID: "entra", ObjectID: app, ObjectKind: "application_registration"}, {SourceID: "entra", ObjectID: sp, ObjectKind: "service_principal"}}}, "IL005": {Severity: model.SeverityMedium},
	}}
}
func report(t *testing.T, s model.Snapshot, p policy.Policy) model.Report {
	t.Helper()
	r, err := analyze.Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func outcome(t *testing.T, r model.Report, id string) model.RuleOutcome {
	t.Helper()
	for _, x := range r.RuleResults {
		if x.RuleID == id {
			return x.Outcome
		}
	}
	t.Fatal("missing rule")
	return ""
}

func TestGraphCollectionIdentityProjectionAndRules(t *testing.T) {
	f := baseFixture()
	s := collect(t, f)
	if !s.Sources[0].Complete || len(s.Entities) != 9 || len(s.Relationships) != 7 {
		t.Fatalf("unexpected inventory: entities=%d edges=%d source=%+v", len(s.Entities), len(s.Relationships), s.Sources)
	}
	a := find(t, s, "application_registration", tenant+"/"+app)
	principal := find(t, s, "service_principal", tenant+"/"+sp)
	if a.ID == principal.ID || a.NativeID == tenant+"/"+appID {
		t.Fatal("appId/object IDs conflated")
	}
	registered := 0
	for _, edge := range s.Relationships {
		if edge.Type == "registered_as" {
			registered++
			if edge.From != a.ID || edge.To != principal.ID || edge.AssertionKind != model.AssertionConfigured {
				t.Fatal("wrong registration correlation")
			}
		}
	}
	if registered != 1 {
		t.Fatal("registration evidence absent")
	}
	ownerEntity := find(t, s, "owner", tenant+"/"+owner)
	if ownerEntity.Name != "" || string(principal.Attributes["owners_count"]) != "1" {
		t.Fatal("limited owner treated as absent or personal data retained")
	}
	role := find(t, s, "role", "")
	if string(role.Attributes["app_role_id"]) != `"`+roleID+`"` {
		t.Fatal("requested role used as granted role")
	}
	r := report(t, s, testPolicy())
	if len(r.Findings) != 3 {
		t.Fatalf("expected validity, missing application owner and actual grant findings: %d", len(r.Findings))
	}
	for _, id := range []string{"IL003", "IL004", "IL005"} {
		if outcome(t, r, id) != model.OutcomeFail {
			t.Fatalf("%s did not detect expected issue", id)
		}
	}
	r2 := report(t, s, testPolicy())
	for i := range r.Findings {
		if r.Findings[i].ID != r2.Findings[i].ID {
			t.Fatal("unstable finding IDs")
		}
	}
	for _, query := range f.queries {
		if strings.Contains(query, "/users/") || strings.Contains(query, "/organization") || strings.Contains(query, "management.azure.com") {
			t.Fatal("out-of-scope inventory")
		}
	}
}

func TestAllowedGrantThresholdAndSeparateOwners(t *testing.T) {
	s := collect(t, baseFixture())
	p := testPolicy()
	p.MaxClientSecretValidity = 30 * 24 * time.Hour
	rule := p.Rules["IL004"]
	rule.RequireOwnersFor = rule.RequireOwnersFor[1:]
	p.Rules["IL004"] = rule
	rule = p.Rules["IL005"]
	rule.AllowedAppRoles = []policy.EntraAppRole{{SourceID: "entra", PrincipalObjectID: sp, ResourceObjectID: resource, AppRoleID: roleID}}
	p.Rules["IL005"] = rule
	r := report(t, s, p)
	if len(r.Findings) != 0 {
		t.Fatal("valid boundary/owner/allowlist raised finding")
	}
	for _, id := range []string{"IL003", "IL004", "IL005"} {
		if outcome(t, r, id) != model.OutcomePass {
			t.Fatalf("%s not PASS", id)
		}
	}
	rule = p.Rules["IL005"]
	rule.AllowedAppRoles[0].SourceID = "other-tenant-source"
	p.Rules["IL005"] = rule
	if outcome(t, report(t, s, p), "IL005") != model.OutcomeFail {
		t.Fatal("cross-source allowlist matched")
	}
}

func TestDeniedOwnersAndUnresolvedGrantStayUnknown(t *testing.T) {
	for _, tc := range []struct{ name, path, rule, field, kind string }{
		{"owners", "/applications/" + app + "/owners", "IL004", "owners_count", "application_registration"},
		{"assignments", "/servicePrincipals/" + sp + "/appRoleAssignments", "IL005", "app_role_assignments_count", "service_principal"},
		{"role definition", "/servicePrincipals/" + resource, "IL005", "app_role_assignments_count", "service_principal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture()
			f.status[tc.path] = 403
			s := collect(t, f)
			if s.Sources[0].Complete || s.Sources[0].PaginationComplete {
				t.Fatal("403 reported complete")
			}
			e := find(t, s, tc.kind, "")
			if e.FieldStatus[tc.field] == model.FieldKnown {
				t.Fatal("403 field known")
			}
			r := report(t, s, testPolicy())
			if outcome(t, r, tc.rule) != model.OutcomeUnknown {
				t.Fatal("denied metadata treated as PASS/FAIL")
			}
			for _, finding := range r.Findings {
				if finding.RuleID == tc.rule {
					t.Fatal("missing evidence produced finding")
				}
			}
		})
	}
}

func TestRequestedOnlyIsNotGrantedAndResourceDefinitionsRequired(t *testing.T) {
	f := baseFixture()
	f.bodies["/servicePrincipals/"+sp+"/appRoleAssignments"]["value"] = []any{}
	s := collect(t, f)
	if outcome(t, report(t, s, testPolicy()), "IL005") != model.OutcomePass {
		t.Fatal("requested permissions treated as actual grants")
	}
	f = baseFixture()
	f.bodies["/servicePrincipals/"+resource]["appRoles"] = []any{}
	s = collect(t, f)
	if outcome(t, report(t, s, testPolicy()), "IL005") != model.OutcomeUnknown {
		t.Fatal("missing definition guessed")
	}
}

func TestMissingCredentialDatesAndFlexibleFIC(t *testing.T) {
	f := baseFixture()
	f.bodies["/applications/"+app]["passwordCredentials"].([]any)[0].(map[string]any)["endDateTime"] = nil
	s := collect(t, f)
	if s.Sources[0].Complete || outcome(t, report(t, s, testPolicy()), "IL003") != model.OutcomeUnknown {
		t.Fatal("missing dates falsely assessed")
	}
	f = baseFixture()
	f.bodies["/applications/"+app+"/federatedIdentityCredentials"]["value"].([]any)[0].(map[string]any)["claimsMatchingExpression"] = map[string]any{"value": bodyCanary}
	s = collect(t, f)
	e := find(t, s, "federated_credential", "")
	if e.FieldStatus["subject"] != model.FieldUnsupported || s.Sources[0].Complete {
		t.Fatal("flexible FIC treated as standard")
	}
}

func TestPaginationBoundariesAndPartialRetention(t *testing.T) {
	endpoint := "/applications/" + app + "/owners"
	for _, tc := range []struct {
		name, next   string
		wantComplete bool
		calls        int
	}{
		{"safe", entra.GraphAddress + endpoint + "?%24select=id&%24skiptoken=page2", true, 2},
		{"cross origin", "https://attacker.invalid/v1.0" + endpoint + "?$select=id", false, 1},
		{"other endpoint", entra.GraphAddress + "/users?$select=id", false, 1},
		{"beta", "https://graph.microsoft.com/beta" + endpoint + "?$select=id", false, 1},
		{"changed projection", entra.GraphAddress + endpoint + "?$select=id,mail", false, 1},
		{"userinfo", "https://user@graph.microsoft.com/v1.0" + endpoint + "?$select=id", false, 1},
		{"query injection", entra.GraphAddress + endpoint + "?$select=id&$expand=manager", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture()
			calls := 0
			f.handler = func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1.0"+endpoint {
					return nil, nil
				}
				calls++
				if calls == 1 {
					return response(200, `{"value":[{"id":"`+owner+`","@odata.type":"#microsoft.graph.user"}],"@odata.nextLink":`+strconvJSON(tc.next)+`}`), nil
				}
				return response(200, `{"value":[]}`), nil
			}
			s := collect(t, f)
			if s.Sources[0].Complete != tc.wantComplete || calls != tc.calls {
				t.Fatalf("unsafe pagination or wrong coverage: %d %+v", calls, s.Sources)
			}
			if len(s.Entities) == 0 {
				t.Fatal("partial data lost")
			}
		})
	}
	t.Run("second page denied", func(t *testing.T) {
		f := baseFixture()
		f.handler = func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/v1.0"+endpoint {
				return nil, nil
			}
			if r.URL.Query().Get("$skiptoken") != "" {
				return response(403, bodyCanary), nil
			}
			next := entra.GraphAddress + endpoint + "?" + url.Values{"$select": {"id"}, "$skiptoken": {"CURSOR_CANARY"}}.Encode()
			return response(200, `{"value":[{"id":"`+owner+`","@odata.type":"#microsoft.graph.user"}],"@odata.nextLink":`+strconvJSON(next)+`}`), nil
		}
		s := collect(t, f)
		e := find(t, s, "application_registration", tenant+"/"+app)
		if e.FieldStatus["owners_count"] != model.FieldPermissionDenied {
			t.Fatal("partial owners passed")
		}
		encoded, _ := json.Marshal(s)
		if strings.Contains(string(encoded), "CURSOR_CANARY") {
			t.Fatal("opaque cursor persisted")
		}
	})
}
func strconvJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestHTTPFailuresRetriesAndAuthRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"auth expired", 401, bodyCanary, "HTTP_401"}, {"malformed", 200, "{BODY_CANARY_DO_NOT_RETAIN", "invalid_metadata_json"}, {"oversize", 200, strings.Repeat("x", (2<<20)+1), "response_too_large"}, {"redirect", 302, "", "HTTP_302"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture()
			f.handler = func(r *http.Request) (*http.Response, error) { return response(tc.status, tc.body), nil }
			s := collect(t, f)
			if s.Sources[0].Complete || s.Sources[0].ErrorCode != tc.want {
				t.Fatalf("wrong failure: %+v", s.Sources)
			}
			if tc.status == 401 && f.calls != 1 {
				t.Fatal("expired token reused")
			}
		})
	}
	t.Run("bounded retry", func(t *testing.T) {
		f := baseFixture()
		attempts := 0
		f.handler = func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/v1.0/applications/"+app {
				return nil, nil
			}
			attempts++
			if attempts < 3 {
				resp := response(429, bodyCanary)
				resp.Header.Set("Retry-After", "0")
				return resp, nil
			}
			return nil, nil
		}
		s := collect(t, f)
		if !s.Sources[0].Complete || attempts != 3 {
			t.Fatal("retry failed")
		}
	})
	for _, retryAfter := range []string{"3600", "18446744074", "-1"} {
		t.Run("unbounded retry-after "+retryAfter, func(t *testing.T) {
			f := baseFixture()
			f.handler = func(r *http.Request) (*http.Response, error) {
				resp := response(429, bodyCanary)
				resp.Header.Set("Retry-After", retryAfter)
				return resp, nil
			}
			s := collect(t, f)
			if s.Sources[0].ErrorCode != "rate_limited" {
				t.Fatal("unbounded retry accepted")
			}
		})
	}
	t.Run("transport error", func(t *testing.T) {
		f := baseFixture()
		f.handler = func(r *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("transport %s %s", authCanary, bodyCanary)
		}
		s := collect(t, f)
		if s.Sources[0].ErrorCode != "transport_error" {
			t.Fatal("raw transport error retained")
		}
	})
}

func TestRepeatedAndExhaustedPagination(t *testing.T) {
	for _, mode := range []string{"repeat", "limit"} {
		t.Run(mode, func(t *testing.T) {
			f := baseFixture()
			calls := 0
			endpoint := "/applications/" + app + "/owners"
			f.handler = func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1.0"+endpoint {
					return nil, nil
				}
				calls++
				cursor := "same"
				if mode == "limit" {
					cursor = fmt.Sprint(calls)
				}
				next := entra.GraphAddress + endpoint + "?" + url.Values{"$select": {"id"}, "$skiptoken": {cursor}}.Encode()
				return response(200, `{"value":[],"@odata.nextLink":`+strconvJSON(next)+`}`), nil
			}
			s := collect(t, f)
			want := "repeated_next_link"
			if mode == "limit" {
				want = "page_limit"
			}
			if s.Sources[0].Complete || s.Sources[0].ErrorCode != want || calls > 50 {
				t.Fatalf("unbounded pagination: %d %+v", calls, s.Sources)
			}
		})
	}
}

func TestObjectMismatchNoMergeAndMissingValues(t *testing.T) {
	f := baseFixture()
	f.bodies["/servicePrincipals/"+sp]["appId"] = resourceApp
	s := collect(t, f)
	for _, edge := range s.Relationships {
		if edge.Type == "registered_as" {
			t.Fatal("equal display names merged despite different app IDs")
		}
	}
	f = baseFixture()
	f.bodies["/applications/"+app]["id"] = sp
	s = collect(t, f)
	if s.Sources[0].Complete {
		t.Fatal("wrong object ID accepted")
	}
	f = baseFixture()
	delete(f.bodies["/applications/"+app+"/owners"], "value")
	s = collect(t, f)
	if s.Sources[0].Complete {
		t.Fatal("missing collection treated as empty")
	}
}
