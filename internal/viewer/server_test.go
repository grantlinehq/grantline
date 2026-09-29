package viewer

import (
	"encoding/json"
	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"github.com/grantlinehq/grantline/internal/snapshot"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reportFixture(t *testing.T) model.Report {
	t.Helper()
	s, err := snapshot.Load("../../testdata/synthetic/wildcard-rbac.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load("../../testdata/synthetic/grantline.policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r, err := analyze.Analyze(s, p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestViewerSessionAndRequestBoundaries(t *testing.T) {
	r := reportFixture(t)
	token, _ := Token()
	h, err := New(r, "127.0.0.1:8080", token)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, host, origin, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
		q.Host = host
		if origin != "" {
			q.Header.Set("Origin", origin)
		}
		if method == "POST" {
			q.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			q.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, q)
		return w
	}
	for _, path := range []string{"/api/report", "/api/report/download", "/api/graph?entity=x"} {
		w := request("GET", path, "127.0.0.1:8080", "", "", nil)
		if w.Code != 401 || strings.Contains(w.Body.String(), "k8s-lab") {
			t.Fatal("unauthenticated data exposed")
		}
	}
	for _, host := range []string{"localhost:8080", "example.invalid:8080", "127.0.0.1:9000"} {
		if request("GET", "/", host, "", "", nil).Code != 403 {
			t.Fatal("unexpected host accepted")
		}
	}
	for _, origin := range []string{"", "http://example.invalid", "null"} {
		if request("POST", "/api/session", "127.0.0.1:8080", origin, `{"token":"`+token+`"}`, nil).Code != 403 {
			t.Fatal("unexpected origin accepted")
		}
	}
	w := request("POST", "/api/session", "127.0.0.1:8080", "http://127.0.0.1:8080", `{"token":"`+token+`"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("session attributes missing")
	}
	cookie := cookies[0]
	w = request("GET", "/api/report", "127.0.0.1:8080", "", "", cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("authenticated report unavailable or uncached policy missing")
	}
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("access code entered report")
	}
	if request("GET", "/?token=unused", "127.0.0.1:8080", "", "", cookie).Code != 400 {
		t.Fatal("query-based access accepted")
	}
	if request("POST", "/api/logout", "127.0.0.1:8080", "http://127.0.0.1:8080", "", cookie).Code != 204 || request("GET", "/api/report", "127.0.0.1:8080", "", "", cookie).Code != 401 {
		t.Fatal("logout did not revoke session")
	}
	w = request("GET", "/", "127.0.0.1:8080", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/assets/") {
		t.Fatal("embedded assets unavailable")
	}
	if request("GET", "/assets/", "127.0.0.1:8080", "", "", nil).Code == 200 {
		t.Fatal("asset directory listing exposed")
	}
}
func TestViewerRejectsInvalidReports(t *testing.T) {
	r := reportFixture(t)
	data, _ := json.Marshal(r)
	if _, err := Parse(data); err != nil {
		t.Fatal(err)
	}
	r.Findings[0].AffectedEntityIDs = []string{"missing"}
	if Validate(r) == nil {
		t.Fatal("dangling finding accepted")
	}
	r = reportFixture(t)
	r.Snapshot = nil
	if Validate(r) == nil {
		t.Fatal("legacy report accepted without inventory")
	}
	if _, err := Parse(append(data, []byte(" {}")...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	for _, addr := range []string{"0.0.0.0:8080", "localhost:8080", "127.0.0.1:0", "[::]:8080"} {
		if Address(addr) == nil {
			t.Fatal("non-loopback address accepted")
		}
	}
}
func TestGraphHasDeterministicCapAndValidEndpoints(t *testing.T) {
	r := reportFixture(t)
	s := r.Snapshot
	root := s.Entities[0]
	s.Relationships = nil
	for i := 0; i < 90; i++ {
		e := root
		e.NativeID = fmt.Sprintf("graph-node-%d", i)
		e.ID = model.EntityID(e.SourceID, e.Kind, e.NativeID)
		s.Entities = append(s.Entities, e)
		s.Relationships = append(s.Relationships, model.Relationship{ID: fmt.Sprintf("edge-%03d", i), From: root.ID, To: e.ID, Type: "bound_to", AssertionKind: model.AssertionDeclared})
	}
	g := Graph(s, root.ID, "", "", 1)
	if len(g.Nodes) != 75 || !g.Truncated || len(g.Edges) != 74 {
		t.Fatalf("cap: %+v", g)
	}
	ids := map[string]bool{}
	for _, e := range g.Nodes {
		ids[e.ID] = true
	}
	for _, e := range g.Edges {
		if !ids[e.From] || !ids[e.To] {
			t.Fatal("dangling graph edge")
		}
	}
	filtered := Graph(s, root.ID, "observed", "", 1)
	if len(filtered.Nodes) != 1 || len(filtered.Edges) != 0 || filtered.Truncated {
		t.Fatal("assertion filter ignored")
	}
}
