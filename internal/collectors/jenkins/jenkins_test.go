package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

func TestLiteralReferences(t *testing.T) {
	cases := []struct {
		name, source string
		ids          []string
		unresolved   bool
	}{
		{"declarative", `pipeline { environment { A = credentials('store/dev'); B = credentials("prod-id") } }`, []string{"store/dev", "prod-id"}, false},
		{"bindings", `withCredentials([string(credentialsId: 'a', variable: 'V'), usernamePassword(usernameVariable:'U', credentialsId: "b", passwordVariable:'P'), file(credentialsId:'c', variable:'F'), sshUserPrivateKey(credentialsId:'d', keyFileVariable:'K'), certificate(credentialsId:'e', keystoreVariable:'E'), usernameColonPassword(credentialsId:'f', variable:'F'),]) { sh 'true' }`, []string{"a", "b", "c", "d", "e", "f"}, false},
		{"opaque", "// credentials('comment')\n/* withCredentials([string(credentialsId:'comment')]) */\nsh ''' credentials('shell') '''; echo \"credentials('text')\"", nil, false},
		{"dynamic", `credentials(prefix + '-id'); withCredentials([string(credentialsId: dynamic, variable:'V')])`, nil, true},
		{"interpolated", `credentials("${name}")`, nil, true},
		{"gstring expression", `echo "${credentials('hidden')}"`, nil, true},
		{"shared library", `@Library('shared') _; credentials('visible')`, []string{"visible"}, true},
		{"loaded", `load 'other.groovy'`, nil, true},
		{"unknown binding", `withCredentials([custom(credentialsId:'id')]){}`, nil, true},
		{"multiple IDs", `withCredentials([string(credentialsId:'a', credentialsId:'b')]){}`, nil, true},
		{"nested false match", `withCredentials([string(credentialsId: helper('x'), variable: 'V')]){}`, nil, true},
		{"unterminated", `credentials('a`, nil, true},
		{"unbalanced", `node { credentials('a')`, nil, true},
		{"slashy", `def x = /credentials('fake')/`, nil, true},
		{"qualified", `helper.credentials('not-step')`, nil, true},
		{"quoted method", `"credentials"('hidden')`, nil, true},
		{"literal escapes unsupported", `credentials('escaped\u002did')`, nil, true},
		{"benign", `node { stage('build') { echo 'hello' } }`, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseJenkinsfile([]byte(tc.source))
			var ids []string
			for _, ref := range result.References {
				ids = append(ids, ref.ID)
				if ref.Line < 1 {
					t.Fatal("missing line evidence")
				}
			}
			if !reflect.DeepEqual(ids, tc.ids) || result.Unresolved != tc.unresolved {
				t.Fatalf("got %+v; expected ids=%v unresolved=%v", result, tc.ids, tc.unresolved)
			}
		})
	}
}

func pinnedFile(t *testing.T, content string) Jenkinsfile {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Jenkinsfile"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", dir}, args...)...)
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git fixture: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "Jenkinsfile")
	git("-c", "user.name=Grantline Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
	return Jenkinsfile{Repository: dir, Commit: git("rev-parse", "HEAD"), Path: "Jenkinsfile"}
}

func TestPinnedGitIsReadOnlyAndBounded(t *testing.T) {
	file := pinnedFile(t, `credentials('pinned')`)
	if err := os.WriteFile(filepath.Join(file.Repository, file.Path), []byte(`credentials('working-copy')`), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readPinnedFile(context.Background(), file)
	if err != nil || string(data) != `credentials('pinned')` {
		t.Fatalf("not pinned: %v", err)
	}
	file.Commit = strings.Repeat("0", 40)
	if _, err := readPinnedFile(context.Background(), file); err == nil {
		t.Fatal("missing commit accepted")
	}
	file = pinnedFile(t, strings.Repeat("x", maxJenkinsfileBytes+1))
	if _, err := readPinnedFile(context.Background(), file); err == nil {
		t.Fatal("oversize blob accepted")
	}
	file.Path = "missing"
	if _, err := readPinnedFile(context.Background(), file); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestPinnedGitRejectsPromisorAndSymlink(t *testing.T) {
	file := pinnedFile(t, `credentials('literal')`)
	if err := exec.Command("git", "-C", file.Repository, "config", "remote.origin.promisor", "true").Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := readPinnedFile(context.Background(), file); err == nil {
		t.Fatal("promisor repository accepted")
	}
	file = pinnedFile(t, `credentials('literal')`)
	if err := os.Symlink("Jenkinsfile", filepath.Join(file.Repository, "link")); err != nil {
		t.Skip("symlink unavailable")
	}
	if err := exec.Command("git", "-C", file.Repository, "add", "link").Run(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "-C", file.Repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "link fixture").Run(); err != nil {
		t.Fatal(err)
	}
	commit, err := exec.Command("git", "-C", file.Repository, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	file.Commit = strings.TrimSpace(string(commit))
	file.Path = "link"
	if _, err := readPinnedFile(context.Background(), file); err == nil {
		t.Fatal("symlink accepted as Jenkinsfile")
	}
}

func testConfig(t *testing.T, address string) Config {
	t.Helper()
	t.Setenv("JENKINS_TEST_USER", "observer")
	t.Setenv("JENKINS_TEST_AUTH", "AUTH_CANARY_NEVER_RETAIN")
	return Config{ID: "jenkins-test", Address: address, UsernameEnv: "JENKINS_TEST_USER", TokenEnv: "JENKINS_TEST_AUTH", Scope: "jenkins/test", BuildLimit: 2, Jobs: []Job{{Path: "team/job one", Kind: "job"}}}
}

const jobJSON = `{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","fullName":"team/job one","buildable":true,"builds":[{"number":12,"result":"SUCCESS","building":false,"timestamp":1234,"duration":56}],"description":"BODY_CANARY_NEVER_RETAIN","actions":[{"password":"BODY_CANARY_NEVER_RETAIN"}]}`

func TestCollectorProjectionAndEvidence(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "observer" || pass != "AUTH_CANARY_NEVER_RETAIN" {
			t.Error("missing observer auth")
		}
		if r.Method != "GET" || r.URL.Path != "/context/job/team/job/job one/api/json" {
			t.Errorf("unexpected endpoint %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("tree") != "_class,fullName,buildable,builds[number,result,building,timestamp,duration]{0,2}" || len(r.URL.Query()) != 1 {
			t.Error("unbounded/unexpected query")
		}
		requests = append(requests, r.URL.Path)
		fmt.Fprint(w, jobJSON)
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL+"/context")
	file := pinnedFile(t, "// SOURCE_CANARY_NEVER_RETAIN\ncredentials('same-id');\nwithCredentials([string(credentialsId:'same-id', variable:'V')]) {}")
	cfg.Jobs[0].Jenkinsfile = &file
	snapshot, err := (Collector{Config: cfg, Now: func() time.Time { return time.Unix(100, 0) }}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || len(snapshot.Entities) != 2 || len(snapshot.Relationships) != 1 || !snapshot.Sources[0].Complete {
		t.Fatalf("unexpected snapshot shape: %+v", snapshot.Sources)
	}
	for _, edge := range snapshot.Relationships {
		if edge.AssertionKind != model.AssertionDeclared || len(edge.EvidenceIDs) != 4 {
			t.Fatal("file association must remain declared with line/API/declaration evidence")
		}
	}
	for _, entity := range snapshot.Entities {
		if entity.Kind == "credential_reference" && (entity.NativeID != CredentialNativeID(cfg.Jobs[0].Path, "same-id") || entity.Provenance != model.ProvenanceProviderExport) {
			t.Fatal("reference identity/provenance incorrect")
		}
	}
	encoded, _ := json.Marshal(snapshot)
	for _, canary := range []string{"AUTH_CANARY_NEVER_RETAIN", "BODY_CANARY_NEVER_RETAIN", "SOURCE_CANARY_NEVER_RETAIN", file.Repository} {
		if strings.Contains(string(encoded), canary) {
			t.Fatal("private input leaked")
		}
	}
}

func TestCollectorPartialResponses(t *testing.T) {
	cases := []struct {
		name, body, code string
		status           int
		entities         int
	}{
		{"forbidden", "BODY_CANARY_NEVER_RETAIN", "HTTP_403", 403, 0},
		{"unauthorized", "BODY_CANARY_NEVER_RETAIN", "HTTP_401", 401, 0},
		{"missing", "BODY_CANARY_NEVER_RETAIN", "HTTP_404", 404, 0},
		{"malformed", "{BODY_CANARY_NEVER_RETAIN", "invalid_metadata_json", 200, 0},
		{"missing fields", `{"_class":"job","fullName":"team/job one"}`, "incomplete_build_metadata", 200, 1},
		{"wrong identity", strings.Replace(jobJSON, "team/job one", "some-other-job", 1), "unexpected_item_identity", 200, 0},
		{"unknown result", strings.Replace(jobJSON, "SUCCESS", "BODY_CANARY_NEVER_RETAIN", 1), "incomplete_build_metadata", 200, 1},
		{"oversized", strings.Repeat("x", maxResponseBytes+1), "response_too_large", 200, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			snapshot, err := (Collector{Config: testConfig(t, server.URL)}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			s := snapshot.Sources[0]
			if s.Complete || s.PaginationComplete || s.Status != model.SourcePartial || s.ErrorCode != tc.code || len(snapshot.Entities) != tc.entities {
				t.Fatalf("wrong coverage: %+v", s)
			}
			encoded, _ := json.Marshal(snapshot)
			if strings.Contains(string(encoded), "BODY_CANARY_NEVER_RETAIN") {
				t.Fatal("response leaked")
			}
		})
	}
}

func TestRetryRedirectAndCancellation(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls < 3 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					return
				}
				fmt.Fprint(w, jobJSON)
			}))
			defer server.Close()
			snapshot, err := (Collector{Config: testConfig(t, server.URL)}).Collect(context.Background())
			if err != nil || !snapshot.Sources[0].Complete || calls != 3 {
				t.Fatalf("retry failure: %v calls %d", err, calls)
			}
		})
	}
	t.Run("bounded retry after", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Retry-After", "99999")
			w.WriteHeader(429)
		}))
		defer server.Close()
		snapshot, err := (Collector{Config: testConfig(t, server.URL)}).Collect(context.Background())
		if err != nil || calls != 1 || snapshot.Sources[0].ErrorCode != "rate_limited" {
			t.Fatal("unbounded Retry-After")
		}
	})
	t.Run("no redirect credential forwarding", func(t *testing.T) {
		followed := false
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
		defer dest.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 302) }))
		defer server.Close()
		snapshot, err := (Collector{Config: testConfig(t, server.URL), Client: &http.Client{}}).Collect(context.Background())
		if err != nil || followed || snapshot.Sources[0].ErrorCode != "HTTP_302" {
			t.Fatal("redirect not blocked")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snapshot, err := (Collector{Config: testConfig(t, "http://127.0.0.1:1")}).Collect(ctx)
		if err != nil || snapshot.Sources[0].Complete {
			t.Fatal("cancelled collection succeeded")
		}
	})
}

func TestFolderNoRecursionAndDynamicCoverage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/job/team/api/json" {
			if r.URL.Query().Get("tree") != "_class,fullName" {
				t.Error("folder enumeration")
			}
			fmt.Fprint(w, `{"_class":"com.cloudbees.hudson.plugins.folder.Folder","fullName":"team","jobs":[{"name":"never-follow"}]}`)
			return
		}
		if r.URL.Path != "/job/team/job/job one/api/json" {
			t.Error("out of scope request")
		}
		fmt.Fprint(w, jobJSON)
	}))
	defer server.Close()
	cfg := testConfig(t, server.URL)
	file := pinnedFile(t, `credentials('visible'); credentials(dynamic)`)
	cfg.Jobs[0].Jenkinsfile = &file
	cfg.Jobs = append(cfg.Jobs, Job{Path: "team", Kind: "folder"})
	snapshot, err := (Collector{Config: cfg}).Collect(context.Background())
	if err != nil || snapshot.Sources[0].Complete || !snapshot.Sources[0].PaginationComplete || len(snapshot.Entities) != 3 || snapshot.Sources[0].ErrorCode != "unresolved_jenkinsfile" {
		t.Fatalf("wrong partial static coverage: %v %+v", err, snapshot.Sources)
	}
	if CredentialNativeID("team/a", "same") == CredentialNativeID("team/b", "same") {
		t.Fatal("job-scoped references merged")
	}
}

func TestConfigBounds(t *testing.T) {
	valid := testConfig(t, "http://127.0.0.1:8081")
	for _, path := range []string{"../job", "a//b", "a/*", "a/..", "a?query", "a%2fb", strings.Repeat("a/", MaxDepth) + "b"} {
		cfg := valid
		cfg.Jobs = []Job{{Path: path, Kind: "job"}}
		if cfg.Validate() == nil {
			t.Errorf("accepted path %q", path)
		}
	}
	for _, address := range []string{"http://remote.example", "https://user:pass@example.com", "https://example.com?q=1", "https://example.com/#frag"} {
		cfg := valid
		cfg.Address = address
		if cfg.Validate() == nil {
			t.Errorf("accepted address %q", address)
		}
	}
	cfg := valid
	cfg.BuildLimit = MaxBuilds + 1
	if cfg.Validate() == nil {
		t.Fatal("unbounded builds")
	}
	cfg = valid
	cfg.Jobs = append(append([]Job{}, cfg.Jobs...), cfg.Jobs[0])
	if cfg.Validate() == nil {
		t.Fatal("duplicate jobs")
	}
}
