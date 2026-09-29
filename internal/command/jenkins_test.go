package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/collectors/jenkins"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/snapshot"
)

func TestJenkinsCLICompletenessAndBindings(t *testing.T) {
	t.Setenv("CLI_JENKINS_USER", "observer")
	t.Setenv("CLI_JENKINS_AUTH", "CLI_AUTH_CANARY")
	t.Setenv("CLI_VAULT_AUTH", "CLI_VAULT_CANARY")
	for _, scenario := range []string{"complete", "forbidden", "missing_auth", "dangling_binding", "invalid_binding"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/job/deploy/api/json" {
					if scenario == "forbidden" {
						w.WriteHeader(403)
						fmt.Fprint(w, "DO_NOT_RETAIN_RESPONSE")
						return
					}
					fmt.Fprint(w, `{"_class":"job","fullName":"deploy","buildable":true,"builds":[]}`)
					return
				}
				if r.URL.Path == "/v1/auth/approle/role/deploy" {
					fmt.Fprint(w, `{"data":{"token_policies":[]}}`)
					return
				}
				t.Errorf("unexpected endpoint %s", r.URL.Path)
				w.WriteHeader(404)
			}))
			defer server.Close()
			cfg := config.Config{SchemaVersion: 1, Sources: []config.Source{
				{ID: "j", Kind: "jenkins", Scope: "jenkins/test", Address: server.URL, UsernameEnv: "CLI_JENKINS_USER", TokenEnv: "CLI_JENKINS_AUTH", Jobs: []jenkins.Job{{Path: "deploy", Kind: "job"}}},
				{ID: "v", Kind: "vault", Scope: "vault/test", Address: server.URL, TokenEnv: "CLI_VAULT_AUTH", AuthRoles: []config.VaultAuthRole{{Mount: "approle", Name: "deploy", Type: "approle"}}},
			}}
			if scenario == "missing_auth" {
				cfg.Sources[0].TokenEnv = "UNSET_JENKINS_AUTH_FOR_TEST"
				t.Setenv("UNSET_JENKINS_AUTH_FOR_TEST", "")
			}
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			output := filepath.Join(dir, "snapshot.json")
			data, _ := json.Marshal(cfg)
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"collect", "--config", configPath, "--out", output}
			if scenario == "dangling_binding" || scenario == "invalid_binding" {
				decl := bindings.Config{SchemaVersion: 1, JenkinsVault: []bindings.JenkinsVault{{JenkinsSourceID: "j", VaultSourceID: "v", CredentialNativeID: "deploy/credentials/missing", RoleNativeID: "approle/deploy"}}}
				if scenario == "invalid_binding" {
					decl.JenkinsVault[0].JenkinsSourceID = "unknown"
				}
				path := filepath.Join(dir, "bindings.json")
				data, _ := json.Marshal(decl)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--bindings", path)
			}
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			want := 2
			if scenario == "complete" {
				want = 0
			}
			if code != want {
				t.Fatalf("exit=%d want=%d stderr=%s", code, want, &stderr)
			}
			if scenario == "invalid_binding" {
				if calls != 0 {
					t.Fatal("invalid bindings performed network calls")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("invalid binding wrote snapshot")
				}
				return
			}
			s, err := snapshot.Load(output)
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Sources) != 2 || !s.Sources[1].Complete {
				t.Fatal("Jenkins failure erased Vault coverage")
			}
			data, err = os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			for _, canary := range []string{"CLI_AUTH_CANARY", "CLI_VAULT_CANARY", "DO_NOT_RETAIN_RESPONSE"} {
				if strings.Contains(string(data)+stderr.String(), canary) {
					t.Fatal("credential/body leaked")
				}
			}
			policyPath := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(policyPath, []byte("schema_version: 1\nrequired_sources:\n  - j\n  - v\nrules:\n  IL001:\n    severity: medium\n    allowed_grants:\n"), 0600); err != nil {
				t.Fatal(err)
			}
			stderr.Reset()
			code = Run([]string{"analyze", "--snapshot", output, "--policy", policyPath, "--out", filepath.Join(dir, "report.json")}, &stdout, &stderr)
			if code != want {
				t.Fatalf("analyze exit=%d want=%d stderr=%s", code, want, &stderr)
			}
		})
	}
}
