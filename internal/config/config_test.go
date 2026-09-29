package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJenkinsConfigPinnedPathAndStrictFields(t *testing.T) {
	body := `schema_version: 1
sources:
  - id: j
    kind: jenkins
    scope: jenkins/test
    address: http://127.0.0.1:8081
    username_env: JENKINS_USER
    token_env: JENKINS_AUTH
    jobs:
      - path: team/build
        kind: job
        jenkinsfile:
          repository: source
          commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          path: Jenkinsfile
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].Jobs[0].Jenkinsfile.Repository != filepath.Join(dir, "source") {
		t.Fatal("relative repository is not config-relative")
	}
	for _, bad := range []string{strings.Replace(body, "commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "commit: main", 1), strings.Replace(body, "username_env:", "username:", 1), strings.Replace(body, "    jobs:", "    policies: [wrong-provider-field]\n    jobs:", 1)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("invalid Jenkins config accepted")
		}
	}
}

func TestGitHubStrictSourceAndNestedFields(t *testing.T) {
	body := `schema_version: 1
sources:
  - id: gh
    kind: github
    scope: github/demo
    token_env: GITHUB_TEST_TOKEN
    repositories:
      - name: owner/repo
        repository_id: "34"
        refs: [refs/heads/main]
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	for name, input := range map[string]string{
		"valid":                body,
		"wrong provider":       strings.Replace(body, "kind: github", "kind: entra", 1),
		"unknown nested field": strings.Replace(body, "        refs:", "        credential: CONFIG_SECRET_CANARY\n        refs:", 1),
		"foreign field":        strings.Replace(body, "    repositories:", "    kubeconfig_path: /other\n    repositories:", 1),
		"ambiguous ref":        strings.Replace(body, "refs/heads/main", "main", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if name == "valid" {
				if err != nil || len(c.Sources[0].GitHubConfig().Repositories) != 1 {
					t.Fatal("GitHub source was not loaded", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "CONFIG_SECRET_CANARY") {
				t.Fatal("invalid config accepted or leaked")
			}
		})
	}
}
