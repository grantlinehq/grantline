package command

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/snapshot"
)

func TestEntraMissingAuthWritesPartialAndAnalyzeExitTwo(t *testing.T) {
	t.Setenv("M4_UNSET_TOKEN", "")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	out := filepath.Join(dir, "snapshot.json")
	body := `schema_version: 1
sources:
  - id: entra-lab
    kind: entra
    tenant_id: 11111111-1111-1111-1111-111111111111
    scope: tenant/11111111-1111-1111-1111-111111111111
    token_env: M4_UNSET_TOKEN
    applications:
      - 22222222-2222-2222-2222-222222222222
`
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"collect", "--config", cfg, "--out", out}, &stdout, &stderr); code != 2 {
		t.Fatalf("collect=%d stderr=%s", code, &stderr)
	}
	s, err := snapshot.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if s.Sources[0].Complete || s.Sources[0].ErrorCode != "credentials_unavailable" {
		t.Fatal("missing authentication treated as success")
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("schema_version: 1\nrequired_sources:\n  - entra-lab\nlimits:\n  max_client_secret_validity: 168h\nrules:\n  IL003:\n    severity: medium\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	reportPath := filepath.Join(dir, "report.json")
	if code := Run([]string{"analyze", "--snapshot", out, "--policy", policy, "--out", reportPath}, &stdout, &stderr); code != 2 {
		t.Fatalf("analyze=%d stderr=%s", code, &stderr)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.RuleResults) != 1 || report.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal("unconfigured rules emitted or missing coverage passed")
	}
	for _, path := range []string{out, reportPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("insecure artifact mode")
		}
	}
}

func TestEntraConfigErrorDoesNotEchoTokenInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nsources: [\n  token: INPUT_SECRET_CANARY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"collect", "--config", path, "--out", filepath.Join(dir, "out.json")}, &stdout, &stderr); code != 2 {
		t.Fatal("invalid config passed")
	}
	if strings.Contains(stderr.String(), "INPUT_SECRET_CANARY") {
		t.Fatal("config diagnostic leaked input")
	}
}
