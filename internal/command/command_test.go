package command

import (
	"bytes"
	"github.com/grantlinehq/grantline/internal/snapshot"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"version"}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %s", exitCode, stderr.String())
	}
	if stdout.String() != "grantline v0.1.0-dev\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestGitHubMissingCredentialWritesValidPartialSnapshot(t *testing.T) {
	t.Setenv("GRANTLINE_GITHUB_TEST_MISSING", "")
	dir := t.TempDir()
	configPath, out := filepath.Join(dir, "config.json"), filepath.Join(dir, "snapshot.json")
	body := `{"schema_version":1,"sources":[{"id":"gh","kind":"github","scope":"github/test","token_env":"GRANTLINE_GITHUB_TEST_MISSING","repositories":[{"name":"owner/repo","repository_id":"34","refs":["refs/heads/main"]}]}]}`
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"collect", "--config", configPath, "--out", out}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit=%d", code)
	}
	s, err := snapshot.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entities) != 0 || s.Sources[0].Complete || s.Sources[0].ErrorCode != "credentials_unavailable" {
		t.Fatal("missing GitHub credential fabricated successful coverage")
	}
}

func TestCollectRequiresConfigAndOutput(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"collect"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "--config and --out are required") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestServeRequiresReportBeforeListening(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"serve"}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "serve requires --report") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestAnalyzeWritesReportAndHonorsThreshold(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "synthetic")
	reportPath := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{
		"analyze",
		"--snapshot", filepath.Join(root, "wildcard-rbac.snapshot.json"),
		"--policy", filepath.Join(root, "grantline.policy.yaml"),
		"--out", reportPath,
		"--fail-on", "medium",
	}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %s", exitCode, stderr.String())
	}

	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(report), "synthetic_fixture") {
		t.Fatal("report must identify synthetic fixture provenance")
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestAnalyzeMalformedSnapshotReturnsConfigurationError(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "synthetic")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{
		"analyze",
		"--snapshot", filepath.Join(root, "malformed-evidence.snapshot.json"),
		"--policy", filepath.Join(root, "grantline.policy.yaml"),
		"--out", filepath.Join(t.TempDir(), "report.json"),
	}, &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "invalid snapshot") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}
