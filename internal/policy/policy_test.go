package policy

import "testing"

func TestParseStrictM0Policy(t *testing.T) {
	t.Parallel()

	input, err := Load("../../testdata/synthetic/grantline.policy.yaml")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if input.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", input.SchemaVersion)
	}
	if len(input.RequiredSources) != 1 || input.RequiredSources[0] != "k8s-lab" {
		t.Fatalf("unexpected required sources: %#v", input.RequiredSources)
	}
	if input.Rules["IL001"].Severity != "medium" {
		t.Fatalf("IL001 severity = %q, want medium", input.Rules["IL001"].Severity)
	}
}

func TestParseRejectsUnsupportedRule(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte("schema_version: 1\nrequired_sources:\n  - k8s-lab\nrules:\n  IL999:\n    severity: medium\n"))
	if err == nil {
		t.Fatal("expected unsupported rule to be rejected")
	}
}
