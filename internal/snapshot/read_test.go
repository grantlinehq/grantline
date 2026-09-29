package snapshot

import "testing"

func TestLoadRejectsMalformedEvidenceReference(t *testing.T) {
	t.Parallel()

	_, err := Load("../../testdata/synthetic/malformed-evidence.snapshot.json")
	if err == nil {
		t.Fatal("expected malformed fixture to be rejected")
	}
}
