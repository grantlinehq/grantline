package policy

import (
	"strings"
	"testing"
)

const environmentPolicy = `schema_version: 1
required_sources:
  - k8s-lab
rules:
  IL008:
    severity: medium
    separated_environments:
      - first: dev
        second: prod
    allowed_shared_identities:
      - source_id: k8s-lab
        kind: service_account
        native_id: exact-uid
        first: dev
        second: prod
        reason: Reviewed shared service
`

func TestEnvironmentPolicyStrictParsing(t *testing.T) {
	p, err := Parse([]byte(environmentPolicy))
	if err != nil || len(p.Rules["IL008"].AllowedSharedIdentities) != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(environmentPolicy, "kind: service_account", "kind: credential_reference", 1), strings.Replace(environmentPolicy, "reason: Reviewed shared service", "reason: \"\"", 1), strings.Replace(environmentPolicy, "second: prod", "second: dev", 1), strings.Replace(environmentPolicy, "native_id:", "display_name:", 1), strings.Replace(environmentPolicy, "IL008:", "IL007:", 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("invalid environment policy accepted")
		}
	}
}
