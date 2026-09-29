package policy

import (
	"strings"
	"testing"
	"time"
)

const entraPolicy = `schema_version: 1
required_sources:
  - entra-lab
limits:
  max_client_secret_validity: 168h
rules:
  IL003:
    severity: medium
  IL004:
    severity: low
    require_owners_for:
      - source_id: entra-lab
        object_id: 22222222-2222-2222-2222-222222222222
        object_kind: application_registration
  IL005:
    severity: medium
    allowed_app_roles:
      - source_id: entra-lab
        principal_object_id: 33333333-3333-3333-3333-333333333333
        resource_object_id: 44444444-4444-4444-4444-444444444444
        app_role_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
`

func TestEntraPolicyExactFields(t *testing.T) {
	p, err := Parse([]byte(entraPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxClientSecretValidity != 168*time.Hour || len(p.Rules) != 3 || len(p.Rules["IL004"].RequireOwnersFor) != 1 || len(p.Rules["IL005"].AllowedAppRoles) != 1 {
		t.Fatal("policy shape incorrect")
	}
	for _, bad := range []string{
		strings.Replace(entraPolicy, "168h", "0h", 1),
		strings.Replace(entraPolicy, "limits:\n  max_client_secret_validity: 168h\n", "", 1),
		strings.Replace(entraPolicy, "    allowed_app_roles:", "    allowed_grants:", 1),
		strings.Replace(entraPolicy, "object_kind: application_registration", "object_kind: owner", 1),
		strings.Replace(entraPolicy, "principal_object_id: 33333333-3333-3333-3333-333333333333", "principal_object_id: display-name", 1),
		strings.Replace(entraPolicy, "  max_client_secret_validity: 168h", "  max_client_secret_validity: 168h\n  max_client_secret_validity: 20h", 1),
		strings.Replace(entraPolicy, "        resource_object_id:", "        unexpected_field:", 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("invalid Entra policy accepted")
		}
	}
}
