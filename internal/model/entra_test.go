package model

import (
	"encoding/json"
	"testing"
)

func TestEntraNestedMetadataProjection(t *testing.T) {
	for _, raw := range []string{`[{"resource_app_id":"11111111-1111-1111-1111-111111111111","permission_id":"22222222-2222-2222-2222-222222222222","permission_type":"Role","secretText":"CANARY"}]`, `null`, `[{"resource_app_id":"display-name","permission_id":"22222222-2222-2222-2222-222222222222","permission_type":"Role"}]`} {
		if validateEntraAttribute("requested_permissions", json.RawMessage(raw)) == nil {
			t.Fatal("unknown/sensitive nested metadata accepted")
		}
	}
	for _, tc := range []struct{ key, raw string }{{"owners_count", "null"}, {"owners_count", "-1"}, {"object_id", `"display-name"`}, {"role_enabled", "null"}, {"end_time", `"never"`}} {
		if validateEntraAttribute(tc.key, json.RawMessage(tc.raw)) == nil {
			t.Fatal("invalid typed metadata accepted")
		}
	}
}
