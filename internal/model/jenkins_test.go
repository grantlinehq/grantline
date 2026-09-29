package model

import (
	"encoding/json"
	"testing"
)

func TestJenkinsMetadataRejectsArbitraryNestedFields(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		ok         bool
	}{
		{"builds", `[]`, true},
		{"builds", `[{"number":1,"result":"SUCCESS","building":false,"timestamp":1,"duration":2}]`, true},
		{"builds", `[{"number":1,"result":null,"building":true,"timestamp":1,"duration":0}]`, true},
		{"builds", `[{"number":1,"result":"SUCCESS","building":false,"timestamp":1,"duration":2,"parameters":{"password":"CANARY"}}]`, false},
		{"builds", `[{"number":1,"result":"CANARY","building":false,"timestamp":1,"duration":2}]`, false},
		{"builds", `null`, false},
		{"builds", `[{"number":1}]`, false},
		{"buildable", `null`, false},
		{"credential_reference_count", `-1`, false},
		{"jenkinsfile_commit", `"main"`, false},
	} {
		if err := validateJobAttribute(tc.key, json.RawMessage(tc.value)); (err == nil) != tc.ok {
			t.Errorf("%s: valid=%v err=%v", tc.key, tc.ok, err)
		}
	}
}
