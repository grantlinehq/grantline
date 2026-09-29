package bindings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grantlinehq/grantline/internal/config"
)

func TestBindingInputValidation(t *testing.T) {
	sources := []config.Source{{ID: "j", Kind: "jenkins"}, {ID: "v", Kind: "vault"}}
	valid := "schema_version: 1\njenkins_vault:\n  - jenkins_source_id: j\n    credential_native_id: team/job/credentials/id\n    vault_source_id: v\n    role_native_id: approle/deploy\n"
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"valid", valid, true},
		{"wrong version", strings.Replace(valid, "schema_version: 1", "schema_version: 2", 1), false},
		{"wrong source kind", strings.Replace(valid, "vault_source_id: v", "vault_source_id: j", 1), false},
		{"unknown field", valid + "    sensitive_unknown_field: INPUT_CANARY\n", false},
		{"duplicate key", valid + "    role_native_id: duplicate\n", false},
		{"missing native ID", strings.Replace(valid, "    role_native_id: approle/deploy\n", "", 1), false},
		{"oversized", strings.Repeat("x", (1<<20)+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bindings.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path, sources)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected result %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "INPUT_CANARY") {
				t.Fatal("input leaked")
			}
		})
	}
	d := JenkinsVault{JenkinsSourceID: "j", VaultSourceID: "v", CredentialNativeID: "job/credentials/id", RoleNativeID: "approle/deploy"}
	if (Config{SchemaVersion: 1, JenkinsVault: []JenkinsVault{d, d}}).Validate(sources) == nil {
		t.Fatal("duplicate accepted")
	}
}
