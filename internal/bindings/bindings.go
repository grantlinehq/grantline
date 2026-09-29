// Package bindings reads explicit declarations separately from provider access
// configuration and risk policy. It never discovers connections by display name.
package bindings

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/grantlinehq/grantline/internal/config"
	"sigs.k8s.io/yaml"
)

type Config struct {
	VaultKubernetes []VaultKubernetes `json:"vault_kubernetes"`
	Applications    []Application     `json:"applications"`
	SpireKubernetes []SpireKubernetes `json:"spire_kubernetes"`
	SchemaVersion   int               `json:"schema_version"`
	JenkinsVault    []JenkinsVault    `json:"jenkins_vault"`
}

type VaultKubernetes struct {
	VaultSourceID      string `json:"vault_source_id"`
	Mount              string `json:"mount"`
	KubernetesSourceID string `json:"kubernetes_source_id"`
}

type JenkinsVault struct {
	JenkinsSourceID    string `json:"jenkins_source_id"`
	CredentialNativeID string `json:"credential_native_id"`
	VaultSourceID      string `json:"vault_source_id"`
	RoleNativeID       string `json:"role_native_id"`
}

func Load(path string, sources []config.Source) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("bindings file unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return Config{}, fmt.Errorf("bindings file unreadable or exceeds size limit")
	}
	var result Config
	// Parser diagnostics may include input. Never echo declaration contents.
	if yaml.UnmarshalStrict(data, &result) != nil {
		return Config{}, fmt.Errorf("bindings must use the documented strict YAML schema")
	}
	return result, result.Validate(sources)
}

func (c Config) Validate(sources []config.Source) error {
	if c.SchemaVersion != 1 || len(c.JenkinsVault) > 1000 {
		return fmt.Errorf("bindings require schema_version 1 and at most 1000 declarations")
	}
	kinds := map[string]string{}
	for _, source := range sources {
		kinds[source.ID] = source.Kind
	}
	if err := c.validateContexts(kinds); err != nil {
		return err
	}
	seen := map[JenkinsVault]bool{}
	for i, item := range c.JenkinsVault {
		if kinds[item.JenkinsSourceID] != "jenkins" || kinds[item.VaultSourceID] != "vault" {
			return fmt.Errorf("binding %d references an unknown or wrong-kind source", i+1)
		}
		if item.CredentialNativeID == "" || item.RoleNativeID == "" || strings.ContainsAny(item.CredentialNativeID+item.RoleNativeID, "\r\n\x00") {
			return fmt.Errorf("binding %d requires explicit native IDs", i+1)
		}
		if seen[item] {
			return fmt.Errorf("binding %d is duplicated", i+1)
		}
		seen[item] = true
	}
	return nil
}
