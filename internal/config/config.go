package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/grantlinehq/grantline/internal/collectors/entra"
	"github.com/grantlinehq/grantline/internal/collectors/github"
	"github.com/grantlinehq/grantline/internal/collectors/jenkins"
	"github.com/grantlinehq/grantline/internal/collectors/spire"

	"sigs.k8s.io/yaml"
)

const SchemaVersion = 1

type Config struct {
	SchemaVersion int      `json:"schema_version"`
	Sources       []Source `json:"sources"`
}

type Source struct {
	Spire              *spire.Options      `json:"spire"`
	Repositories       []github.Repository `json:"repositories"`
	ID                 string              `json:"id"`
	Kind               string              `json:"kind"`
	Scope              string              `json:"scope"`
	KubeconfigPath     string              `json:"kubeconfig_path"`
	Context            string              `json:"context"`
	Address            string              `json:"address"`
	TokenEnv           string              `json:"token_env"`
	AuthRoles          []VaultAuthRole     `json:"auth_roles"`
	Policies           []string            `json:"policies"`
	KubernetesSourceID string              `json:"kubernetes_source_id"`
	UsernameEnv        string              `json:"username_env"`
	BuildLimit         int                 `json:"build_limit"`
	Jobs               []jenkins.Job       `json:"jobs"`
	TenantID           string              `json:"tenant_id"`
	Applications       []string            `json:"applications"`
	ServicePrincipals  []string            `json:"service_principals"`
}

type VaultAuthRole struct {
	Mount string `json:"mount"`
	Name  string `json:"name"`
	Type  string `json:"type"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return Config{}, fmt.Errorf("config unreadable or exceeds 1 MiB limit")
	}
	var config Config
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse config: invalid strict YAML schema")
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	for i := range config.Sources {
		if options := config.Sources[i].Spire; options != nil {
			for _, value := range []*string{&options.ExportPath, &options.WorkloadEvidencePath} {
				if *value != "" && !filepath.IsAbs(*value) {
					*value = filepath.Join(filepath.Dir(path), *value)
				}
			}
		}
		for j := range config.Sources[i].Jobs {
			file := config.Sources[i].Jobs[j].Jenkinsfile
			if file != nil && !filepath.IsAbs(file.Repository) {
				file.Repository = filepath.Join(filepath.Dir(path), file.Repository)
			}
		}
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if len(config.Sources) == 0 {
		return fmt.Errorf("at least one source is required")
	}
	seenIDs := make(map[string]struct{}, len(config.Sources))
	kubernetesSources := make(map[string]struct{})
	for _, source := range config.Sources {
		if err := source.Validate(); err != nil {
			return err
		}
		if _, exists := seenIDs[source.ID]; exists {
			return fmt.Errorf("source id %q is duplicated", source.ID)
		}
		seenIDs[source.ID] = struct{}{}
		if source.Kind == "kubernetes" {
			kubernetesSources[source.ID] = struct{}{}
		}
	}
	for _, source := range config.Sources {
		if source.Kind == "vault" && source.KubernetesSourceID != "" {
			if _, exists := kubernetesSources[source.KubernetesSourceID]; !exists {
				return fmt.Errorf("Vault source %q references unknown kubernetes_source_id %q", source.ID, source.KubernetesSourceID)
			}
		}
	}
	return nil
}

func (source Source) Validate() error {
	if source.Kind != "spire" && source.Spire != nil {
		return fmt.Errorf("SPIRE fields require a SPIRE source")
	}
	if source.ID == "" || source.Kind == "" || source.Scope == "" {
		return fmt.Errorf("source id, kind, and scope are required")
	}
	if strings.ContainsAny(source.ID, " \t\n") {
		return fmt.Errorf("source id cannot contain whitespace")
	}
	if source.Kind != "jenkins" && (source.UsernameEnv != "" || source.BuildLimit != 0 || len(source.Jobs) != 0) {
		return fmt.Errorf("Jenkins fields require a Jenkins source")
	}
	if source.Kind != "entra" && (source.TenantID != "" || len(source.Applications) != 0 || len(source.ServicePrincipals) != 0) {
		return fmt.Errorf("Entra fields require an Entra source")
	}
	if source.Kind != "github" && len(source.Repositories) != 0 {
		return fmt.Errorf("GitHub fields require a GitHub source")
	}
	switch source.Kind {
	case "spire":
		if source.Spire == nil || source.KubeconfigPath != "" || source.Context != "" || source.Address != "" || source.TokenEnv != "" || len(source.AuthRoles) != 0 || len(source.Policies) != 0 || source.KubernetesSourceID != "" {
			return fmt.Errorf("SPIRE source requires spire options and no foreign provider fields")
		}
		return source.SpireConfig().Validate()
	case "github":
		if source.KubeconfigPath != "" || source.Context != "" || len(source.AuthRoles) != 0 || len(source.Policies) != 0 || source.KubernetesSourceID != "" {
			return fmt.Errorf("GitHub source contains fields for another provider")
		}
		return source.GitHubConfig().Validate()
	case "entra":
		if source.KubeconfigPath != "" || source.Context != "" || len(source.AuthRoles) != 0 || len(source.Policies) != 0 || source.KubernetesSourceID != "" {
			return fmt.Errorf("Entra source contains fields for another provider")
		}
		return source.EntraConfig().Validate()
	case "jenkins":
		if source.KubeconfigPath != "" || source.Context != "" || len(source.AuthRoles) != 0 || len(source.Policies) != 0 || source.KubernetesSourceID != "" {
			return fmt.Errorf("Jenkins source contains fields for another provider")
		}
		return source.JenkinsConfig().Validate()
	case "kubernetes":
		if source.KubeconfigPath == "" || !strings.HasPrefix(source.Scope, "cluster/") {
			return fmt.Errorf("Kubernetes source %q requires kubeconfig_path and cluster scope", source.ID)
		}
	case "vault":
		if source.Address == "" || source.TokenEnv == "" || !strings.HasPrefix(source.Scope, "vault/") {
			return fmt.Errorf("Vault source %q requires address, token_env, and vault scope", source.ID)
		}
		for _, role := range source.AuthRoles {
			if role.Mount == "" || role.Name == "" || (role.Type != "approle" && role.Type != "kubernetes") {
				return fmt.Errorf("Vault source %q has an invalid auth_roles entry", source.ID)
			}
		}
	default:
		return fmt.Errorf("source %q kind %q is not supported", source.ID, source.Kind)
	}
	return nil
}

func (source Source) JenkinsConfig() jenkins.Config {
	return jenkins.Config{ID: source.ID, Address: source.Address, UsernameEnv: source.UsernameEnv, TokenEnv: source.TokenEnv, Scope: source.Scope, BuildLimit: source.BuildLimit, Jobs: source.Jobs}
}

func (source Source) EntraConfig() entra.Config {
	return entra.Config{ID: source.ID, Scope: source.Scope, TenantID: source.TenantID, Address: source.Address, TokenEnv: source.TokenEnv, Applications: source.Applications, ServicePrincipals: source.ServicePrincipals}
}

func (source Source) GitHubConfig() github.Config {
	return github.Config{ID: source.ID, Scope: source.Scope, Address: source.Address, TokenEnv: source.TokenEnv, Repositories: source.Repositories}
}

func (source Source) SpireConfig() spire.Config {
	c := spire.Config{ID: source.ID, Scope: source.Scope}
	if source.Spire != nil {
		c.Options = *source.Spire
	}
	return c
}
