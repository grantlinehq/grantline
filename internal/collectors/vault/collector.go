package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

const maxResponseBytes = 1 << 20

type Config struct {
	ID        string
	Address   string
	TokenEnv  string
	Scope     string
	AuthRoles []AuthRole
	Policies  []string
}

type AuthRole struct {
	Mount string
	Name  string
	Type  string
}

func (config Config) Validate() error {
	if config.ID == "" || config.Address == "" || config.TokenEnv == "" || config.Scope == "" {
		return fmt.Errorf("id, address, token_env, and scope are required")
	}
	parsed, err := url.Parse(config.Address)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return fmt.Errorf("address must be an absolute http or https URL")
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		return fmt.Errorf("http address is allowed only for loopback Vault labs")
	}
	for _, role := range config.AuthRoles {
		if role.Mount == "" || role.Name == "" || (role.Type != "approle" && role.Type != "kubernetes") {
			return fmt.Errorf("each auth role requires mount, name, and type=approle|kubernetes")
		}
	}
	return nil
}

type Collector struct {
	// Credentials are injected per collection by the server; nil preserves CLI environment input.
	Credentials func(string) string
	Config      Config
	Client      *http.Client
	Now         func() time.Time
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if err := collector.Config.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	token := collector.credential(collector.Config.TokenEnv)
	if token == "" {
		return model.Snapshot{}, fmt.Errorf("Vault token environment variable %q is empty", collector.Config.TokenEnv)
	}
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	observed := now().UTC()
	client := collector.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	c := collection{config: collector.Config, client: client, token: token, observed: observed, source: model.Source{ID: collector.Config.ID, Kind: "vault", Scope: collector.Config.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}}
	for _, role := range collector.Config.AuthRoles {
		if err := c.addRole(ctx, role); err != nil {
			c.fail("auth/"+role.Mount+"/role/"+role.Name, err)
		}
	}
	for _, name := range collector.Config.Policies {
		if err := c.addPolicy(ctx, name); err != nil {
			c.fail("sys/policies/acl/"+name, err)
		}
	}
	c.sort()
	return model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: observed, Entities: c.entities, Evidence: c.evidence, Sources: []model.Source{c.source}}, nil
}

type collection struct {
	config   Config
	client   *http.Client
	token    string
	observed time.Time
	source   model.Source
	entities []model.Entity
	evidence []model.Evidence
}
type envelope struct {
	Data json.RawMessage `json:"data"`
}
type roleData struct {
	BoundServiceAccountNames      []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	TokenPolicies                 []string `json:"token_policies"`
}
type policyData struct {
	Name string `json:"name"`
}

func (c *collection) addRole(ctx context.Context, role AuthRole) error {
	var data roleData
	path := "auth/" + role.Mount + "/role/" + role.Name
	if err := c.get(ctx, path, &data); err != nil {
		return err
	}
	attrs := map[string]json.RawMessage{"auth_mount": q(role.Mount), "auth_type": q(role.Type), "policy_names": qa(data.TokenPolicies)}
	status := map[string]model.FieldStatus{"auth_mount": model.FieldKnown, "auth_type": model.FieldKnown, "policy_names": model.FieldKnown}
	if role.Type == "kubernetes" {
		attrs["bound_service_account_names"] = qa(data.BoundServiceAccountNames)
		attrs["bound_service_account_namespaces"] = qa(data.BoundServiceAccountNamespaces)
		status["bound_service_account_names"] = model.FieldKnown
		status["bound_service_account_namespaces"] = model.FieldKnown
	}
	native := role.Mount + "/" + role.Name
	c.entities = append(c.entities, model.Entity{ID: model.EntityID(c.config.ID, "vault_auth_role", native), Kind: "vault_auth_role", SourceID: c.config.ID, NativeID: native, Scope: c.config.Scope + "/auth/" + role.Mount, Name: role.Name, Attributes: attrs, FieldStatus: status, ObservedAt: c.observed, Provenance: model.ProvenanceLiveAPI})
	fields := []string{"policy_names"}
	if role.Type == "kubernetes" {
		fields = append(fields, "bound_service_account_names", "bound_service_account_namespaces")
	}
	c.evidence = append(c.evidence, evidence(c.config.ID, native, path, fields, c.observed))
	c.source.PermissionsObserved = append(c.source.PermissionsObserved, "vault:"+path+":read")
	return nil
}
func (c *collection) addPolicy(ctx context.Context, name string) error {
	var data policyData
	path := "sys/policies/acl/" + name
	if err := c.get(ctx, path, &data); err != nil {
		return err
	}
	if data.Name == "" {
		data.Name = name
	}
	c.entities = append(c.entities, model.Entity{ID: model.EntityID(c.config.ID, "policy", data.Name), Kind: "policy", SourceID: c.config.ID, NativeID: data.Name, Scope: c.config.Scope, Name: data.Name, Attributes: map[string]json.RawMessage{"policy_kind": q("acl")}, FieldStatus: map[string]model.FieldStatus{"policy_kind": model.FieldKnown}, ObservedAt: c.observed, Provenance: model.ProvenanceLiveAPI})
	c.evidence = append(c.evidence, evidence(c.config.ID, data.Name, path, []string{"name"}, c.observed))
	c.source.PermissionsObserved = append(c.source.PermissionsObserved, "vault:"+path+":read")
	return nil
}
func (c *collection) get(ctx context.Context, path string, target any) error {
	base := strings.TrimRight(c.config.Address, "/") + "/v1/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP_%d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("response_too_large")
	}
	var response envelope
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("invalid JSON response")
	}
	return json.Unmarshal(response.Data, target)
}
func (c *collection) fail(path string, err error) {
	c.source.Complete = false
	c.source.PaginationComplete = false
	c.source.Status = model.SourcePartial
	c.source.Warnings = append(c.source.Warnings, "Vault "+path+" unavailable: "+err.Error())
	c.source.ErrorCode = "collection_error"
}
func (c *collection) sort() {
	sort.Strings(c.source.PermissionsObserved)
	sort.Strings(c.source.Warnings)
	sort.Slice(c.entities, func(i, j int) bool { return c.entities[i].ID < c.entities[j].ID })
	sort.Slice(c.evidence, func(i, j int) bool { return c.evidence[i].ID < c.evidence[j].ID })
}
func q(value string) json.RawMessage { result, _ := json.Marshal(value); return result }
func qa(value []string) json.RawMessage {
	sort.Strings(value)
	result, _ := json.Marshal(value)
	return result
}
func evidence(source, native, path string, fields []string, at time.Time) model.Evidence {
	locator := "vault://" + source + "/v1/" + path
	return model.Evidence{ID: model.EvidenceID(source, native, locator), SourceID: source, NativeID: native, Locator: locator, Fields: fields, ObservedAt: at, AssertionKind: model.AssertionObserved}
}

func (collector Collector) credential(name string) string {
	if collector.Credentials != nil {
		return collector.Credentials(name)
	}
	return os.Getenv(name)
}
