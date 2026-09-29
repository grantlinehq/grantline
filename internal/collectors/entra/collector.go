package entra

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

type Collector struct {
	// Credentials are injected per collection by the server; nil preserves CLI environment input.
	Credentials func(string) string
	Config      Config
	Client      *http.Client
	Now         func() time.Time
}
type collection struct {
	config         Config
	client         *http.Client
	base, token    string
	at             time.Time
	requests       int
	exhausted      bool
	snapshot       model.Snapshot
	source         model.Source
	entities       map[string]*model.Entity
	evidence       map[string]bool
	relationships  map[string]bool
	resources      map[string]*directoryObject
	resourceErrors map[string]string
	resourceReads  int
}
type credential struct {
	KeyID string  `json:"keyId"`
	Start *string `json:"startDateTime"`
	End   *string `json:"endDateTime"`
	Type  string  `json:"type"`
}
type appRole struct {
	ID          string    `json:"id"`
	Value       *string   `json:"value"`
	Enabled     *bool     `json:"isEnabled"`
	MemberTypes *[]string `json:"allowedMemberTypes"`
}
type requestedResource struct {
	AppID  string `json:"resourceAppId"`
	Access *[]struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"resourceAccess"`
}
type directoryObject struct {
	ID          string               `json:"id"`
	AppID       string               `json:"appId"`
	DisplayName string               `json:"displayName"`
	Type        string               `json:"servicePrincipalType"`
	Passwords   *[]credential        `json:"passwordCredentials"`
	Keys        *[]credential        `json:"keyCredentials"`
	Requested   *[]requestedResource `json:"requiredResourceAccess"`
	Roles       *[]appRole           `json:"appRoles"`
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if err := collector.Config.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	now := time.Now
	if collector.Now != nil {
		now = collector.Now
	}
	at := now().UTC()
	client := http.Client{Timeout: 15 * time.Second}
	if collector.Client != nil {
		client = *collector.Client
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := collection{config: collector.Config, client: &client, base: GraphAddress, token: collector.credential(collector.Config.TokenEnv), at: at,
		snapshot: model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at},
		source:   model.Source{ID: collector.Config.ID, Kind: "entra", Scope: collector.Config.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI},
		entities: map[string]*model.Entity{}, evidence: map[string]bool{}, relationships: map[string]bool{}, resources: map[string]*directoryObject{}, resourceErrors: map[string]string{}}
	if c.token == "" || len(c.token) > 32768 || strings.ContainsAny(c.token, " \t\r\n\x00") {
		c.fail("authentication", "credentials_unavailable")
	} else {
		for _, id := range c.config.Applications {
			c.collectObject(ctx, "applications", id)
		}
		for _, id := range c.config.ServicePrincipals {
			c.collectObject(ctx, "servicePrincipals", id)
		}
		c.registeredAs()
	}
	for _, entity := range c.entities {
		c.snapshot.Entities = append(c.snapshot.Entities, *entity)
	}
	sort.Slice(c.snapshot.Entities, func(i, j int) bool { return c.snapshot.Entities[i].ID < c.snapshot.Entities[j].ID })
	sort.Slice(c.snapshot.Evidence, func(i, j int) bool { return c.snapshot.Evidence[i].ID < c.snapshot.Evidence[j].ID })
	sort.Slice(c.snapshot.Relationships, func(i, j int) bool { return c.snapshot.Relationships[i].ID < c.snapshot.Relationships[j].ID })
	sort.Strings(c.source.Warnings)
	sort.Strings(c.source.PermissionsObserved)
	c.snapshot.Sources = []model.Source{c.source}
	return c.snapshot, c.snapshot.Validate()
}

func (c *collection) collectObject(ctx context.Context, collectionName, id string) {
	endpoint := "/" + collectionName + "/" + id
	fields := "id,appId,displayName,passwordCredentials,keyCredentials"
	kind := "application_registration"
	if collectionName == "applications" {
		fields += ",requiredResourceAccess"
	} else {
		fields += ",servicePrincipalType,appRoles"
		kind = "service_principal"
	}
	var response directoryObject
	if code := c.get(ctx, endpoint, fields, &response); code != "" {
		c.fail(endpoint, code)
		return
	}
	if response.ID != id || !guid.MatchString(response.AppID) || !safeText(response.DisplayName, 512) {
		c.fail(endpoint, "invalid_object_identity")
		return
	}
	entity := c.entity(kind, objectNative(c.config.TenantID, id), response.DisplayName)
	c.set(entity, "object_id", id)
	c.set(entity, "app_id", response.AppID)
	c.set(entity, "collection_role", "selected")
	evidence := c.record(entity.NativeID, endpoint, []string{"id", "appId"}, model.AssertionObserved)
	if kind == "service_principal" {
		switch response.Type {
		case "Application", "ManagedIdentity", "Legacy":
			c.set(entity, "principal_type", response.Type)
		default:
			entity.FieldStatus["principal_type"] = model.FieldUnsupported
			c.fail(endpoint, "unsupported_principal_type")
		}
		c.resources[id] = &response
	}
	c.credentials(entity, collectionName, id, "client_secret", response.Passwords, evidence)
	c.credentials(entity, collectionName, id, "certificate", response.Keys, evidence)
	if kind == "application_registration" {
		c.requested(entity, response.Requested, endpoint)
		c.federated(ctx, entity, id)
	}
	c.owners(ctx, entity, endpoint)
	if kind == "service_principal" {
		c.assignments(ctx, entity, id)
	}
}

func (c *collection) entity(kind, native, name string) *model.Entity {
	id := model.EntityID(c.config.ID, kind, native)
	if previous, ok := c.entities[id]; ok {
		return previous
	}
	e := &model.Entity{ID: id, Kind: kind, SourceID: c.config.ID, NativeID: native, Scope: c.config.Scope, Name: name, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: c.at, Provenance: model.ProvenanceLiveAPI}
	c.set(e, "tenant_id", c.config.TenantID)
	c.entities[id] = e
	return e
}
func (c *collection) set(e *model.Entity, key string, value any) {
	data, _ := json.Marshal(value)
	e.Attributes[key] = data
	e.FieldStatus[key] = model.FieldKnown
}
func (c *collection) record(native, endpoint string, fields []string, assertion model.AssertionKind) string {
	locator := "graph/v1.0" + endpoint
	id := model.EvidenceID(c.config.ID, native, locator)
	if !c.evidence[id] {
		c.snapshot.Evidence = append(c.snapshot.Evidence, model.Evidence{ID: id, SourceID: c.config.ID, NativeID: native, Locator: locator, Fields: fields, AssertionKind: assertion, ObservedAt: c.at})
		c.evidence[id] = true
	}
	return id
}
func (c *collection) edge(from, to *model.Entity, kind string, evidence ...string) {
	id := model.RelationshipID(from.ID, to.ID, kind, c.config.Scope)
	if c.relationships[id] {
		return
	}
	c.relationships[id] = true
	sort.Strings(evidence)
	c.snapshot.Relationships = append(c.snapshot.Relationships, model.Relationship{ID: id, From: from.ID, To: to.ID, Type: kind, Scope: c.config.Scope, AssertionKind: model.AssertionConfigured, EvidenceIDs: evidence, ObservedAt: c.at})
}
func (c *collection) fail(endpoint, code string) {
	c.source.Status = model.SourcePartial
	c.source.Complete = false
	c.source.PaginationComplete = false
	if c.source.ErrorCode == "" {
		c.source.ErrorCode = code
	}
	c.source.Warnings = append(c.source.Warnings, "Graph "+endpoint+": "+code)
}
func (c *collection) coverage(e *model.Entity, key, endpoint, code string, count int) {
	if code == "" {
		c.set(e, key, count)
		c.source.PermissionsObserved = append(c.source.PermissionsObserved, "graph:"+endpoint+":read")
		return
	}
	e.FieldStatus[key] = model.FieldUnknown
	if code == "HTTP_403" {
		e.FieldStatus[key] = model.FieldPermissionDenied
	}
	c.fail(endpoint, code)
}
func (c *collection) registeredAs() {
	for _, app := range c.entities {
		if app.Kind != "application_registration" {
			continue
		}
		for _, sp := range c.entities {
			if sp.Kind != "service_principal" || string(sp.Attributes["collection_role"]) != `"selected"` {
				continue
			}
			if string(app.Attributes["app_id"]) != string(sp.Attributes["app_id"]) {
				continue
			}
			var a, s string
			json.Unmarshal(app.Attributes["object_id"], &a)
			json.Unmarshal(sp.Attributes["object_id"], &s)
			c.edge(app, sp, "registered_as", c.record(app.NativeID, "/applications/"+a, []string{"id", "appId"}, model.AssertionObserved), c.record(sp.NativeID, "/servicePrincipals/"+s, []string{"id", "appId"}, model.AssertionObserved))
		}
	}
}

func (collector Collector) credential(name string) string {
	if collector.Credentials != nil {
		return collector.Credentials(name)
	}
	return os.Getenv(name)
}
