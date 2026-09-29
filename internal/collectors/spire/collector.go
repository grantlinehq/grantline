package spire

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type Collector struct {
	Config Config
	Client entryv1.EntryClient
	Now    func() time.Time
}
type collection struct {
	config   Config
	snapshot model.Snapshot
	source   model.Source
	entities map[string]*model.Entity
}

func (collector Collector) Collect(ctx context.Context) (model.Snapshot, error) {
	if err := collector.Config.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	at := time.Now().UTC()
	if collector.Now != nil {
		at = collector.Now().UTC()
	}
	c := collection{config: collector.Config, snapshot: model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: at}, source: model.Source{ID: collector.Config.ID, Kind: "spire", Scope: collector.Config.Scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceLiveAPI}, entities: map[string]*model.Entity{}}
	if c.config.ExportPath != "" {
		return c.importExport()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := collector.Client
	if client == nil {
		conn, err := grpc.NewClient("passthrough:///spire-local", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.config.SocketPath)
		}), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(2<<20)))
		if err != nil {
			c.fail("socket_unavailable")
			return c.finish()
		}
		defer conn.Close()
		client = entryv1.NewEntryClient(conn)
	}
	seen := map[string]bool{}
	total := 0
	for _, parent := range c.config.ParentIDs {
		id, _ := spiffeid.FromString(parent)
		token := ""
		tokens := map[string]bool{}
		complete := false
		for page := 0; page < 50; page++ {
			requestCtx, requestCancel := context.WithTimeout(ctx, 10*time.Second)
			response, err := client.ListEntries(requestCtx, &entryv1.ListEntriesRequest{Filter: &entryv1.ListEntriesRequest_Filter{ByParentId: &types.SPIFFEID{TrustDomain: id.TrustDomain().String(), Path: id.Path()}}, PageSize: 100, PageToken: token, OutputMask: &types.EntryMask{SpiffeId: true, ParentId: true, Selectors: true, X509SvidTtl: true, JwtSvidTtl: true, FederatesWith: true, Admin: true, Downstream: true, ExpiresAt: true, RevisionNumber: true, CreatedAt: true}})
			requestCancel()
			if err != nil {
				code := "entry_api_unavailable"
				if status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unauthenticated {
					code = "entry_api_permission_denied"
				}
				c.fail(code)
				break
			}
			if response == nil || len(response.Entries) > 100 {
				c.fail("invalid_entry_page")
				break
			}
			c.source.PermissionsObserved = []string{"spire:entry.v1.Entry/ListEntries:local_uds"}
			for _, entry := range response.Entries {
				total++
				if total > 1000 {
					c.fail("entry_limit_exceeded")
					break
				}
				if !validEntry(entry, parent, c.config.TrustDomain) || seen[entry.GetId()] {
					c.fail("invalid_or_duplicate_entry")
					continue
				}
				seen[entry.Id] = true
				c.addEntry(entry)
			}
			if total > 1000 {
				break
			}
			token = response.NextPageToken
			if token == "" {
				complete = true
				break
			}
			if len(token) > 4096 || tokens[token] {
				c.fail("invalid_pagination")
				break
			}
			tokens[token] = true
		}
		if !complete {
			c.fail("entry_listing_incomplete")
		}
		if total > 1000 || ctx.Err() != nil {
			break
		}
	}
	c.resolveParents()
	return c.finish()
}

func uri(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return "spiffe://" + id.TrustDomain + id.Path
}
func validEntry(e *types.Entry, parent, domain string) bool {
	if e == nil || !model.SpireEntryID.MatchString(e.Id) || uri(e.ParentId) != parent || !model.SpireURIInDomain(uri(e.SpiffeId), domain) || !model.SpireURIInDomain(parent, domain) || len(e.Selectors) == 0 || len(e.Selectors) > 100 || e.X509SvidTtl < 0 || e.JwtSvidTtl < 0 || e.ExpiresAt < 0 || e.CreatedAt < 0 || e.RevisionNumber < 0 || len(e.FederatesWith) > 100 {
		return false
	}
	selectors := map[model.SpireSelector]bool{}
	for _, s := range e.Selectors {
		if s == nil || !model.SpireSelectorType.MatchString(s.Type) || s.Value == "" || !model.GitHubText(s.Value, 1024) {
			return false
		}
		key := model.SpireSelector{Type: s.Type, Value: s.Value}
		if selectors[key] {
			return false
		}
		selectors[key] = true
	}
	domains := map[string]bool{}
	for _, d := range e.FederatesWith {
		if !model.SpireTrustDomain(d) || domains[d] {
			return false
		}
		domains[d] = true
	}
	return true
}
func (c *collection) entity(kind, native string) *model.Entity {
	id := model.EntityID(c.config.ID, kind, native)
	if e := c.entities[id]; e != nil {
		return e
	}
	e := &model.Entity{ID: id, Kind: kind, SourceID: c.config.ID, NativeID: native, Scope: c.config.Scope, Name: native, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: c.snapshot.CollectedAt, Provenance: model.ProvenanceLiveAPI}
	set(e, "trust_domain", c.config.TrustDomain)
	c.entities[id] = e
	return e
}
func set(e *model.Entity, key string, value any) {
	e.Attributes[key], _ = json.Marshal(value)
	e.FieldStatus[key] = model.FieldKnown
}
func (c *collection) addEntry(entry *types.Entry) {
	e := c.entity("spire_entry", "entry/"+entry.Id)
	set(e, "entry_id", entry.Id)
	set(e, "spiffe_id", uri(entry.SpiffeId))
	set(e, "parent_spiffe_id", uri(entry.ParentId))
	kind := "workload"
	if uri(entry.ParentId) == "spiffe://"+c.config.TrustDomain+"/spire/server" {
		kind = "node_alias"
	}
	set(e, "entry_kind", kind)
	selectors := make([]model.SpireSelector, 0, len(entry.Selectors))
	for _, s := range entry.Selectors {
		selectors = append(selectors, model.SpireSelector{Type: s.Type, Value: s.Value})
	}
	sort.Slice(selectors, func(i, j int) bool {
		if selectors[i].Type != selectors[j].Type {
			return selectors[i].Type < selectors[j].Type
		}
		return selectors[i].Value < selectors[j].Value
	})
	set(e, "selectors", selectors)
	for key, value := range map[string]int32{"x509": entry.X509SvidTtl, "jwt": entry.JwtSvidTtl} {
		mode := "inherited"
		e.FieldStatus[key+"_svid_ttl_seconds"] = model.FieldUnknown
		if value > 0 {
			mode = "explicit"
			set(e, key+"_svid_ttl_seconds", value)
		}
		set(e, key+"_ttl_mode", mode)
	}
	domains := append([]string{}, entry.FederatesWith...)
	sort.Strings(domains)
	set(e, "federates_with", domains)
	set(e, "admin", entry.Admin)
	set(e, "downstream", entry.Downstream)
	set(e, "entry_expires_at", entry.ExpiresAt)
	set(e, "entry_created_at", entry.CreatedAt)
	set(e, "revision_number", entry.RevisionNumber)
	fields := []string{}
	for key := range e.Attributes {
		fields = append(fields, key)
	}
	sort.Strings(fields)
	evidence := c.record(e.NativeID, "spire/entry/"+entry.Id, fields, model.AssertionConfigured)
	identity := c.entity("spiffe_identity", uri(entry.SpiffeId))
	set(identity, "spiffe_id", identity.NativeID)
	parent := c.entity("spiffe_identity", uri(entry.ParentId))
	set(parent, "spiffe_id", parent.NativeID)
	domain := c.entity("trust_domain", "spiffe://"+c.config.TrustDomain)
	c.edge(e, identity, "assigned_spiffe_id", evidence)
	c.edge(e, parent, "bound_to", evidence)
	c.edge(e, domain, "bound_to", evidence)
}
func (c *collection) resolveParents() {
	for _, e := range c.entities {
		if e.Kind != "spire_entry" {
			continue
		}
		var kind, parent string
		json.Unmarshal(e.Attributes["entry_kind"], &kind)
		json.Unmarshal(e.Attributes["parent_spiffe_id"], &parent)
		ids := []string{}
		attestors := map[string]bool{}
		if kind == "workload" {
			for _, alias := range c.entities {
				if alias.Kind != "spire_entry" {
					continue
				}
				var aliasKind, aliasURI, entryID string
				json.Unmarshal(alias.Attributes["entry_kind"], &aliasKind)
				json.Unmarshal(alias.Attributes["spiffe_id"], &aliasURI)
				json.Unmarshal(alias.Attributes["entry_id"], &entryID)
				if aliasKind != "node_alias" || aliasURI != parent {
					continue
				}
				ids = append(ids, entryID)
				var selectors []model.SpireSelector
				json.Unmarshal(alias.Attributes["selectors"], &selectors)
				for _, s := range selectors {
					attestors[s.Type] = true
				}
			}
		}
		if len(ids) > 100 {
			c.fail("parent_alias_limit_exceeded")
		}
		if kind == "workload" && (len(ids) == 0 || len(ids) > 100) {
			e.FieldStatus["parent_entry_ids"] = model.FieldUnknown
			e.FieldStatus["parent_attestor_types"] = model.FieldUnknown
			continue
		}
		sort.Strings(ids)
		types := []string{}
		for typ := range attestors {
			types = append(types, typ)
		}
		sort.Strings(types)
		set(e, "parent_entry_ids", ids)
		set(e, "parent_attestor_types", types)
	}
}
func (c *collection) record(native, locator string, fields []string, assertion model.AssertionKind) string {
	id := model.EvidenceID(c.config.ID, native, locator)
	c.snapshot.Evidence = append(c.snapshot.Evidence, model.Evidence{ID: id, SourceID: c.config.ID, NativeID: native, Locator: locator, Fields: fields, AssertionKind: assertion, ObservedAt: c.snapshot.CollectedAt})
	return id
}
func (c *collection) edge(from, to *model.Entity, kind, evidence string) {
	c.snapshot.Relationships = append(c.snapshot.Relationships, model.Relationship{ID: model.RelationshipID(from.ID, to.ID, kind, c.config.Scope), From: from.ID, To: to.ID, Type: kind, Scope: c.config.Scope, AssertionKind: model.AssertionConfigured, EvidenceIDs: []string{evidence}, ObservedAt: c.snapshot.CollectedAt})
}
func (c *collection) fail(code string) {
	c.source.Status = model.SourcePartial
	c.source.Complete = false
	c.source.PaginationComplete = false
	if c.source.ErrorCode == "" {
		c.source.ErrorCode = code
	}
	for _, v := range c.source.Warnings {
		if v == code {
			return
		}
	}
	c.source.Warnings = append(c.source.Warnings, code)
}
func (c *collection) finish() (model.Snapshot, error) {
	for _, e := range c.entities {
		c.snapshot.Entities = append(c.snapshot.Entities, *e)
	}
	sort.Slice(c.snapshot.Entities, func(i, j int) bool { return c.snapshot.Entities[i].ID < c.snapshot.Entities[j].ID })
	sort.Slice(c.snapshot.Relationships, func(i, j int) bool { return c.snapshot.Relationships[i].ID < c.snapshot.Relationships[j].ID })
	sort.Slice(c.snapshot.Evidence, func(i, j int) bool { return c.snapshot.Evidence[i].ID < c.snapshot.Evidence[j].ID })
	sort.Strings(c.source.Warnings)
	c.snapshot.Sources = []model.Source{c.source}
	return c.snapshot, c.snapshot.Validate()
}
