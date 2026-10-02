// demo-catalog evaluates offline metadata with the real Grantline rules.
// It does not contact providers or install permissions in labs or tenants.
package demolab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"github.com/grantlinehq/grantline/internal/viewer"
)

const tenant = "00000000-0000-4000-8000-000000000001"
const domain = "demo.grantline.test"

var services = []string{"payments", "checkout", "ledger", "billing", "fulfillment", "analytics", "notifications", "inventory", "search", "customer-sync", "backup", "release"}

type catalog struct {
	snapshot  model.Snapshot
	policy    policy.Policy
	bindings  bindings.Config
	controls  map[string][]string
	evidence  map[string]string
	sourceIDs map[string]string
}

// Write exports optional offline artifacts from the same inputs used by demo collection.
func Write(out string, now time.Time) error {
	c := buildCatalog(now)
	report, err := c.analyze()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		return err
	}
	for name, value := range map[string]any{"snapshot.json": c.snapshot, "report.json": report, "bindings.json": c.bindings, "manifest.json": c.manifest(report)} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(out, name), append(data, '\n'), 0644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(out, "policy.yaml"), []byte(c.policyYAML()), 0644)
}
func uuid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012x", n) }
func name(i int) string { return fmt.Sprintf("%s-%02d", services[i%len(services)], i+1) }

func buildCatalog(now time.Time) catalog { return buildCatalogWithIDs(now, nil) }
func buildCatalogWithIDs(now time.Time, sourceIDs map[string]string) catalog {
	yes := true
	c := catalog{snapshot: model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: now, Entities: []model.Entity{}, Relationships: []model.Relationship{}, Evidence: []model.Evidence{}, Sources: []model.Source{}}, policy: policy.Policy{SchemaVersion: 1, MaxClientSecretValidity: 720 * time.Hour, MaxX509SVIDTTL: time.Hour, MaxJWTSVIDTTL: 15 * time.Minute, Rules: map[string]policy.Rule{
		"IL001": {Severity: model.SeverityCritical}, "IL002": {Severity: model.SeverityHigh}, "IL003": {Severity: model.SeverityMedium}, "IL004": {Severity: model.SeverityLow}, "IL005": {Severity: model.SeverityCritical}, "IL006": {Severity: model.SeverityHigh, ForbidNamespaceOnly: &yes}, "IL007": {Severity: model.SeverityLow}, "IL008": {Severity: model.SeverityMedium, SeparatedEnvironments: []policy.EnvironmentPair{{First: "production", Second: "development"}, {First: "production", Second: "staging"}}},
	}}, bindings: bindings.Config{SchemaVersion: 1}, controls: map[string][]string{}, evidence: map[string]string{}}
	c.sourceIDs = sourceIDs
	for _, kind := range []string{"kubernetes", "vault", "jenkins", "entra", "github", "spire"} {
		scope := "demo/" + kind
		if kind == "entra" {
			scope = "tenant/" + tenant
		}
		if kind == "spire" {
			scope = "trust-domain/" + domain
		}
		id := c.sourceID("demo-" + kind)
		c.snapshot.Sources = append(c.snapshot.Sources, model.Source{ID: id, Kind: kind, Scope: scope, Status: model.SourceOK, Complete: true, PaginationComplete: true, Provenance: model.ProvenanceSyntheticFixture, PermissionsObserved: []string{}, Warnings: []string{"Offline synthetic demo metadata; no provider request was made."}})
		c.policy.RequiredSources = append(c.policy.RequiredSources, id)
	}
	accounts := c.kubernetes()
	c.vault(accounts)
	apps := c.entra()
	c.spire()
	c.automation(apps)
	return c
}
func (c *catalog) entity(kind, source, native, display string, attrs map[string]any) model.Entity {
	originalSource := source
	source = c.sourceID(source)
	scope := ""
	for _, s := range c.snapshot.Sources {
		if s.ID == source {
			scope = s.Scope
		}
	}
	if originalSource == "demo-github" {
		scope += "/repo/" + attrs["repository_id"].(string)
	}
	e := model.Entity{ID: model.EntityID(source, kind, native), Kind: kind, SourceID: source, NativeID: native, Name: display, Scope: scope, Attributes: map[string]json.RawMessage{}, FieldStatus: map[string]model.FieldStatus{}, ObservedAt: c.snapshot.CollectedAt, Provenance: model.ProvenanceSyntheticFixture}
	fields := []string{"native_id"}
	for k, v := range attrs {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		e.Attributes[k] = b
		e.FieldStatus[k] = model.FieldKnown
		fields = append(fields, k)
	}
	sort.Strings(fields)
	locator := "synthetic/demo-catalog/" + kind + "/" + native
	v := model.Evidence{ID: model.EvidenceID(source, native, locator), SourceID: source, NativeID: native, Locator: locator, Fields: fields, ObservedAt: c.snapshot.CollectedAt, AssertionKind: model.AssertionConfigured}
	c.snapshot.Entities = append(c.snapshot.Entities, e)
	c.snapshot.Evidence = append(c.snapshot.Evidence, v)
	c.evidence[e.ID] = v.ID
	return e
}
func (c *catalog) edge(from, to model.Entity, typ string, assertion model.AssertionKind) {
	c.snapshot.Relationships = append(c.snapshot.Relationships, model.Relationship{ID: model.RelationshipID(from.ID, to.ID, typ, from.Scope), From: from.ID, To: to.ID, Type: typ, Scope: from.Scope, AssertionKind: assertion, ObservedAt: c.snapshot.CollectedAt, EvidenceIDs: []string{c.evidence[from.ID], c.evidence[to.ID]}})
}
func (c *catalog) member(index int, e model.Entity, environment string) {
	a := &c.bindings.Applications[index]
	a.Members = append(a.Members, bindings.Member{Reference: bindings.Reference{SourceID: e.SourceID, Kind: e.Kind, NativeID: e.NativeID}, Environment: environment})
}
func (c *catalog) control(rule string, e model.Entity) {
	c.controls[rule] = append(c.controls[rule], e.ID)
}
func (c *catalog) analyze() (model.Report, error) {
	r, err := (analyze.Analyzer{Bindings: &c.bindings, Now: func() time.Time { return c.snapshot.CollectedAt }}).Analyze(c.snapshot, c.policy)
	if err != nil {
		return r, err
	}
	// Rule evaluation may traverse maps; export a canonical finding reference order.
	for i := range r.RuleResults {
		sort.Strings(r.RuleResults[i].FindingIDs)
	}
	r.FixtureNotice = "Demo catalog: 36 business scenarios across six synthetic sources. Severity is assigned by the demo policy; this is not live source data."
	return r, viewer.Validate(r)
}
func severityCounts(r model.Report) map[model.Severity]int {
	counts := map[model.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}
func (c *catalog) manifest(r model.Report) map[string]any {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.RuleID]++
	}
	return map[string]any{"name": "Grantline demo catalog", "provenance": "synthetic_fixture", "generated_at": r.GeneratedAt, "findings": len(r.Findings), "severity_counts": severityCounts(r), "rule_counts": counts, "entities": len(r.Snapshot.Entities), "relationships": len(r.Snapshot.Relationships), "evidence": len(r.Evidence), "business_scenarios": c.bindings.Applications, "negative_controls_by_rule": c.controls, "limitations": []string{"Severity levels are explicit choices in the demo policy, not universal risk scores.", "Jenkins and GitHub add identity relationships; IL001-IL008 contain no standalone Jenkins/GitHub risk rules.", "No credential values, provider calls, runtime authentication or permission changes are involved."}}
}
func (c *catalog) policyYAML() string {
	var b strings.Builder
	b.WriteString("# Demo-only risk grading for synthetic metadata.\nschema_version: 1\nrequired_sources:\n")
	for _, id := range c.policy.RequiredSources {
		fmt.Fprintf(&b, "  - %s\n", id)
	}
	b.WriteString("limits:\n  max_client_secret_validity: 720h\n  max_x509_svid_ttl: 1h\n  max_jwt_svid_ttl: 15m\nrules:\n")
	for _, id := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008"} {
		r := c.policy.Rules[id]
		fmt.Fprintf(&b, "  %s:\n    severity: %s\n", id, r.Severity)
		if id == "IL002" {
			b.WriteString("    allowed_kubernetes_bindings:\n")
			for _, v := range r.AllowedVaultKubernetesBindings {
				fmt.Fprintf(&b, "      - vault_source_id: %s\n        role_native_id: %s\n        kubernetes_source_id: %s\n        service_account_id: %s\n", v.VaultSourceID, v.RoleNativeID, v.KubernetesSourceID, v.ServiceAccountID)
			}
		}
		if id == "IL004" {
			b.WriteString("    require_owners_for:\n")
			for _, v := range r.RequireOwnersFor {
				fmt.Fprintf(&b, "      - source_id: %s\n        object_id: %s\n        object_kind: %s\n", v.SourceID, v.ObjectID, v.ObjectKind)
			}
		}
		if id == "IL005" {
			b.WriteString("    allowed_app_roles:\n")
			for _, v := range r.AllowedAppRoles {
				fmt.Fprintf(&b, "      - source_id: %s\n        principal_object_id: %s\n        resource_object_id: %s\n        app_role_id: %s\n", v.SourceID, v.PrincipalObjectID, v.ResourceObjectID, v.AppRoleID)
			}
		}
		if id == "IL006" {
			b.WriteString("    forbid_namespace_only: true\n")
		}
		if id == "IL008" {
			b.WriteString("    separated_environments:\n")
			for _, v := range r.SeparatedEnvironments {
				fmt.Fprintf(&b, "      - first: %s\n        second: %s\n", v.First, v.Second)
			}
		}
	}
	return b.String()
}

func (c *catalog) sourceID(id string) string {
	if mapped := c.sourceIDs[id]; mapped != "" {
		return mapped
	}
	return id
}
