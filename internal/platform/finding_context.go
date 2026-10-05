package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

// Investigation context is a presentation projection, never a changed finding,
// inferred authorization or a replacement for the original report evidence.
type findingContext struct {
	Subject            string        `json:"subject"`
	SourceIDs          []string      `json:"source_ids"`
	Scope              string        `json:"scope"`
	IdentityCount      int           `json:"identity_count"`
	ConfigurationCount int           `json:"configuration_count"`
	UnresolvedCount    int           `json:"unresolved_count"`
	Facts              []findingFact `json:"facts"`
	RuleOutcome        string        `json:"rule_outcome"`
	RuleLimitations    []string      `json:"rule_limitations"`
	PolicyAvailable    bool          `json:"policy_available"`
	PolicyRevision     *int          `json:"policy_revision"`
	ObservedAt         string        `json:"observed_at"`
}
type findingFact struct {
	Label    string `json:"label"`
	Observed string `json:"observed"`
	Expected string `json:"expected,omitempty"`
}
type findingRunContext struct {
	Rules      []model.RuleResult
	Policy     policy.Policy
	HasPolicy  bool
	Revision   *int
	ObservedAt string
}

func (s *Server) findingContexts(ctx context.Context, run string, findings []model.Finding) (map[string]findingContext, error) {
	result := map[string]findingContext{}
	if len(findings) == 0 {
		return result, nil
	}
	ids := []string{}
	for _, f := range findings {
		ids = append(ids, f.AffectedEntityIDs...)
	}
	raw, err := jsonRows(ctx, s.db, "SELECT body FROM objects WHERE run_id=$1 AND category='identities' AND id=ANY($2)", run, ids)
	if err != nil {
		return nil, err
	}
	entities := map[string]model.Entity{}
	parents := []string{}
	for _, body := range raw {
		var e model.Entity
		if err = json.Unmarshal(body, &e); err != nil {
			return nil, err
		}
		entities[e.ID] = e
		if e.Kind == "credential_metadata" {
			if id := knownString(e, "parent_object_id"); id != "" {
				parents = append(parents, id)
			}
		}
	}
	// One batch resolves credential display parents, including exact source/kind
	// checks below. A matching object ID in another connection is not that parent.
	if len(parents) > 0 {
		raw, err = jsonRows(ctx, s.db, "SELECT body FROM objects WHERE run_id=$1 AND category='identities' AND body->'attributes'->>'object_id'=ANY($2)", run, parents)
		if err != nil {
			return nil, err
		}
		for _, body := range raw {
			var e model.Entity
			if err = json.Unmarshal(body, &e); err != nil {
				return nil, err
			}
			entities[e.ID] = e
		}
	}
	var rules, connections []byte
	var observed, kind string
	var revision sql.NullInt64
	var text sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT p.report->'rule_results',COALESCE(p.report->>'snapshot_collected_at',''),r.kind,r.config_revision,r.configuration->>'policy',r.configuration->'connections' FROM reports p JOIN runs r ON r.id=p.run_id WHERE p.run_id=$1`, run).Scan(&rules, &observed, &kind, &revision, &text, &connections)
	if err != nil {
		return nil, err
	}
	meta := findingRunContext{ObservedAt: observed}
	if len(rules) > 0 {
		if err = json.Unmarshal(rules, &meta.Rules); err != nil {
			return nil, err
		}
	}
	// Never substitute today's workspace policy for a historical/imported report.
	if kind == "collection" && text.Valid {
		var recorded []Connection
		if json.Unmarshal(connections, &recorded) == nil {
			sources := []config.Source{}
			for _, c := range recorded {
				sources = append(sources, c.Source)
			}
			if p, e := effectivePolicy(text.String, sources); e == nil {
				meta.Policy, meta.HasPolicy = p, true
			}
		}
	}
	if revision.Valid {
		n := int(revision.Int64)
		meta.Revision = &n
	}
	for _, f := range findings {
		result[f.ID] = describeFinding(f, entities, meta)
	}
	return result, nil
}

func nativePrincipal(kind string) bool {
	return kind == "service_account" || kind == "service_principal" || kind == "spiffe_identity"
}
func knownAttribute(e model.Entity, key string, value any) bool {
	return e.FieldStatus[key] == model.FieldKnown && json.Unmarshal(e.Attributes[key], value) == nil
}
func knownString(e model.Entity, key string) string {
	var value string
	if !knownAttribute(e, key, &value) {
		return ""
	}
	return value
}
func entityDisplay(e model.Entity) string {
	if e.Kind == "spire_entry" {
		if uri := knownString(e, "spiffe_id"); uri != "" {
			return uri
		}
	}
	if e.Name != "" {
		return e.Name
	}
	return e.NativeID
}
func readableDuration(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	}
	return d.String()
}

func describeFinding(f model.Finding, entities map[string]model.Entity, meta findingRunContext) findingContext {
	c := findingContext{SourceIDs: []string{}, Facts: []findingFact{}, RuleLimitations: []string{}, PolicyAvailable: meta.HasPolicy, PolicyRevision: meta.Revision, ObservedAt: meta.ObservedAt}
	for _, r := range meta.Rules {
		if r.RuleID == f.RuleID {
			c.RuleOutcome = string(r.Outcome)
			c.RuleLimitations = append(c.RuleLimitations, r.Limitations...)
		}
	}
	affected := []model.Entity{}
	sources := map[string]bool{}
	for _, id := range f.AffectedEntityIDs {
		e, ok := entities[id]
		if !ok {
			c.UnresolvedCount++
			continue
		}
		affected = append(affected, e)
		sources[e.SourceID] = true
		if nativePrincipal(e.Kind) {
			c.IdentityCount++
		} else {
			c.ConfigurationCount++
		}
	}
	sort.SliceStable(affected, func(i, j int) bool {
		if nativePrincipal(affected[i].Kind) != nativePrincipal(affected[j].Kind) {
			return nativePrincipal(affected[i].Kind)
		}
		return affected[i].ID < affected[j].ID
	})
	for source := range sources {
		c.SourceIDs = append(c.SourceIDs, source)
	}
	sort.Strings(c.SourceIDs)
	if len(affected) > 0 {
		c.Subject, c.Scope = entityDisplay(affected[0]), affected[0].Scope
	}
	add := func(label, observed, expected string) {
		c.Facts = append(c.Facts, findingFact{label, observed, expected})
	}
	for _, e := range affected {
		switch f.RuleID {
		case "IL001":
			var rules []model.RBACRule
			if e.Kind != "role" || !knownAttribute(e, "rbac_rules", &rules) {
				continue
			}
			for _, r := range rules {
				groups := append([]string{}, r.APIGroups...)
				for i, group := range groups {
					if group == "" {
						groups[i] = "core"
					}
				}
				text := "API groups: " + strings.Join(groups, ", ") + "; resources: " + strings.Join(r.Resources, ", ") + "; verbs: " + strings.Join(r.Verbs, ", ")
				if strings.Contains(text+strings.Join(r.NonResourceURL, ", "), "*") {
					if len(r.NonResourceURL) > 0 {
						text += "; non-resource URLs: " + strings.Join(r.NonResourceURL, ", ")
					}
					add("Collected wildcard rule · "+entityDisplay(e), text, "Review the required operations and the exact approved exception.")
				}
			}
		case "IL002":
			for _, field := range []struct{ key, label string }{{"bound_service_account_names", "Bound service accounts"}, {"bound_service_account_namespaces", "Bound namespaces"}} {
				var values []string
				if knownAttribute(e, field.key, &values) {
					add(field.label, strings.Join(values, ", "), "Exact reviewed subject bindings; no wildcard.")
				}
			}
		case "IL003":
			for _, parent := range entities {
				if parent.SourceID == e.SourceID && parent.Kind == knownString(e, "parent_kind") && knownString(parent, "object_id") == knownString(e, "parent_object_id") && knownString(e, "parent_object_id") != "" {
					c.Subject = entityDisplay(parent)
					break
				}
			}
			start, a := time.Parse(time.RFC3339Nano, knownString(e, "start_time"))
			end, b := time.Parse(time.RFC3339Nano, knownString(e, "end_time"))
			if a == nil && b == nil && !end.Before(start) {
				limit := ""
				if meta.HasPolicy {
					limit = "Maximum " + readableDuration(meta.Policy.MaxClientSecretValidity)
				}
				add("Configured secret validity", readableDuration(end.Sub(start)), limit)
				add("Configured validity dates", start.Format(time.RFC3339)+" → "+end.Format(time.RFC3339), "")
			}
		case "IL004":
			var count int
			if knownAttribute(e, "owners_count", &count) {
				add("Collected directory owners", fmt.Sprint(count), "At least one directory owner on this selected target.")
			}
		case "IL005":
			if value := knownString(e, "app_role_id"); value != "" {
				add("Assigned application role ID", value, "An exact approved source/principal/resource/role entry.")
			}
		case "IL006":
			var selectors []model.SpireSelector
			if knownAttribute(e, "selectors", &selectors) {
				values := []string{}
				for _, selector := range selectors {
					values = append(values, selector.Type+":"+selector.Value)
				}
				add("Configured workload selectors", strings.Join(values, ", "), "Constrain the intended workload beyond its namespace.")
			}
		case "IL007":
			for _, typ := range []string{"x509", "jwt"} {
				if model.FindingID(f.RuleID, f.RuleVersion, e.ID, typ) != f.ID {
					continue
				}
				var seconds int64
				if knownString(e, typ+"_ttl_mode") == "explicit" && knownAttribute(e, typ+"_svid_ttl_seconds", &seconds) && seconds > 0 {
					limit := ""
					if meta.HasPolicy {
						d := meta.Policy.MaxX509SVIDTTL
						if typ == "jwt" {
							d = meta.Policy.MaxJWTSVIDTTL
						}
						limit = "Maximum " + readableDuration(d)
					}
					add(strings.ToUpper(typ)+" configured SVID lifetime", fmt.Sprintf("%d seconds", seconds), limit)
				}
			}
		case "IL008":
			if !meta.HasPolicy {
				continue
			}
			for _, pair := range meta.Policy.Rules[f.RuleID].SeparatedEnvironments {
				environments := []string{pair.First, pair.Second}
				sort.Strings(environments)
				if model.FindingID(f.RuleID, f.RuleVersion, e.ID, environments[0], environments[1]) == f.ID {
					add("Declared environment membership", pair.First+" + "+pair.Second, "Separate native principals or an exact documented shared-service exception.")
				}
			}
		}
	}
	return c
}
