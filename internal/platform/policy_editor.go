package platform

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/config"
	"github.com/grantlinehq/grantline/internal/correlate"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	"sigs.k8s.io/yaml"
)

type fieldIssue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

func invalidFields(w http.ResponseWriter, issues []fieldIssue) {
	sortIssues(issues)
	send(w, 400, map[string]any{"error": "validation_failed", "message": "Review the highlighted fields and try again.", "fields": issues})
}

var diagnosticLine = regexp.MustCompile(`(?:policy )?line ([0-9]+)`)

func policyIssue(err error) fieldIssue {
	v := fieldIssue{Field: "policy", Message: "Use the supported policy fields and exact identifiers. See the configuration guide."}
	text := err.Error()
	if strings.Contains(text, "required_sources") {
		v.Field = "required_sources"
	}
	for _, limit := range []string{"max_client_secret_validity", "max_x509_svid_ttl", "max_jwt_svid_ttl"} {
		if strings.Contains(text, limit) {
			v.Field = "limits." + limit
			break
		}
	}
	if strings.Contains(text, "M7 supports") {
		v.Message = "Enable at least one of IL001–IL008."
		return v
	}
	if m := diagnosticLine.FindStringSubmatch(text); len(m) == 2 {
		v.Line, _ = strconv.Atoi(m[1])
	}
	// Policy parser diagnostics are fixed messages, except unsupported rule names.
	// Never reflect user-supplied values from parser/validation errors.
	if !strings.Contains(text, "unsupported rule") && !strings.ContainsAny(text, "\"\r\n") && len(text) <= 240 {
		v.Message = text
	}
	return v
}
func configurationIssues(policyText, bindingText string, sources []config.Source) []fieldIssue {
	issues := []fieldIssue{}
	if len(policyText) > policy.MaxPolicyBytes {
		issues = append(issues, fieldIssue{Field: "policy", Message: "Policy must not exceed 1 MiB."})
	} else if policyText != "" {
		if _, err := policy.Parse([]byte(policyText)); err != nil {
			issues = append(issues, policyIssue(err))
		}
	}
	if len(bindingText) > 1<<20 {
		issues = append(issues, fieldIssue{Field: "bindings", Message: "Context declarations must not exceed 1 MiB."})
	} else if bindingText != "" {
		var b bindings.Config
		if err := yaml.UnmarshalStrict([]byte(bindingText), &b); err != nil {
			v := fieldIssue{Field: "bindings", Message: "Use the documented context fields and two-space YAML indentation. Unknown or duplicate fields are not accepted."}
			if m := diagnosticLine.FindStringSubmatch(err.Error()); len(m) == 2 {
				v.Line, _ = strconv.Atoi(m[1])
			}
			issues = append(issues, v)
		} else if err = b.Validate(sources); err != nil {
			issues = append(issues, fieldIssue{Field: "bindings", Message: err.Error()})
		}
	}
	return issues
}

type policyForm struct {
	RequiredSources []string               `json:"required_sources"`
	Rules           map[string]policy.Rule `json:"rules"`
	Limits          map[string]string      `json:"limits"`
}

func policyToForm(p policy.Policy) policyForm {
	return policyForm{p.RequiredSources, p.Rules, map[string]string{
		"max_client_secret_validity": p.MaxClientSecretValidity.String(),
		"max_x509_svid_ttl":          p.MaxX509SVIDTTL.String(), "max_jwt_svid_ttl": p.MaxJWTSVIDTTL.String(),
	}}
}
func (f policyForm) parsed() (policy.Policy, []fieldIssue) {
	p := policy.Policy{SchemaVersion: 1, RequiredSources: f.RequiredSources, Rules: f.Rules}
	issues := []fieldIssue{}
	for key, target := range map[string]*time.Duration{"max_client_secret_validity": &p.MaxClientSecretValidity, "max_x509_svid_ttl": &p.MaxX509SVIDTTL, "max_jwt_svid_ttl": &p.MaxJWTSVIDTTL} {
		if f.Limits[key] == "" {
			continue
		}
		v, err := time.ParseDuration(f.Limits[key])
		if err != nil || v < 0 {
			issues = append(issues, fieldIssue{Field: "limits." + key, Message: "Use a duration such as 168h, 24h or 15m. Active lifetime rules require positive values."})
		} else {
			*target = v
		}
	}
	for key := range f.Limits {
		if key != "max_client_secret_validity" && key != "max_x509_svid_ttl" && key != "max_jwt_svid_ttl" {
			issues = append(issues, fieldIssue{Field: "limits", Message: "Only the three documented lifetime limits are supported."})
		}
	}
	if len(issues) == 0 {
		if err := p.Validate(); err != nil {
			issues = append(issues, policyIssue(err))
		}
	}
	return p, issues
}
func effectivePolicy(text string, sources []config.Source) (policy.Policy, error) {
	if text == "" {
		return defaultPolicy(sources), nil
	}
	return policy.Parse([]byte(text))
}
func (s *Server) enabledPolicySources(ctx context.Context) ([]config.Source, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT config FROM integrations WHERE enabled ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sources := []config.Source{}
	for rows.Next() {
		var raw []byte
		var c Connection
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		sources = append(sources, c.Source)
	}
	return sources, rows.Err()
}
func (s *Server) policyEditor(w http.ResponseWriter, r *http.Request) {
	var text string
	var revision int
	if s.db.QueryRowContext(r.Context(), "SELECT policy,revision FROM workspace WHERE id=1").Scan(&text, &revision) != nil {
		fail(w, 503, "settings_unavailable")
		return
	}
	sources, err := s.enabledPolicySources(r.Context())
	if err != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	p, err := effectivePolicy(text, sources)
	if err != nil {
		invalidFields(w, []fieldIssue{policyIssue(err)})
		return
	}
	// Defaults may have no required sources before the first connection is enabled.
	canonical, _ := policy.Encode(p)
	send(w, 200, map[string]any{"revision": revision, "mode": map[bool]string{true: "defaults", false: "custom"}[text == ""], "effective": policyToForm(p), "defaults": policyToForm(defaultPolicy(sources)), "yaml": canonical})
}

type policyCandidate struct {
	Policy   *string     `json:"policy"`
	Form     *policyForm `json:"form"`
	Bindings string      `json:"bindings"`
	Revision int         `json:"revision"`
	Preview  bool        `json:"preview"`
}

func coverageReduction(before, after policy.Policy) []string {
	warnings := []string{}
	for _, id := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008"} {
		if _, was := before.Rules[id]; was {
			if _, now := after.Rules[id]; !now {
				warnings = append(warnings, id+" will be disabled.")
			}
		}
	}
	for _, id := range before.RequiredSources {
		found := false
		for _, next := range after.RequiredSources {
			if id == next {
				found = true
			}
		}
		if !found {
			warnings = append(warnings, "A previously required source will no longer be required for complete coverage.")
			break
		}
	}
	return warnings
}
func (s *Server) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyCandidate
	if decode(r, &in) != nil || (in.Policy == nil) == (in.Form == nil) {
		invalidFields(w, []fieldIssue{{Field: "policy", Message: "Supply either a policy form or YAML, not both."}})
		return
	}
	var current string
	var revision int
	if s.db.QueryRowContext(r.Context(), "SELECT policy,revision FROM workspace WHERE id=1").Scan(&current, &revision) != nil {
		fail(w, 503, "settings_unavailable")
		return
	}
	if revision != in.Revision {
		fail(w, 409, "settings_changed_reload")
		return
	}
	sources, err := s.enabledPolicySources(r.Context())
	if err != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	all, err := s.integrationSources(r.Context())
	if err != nil {
		fail(w, 503, "database_unavailable")
		return
	}
	text := ""
	var p policy.Policy
	if in.Form != nil {
		var issues []fieldIssue
		p, issues = in.Form.parsed()
		if len(issues) > 0 {
			invalidFields(w, issues)
			return
		}
		text, err = policy.Encode(p)
		if err != nil {
			invalidFields(w, []fieldIssue{policyIssue(err)})
			return
		}
	} else {
		text = *in.Policy
	}
	if issues := configurationIssues(text, in.Bindings, all); len(issues) > 0 {
		invalidFields(w, issues)
		return
	}
	p, err = effectivePolicy(text, sources)
	if err != nil {
		invalidFields(w, []fieldIssue{policyIssue(err)})
		return
	}
	before, err := effectivePolicy(current, sources)
	if err != nil {
		fail(w, 409, "stored_policy_invalid")
		return
	}
	warnings := coverageReduction(before, p)
	for _, id := range p.RequiredSources {
		found := false
		for _, source := range sources {
			if id == source.ID {
				found = true
			}
		}
		if !found {
			warnings = append(warnings, "A required source is paused or absent. Coverage can remain UNKNOWN until it is available.")
			break
		}
	}
	disabled := []string{}
	for _, id := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008"} {
		if _, ok := p.Rules[id]; !ok {
			disabled = append(disabled, id)
		}
	}
	canonical, _ := policy.Encode(p)
	out := map[string]any{"valid": true, "policy": text, "yaml": canonical, "effective": policyToForm(p), "disabled_rules": disabled, "warnings": warnings, "requires_acknowledgement": len(coverageReduction(before, p)) > 0, "revision": revision}
	if in.Preview {
		select {
		case s.previewSlots <- struct{}{}:
			defer func() { <-s.previewSlots }()
		default:
			fail(w, 429, "preview_busy_try_again")
			return
		}
		out["preview"] = s.previewPolicy(r.Context(), p, in.Bindings)
	}
	send(w, 200, out)
}

// Only Grantline context-derived evidence/edges are removed. Provider evidence
// and GitHub identity declarations retain their provenance and exact IDs.
func previewSnapshot(snapshot model.Snapshot, connections []Connection) (model.Snapshot, error) {
	removed := map[string]bool{}
	evidence := []model.Evidence{}
	for _, v := range snapshot.Evidence {
		if v.AssertionKind == model.AssertionDeclared && strings.HasPrefix(v.Locator, "bindings/") {
			removed[v.ID] = true
		} else {
			evidence = append(evidence, v)
		}
	}
	edges := []model.Relationship{}
	for _, edge := range snapshot.Relationships {
		derived := false
		for _, id := range edge.EvidenceIDs {
			derived = derived || removed[id]
		}
		if !derived {
			edges = append(edges, edge)
		}
	}
	snapshot.Evidence = evidence
	snapshot.Relationships = edges
	maps := []correlate.VaultKubernetesBinding{}
	for _, c := range connections {
		if c.Source.Kind == "vault" && c.Source.KubernetesSourceID != "" {
			maps = append(maps, correlate.VaultKubernetesBinding{VaultSourceID: c.Source.ID, KubernetesSourceID: c.Source.KubernetesSourceID})
		}
	}
	// Rebuild configured trust if a declaration previously occupied the same ID.
	if len(maps) > 0 {
		if err := correlate.AddVaultKubernetesTrusts(&snapshot, maps); err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}
func (s *Server) previewPolicy(ctx context.Context, p policy.Policy, bindingText string) any {
	var raw, configuration []byte
	var id, kind string
	err := s.db.QueryRowContext(ctx, `SELECT r.report,r.run_id,j.kind,j.configuration FROM reports r JOIN runs j ON j.id=r.run_id ORDER BY r.created_at DESC,r.run_id DESC LIMIT 1`).Scan(&raw, &id, &kind, &configuration)
	if err == sql.ErrNoRows {
		return map[string]any{"available": false, "message": "Collect or import a report to preview policy effects. Validation is still available."}
	}
	if err != nil {
		return map[string]any{"available": false, "message": "The saved report is unavailable. Try again later."}
	}
	var previous model.Report
	var run struct {
		Connections []Connection `json:"connections"`
	}
	if json.Unmarshal(raw, &previous) != nil || previous.Snapshot == nil {
		return map[string]any{"available": false, "message": "This report has no reusable snapshot. Collect a new report."}
	}
	_ = json.Unmarshal(configuration, &run)
	b := bindings.Config{SchemaVersion: 1}
	if bindingText != "" {
		if yaml.UnmarshalStrict([]byte(bindingText), &b) != nil {
			return map[string]any{"available": false, "message": "Context declarations are invalid."}
		}
	}
	snapshot, err := previewSnapshot(*previous.Snapshot, run.Connections)
	if err != nil {
		return map[string]any{"available": false, "message": "The saved snapshot lacks evidence needed to rebuild configured relationships. Collect a new report."}
	}
	next, err := (analyze.Analyzer{Bindings: &b}).Analyze(snapshot, p)
	if err != nil {
		return map[string]any{"available": false, "message": "The saved snapshot cannot evaluate this configuration. Check that its sources match your context declarations, or collect a new report."}
	}
	counts := func(report model.Report) map[string]int {
		out := map[string]int{}
		for _, f := range report.Findings {
			out[f.RuleID]++
		}
		return out
	}
	oldCounts, newCounts := counts(previous), counts(next)
	oldOutcomes, newOutcomes := map[string]model.RuleOutcome{}, map[string]model.RuleOutcome{}
	for _, v := range previous.RuleResults {
		oldOutcomes[v.RuleID] = v.Outcome
	}
	for _, v := range next.RuleResults {
		newOutcomes[v.RuleID] = v.Outcome
	}
	rules := []map[string]any{}
	for _, rule := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008"} {
		rules = append(rules, map[string]any{"id": rule, "before": oldCounts[rule], "after": newCounts[rule], "before_outcome": oldOutcomes[rule], "after_outcome": newOutcomes[rule]})
	}
	old, newIDs := map[string]bool{}, map[string]bool{}
	for _, f := range previous.Findings {
		old[f.ID] = true
	}
	for _, f := range next.Findings {
		newIDs[f.ID] = true
	}
	added, removed := 0, 0
	for id := range newIDs {
		if !old[id] {
			added++
		}
	}
	for id := range old {
		if !newIDs[id] {
			removed++
		}
	}
	return map[string]any{"available": true, "run_id": id, "run_kind": kind, "observed_at": previous.SnapshotCollectedAt, "fixture_notice": previous.FixtureNotice, "before": len(previous.Findings), "after": len(next.Findings), "added": added, "no_longer_reported": removed, "rules": rules, "completeness": next.Completeness, "binding_issues": next.BindingIssues, "message": "Simulation on saved evidence, not a new scan. Collection gaps are retained. Fewer findings do not mean remediation; reports, triage and connections remain unchanged."}
}

// Deterministic diagnostics and tests should not depend on Go map iteration.
func sortIssues(issues []fieldIssue) {
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Field < issues[j].Field })
}
