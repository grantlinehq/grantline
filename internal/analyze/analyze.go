package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/bindings"
	"github.com/grantlinehq/grantline/internal/graph"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
)

const il001Version = "1"

type Analyzer struct {
	Now      func() time.Time
	Bindings *bindings.Config
}

func Analyze(snapshot model.Snapshot, configuredPolicy policy.Policy) (model.Report, error) {
	return Analyzer{}.Analyze(snapshot, configuredPolicy)
}

func (analyzer Analyzer) Analyze(snapshot model.Snapshot, configuredPolicy policy.Policy) (model.Report, error) {
	if err := configuredPolicy.Validate(); err != nil {
		return model.Report{}, fmt.Errorf("validate policy: %w", err)
	}
	contexts, issues, err := applyContexts(&snapshot, analyzer.Bindings)
	if err != nil {
		return model.Report{}, err
	}
	graph, err := graph.Build(snapshot)
	if err != nil {
		return model.Report{}, err
	}

	now := time.Now
	if analyzer.Now != nil {
		now = analyzer.Now
	}

	report := model.Report{
		Snapshot:            &snapshot,
		Contexts:            contexts,
		BindingIssues:       issues,
		SchemaVersion:       model.ReportSchemaVersion,
		GeneratedAt:         now().UTC(),
		SnapshotCollectedAt: snapshot.CollectedAt,
		InputProvenances:    inputProvenances(snapshot),
		Completeness:        assessCompleteness(snapshot, configuredPolicy),
		Evidence:            sortedEvidence(snapshot.Evidence),
	}
	if includesSyntheticFixture(report.InputProvenances) {
		report.FixtureNotice = "This report was generated from synthetic_fixture input and is not live source data."
	}

	if rule, exists := configuredPolicy.Rules["IL001"]; exists {
		il001Result, il001Findings := evaluateIL001(graph, snapshot, rule, report.Completeness)
		report.RuleResults = append(report.RuleResults, il001Result)
		report.Findings = append(report.Findings, il001Findings...)
	}
	if rule, exists := configuredPolicy.Rules["IL002"]; exists {
		result, findings := evaluateIL002(graph, snapshot, rule, report.Completeness)
		report.RuleResults = append(report.RuleResults, result)
		report.Findings = append(report.Findings, findings...)
	}
	for _, ruleID := range []string{"IL003", "IL004", "IL005"} {
		if _, exists := configuredPolicy.Rules[ruleID]; exists {
			result, findings := evaluateEntra(ruleID, graph, snapshot, configuredPolicy)
			report.RuleResults = append(report.RuleResults, result)
			report.Findings = append(report.Findings, findings...)
		}
	}
	for _, id := range []string{"IL006", "IL007"} {
		if _, ok := configuredPolicy.Rules[id]; ok {
			result, findings := evaluateSpire(id, graph, snapshot, configuredPolicy)
			report.RuleResults = append(report.RuleResults, result)
			report.Findings = append(report.Findings, findings...)
		}
	}
	if rule, ok := configuredPolicy.Rules["IL008"]; ok {
		result, findings, exceptions := evaluateIL008(graph, snapshot, contexts, issues, rule, report.Completeness)
		report.RuleResults = append(report.RuleResults, result)
		report.Findings = append(report.Findings, findings...)
		report.PolicyExceptions = exceptions
	}
	sort.Slice(report.RuleResults, func(i, j int) bool { return report.RuleResults[i].RuleID < report.RuleResults[j].RuleID })
	sort.Slice(report.Findings, func(i, j int) bool { return report.Findings[i].ID < report.Findings[j].ID })
	normalizeReportLists(&report)
	return report, nil
}

func evaluateIL002(graph graph.Graph, snapshot model.Snapshot, rule policy.Rule, completeness model.Completeness) (model.RuleResult, []model.Finding) {
	result := model.RuleResult{RuleID: "IL002", RuleVersion: "1"}
	if !completeness.Complete {
		result.Outcome = model.OutcomeUnknown
		result.Limitations = requiredCoverageLimitations(completeness)
		return result, nil
	}
	sourceKinds := map[string]string{}
	for _, source := range snapshot.Sources {
		sourceKinds[source.ID] = source.Kind
	}
	var findings []model.Finding
	assessed := false
	for _, role := range graph.Entities {
		if role.Kind != "vault_auth_role" || sourceKinds[role.SourceID] != "vault" || vaultAuthType(role) != "kubernetes" {
			continue
		}
		names, namesKnown := vaultStringList(role, "bound_service_account_names")
		namespaces, namespacesKnown := vaultStringList(role, "bound_service_account_namespaces")
		if !namesKnown || !namespacesKnown {
			result.Limitations = append(result.Limitations, "A Vault Kubernetes auth role has unknown subject bindings.")
			continue
		}
		assessed = true
		if vaultBindingAllowed(role, graph, rule) && !listContainsWildcard(names) && !listContainsWildcard(namespaces) {
			continue
		}
		if !listContainsWildcard(names) && !listContainsWildcard(namespaces) && vaultBindingAllowed(role, graph, rule) {
			continue
		}
		evidenceIDs := entityEvidence(snapshot, role.SourceID, role.NativeID)
		for _, edge := range graph.Outgoing(role.ID, "trusts_subject") {
			evidenceIDs = append(evidenceIDs, edge.EvidenceIDs...)
		}
		findings = append(findings, model.Finding{
			ID:     model.FindingID("IL002", "1", role.ID, strings.Join(names, ","), strings.Join(namespaces, ",")),
			RuleID: "IL002", RuleVersion: "1", Severity: rule.Severity,
			AffectedEntityIDs: []string{role.ID}, EvidenceIDs: sortedUnique(evidenceIDs),
			Condition:      "A Vault Kubernetes auth role has a subject binding outside the exact IL002 policy allowlist or contains a wildcard.",
			Description:    fmt.Sprintf("Vault Kubernetes auth role %q binds service accounts %q in namespaces %q.", role.NativeID, names, namespaces),
			Recommendation: "Restrict the role to exact reviewed service account and namespace bindings, or add an exact IL002 policy allowlist entry.",
			Limitations:    []string{"This is configured Vault auth role metadata, not proof of a successful login or effective policy access."},
		})
	}
	result.FindingIDs = make([]string, len(findings))
	for i := range findings {
		result.FindingIDs[i] = findings[i].ID
	}
	switch {
	case len(findings) > 0:
		result.Outcome = model.OutcomeFail
	case len(result.Limitations) > 0:
		result.Outcome = model.OutcomeUnknown
	case !assessed:
		result.Outcome = model.OutcomeNotApplicable
	default:
		result.Outcome = model.OutcomePass
	}
	return result, findings
}

func vaultAuthType(entity model.Entity) string {
	value, _ := vaultString(entity, "auth_type")
	return value
}
func vaultString(entity model.Entity, key string) (string, bool) {
	raw, ok := entity.Attributes[key]
	if !ok || entity.FieldStatus[key] != model.FieldKnown {
		return "", false
	}
	var value string
	return value, json.Unmarshal(raw, &value) == nil
}
func vaultStringList(entity model.Entity, key string) ([]string, bool) {
	raw, ok := entity.Attributes[key]
	if !ok || entity.FieldStatus[key] != model.FieldKnown {
		return nil, false
	}
	var value []string
	return value, json.Unmarshal(raw, &value) == nil
}
func vaultBindingAllowed(role model.Entity, graph graph.Graph, rule policy.Rule) bool {
	for _, binding := range rule.AllowedVaultKubernetesBindings {
		if binding.VaultSourceID != role.SourceID || binding.RoleNativeID != role.NativeID {
			continue
		}
		for _, edge := range graph.Outgoing(role.ID, "trusts_subject") {
			subject := graph.Entities[edge.To]
			if subject.SourceID == binding.KubernetesSourceID && subject.NativeID == binding.ServiceAccountID {
				return true
			}
		}
	}
	return false
}
func entityEvidence(snapshot model.Snapshot, sourceID, nativeID string) []string {
	var result []string
	for _, e := range snapshot.Evidence {
		if e.SourceID == sourceID && e.NativeID == nativeID {
			result = append(result, e.ID)
		}
	}
	return result
}

func assessCompleteness(snapshot model.Snapshot, configuredPolicy policy.Policy) model.Completeness {
	sources := make(map[string]model.Source, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		sources[source.ID] = source
	}

	requiredIDs := append([]string(nil), configuredPolicy.RequiredSources...)
	sort.Strings(requiredIDs)
	result := model.Completeness{
		Complete:        true,
		RequiredSources: make([]model.SourceAssessment, 0, len(requiredIDs)),
	}
	for _, sourceID := range requiredIDs {
		assessment := model.SourceAssessment{SourceID: sourceID}
		source, present := sources[sourceID]
		if !present {
			assessment.Limitations = []string{"Required source is missing from the snapshot."}
			result.Complete = false
			result.RequiredSources = append(result.RequiredSources, assessment)
			continue
		}

		assessment.Present = true
		assessment.Status = string(source.Status)
		assessment.Complete = source.Complete
		assessment.PaginationComplete = source.PaginationComplete
		switch {
		case source.Status != model.SourceOK:
			assessment.Limitations = append(assessment.Limitations, "Source status is not ok.")
		case !source.Complete:
			assessment.Limitations = append(assessment.Limitations, "Source collection is incomplete.")
		case !source.PaginationComplete:
			assessment.Limitations = append(assessment.Limitations, "Source pagination is incomplete.")
		}
		assessment.SatisfiesRequiredCoverage = len(assessment.Limitations) == 0
		if !assessment.SatisfiesRequiredCoverage {
			result.Complete = false
		}
		result.RequiredSources = append(result.RequiredSources, assessment)
	}
	return result
}

func evaluateIL001(
	graph graph.Graph,
	snapshot model.Snapshot,
	rule policy.Rule,
	completeness model.Completeness,
) (model.RuleResult, []model.Finding) {
	result := model.RuleResult{
		RuleID:      "IL001",
		RuleVersion: il001Version,
	}
	if !completeness.Complete {
		result.Outcome = model.OutcomeUnknown
		result.Limitations = requiredCoverageLimitations(completeness)
		return result, nil
	}

	sourceKinds := make(map[string]string, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		sourceKinds[source.ID] = source.Kind
	}

	bindingIDs := make([]string, 0)
	for entityID, entity := range graph.Entities {
		if entity.Kind == "role_binding" && sourceKinds[entity.SourceID] == "kubernetes" {
			bindingIDs = append(bindingIDs, entityID)
		}
	}
	sort.Strings(bindingIDs)

	limitations := make([]string, 0)
	findings := make([]model.Finding, 0)
	seenFindingIDs := make(map[string]struct{})
	assessedGrant := false
	for _, bindingID := range bindingIDs {
		binding := graph.Entities[bindingID]
		grants := graph.Outgoing(bindingID, "grants_role")
		subjects := graph.Outgoing(bindingID, "bound_to")
		if len(grants) == 0 || len(subjects) == 0 {
			limitations = append(limitations, "A Kubernetes role_binding lacks either a grants_role or bound_to relationship.")
			continue
		}

		for _, grant := range grants {
			role := graph.Entities[grant.To]
			if role.Kind != "role" || role.SourceID != binding.SourceID {
				limitations = append(limitations, "A Kubernetes grants_role relationship does not resolve to a role in the binding source.")
				continue
			}
			if _, err := knownRoleKind(role); err != nil {
				limitations = append(limitations, "A bound Kubernetes role has unknown or unsupported role_kind.")
				continue
			}
			rules, err := roleRBACRules(role)
			if err != nil {
				limitations = append(limitations, "A bound Kubernetes role has unknown or unsupported rbac_rules.")
				continue
			}

			for _, subject := range subjects {
				serviceAccount := graph.Entities[subject.To]
				if serviceAccount.Kind != "service_account" || serviceAccount.SourceID != binding.SourceID {
					limitations = append(limitations, "A Kubernetes bound_to relationship does not resolve to a service account in the binding source.")
					continue
				}
				if grant.Scope != subject.Scope || grant.Scope != binding.Scope {
					limitations = append(limitations, "Kubernetes role binding scope is inconsistent across its entity and relationships.")
					continue
				}

				assessedGrant = true
				for _, rbacRule := range rules {
					if !containsWildcard(rbacRule) {
						continue
					}
					if rule.AllowsGrant(role.SourceID, role.NativeID, serviceAccount.NativeID, grant.Scope) {
						continue
					}
					finding := wildcardFinding(rule, binding, role, serviceAccount, grant, subject, rbacRule)
					if _, duplicate := seenFindingIDs[finding.ID]; duplicate {
						continue
					}
					seenFindingIDs[finding.ID] = struct{}{}
					findings = append(findings, finding)
				}
			}
		}
	}

	sort.Slice(findings, func(left, right int) bool {
		return findings[left].ID < findings[right].ID
	})
	result.FindingIDs = make([]string, 0, len(findings))
	for _, finding := range findings {
		result.FindingIDs = append(result.FindingIDs, finding.ID)
	}
	result.Limitations = sortedUnique(limitations)

	switch {
	case len(findings) > 0:
		result.Outcome = model.OutcomeFail
	case len(result.Limitations) > 0:
		result.Outcome = model.OutcomeUnknown
	case !assessedGrant:
		result.Outcome = model.OutcomeNotApplicable
	default:
		result.Outcome = model.OutcomePass
	}
	return result, findings
}

func wildcardFinding(
	rule policy.Rule,
	binding model.Entity,
	role model.Entity,
	serviceAccount model.Entity,
	grant model.Relationship,
	subject model.Relationship,
	rbacRule model.RBACRule,
) model.Finding {
	fingerprint, _ := json.Marshal(rbacRule)
	return model.Finding{
		ID:          model.FindingID("IL001", il001Version, grant.ID, subject.ID, string(fingerprint)),
		RuleID:      "IL001",
		RuleVersion: il001Version,
		Severity:    rule.Severity,
		AffectedEntityIDs: sortedUnique([]string{
			binding.ID,
			role.ID,
			serviceAccount.ID,
		}),
		AffectedRelationshipIDs: sortedUnique([]string{
			grant.ID,
			subject.ID,
		}),
		EvidenceIDs: sortedUnique(append(
			append([]string(nil), grant.EvidenceIDs...),
			subject.EvidenceIDs...,
		)),
		Condition: "A wildcard RBAC rule is bound to a Kubernetes service account without an exact IL001 policy allowlist entry.",
		Description: fmt.Sprintf(
			"Role %q is bound to service account %q in scope %q and contains a wildcard RBAC rule.",
			role.NativeID,
			serviceAccount.NativeID,
			grant.Scope,
		),
		Recommendation: "Replace wildcard RBAC values with the minimum required apiGroups, resources, and verbs, or add an exact reviewed allowlist entry.",
		Limitations: []string{
			"This is a configured RBAC grant, not proof of effective runtime access or a successful login.",
		},
	}
}

func knownRoleKind(entity model.Entity) (string, error) {
	if entity.FieldStatus["role_kind"] != model.FieldKnown {
		return "", fmt.Errorf("role_kind is not known")
	}
	raw, ok := entity.Attributes["role_kind"]
	if !ok {
		return "", fmt.Errorf("role_kind is missing")
	}
	var roleKind string
	if err := json.Unmarshal(raw, &roleKind); err != nil {
		return "", fmt.Errorf("role_kind is invalid")
	}
	if roleKind != "Role" && roleKind != "ClusterRole" {
		return "", fmt.Errorf("role_kind is unsupported")
	}
	return roleKind, nil
}

func roleRBACRules(entity model.Entity) ([]model.RBACRule, error) {
	if entity.FieldStatus["rbac_rules"] != model.FieldKnown {
		return nil, fmt.Errorf("rbac_rules is not known")
	}
	raw, ok := entity.Attributes["rbac_rules"]
	if !ok {
		return nil, fmt.Errorf("rbac_rules is missing")
	}
	if err := model.ValidateRBACRules(raw); err != nil {
		return nil, err
	}
	var rules []model.RBACRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("decode rbac_rules")
	}
	return rules, nil
}

func containsWildcard(rule model.RBACRule) bool {
	return listContainsWildcard(rule.APIGroups) ||
		listContainsWildcard(rule.Resources) ||
		listContainsWildcard(rule.Verbs)
}

func listContainsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func requiredCoverageLimitations(completeness model.Completeness) []string {
	limitations := make([]string, 0)
	for _, assessment := range completeness.RequiredSources {
		if !assessment.SatisfiesRequiredCoverage {
			limitations = append(limitations, assessment.Limitations...)
		}
	}
	return sortedUnique(limitations)
}

func inputProvenances(snapshot model.Snapshot) []model.Provenance {
	seen := make(map[model.Provenance]struct{})
	for _, source := range snapshot.Sources {
		seen[source.Provenance] = struct{}{}
	}
	for _, entity := range snapshot.Entities {
		seen[entity.Provenance] = struct{}{}
	}
	result := make([]model.Provenance, 0, len(seen))
	for provenance := range seen {
		result = append(result, provenance)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left] < result[right]
	})
	return result
}

func includesSyntheticFixture(provenances []model.Provenance) bool {
	for _, provenance := range provenances {
		if provenance == model.ProvenanceSyntheticFixture {
			return true
		}
	}
	return false
}

func sortedEvidence(evidence []model.Evidence) []model.Evidence {
	result := append([]model.Evidence(nil), evidence...)
	sort.Slice(result, func(left, right int) bool {
		return result[left].ID < result[right].ID
	})
	return result
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	writeIndex := 1
	for readIndex := 1; readIndex < len(result); readIndex++ {
		if result[readIndex] == result[writeIndex-1] {
			continue
		}
		result[writeIndex] = result[readIndex]
		writeIndex++
	}
	return result[:writeIndex]
}
