package policy

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

const MaxPolicyBytes = 1 << 20

type Policy struct {
	SchemaVersion           int
	RequiredSources         []string
	Rules                   map[string]Rule
	MaxClientSecretValidity time.Duration
	MaxX509SVIDTTL          time.Duration
	MaxJWTSVIDTTL           time.Duration
}

type Rule struct {
	SeparatedEnvironments          []EnvironmentPair
	AllowedSharedIdentities        []SharedIdentity
	ForbidNamespaceOnly            *bool
	Severity                       model.Severity
	AllowedGrants                  []AllowedGrant
	AllowedVaultKubernetesBindings []AllowedVaultKubernetesBinding
	RequireOwnersFor               []EntraOwnerTarget
	AllowedAppRoles                []EntraAppRole
}

type EntraOwnerTarget struct{ SourceID, ObjectID, ObjectKind string }
type EntraAppRole struct{ SourceID, PrincipalObjectID, ResourceObjectID, AppRoleID string }

type AllowedGrant struct {
	SourceID               string
	RoleNativeID           string
	ServiceAccountNativeID string
	Scope                  string
}

type AllowedVaultKubernetesBinding struct {
	VaultSourceID      string
	RoleNativeID       string
	KubernetesSourceID string
	ServiceAccountID   string
}

type yamlLine struct {
	number int
	indent int
	text   string
}

func Load(path string) (Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("stat policy: %w", err)
	}
	if info.Size() > MaxPolicyBytes {
		return Policy{}, fmt.Errorf("policy exceeds the %d-byte M0 limit", MaxPolicyBytes)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse accepts the documented, strict M0 YAML subset. Unsupported YAML
// constructs fail rather than being interpreted with broader semantics.
func Parse(data []byte) (Policy, error) {
	lines, err := tokenize(data)
	if err != nil {
		return Policy{}, err
	}

	result := Policy{Rules: make(map[string]Rule)}
	seenTopLevel := make(map[string]struct{})

	for position := 0; position < len(lines); {
		line := lines[position]
		if line.indent != 0 {
			return Policy{}, lineError(line, "top-level key must have no indentation")
		}
		key, value, err := splitMapping(line)
		if err != nil {
			return Policy{}, err
		}
		if _, duplicate := seenTopLevel[key]; duplicate {
			return Policy{}, lineError(line, "duplicate top-level key")
		}
		seenTopLevel[key] = struct{}{}

		switch key {
		case "limits":
			if value != "" {
				return Policy{}, lineError(line, "limits must be a mapping")
			}
			position++
			if position >= len(lines) || lines[position].indent != 2 {
				return Policy{}, lineError(line, "limits requires a duration mapping")
			}
			seenLimits := map[string]bool{}
			for position < len(lines) && lines[position].indent > 0 {
				child := lines[position]
				if child.indent != 2 {
					return Policy{}, lineError(child, "limit keys require two-space indentation")
				}
				name, text, e := splitMapping(child)
				if e != nil {
					return Policy{}, e
				}
				if seenLimits[name] {
					return Policy{}, lineError(child, "duplicate limit")
				}
				seenLimits[name] = true
				duration, e := time.ParseDuration(text)
				if e != nil || duration <= 0 {
					return Policy{}, lineError(child, "limit must be a positive duration")
				}
				switch name {
				case "max_client_secret_validity":
					result.MaxClientSecretValidity = duration
				case "max_x509_svid_ttl":
					result.MaxX509SVIDTTL = duration
				case "max_jwt_svid_ttl":
					result.MaxJWTSVIDTTL = duration
				default:
					return Policy{}, lineError(child, "unsupported limit")
				}
				position++
			}
		case "schema_version":
			scalar, err := parseScalar(line, value)
			if err != nil {
				return Policy{}, err
			}
			version, err := strconv.Atoi(scalar)
			if err != nil {
				return Policy{}, lineError(line, "schema_version must be an integer")
			}
			result.SchemaVersion = version
			position++
		case "required_sources":
			if value != "" {
				return Policy{}, lineError(line, "required_sources must be a block list")
			}
			position++
			sources, next, err := parseSourceList(lines, position)
			if err != nil {
				return Policy{}, err
			}
			result.RequiredSources = sources
			position = next
		case "rules":
			if value != "" {
				return Policy{}, lineError(line, "rules must be a mapping")
			}
			position++
			rules, next, err := parseRules(lines, position)
			if err != nil {
				return Policy{}, err
			}
			result.Rules = rules
			position = next
		default:
			return Policy{}, lineError(line, "unsupported top-level key")
		}
	}

	if err := result.Validate(); err != nil {
		return Policy{}, fmt.Errorf("invalid policy: %w", err)
	}
	return result, nil
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1")
	}
	if len(policy.RequiredSources) == 0 {
		return fmt.Errorf("required_sources must not be empty")
	}
	if hasDuplicate(policy.RequiredSources) {
		return fmt.Errorf("required_sources contains a duplicate")
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > 8 {
		return fmt.Errorf("M7 supports IL001 through IL008")
	}
	for ruleID, rule := range policy.Rules {
		if ruleID != "IL001" && ruleID != "IL002" && ruleID != "IL003" && ruleID != "IL004" && ruleID != "IL005" && ruleID != "IL006" && ruleID != "IL007" && ruleID != "IL008" {
			return fmt.Errorf("unsupported rule %q", ruleID)
		}
		if model.SeverityRank(rule.Severity) == 0 {
			return fmt.Errorf("%s severity is invalid", ruleID)
		}
	}
	if _, ok := policy.Rules["IL003"]; ok && policy.MaxClientSecretValidity <= 0 {
		return fmt.Errorf("IL003 requires limits.max_client_secret_validity")
	}
	if rule, ok := policy.Rules["IL006"]; ok && rule.ForbidNamespaceOnly == nil {
		return fmt.Errorf("IL006 requires forbid_namespace_only")
	}
	if _, ok := policy.Rules["IL007"]; ok && (policy.MaxX509SVIDTTL <= 0 || policy.MaxJWTSVIDTTL <= 0 || policy.MaxX509SVIDTTL%time.Second != 0 || policy.MaxJWTSVIDTTL%time.Second != 0) {
		return fmt.Errorf("IL007 requires positive whole-second max_x509_svid_ttl and max_jwt_svid_ttl limits")
	}
	for ruleID, rule := range policy.Rules {
		if err := validateEnvironments(ruleID, rule); err != nil {
			return err
		}
		if ruleID != "IL006" && rule.ForbidNamespaceOnly != nil {
			return fmt.Errorf("namespace-only setting requires IL006")
		}
		if ruleID != "IL001" && len(rule.AllowedGrants) > 0 || ruleID != "IL002" && len(rule.AllowedVaultKubernetesBindings) > 0 || ruleID != "IL004" && len(rule.RequireOwnersFor) > 0 || ruleID != "IL005" && len(rule.AllowedAppRoles) > 0 {
			return fmt.Errorf("rule contains configuration for another rule")
		}
		seenOwners := map[EntraOwnerTarget]bool{}
		for _, target := range rule.RequireOwnersFor {
			if target.SourceID == "" || !validObjectID(target.ObjectID) || (target.ObjectKind != "application_registration" && target.ObjectKind != "service_principal") || seenOwners[target] {
				return fmt.Errorf("IL004 requires unique exact source_id, object_id and object_kind targets")
			}
			seenOwners[target] = true
		}
		seenRoles := map[EntraAppRole]bool{}
		for _, grant := range rule.AllowedAppRoles {
			if grant.SourceID == "" || !validObjectID(grant.PrincipalObjectID) || !validObjectID(grant.ResourceObjectID) || !validObjectID(grant.AppRoleID) || seenRoles[grant] {
				return fmt.Errorf("IL005 requires unique exact source_id, principal_object_id, resource_object_id and app_role_id entries")
			}
			seenRoles[grant] = true
		}
	}
	if rule, ok := policy.Rules["IL001"]; ok {
		for index, grant := range rule.AllowedGrants {
			if grant.SourceID == "" || grant.RoleNativeID == "" || grant.ServiceAccountNativeID == "" || grant.Scope == "" {
				return fmt.Errorf("IL001 allowed_grants entry at index %d must contain source_id, role_native_id, service_account_native_id, and scope", index)
			}
		}
	}
	if rule, ok := policy.Rules["IL002"]; ok {
		for index, binding := range rule.AllowedVaultKubernetesBindings {
			if binding.VaultSourceID == "" || binding.RoleNativeID == "" || binding.KubernetesSourceID == "" || binding.ServiceAccountID == "" {
				return fmt.Errorf("IL002 allowed_kubernetes_bindings entry at index %d must contain vault_source_id, role_native_id, kubernetes_source_id, and service_account_id", index)
			}
		}
	}
	return nil
}

func (rule Rule) AllowsGrant(sourceID, roleNativeID, serviceAccountNativeID, scope string) bool {
	for _, allowed := range rule.AllowedGrants {
		if allowed.SourceID == sourceID &&
			allowed.RoleNativeID == roleNativeID &&
			allowed.ServiceAccountNativeID == serviceAccountNativeID &&
			allowed.Scope == scope {
			return true
		}
	}
	return false
}

func tokenize(data []byte) ([]yamlLine, error) {
	rawLines := strings.Split(string(data), "\n")
	result := make([]yamlLine, 0, len(rawLines))
	for index, raw := range rawLines {
		raw = strings.TrimSuffix(raw, "\r")
		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("policy line %d: tabs are unsupported", index+1)
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, " #") {
			return nil, fmt.Errorf("policy line %d: inline comments are unsupported", index+1)
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent%2 != 0 {
			return nil, fmt.Errorf("policy line %d: indentation must use two-space levels", index+1)
		}
		result = append(result, yamlLine{
			number: index + 1,
			indent: indent,
			text:   trimmed,
		})
	}
	return result, nil
}

func parseSourceList(lines []yamlLine, position int) ([]string, int, error) {
	result := make([]string, 0)
	for position < len(lines) && lines[position].indent > 0 {
		line := lines[position]
		if line.indent != 2 || !strings.HasPrefix(line.text, "- ") {
			return nil, 0, lineError(line, "required_sources entries must be two-space list items")
		}
		value, err := parseScalar(line, strings.TrimSpace(strings.TrimPrefix(line.text, "- ")))
		if err != nil {
			return nil, 0, err
		}
		result = append(result, value)
		position++
	}
	return result, position, nil
}

func parseRules(lines []yamlLine, position int) (map[string]Rule, int, error) {
	result := make(map[string]Rule)
	for position < len(lines) && lines[position].indent > 0 {
		line := lines[position]
		if line.indent != 2 {
			return nil, 0, lineError(line, "rule names must be indented by two spaces")
		}
		ruleID, value, err := splitMapping(line)
		if err != nil {
			return nil, 0, err
		}
		if value != "" {
			return nil, 0, lineError(line, "rule must be a mapping")
		}
		if _, duplicate := result[ruleID]; duplicate {
			return nil, 0, lineError(line, "duplicate rule")
		}

		position++
		rule, next, err := parseRule(lines, position, ruleID)
		if err != nil {
			return nil, 0, err
		}
		result[ruleID] = rule
		position = next
	}
	return result, position, nil
}

func parseRule(lines []yamlLine, position int, ruleID string) (Rule, int, error) {
	result := Rule{}
	seen := make(map[string]struct{})

	for position < len(lines) && lines[position].indent > 2 {
		line := lines[position]
		if line.indent != 4 {
			return Rule{}, 0, lineError(line, "rule keys must be indented by four spaces")
		}
		key, value, err := splitMapping(line)
		if err != nil {
			return Rule{}, 0, err
		}
		if _, duplicate := seen[key]; duplicate {
			return Rule{}, 0, lineError(line, "duplicate rule key")
		}
		seen[key] = struct{}{}
		if key != "severity" && !((ruleID == "IL001" && key == "allowed_grants") || (ruleID == "IL002" && key == "allowed_kubernetes_bindings") || (ruleID == "IL004" && key == "require_owners_for") || (ruleID == "IL005" && key == "allowed_app_roles") || (ruleID == "IL006" && key == "forbid_namespace_only") || (ruleID == "IL008" && (key == "separated_environments" || key == "allowed_shared_identities"))) {
			return Rule{}, 0, lineError(line, "unsupported key for this rule")
		}

		switch key {
		case "separated_environments", "allowed_shared_identities":
			if value != "" {
				return Rule{}, 0, lineError(line, "environment settings must be block lists")
			}
			entries, next, e := parseEnvironmentEntries(lines, position+1, key)
			if e != nil {
				return Rule{}, 0, e
			}
			position = next
			for _, entry := range entries {
				pair := EnvironmentPair{entry["first"], entry["second"]}
				if key == "separated_environments" {
					result.SeparatedEnvironments = append(result.SeparatedEnvironments, pair)
				} else {
					result.AllowedSharedIdentities = append(result.AllowedSharedIdentities, SharedIdentity{EnvironmentPair: pair, SourceID: entry["source_id"], Kind: entry["kind"], NativeID: entry["native_id"], Reason: entry["reason"]})
				}
			}
		case "forbid_namespace_only":
			if value != "true" && value != "false" {
				return Rule{}, 0, lineError(line, "forbid_namespace_only requires true or false")
			}
			b := value == "true"
			result.ForbidNamespaceOnly = &b
			position++
		case "require_owners_for", "allowed_app_roles":
			if value != "" {
				return Rule{}, 0, lineError(line, "Entra rule targets must be a block list")
			}
			position++
			entries, next, e := parseEntraEntries(lines, position, key)
			if e != nil {
				return Rule{}, 0, e
			}
			position = next
			for _, entry := range entries {
				if key == "require_owners_for" {
					result.RequireOwnersFor = append(result.RequireOwnersFor, EntraOwnerTarget{SourceID: entry["source_id"], ObjectID: entry["object_id"], ObjectKind: entry["object_kind"]})
				} else {
					result.AllowedAppRoles = append(result.AllowedAppRoles, EntraAppRole{SourceID: entry["source_id"], PrincipalObjectID: entry["principal_object_id"], ResourceObjectID: entry["resource_object_id"], AppRoleID: entry["app_role_id"]})
				}
			}
		case "severity":
			scalar, err := parseScalar(line, value)
			if err != nil {
				return Rule{}, 0, err
			}
			result.Severity = model.Severity(scalar)
			position++
		case "allowed_grants":
			if value != "" {
				return Rule{}, 0, lineError(line, "allowed_grants must be a block list")
			}
			position++
			grants, next, err := parseAllowedGrants(lines, position)
			if err != nil {
				return Rule{}, 0, err
			}
			result.AllowedGrants = grants
			position = next
		case "allowed_kubernetes_bindings":
			if value != "" {
				return Rule{}, 0, lineError(line, "allowed_kubernetes_bindings must be a block list")
			}
			position++
			bindings, next, err := parseAllowedVaultKubernetesBindings(lines, position)
			if err != nil {
				return Rule{}, 0, err
			}
			result.AllowedVaultKubernetesBindings = bindings
			position = next
		default:
			return Rule{}, 0, lineError(line, "unsupported rule key")
		}

	}
	return result, position, nil
}

func parseAllowedVaultKubernetesBindings(lines []yamlLine, position int) ([]AllowedVaultKubernetesBinding, int, error) {
	result := make([]AllowedVaultKubernetesBinding, 0)
	for position < len(lines) && lines[position].indent > 4 {
		line := lines[position]
		if line.indent != 6 || !strings.HasPrefix(line.text, "- ") {
			return nil, 0, lineError(line, "allowed_kubernetes_bindings entries must be six-space list items")
		}
		entry := AllowedVaultKubernetesBinding{}
		key, value, err := splitMappingText(line, strings.TrimSpace(strings.TrimPrefix(line.text, "- ")))
		if err != nil {
			return nil, 0, err
		}
		if err := setVaultBindingField(&entry, key, value, line); err != nil {
			return nil, 0, err
		}
		position++
		seen := map[string]struct{}{key: {}}
		for position < len(lines) && lines[position].indent > 6 {
			child := lines[position]
			if child.indent != 8 {
				return nil, 0, lineError(child, "allowed_kubernetes_bindings keys must be indented by eight spaces")
			}
			childKey, childValue, err := splitMapping(child)
			if err != nil {
				return nil, 0, err
			}
			if _, duplicate := seen[childKey]; duplicate {
				return nil, 0, lineError(child, "duplicate allowed_kubernetes_bindings key")
			}
			seen[childKey] = struct{}{}
			if err := setVaultBindingField(&entry, childKey, childValue, child); err != nil {
				return nil, 0, err
			}
			position++
		}
		result = append(result, entry)
	}
	return result, position, nil
}

func setVaultBindingField(entry *AllowedVaultKubernetesBinding, key, value string, line yamlLine) error {
	scalar, err := parseScalar(line, value)
	if err != nil {
		return err
	}
	switch key {
	case "vault_source_id":
		entry.VaultSourceID = scalar
	case "role_native_id":
		entry.RoleNativeID = scalar
	case "kubernetes_source_id":
		entry.KubernetesSourceID = scalar
	case "service_account_id":
		entry.ServiceAccountID = scalar
	default:
		return lineError(line, "unsupported allowed_kubernetes_bindings key")
	}
	return nil
}

func parseAllowedGrants(lines []yamlLine, position int) ([]AllowedGrant, int, error) {
	result := make([]AllowedGrant, 0)
	for position < len(lines) && lines[position].indent > 4 {
		line := lines[position]
		if line.indent != 6 || !strings.HasPrefix(line.text, "- ") {
			return nil, 0, lineError(line, "allowed_grants entries must be six-space list items")
		}

		entry := AllowedGrant{}
		key, value, err := splitMappingText(line, strings.TrimSpace(strings.TrimPrefix(line.text, "- ")))
		if err != nil {
			return nil, 0, err
		}
		if err := setGrantField(&entry, key, value, line); err != nil {
			return nil, 0, err
		}
		position++

		seen := map[string]struct{}{key: {}}
		for position < len(lines) && lines[position].indent > 6 {
			child := lines[position]
			if child.indent != 8 {
				return nil, 0, lineError(child, "allowed_grants keys must be indented by eight spaces")
			}
			childKey, childValue, err := splitMapping(child)
			if err != nil {
				return nil, 0, err
			}
			if _, duplicate := seen[childKey]; duplicate {
				return nil, 0, lineError(child, "duplicate allowed_grants key")
			}
			seen[childKey] = struct{}{}
			if err := setGrantField(&entry, childKey, childValue, child); err != nil {
				return nil, 0, err
			}
			position++
		}
		result = append(result, entry)
	}
	return result, position, nil
}

func setGrantField(entry *AllowedGrant, key, value string, line yamlLine) error {
	scalar, err := parseScalar(line, value)
	if err != nil {
		return err
	}
	switch key {
	case "source_id":
		entry.SourceID = scalar
	case "role_native_id":
		entry.RoleNativeID = scalar
	case "service_account_native_id":
		entry.ServiceAccountNativeID = scalar
	case "scope":
		entry.Scope = scalar
	default:
		return lineError(line, "unsupported allowed_grants key")
	}
	return nil
}

func splitMapping(line yamlLine) (string, string, error) {
	return splitMappingText(line, line.text)
}

func splitMappingText(line yamlLine, text string) (string, string, error) {
	separator := strings.Index(text, ":")
	if separator < 1 {
		return "", "", lineError(line, "expected a mapping key")
	}
	key := strings.TrimSpace(text[:separator])
	if !isValidKey(key) {
		return "", "", lineError(line, "mapping key is invalid")
	}
	return key, strings.TrimSpace(text[separator+1:]), nil
}

func parseScalar(line yamlLine, value string) (string, error) {
	if value == "" {
		return "", lineError(line, "scalar value is required")
	}
	if strings.ContainsAny(value, "[]{}&*!|>@`") || strings.Contains(value, "#") {
		return "", lineError(line, "YAML flow, tag, anchor, alias, and comment syntax is unsupported")
	}
	if strings.HasPrefix(value, "- ") {
		return "", lineError(line, "nested sequences are unsupported")
	}
	return value, nil
}

func isValidKey(value string) bool {
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return value != ""
}

func hasDuplicate(values []string) bool {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index] == sorted[index-1] {
			return true
		}
	}
	return false
}

func lineError(line yamlLine, message string) error {
	return fmt.Errorf("policy line %d: %s", line.number, message)
}
