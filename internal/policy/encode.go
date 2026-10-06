package policy

import (
	"fmt"
	"strings"
)

// Encode writes the same strict subset accepted by Parse. It does not merge
// defaults or omit supported exceptions when a policy is edited in a form.
func Encode(p Policy) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("schema_version: 1\nrequired_sources:\n")
	scalar := func(v string) error {
		if strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\t\x00") {
			return fmt.Errorf("policy values must be single-line scalars without surrounding whitespace")
		}
		_, err := parseScalar(yamlLine{}, v)
		return err
	}
	for _, id := range p.RequiredSources {
		if err := scalar(id); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "  - %s\n", id)
	}
	if p.MaxClientSecretValidity != 0 || p.MaxX509SVIDTTL != 0 || p.MaxJWTSVIDTTL != 0 {
		b.WriteString("limits:\n")
	}
	for _, v := range []struct{ key, value string }{
		{"max_client_secret_validity", p.MaxClientSecretValidity.String()},
		{"max_x509_svid_ttl", p.MaxX509SVIDTTL.String()},
		{"max_jwt_svid_ttl", p.MaxJWTSVIDTTL.String()},
	} {
		if v.value != "0s" {
			fmt.Fprintf(&b, "  %s: %s\n", v.key, v.value)
		}
	}
	b.WriteString("rules:\n")
	entries := func(key string, fields []string, rows [][]string) error {
		if len(rows) == 0 {
			return nil
		}
		fmt.Fprintf(&b, "    %s:\n", key)
		for _, row := range rows {
			for i, value := range row {
				if err := scalar(value); err != nil {
					return err
				}
				indent := "        "
				if i == 0 {
					indent = "      - "
				}
				fmt.Fprintf(&b, "%s%s: %s\n", indent, fields[i], value)
			}
		}
		return nil
	}
	for _, id := range []string{"IL001", "IL002", "IL003", "IL004", "IL005", "IL006", "IL007", "IL008", "IL009"} {
		r, ok := p.Rules[id]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "  %s:\n    severity: %s\n", id, r.Severity)
		if r.ForbidNamespaceOnly != nil {
			fmt.Fprintf(&b, "    forbid_namespace_only: %t\n", *r.ForbidNamespaceOnly)
		}
		var rows [][]string
		for _, v := range r.AllowedGrants {
			rows = append(rows, []string{v.SourceID, v.RoleNativeID, v.ServiceAccountNativeID, v.Scope})
		}
		if err := entries("allowed_grants", []string{"source_id", "role_native_id", "service_account_native_id", "scope"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.AllowedVaultKubernetesBindings {
			rows = append(rows, []string{v.VaultSourceID, v.RoleNativeID, v.KubernetesSourceID, v.ServiceAccountID})
		}
		if err := entries("allowed_kubernetes_bindings", []string{"vault_source_id", "role_native_id", "kubernetes_source_id", "service_account_id"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.RequireOwnersFor {
			rows = append(rows, []string{v.SourceID, v.ObjectID, v.ObjectKind})
		}
		if err := entries("require_owners_for", []string{"source_id", "object_id", "object_kind"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.AllowedAppRoles {
			rows = append(rows, []string{v.SourceID, v.PrincipalObjectID, v.ResourceObjectID, v.AppRoleID})
		}
		if err := entries("allowed_app_roles", []string{"source_id", "principal_object_id", "resource_object_id", "app_role_id"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.SeparatedEnvironments {
			rows = append(rows, []string{v.First, v.Second})
		}
		if err := entries("separated_environments", []string{"first", "second"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.AllowedSharedIdentities {
			rows = append(rows, []string{v.First, v.Second, v.SourceID, v.Kind, v.NativeID, v.Reason})
		}
		if err := entries("allowed_shared_identities", []string{"first", "second", "source_id", "kind", "native_id", "reason"}, rows); err != nil {
			return "", err
		}
		rows = nil
		for _, v := range r.AllowedSharedVaultRoles {
			rows = append(rows, []string{v.First, v.Second, v.VaultSourceID, v.RoleNativeID, v.Reason})
		}
		if err := entries("allowed_shared_vault_roles", []string{"first", "second", "vault_source_id", "role_native_id", "reason"}, rows); err != nil {
			return "", err
		}
	}
	encoded := b.String()
	if _, err := Parse([]byte(encoded)); err != nil {
		return "", err
	}
	return encoded, nil
}
