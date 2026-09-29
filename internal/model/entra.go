package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

type EntraRequestedPermission struct {
	ResourceAppID  string `json:"resource_app_id"`
	PermissionID   string `json:"permission_id"`
	PermissionType string `json:"permission_type"`
}

var entraUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateEntraAttribute(key string, raw json.RawMessage) error {
	invalid := fmt.Errorf("attribute %q has an unsupported Entra metadata shape", key)
	switch key {
	case "credential_type", "parent_kind", "collection_role", "owner_type", "principal_type":
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return invalid
		}
		choices := map[string][]string{"credential_type": {"client_secret", "certificate"}, "parent_kind": {"application_registration", "service_principal"}, "collection_role": {"selected", "grant_resource"}, "owner_type": {"user", "servicePrincipal", "application", "directoryObject"}, "principal_type": {"Application", "ManagedIdentity", "Legacy"}}
		for _, allowed := range choices[key] {
			if v == allowed {
				return nil
			}
		}
		return invalid
	case "tenant_id", "object_id", "app_id", "parent_object_id", "key_id", "resource_object_id", "resource_app_id", "principal_object_id", "app_role_id":
		var v string
		if json.Unmarshal(raw, &v) != nil || !entraUUID.MatchString(v) {
			return invalid
		}
	case "owners_count", "client_credentials_count", "key_credentials_count", "federated_credentials_count", "app_role_assignments_count":
		var v *int
		if json.Unmarshal(raw, &v) != nil || v == nil || *v < 0 || *v > 5000 {
			return invalid
		}
	case "role_enabled":
		var v *bool
		if json.Unmarshal(raw, &v) != nil || v == nil {
			return invalid
		}
	case "start_time", "end_time":
		var v string
		if json.Unmarshal(raw, &v) != nil {
			return invalid
		}
		if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
			return invalid
		}
	case "audiences":
		var v []string
		if json.Unmarshal(raw, &v) != nil || len(v) == 0 || len(v) > 20 {
			return invalid
		}
		for _, s := range v {
			if s == "" || len(s) > 2048 {
				return invalid
			}
		}
	case "requested_permissions":
		var v []EntraRequestedPermission
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&v) != nil || ensureSingleJSONValue(decoder) != nil || v == nil || len(v) > 5000 {
			return invalid
		}
		for _, p := range v {
			if !entraUUID.MatchString(p.ResourceAppID) || !entraUUID.MatchString(p.PermissionID) || (p.PermissionType != "Role" && p.PermissionType != "Scope") {
				return invalid
			}
		}
	default:
		if validateStringAttribute(raw) != nil {
			return invalid
		}
	}
	return nil
}

func validateEntraIdentity(e Entity, source Source) error {
	read := func(key string) string {
		var s string
		if e.FieldStatus[key] == FieldKnown {
			json.Unmarshal(e.Attributes[key], &s)
		}
		return s
	}
	tenant := read("tenant_id")
	if !entraUUID.MatchString(tenant) || source.Scope != "tenant/"+tenant || e.Scope != source.Scope {
		return fmt.Errorf("Entra entity tenant scope is inconsistent")
	}
	native := ""
	switch e.Kind {
	case "application_registration", "service_principal", "owner":
		object := read("object_id")
		if !entraUUID.MatchString(object) {
			return fmt.Errorf("Entra object identity is missing")
		}
		native = tenant + "/" + object
	case "credential_metadata":
		parent := read("parent_object_id")
		key := read("key_id")
		kind := read("parent_kind")
		if !entraUUID.MatchString(parent) || !entraUUID.MatchString(key) {
			return fmt.Errorf("Entra credential parent/key identity is missing")
		}
		collection := "applications"
		if kind == "service_principal" {
			collection = "servicePrincipals"
		} else if kind != "application_registration" {
			return fmt.Errorf("Entra credential parent kind is invalid")
		}
		var typ string
		json.Unmarshal(e.Attributes["credential_type"], &typ)
		child := "passwordCredentials"
		if typ == "certificate" {
			child = "keyCredentials"
		}
		native = tenant + "/" + collection + "/" + parent + "/" + child + "/" + key
	case "role":
		native = tenant + "/servicePrincipals/" + read("resource_object_id") + "/appRoles/" + read("app_role_id")
	case "role_binding":
		native = tenant + "/servicePrincipals/" + read("principal_object_id") + "/appRoleAssignments/" + read("assignment_id")
	case "federated_credential":
		prefix := tenant + "/applications/" + read("parent_object_id") + "/federatedIdentityCredentials/"
		if len(e.NativeID) > len(prefix) && e.NativeID[:len(prefix)] == prefix && entraUUID.MatchString(e.NativeID[len(prefix):]) {
			native = e.NativeID
		}
	default:
		return fmt.Errorf("unsupported Entra entity kind")
	}
	if native == "" || e.NativeID != native {
		return fmt.Errorf("Entra native identity is inconsistent")
	}
	return nil
}
