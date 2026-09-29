package entra

import (
	"context"
	"encoding/json"

	"github.com/grantlinehq/grantline/internal/model"
)

func (c *collection) assignments(ctx context.Context, parent *model.Entity, id string) {
	endpoint := "/servicePrincipals/" + id + "/appRoleAssignments"
	seen := map[string]bool{}
	count := 0
	unresolved := false
	code := c.list(ctx, endpoint, "id,principalId,principalType,resourceId,appRoleId", func(raw json.RawMessage) bool {
		var value struct {
			ID            string `json:"id"`
			PrincipalID   string `json:"principalId"`
			PrincipalType string `json:"principalType"`
			ResourceID    string `json:"resourceId"`
			RoleID        string `json:"appRoleId"`
		}
		if json.Unmarshal(raw, &value) != nil || !assignmentID.MatchString(value.ID) || seen[value.ID] || value.PrincipalID != id || value.PrincipalType != "ServicePrincipal" || !guid.MatchString(value.ResourceID) || !guid.MatchString(value.RoleID) {
			return false
		}
		seen[value.ID] = true
		binding := c.entity("role_binding", childNative(c.config.TenantID, "servicePrincipals", id, "appRoleAssignments", value.ID), "")
		c.set(binding, "binding_kind", "entra_app_role_assignment")
		c.set(binding, "assignment_id", value.ID)
		c.set(binding, "principal_object_id", id)
		c.set(binding, "resource_object_id", value.ResourceID)
		c.set(binding, "app_role_id", value.RoleID)
		binding.FieldStatus["role_definition_id"] = model.FieldUnknown
		evidence := c.record(binding.NativeID, endpoint+"/"+value.ID, []string{"id", "principalId", "principalType", "resourceId", "appRoleId"}, model.AssertionConfigured)
		c.edge(binding, parent, "bound_to", evidence)
		count++
		resource, errCode := c.resource(ctx, value.ResourceID)
		if errCode != "" {
			if errCode == "HTTP_403" {
				binding.FieldStatus["role_definition_id"] = model.FieldPermissionDenied
			}
			unresolved = true
			c.fail("/servicePrincipals/"+value.ResourceID, errCode)
			return true
		}
		var selected *appRole
		if resource.Roles != nil && len(*resource.Roles) <= 1000 {
			for i, role := range *resource.Roles {
				if role.ID == value.RoleID {
					if selected != nil {
						selected = nil
						break
					}
					selected = &(*resource.Roles)[i]
				}
			}
		}
		if selected == nil || selected.Value == nil || *selected.Value == "" || !safeText(*selected.Value, 512) || selected.Enabled == nil || selected.MemberTypes == nil {
			unresolved = true
			return true
		}
		applicationRole := false
		for _, member := range *selected.MemberTypes {
			if member == "Application" {
				applicationRole = true
			}
		}
		if !applicationRole {
			unresolved = true
			return true
		}
		role := c.entity("role", childNative(c.config.TenantID, "servicePrincipals", value.ResourceID, "appRoles", value.RoleID), *selected.Value)
		c.set(role, "role_kind", "entra_app_role")
		c.set(role, "resource_object_id", value.ResourceID)
		c.set(role, "app_role_id", value.RoleID)
		c.set(role, "role_value", *selected.Value)
		c.set(role, "role_enabled", *selected.Enabled)
		c.set(role, "resource_app_id", resource.AppID)
		c.set(binding, "role_definition_id", role.NativeID)
		definition := c.record(role.NativeID, "/servicePrincipals/"+value.ResourceID+"#appRoles/"+value.RoleID, []string{"id", "value", "isEnabled", "allowedMemberTypes"}, model.AssertionConfigured)
		c.edge(binding, role, "grants_role", evidence, definition)
		return true
	})
	if code == "" && unresolved {
		code = "unresolved_app_role_assignment"
	}
	c.coverage(parent, "app_role_assignments_count", endpoint, code, count)
	if code == "" {
		c.record(parent.NativeID, endpoint, []string{"app_role_assignments_count"}, model.AssertionObserved)
	}
}

func (c *collection) resource(ctx context.Context, id string) (*directoryObject, string) {
	if object, ok := c.resources[id]; ok {
		return object, ""
	}
	if code, ok := c.resourceErrors[id]; ok {
		return nil, code
	}
	if c.resourceReads >= maxResources {
		return nil, "resource_limit"
	}
	c.resourceReads++
	endpoint := "/servicePrincipals/" + id
	var response directoryObject
	code := c.get(ctx, endpoint, "id,appId,displayName,appRoles", &response)
	if code == "" && (response.ID != id || !guid.MatchString(response.AppID) || !safeText(response.DisplayName, 512) || response.Roles == nil) {
		code = "invalid_resource_metadata"
	}
	if code != "" {
		c.resourceErrors[id] = code
		return nil, code
	}
	c.resources[id] = &response
	e := c.entity("service_principal", objectNative(c.config.TenantID, id), response.DisplayName)
	c.set(e, "object_id", id)
	c.set(e, "app_id", response.AppID)
	c.set(e, "collection_role", "grant_resource")
	c.record(e.NativeID, endpoint, []string{"id", "appId", "appRoles"}, model.AssertionObserved)
	return &response, ""
}
