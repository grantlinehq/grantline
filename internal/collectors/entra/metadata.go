package entra

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

func (c *collection) credentials(parent *model.Entity, collectionName, id, typ string, values *[]credential, parentEvidence string) {
	key := "client_credentials_count"
	child := "passwordCredentials"
	if typ == "certificate" {
		key = "key_credentials_count"
		child = "keyCredentials"
	}
	endpoint := "/" + collectionName + "/" + id
	parent.FieldStatus[key] = model.FieldUnknown
	if values == nil {
		c.fail(endpoint, "missing_credential_metadata")
		return
	}
	if len(*values) > 1000 {
		c.fail(endpoint, "credential_limit")
		return
	}
	if len(c.entities)+len(*values) > 20000 {
		c.fail(endpoint, "entity_limit")
		return
	}
	seen := map[string]bool{}
	valid := true
	for _, value := range *values {
		if !guid.MatchString(value.KeyID) || seen[value.KeyID] {
			valid = false
			continue
		}
		seen[value.KeyID] = true
		e := c.entity("credential_metadata", childNative(c.config.TenantID, collectionName, id, child, value.KeyID), "")
		c.set(e, "parent_object_id", id)
		c.set(e, "parent_kind", parent.Kind)
		c.set(e, "key_id", value.KeyID)
		c.set(e, "credential_type", typ)
		if typ == "certificate" && value.Type != "AsymmetricX509Cert" && value.Type != "X509CertAndPassword" {
			e.FieldStatus["credential_type"] = model.FieldUnsupported
			valid = false
		}
		start, startOK := parseTime(value.Start)
		end, endOK := parseTime(value.End)
		e.FieldStatus["start_time"] = model.FieldUnknown
		e.FieldStatus["end_time"] = model.FieldUnknown
		if startOK {
			c.set(e, "start_time", start.Format(time.RFC3339Nano))
		}
		if endOK {
			c.set(e, "end_time", end.Format(time.RFC3339Nano))
		}
		if !startOK || !endOK || end.Before(start) {
			valid = false
			if startOK && endOK {
				e.FieldStatus["end_time"] = model.FieldUnsupported
			}
		}
		evidence := c.record(e.NativeID, endpoint+"#"+child+"/"+value.KeyID, []string{"key_id", "credential_type", "start_time", "end_time"}, model.AssertionConfigured)
		c.edge(parent, e, "references_credential", parentEvidence, evidence)
	}
	if !valid {
		c.fail(endpoint, "incomplete_credential_metadata")
		return
	}
	c.set(parent, key, len(*values))
	c.record(parent.NativeID, endpoint+"#"+child, []string{key}, model.AssertionObserved)
}
func parseTime(value *string) (time.Time, bool) {
	if value == nil || *value == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *value)
	return t.UTC(), err == nil
}

func (c *collection) owners(ctx context.Context, parent *model.Entity, endpoint string) {
	endpoint += "/owners"
	seen := map[string]bool{}
	count := 0
	code := c.list(ctx, endpoint, "id", func(raw json.RawMessage) bool {
		var value struct {
			ID   string `json:"id"`
			Type string `json:"@odata.type"`
		}
		if json.Unmarshal(raw, &value) != nil || !guid.MatchString(value.ID) || seen[value.ID] {
			return false
		}
		seen[value.ID] = true
		if value.Type != "#microsoft.graph.user" && value.Type != "#microsoft.graph.servicePrincipal" && value.Type != "#microsoft.graph.application" && value.Type != "#microsoft.graph.directoryObject" {
			return false
		}
		e := c.entity("owner", objectNative(c.config.TenantID, value.ID), "")
		c.set(e, "object_id", value.ID)
		c.set(e, "owner_type", strings.TrimPrefix(value.Type, "#microsoft.graph."))
		evidence := c.record(e.NativeID, endpoint+"/"+value.ID, []string{"id", "owner_type"}, model.AssertionConfigured)
		c.edge(parent, e, "owned_by", evidence)
		count++
		return true
	})
	c.coverage(parent, "owners_count", endpoint, code, count)
	if code == "" {
		c.record(parent.NativeID, endpoint, []string{"owners_count"}, model.AssertionObserved)
	}
}

func (c *collection) requested(parent *model.Entity, values *[]requestedResource, endpoint string) {
	parent.FieldStatus["requested_permissions"] = model.FieldUnknown
	if values == nil || len(*values) > 1000 {
		c.fail(endpoint, "missing_requested_permissions")
		return
	}
	result := make([]model.EntraRequestedPermission, 0)
	for _, resource := range *values {
		if !guid.MatchString(resource.AppID) || resource.Access == nil {
			c.fail(endpoint, "invalid_requested_permissions")
			return
		}
		for _, access := range *resource.Access {
			if !guid.MatchString(access.ID) || (access.Type != "Role" && access.Type != "Scope") || len(result) >= 5000 {
				c.fail(endpoint, "invalid_requested_permissions")
				return
			}
			result = append(result, model.EntraRequestedPermission{ResourceAppID: resource.AppID, PermissionID: access.ID, PermissionType: access.Type})
		}
	}
	c.set(parent, "requested_permissions", result)
	c.record(parent.NativeID, endpoint+"#requiredResourceAccess", []string{"requested_permissions"}, model.AssertionConfigured)
}

func (c *collection) federated(ctx context.Context, parent *model.Entity, id string) {
	endpoint := "/applications/" + id + "/federatedIdentityCredentials"
	seen := map[string]bool{}
	count := 0
	unsupported := false
	code := c.list(ctx, endpoint, "id,name,issuer,subject,audiences", func(raw json.RawMessage) bool {
		var value struct {
			ID, Name        string
			Issuer, Subject *string
			Audiences       *[]string
			Expression      json.RawMessage `json:"claimsMatchingExpression"`
		}
		if json.Unmarshal(raw, &value) != nil || !guid.MatchString(value.ID) || seen[value.ID] || !safeText(value.Name, 512) {
			return false
		}
		seen[value.ID] = true
		e := c.entity("federated_credential", childNative(c.config.TenantID, "applications", id, "federatedIdentityCredentials", value.ID), value.Name)
		c.set(e, "parent_object_id", id)
		var appID string
		json.Unmarshal(parent.Attributes["app_id"], &appID)
		c.set(e, "app_id", appID)
		e.FieldStatus["issuer"] = model.FieldUnknown
		e.FieldStatus["subject"] = model.FieldUnknown
		e.FieldStatus["audiences"] = model.FieldUnknown
		if value.Issuer == nil || *value.Issuer == "" || !safeText(*value.Issuer, 2048) || value.Subject == nil || *value.Subject == "" || !safeText(*value.Subject, 2048) || value.Audiences == nil || len(*value.Audiences) == 0 || len(*value.Audiences) > 20 {
			unsupported = true
		} else {
			c.set(e, "issuer", *value.Issuer)
			c.set(e, "subject", *value.Subject)
			valid := true
			for _, aud := range *value.Audiences {
				if aud == "" || !safeText(aud, 2048) {
					valid = false
				}
			}
			if valid {
				c.set(e, "audiences", *value.Audiences)
			} else {
				unsupported = true
			}
		}
		if len(value.Expression) > 0 && string(value.Expression) != "null" || value.Subject != nil && strings.ContainsAny(*value.Subject, "*?") {
			e.FieldStatus["subject"] = model.FieldUnsupported
			unsupported = true
		}
		evidence := c.record(e.NativeID, endpoint+"/"+value.ID, []string{"id", "issuer", "subject", "audiences"}, model.AssertionConfigured)
		c.edge(parent, e, "references_credential", evidence)
		count++
		return true
	})
	if code == "" && unsupported {
		code = "unsupported_federation_metadata"
	}
	c.coverage(parent, "federated_credentials_count", endpoint, code, count)
}
