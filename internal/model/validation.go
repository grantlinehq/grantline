package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

var validEntityKinds = map[string]struct{}{
	"business_application":     {},
	"workload":                 {},
	"service_account":          {},
	"application_registration": {},
	"service_principal":        {},
	"federated_credential":     {},
	"workflow":                 {},
	"job":                      {},
	"credential_reference":     {},
	"credential_metadata":      {},
	"vault_auth_role":          {},
	"policy":                   {},
	"role":                     {},
	"role_binding":             {},
	"owner":                    {},
	"spire_entry":              {},
	"spiffe_identity":          {},
	"trust_domain":             {},
}

var validRelationshipTypes = map[string]struct{}{
	"runs_as":                {},
	"bound_to":               {},
	"grants_role":            {},
	"uses_policy":            {},
	"references_credential":  {},
	"trusts_subject":         {},
	"registered_as":          {},
	"owned_by":               {},
	"selector_matches":       {},
	"assigned_spiffe_id":     {},
	"belongs_to_application": {},
}

var validSourceKinds = map[string]struct{}{
	"kubernetes": {},
	"vault":      {},
	"jenkins":    {},
	"github":     {},
	"entra":      {},
	"spire":      {},
}

var allowedAttributesByKind = map[string]map[string]struct{}{
	"spire_entry":              {"trust_domain": {}, "entry_id": {}, "spiffe_id": {}, "parent_spiffe_id": {}, "entry_kind": {}, "selectors": {}, "parent_entry_ids": {}, "parent_attestor_types": {}, "x509_ttl_mode": {}, "jwt_ttl_mode": {}, "x509_svid_ttl_seconds": {}, "jwt_svid_ttl_seconds": {}, "admin": {}, "downstream": {}, "federates_with": {}, "revision_number": {}, "entry_expires_at": {}, "entry_created_at": {}},
	"spiffe_identity":          {"trust_domain": {}, "spiffe_id": {}, "x509_issuance": {}},
	"trust_domain":             {"trust_domain": {}},
	"workflow":                 {"repository_id": {}, "repository_owner_id": {}, "repository_name": {}, "workflow_id": {}, "workflow_path": {}, "workflow_state": {}, "subject_format": {}, "revisions": {}, "smoke_results": {}},
	"application_registration": {"tenant_id": {}, "object_id": {}, "app_id": {}, "collection_role": {}, "owners_count": {}, "client_credentials_count": {}, "key_credentials_count": {}, "federated_credentials_count": {}, "requested_permissions": {}},
	"service_principal":        {"tenant_id": {}, "object_id": {}, "app_id": {}, "collection_role": {}, "principal_type": {}, "owners_count": {}, "client_credentials_count": {}, "key_credentials_count": {}, "app_role_assignments_count": {}},
	"credential_metadata":      {"tenant_id": {}, "parent_object_id": {}, "parent_kind": {}, "key_id": {}, "credential_type": {}, "start_time": {}, "end_time": {}},
	"federated_credential":     {"tenant_id": {}, "parent_object_id": {}, "app_id": {}, "issuer": {}, "subject": {}, "audiences": {}},
	"owner":                    {"tenant_id": {}, "object_id": {}, "owner_type": {}},
	"job": {
		"job_kind": {}, "buildable": {}, "builds": {}, "jenkinsfile_commit": {}, "credential_reference_count": {},
	},
	"credential_reference": {"credential_id": {}, "job_native_id": {}},
	"role": {
		"tenant_id": {}, "resource_object_id": {}, "resource_app_id": {}, "app_role_id": {}, "role_value": {}, "role_enabled": {},
		"role_kind":  {},
		"rbac_rules": {},
	},
	"role_binding": {
		"tenant_id": {}, "assignment_id": {}, "principal_object_id": {}, "resource_object_id": {}, "app_role_id": {}, "role_definition_id": {},
		"binding_kind": {},
	},
	"service_account": {},
	"vault_auth_role": {
		"auth_mount":                       {},
		"auth_type":                        {},
		"bound_service_account_names":      {},
		"bound_service_account_namespaces": {},
		"policy_names":                     {},
	},
	"policy": {
		"policy_kind": {},
	},
}

func (snapshot Snapshot) Validate() error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("snapshot schema_version must be %q", SnapshotSchemaVersion)
	}
	if snapshot.CollectedAt.IsZero() {
		return fmt.Errorf("snapshot collected_at is required")
	}

	sources := make(map[string]Source, len(snapshot.Sources))
	for index, source := range snapshot.Sources {
		if err := validateSource(source); err != nil {
			return fmt.Errorf("source at index %d: %w", index, err)
		}
		if _, exists := sources[source.ID]; exists {
			return fmt.Errorf("source at index %d has a duplicate id", index)
		}
		sources[source.ID] = source
	}

	entities := make(map[string]Entity, len(snapshot.Entities))
	for index, entity := range snapshot.Entities {
		if err := validateEntity(entity, sources); err != nil {
			return fmt.Errorf("entity at index %d: %w", index, err)
		}
		if _, exists := entities[entity.ID]; exists {
			return fmt.Errorf("entity at index %d has a duplicate id", index)
		}
		entities[entity.ID] = entity
	}

	evidence := make(map[string]Evidence, len(snapshot.Evidence))
	for index, item := range snapshot.Evidence {
		if err := validateEvidence(item, sources); err != nil {
			return fmt.Errorf("evidence at index %d: %w", index, err)
		}
		if _, exists := evidence[item.ID]; exists {
			return fmt.Errorf("evidence at index %d has a duplicate id", index)
		}
		evidence[item.ID] = item
	}

	relationshipIDs := make(map[string]struct{}, len(snapshot.Relationships))
	for index, relationship := range snapshot.Relationships {
		if err := validateRelationship(relationship, entities, evidence); err != nil {
			return fmt.Errorf("relationship at index %d: %w", index, err)
		}
		if _, exists := relationshipIDs[relationship.ID]; exists {
			return fmt.Errorf("relationship at index %d has a duplicate id", index)
		}
		relationshipIDs[relationship.ID] = struct{}{}
	}

	return nil
}

func validateSource(source Source) error {
	if source.ID == "" || source.Kind == "" || source.Scope == "" {
		return fmt.Errorf("id, kind, and scope are required")
	}
	if _, ok := validSourceKinds[source.Kind]; !ok {
		return fmt.Errorf("kind is unsupported in this schema")
	}
	if !isValidSourceStatus(source.Status) {
		return fmt.Errorf("status is invalid")
	}
	if !isValidProvenance(source.Provenance) {
		return fmt.Errorf("provenance is invalid")
	}
	if source.Status == SourceOK && source.ErrorCode != "" {
		return fmt.Errorf("an ok source cannot include error_code")
	}
	return nil
}

func validateEntity(entity Entity, sources map[string]Source) error {
	if entity.ID == "" || entity.Kind == "" || entity.SourceID == "" || entity.NativeID == "" || entity.Scope == "" {
		return fmt.Errorf("id, kind, source_id, native_id, and scope are required")
	}
	if _, ok := validEntityKinds[entity.Kind]; !ok {
		return fmt.Errorf("kind is unsupported in this schema")
	}
	if _, ok := sources[entity.SourceID]; !ok {
		return fmt.Errorf("source_id does not reference a source")
	}
	if entity.ID != EntityID(entity.SourceID, entity.Kind, entity.NativeID) {
		return fmt.Errorf("id is not derived from source_id, kind, and native_id")
	}
	if entity.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is required")
	}
	if !isValidProvenance(entity.Provenance) {
		return fmt.Errorf("provenance is invalid")
	}
	if err := validateAttributes(entity); err != nil {
		return err
	}
	if source := sources[entity.SourceID]; source.Kind == "entra" {
		return validateEntraIdentity(entity, source)
	}
	if source := sources[entity.SourceID]; source.Kind == "github" {
		return validateGitHubIdentity(entity, source)
	}
	if source := sources[entity.SourceID]; source.Kind == "spire" {
		return validateSpireIdentity(entity, source)
	}
	return nil
}

func validateAttributes(entity Entity) error {
	allowed, knownKind := allowedAttributesByKind[entity.Kind]
	if !knownKind && len(entity.Attributes) > 0 {
		return fmt.Errorf("attributes are not supported for this entity kind in M0")
	}

	for key, value := range entity.Attributes {
		if isSensitiveFieldName(key) {
			return fmt.Errorf("attribute %q is not permitted", key)
		}
		if !knownKind {
			return fmt.Errorf("attribute %q is not supported in M0", key)
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("attribute %q is not supported in M0", key)
		}
		status, ok := entity.FieldStatus[key]
		if !ok {
			return fmt.Errorf("attribute %q is missing field_status", key)
		}
		if !isValidFieldStatus(status) {
			return fmt.Errorf("attribute %q has an invalid field_status", key)
		}
		if !json.Valid(value) {
			return fmt.Errorf("attribute %q is not valid JSON", key)
		}

		switch key {
		case "trust_domain", "entry_id", "spiffe_id", "parent_spiffe_id", "entry_kind", "selectors", "parent_entry_ids", "parent_attestor_types", "x509_ttl_mode", "jwt_ttl_mode", "x509_svid_ttl_seconds", "jwt_svid_ttl_seconds", "admin", "downstream", "federates_with", "revision_number", "entry_expires_at", "entry_created_at", "x509_issuance":
			if err := validateSpireAttribute(key, value); err != nil {
				return err
			}
		case "repository_id", "repository_owner_id", "repository_name", "workflow_id", "workflow_path", "workflow_state", "subject_format", "revisions", "smoke_results":
			if err := validateGitHubAttribute(key, value); err != nil {
				return err
			}
		case "tenant_id", "object_id", "app_id", "collection_role", "principal_type", "owners_count", "client_credentials_count", "key_credentials_count", "federated_credentials_count", "requested_permissions", "app_role_assignments_count", "parent_object_id", "parent_kind", "key_id", "credential_type", "start_time", "end_time", "issuer", "subject", "audiences", "owner_type", "resource_object_id", "resource_app_id", "app_role_id", "role_value", "role_enabled", "assignment_id", "principal_object_id", "role_definition_id":
			if err := validateEntraAttribute(key, value); err != nil {
				return err
			}
		case "role_kind", "binding_kind", "policy_kind", "auth_mount", "auth_type", "credential_id", "job_native_id":
			if err := validateStringAttribute(value); err != nil {
				return fmt.Errorf("attribute %q: %w", key, err)
			}
		case "rbac_rules":
			if err := ValidateRBACRules(value); err != nil {
				return err
			}
		case "job_kind", "buildable", "builds", "jenkinsfile_commit", "credential_reference_count":
			if err := validateJobAttribute(key, value); err != nil {
				return err
			}
		}
	}

	for key, status := range entity.FieldStatus {
		if isSensitiveFieldName(key) {
			return fmt.Errorf("field_status %q is not permitted", key)
		}
		if !isValidFieldStatus(status) {
			return fmt.Errorf("field_status %q is invalid", key)
		}
		if knownKind {
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("field_status %q is not supported in M0", key)
			}
		}
		if _, hasAttribute := entity.Attributes[key]; !hasAttribute && status == FieldKnown {
			return fmt.Errorf("known field_status %q is missing its attribute", key)
		}
	}

	return nil
}

func validateStringAttribute(raw json.RawMessage) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return fmt.Errorf("must be a non-empty string")
	}
	return nil
}

func ValidateRBACRules(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var rules []RBACRule
	if err := decoder.Decode(&rules); err != nil {
		return fmt.Errorf("rbac_rules has an unsupported shape")
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		return fmt.Errorf("rbac_rules has an unsupported shape")
	}
	for _, rule := range rules {
		if len(rule.Resources) == 0 || len(rule.Verbs) == 0 {
			return fmt.Errorf("rbac_rules requires resources and verbs")
		}
		if err := validateAPIGroupList(rule.APIGroups); err != nil {
			return fmt.Errorf("rbac_rules api_groups: %w", err)
		}
		if err := validateStringList(rule.Resources); err != nil {
			return fmt.Errorf("rbac_rules resources: %w", err)
		}
		if err := validateStringList(rule.Verbs); err != nil {
			return fmt.Errorf("rbac_rules verbs: %w", err)
		}
		if err := validateStringList(rule.ResourceNames); err != nil {
			return fmt.Errorf("rbac_rules resource_names: %w", err)
		}
		if len(rule.NonResourceURL) > 0 {
			return fmt.Errorf("rbac_rules non_resource_urls are unsupported in M0")
		}
	}
	return nil
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("extra or malformed JSON value")
	}
	return nil
}

func validateStringList(values []string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("contains an empty value")
		}
	}
	return nil
}

func validateAPIGroupList(values []string) error {
	for _, value := range values {
		if value != strings.TrimSpace(value) {
			return fmt.Errorf("contains surrounding whitespace")
		}
	}
	return nil
}

func validateEvidence(item Evidence, sources map[string]Source) error {
	if item.ID == "" || item.SourceID == "" || item.NativeID == "" || item.Locator == "" {
		return fmt.Errorf("id, source_id, native_id, and locator are required")
	}
	if _, ok := sources[item.SourceID]; !ok {
		return fmt.Errorf("source_id does not reference a source")
	}
	if strings.Contains(item.Locator, "?") || strings.Contains(item.Locator, "@") {
		return fmt.Errorf("locator cannot contain query or user-info data")
	}
	if item.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is required")
	}
	if !isValidAssertionKind(item.AssertionKind) {
		return fmt.Errorf("assertion_kind is invalid")
	}
	if len(item.Fields) == 0 {
		return fmt.Errorf("fields is required")
	}
	for _, field := range item.Fields {
		if strings.TrimSpace(field) == "" || isSensitiveFieldName(field) {
			return fmt.Errorf("fields contains a forbidden field name")
		}
	}
	return nil
}

func validateRelationship(relationship Relationship, entities map[string]Entity, evidence map[string]Evidence) error {
	if relationship.ID == "" || relationship.From == "" || relationship.To == "" || relationship.Type == "" || relationship.Scope == "" {
		return fmt.Errorf("id, from, to, type, and scope are required")
	}
	if _, ok := entities[relationship.From]; !ok {
		return fmt.Errorf("from does not reference an entity")
	}
	if _, ok := entities[relationship.To]; !ok {
		return fmt.Errorf("to does not reference an entity")
	}
	if relationship.From == relationship.To {
		return fmt.Errorf("from and to must be different entities")
	}
	if _, ok := validRelationshipTypes[relationship.Type]; !ok {
		return fmt.Errorf("type is unsupported in this schema")
	}
	if relationship.ID != RelationshipID(relationship.From, relationship.To, relationship.Type, relationship.Scope) {
		return fmt.Errorf("id is not derived from relationship endpoints, type, and scope")
	}
	if !isValidAssertionKind(relationship.AssertionKind) {
		return fmt.Errorf("assertion_kind is invalid")
	}
	if relationship.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at is required")
	}
	if len(relationship.EvidenceIDs) == 0 {
		return fmt.Errorf("evidence_ids is required")
	}
	seenEvidence := make(map[string]struct{}, len(relationship.EvidenceIDs))
	for _, evidenceID := range relationship.EvidenceIDs {
		if _, ok := evidence[evidenceID]; !ok {
			return fmt.Errorf("evidence_ids contains an unknown reference")
		}
		if _, duplicate := seenEvidence[evidenceID]; duplicate {
			return fmt.Errorf("evidence_ids contains a duplicate reference")
		}
		seenEvidence[evidenceID] = struct{}{}
	}
	return nil
}

func isValidFieldStatus(status FieldStatus) bool {
	switch status {
	case FieldKnown, FieldUnknown, FieldPermissionDenied, FieldUnsupported:
		return true
	default:
		return false
	}
}

func isValidProvenance(provenance Provenance) bool {
	switch provenance {
	case ProvenanceLiveAPI, ProvenanceProviderExport, ProvenanceSyntheticFixture:
		return true
	default:
		return false
	}
}

func isValidAssertionKind(assertion AssertionKind) bool {
	switch assertion {
	case AssertionObserved, AssertionConfigured, AssertionDeclared, AssertionInferred:
		return true
	default:
		return false
	}
}

func isValidSourceStatus(status SourceStatus) bool {
	switch status {
	case SourceOK, SourcePartial, SourceError, SourceDisabled, SourceUnsupported:
		return true
	default:
		return false
	}
}

func isSensitiveFieldName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	for _, term := range []string{"secret", "token", "password", "private_key", "credential_value"} {
		if strings.Contains(normalized, term) {
			return true
		}
	}
	return false
}
