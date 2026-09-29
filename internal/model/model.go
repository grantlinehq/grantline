package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const SnapshotSchemaVersion = "1.0"
const ReportSchemaVersion = "1.0"

type FieldStatus string

const (
	FieldKnown            FieldStatus = "known"
	FieldUnknown          FieldStatus = "unknown"
	FieldPermissionDenied FieldStatus = "permission_denied"
	FieldUnsupported      FieldStatus = "unsupported"
)

type Provenance string

const (
	ProvenanceLiveAPI          Provenance = "live_api"
	ProvenanceProviderExport   Provenance = "provider_export"
	ProvenanceSyntheticFixture Provenance = "synthetic_fixture"
)

type AssertionKind string

const (
	AssertionObserved   AssertionKind = "observed"
	AssertionConfigured AssertionKind = "configured"
	AssertionDeclared   AssertionKind = "declared"
	AssertionInferred   AssertionKind = "inferred"
)

type SourceStatus string

const (
	SourceOK          SourceStatus = "ok"
	SourcePartial     SourceStatus = "partial"
	SourceError       SourceStatus = "error"
	SourceDisabled    SourceStatus = "disabled"
	SourceUnsupported SourceStatus = "unsupported"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type RuleOutcome string

const (
	OutcomePass          RuleOutcome = "PASS"
	OutcomeFail          RuleOutcome = "FAIL"
	OutcomeUnknown       RuleOutcome = "UNKNOWN"
	OutcomeNotApplicable RuleOutcome = "NOT_APPLICABLE"
)

type Snapshot struct {
	SchemaVersion string         `json:"schema_version"`
	CollectedAt   time.Time      `json:"collected_at"`
	Entities      []Entity       `json:"entities"`
	Relationships []Relationship `json:"relationships"`
	Evidence      []Evidence     `json:"evidence"`
	Sources       []Source       `json:"sources"`
}

type Entity struct {
	ID          string                     `json:"id"`
	Kind        string                     `json:"kind"`
	SourceID    string                     `json:"source_id"`
	NativeID    string                     `json:"native_id"`
	Scope       string                     `json:"scope"`
	Name        string                     `json:"name"`
	Attributes  map[string]json.RawMessage `json:"attributes"`
	FieldStatus map[string]FieldStatus     `json:"field_status"`
	ObservedAt  time.Time                  `json:"observed_at"`
	Provenance  Provenance                 `json:"provenance"`
}

type Relationship struct {
	ID            string        `json:"id"`
	From          string        `json:"from"`
	To            string        `json:"to"`
	Type          string        `json:"type"`
	AssertionKind AssertionKind `json:"assertion_kind"`
	EvidenceIDs   []string      `json:"evidence_ids"`
	Scope         string        `json:"scope"`
	ObservedAt    time.Time     `json:"observed_at"`
}

type Evidence struct {
	ID            string        `json:"id"`
	SourceID      string        `json:"source_id"`
	NativeID      string        `json:"native_id"`
	Locator       string        `json:"locator"`
	Fields        []string      `json:"fields"`
	ObservedAt    time.Time     `json:"observed_at"`
	AssertionKind AssertionKind `json:"assertion_kind"`
}

type Source struct {
	ID                  string       `json:"id"`
	Kind                string       `json:"kind"`
	Scope               string       `json:"scope"`
	Status              SourceStatus `json:"status"`
	Complete            bool         `json:"complete"`
	PermissionsObserved []string     `json:"permissions_observed"`
	Warnings            []string     `json:"warnings"`
	PaginationComplete  bool         `json:"pagination_complete"`
	ErrorCode           string       `json:"error_code,omitempty"`
	Provenance          Provenance   `json:"provenance"`
}

type RBACRule struct {
	APIGroups      []string `json:"api_groups"`
	Resources      []string `json:"resources"`
	Verbs          []string `json:"verbs"`
	ResourceNames  []string `json:"resource_names,omitempty"`
	NonResourceURL []string `json:"non_resource_urls,omitempty"`
}

type Report struct {
	PolicyExceptions    []PolicyException `json:"policy_exceptions,omitempty"`
	Snapshot            *Snapshot         `json:"snapshot,omitempty"`
	Contexts            []EntityContext   `json:"contexts,omitempty"`
	BindingIssues       []string          `json:"binding_issues,omitempty"`
	SchemaVersion       string            `json:"schema_version"`
	GeneratedAt         time.Time         `json:"generated_at"`
	SnapshotCollectedAt time.Time         `json:"snapshot_collected_at"`
	InputProvenances    []Provenance      `json:"input_provenances"`
	FixtureNotice       string            `json:"fixture_notice,omitempty"`
	Completeness        Completeness      `json:"completeness"`
	RuleResults         []RuleResult      `json:"rule_results"`
	Findings            []Finding         `json:"findings"`
	Evidence            []Evidence        `json:"evidence"`
}

type PolicyException struct {
	RuleID       string   `json:"rule_id"`
	EntityID     string   `json:"entity_id"`
	Environments []string `json:"environments"`
	Reason       string   `json:"reason"`
}

// EntityContext is operator-declared business metadata, never a provider owner
// or an independent live identity. References always resolve to collected IDs.
type EntityContext struct {
	EntityID        string   `json:"entity_id"`
	ApplicationID   string   `json:"application_id"`
	ApplicationName string   `json:"application_name"`
	Environment     string   `json:"environment"`
	OwnerHint       string   `json:"owner_hint,omitempty"`
	EvidenceIDs     []string `json:"evidence_ids"`
}

type Completeness struct {
	Complete        bool               `json:"complete"`
	RequiredSources []SourceAssessment `json:"required_sources"`
}

type SourceAssessment struct {
	SourceID                  string   `json:"source_id"`
	Present                   bool     `json:"present"`
	Status                    string   `json:"status,omitempty"`
	Complete                  bool     `json:"complete"`
	PaginationComplete        bool     `json:"pagination_complete"`
	SatisfiesRequiredCoverage bool     `json:"satisfies_required_coverage"`
	Limitations               []string `json:"limitations,omitempty"`
}

type RuleResult struct {
	RuleID      string      `json:"rule_id"`
	RuleVersion string      `json:"rule_version"`
	Outcome     RuleOutcome `json:"outcome"`
	FindingIDs  []string    `json:"finding_ids"`
	Limitations []string    `json:"limitations,omitempty"`
}

type Finding struct {
	ID                      string   `json:"id"`
	RuleID                  string   `json:"rule_id"`
	RuleVersion             string   `json:"rule_version"`
	Severity                Severity `json:"severity"`
	AffectedEntityIDs       []string `json:"affected_entity_ids"`
	AffectedRelationshipIDs []string `json:"affected_relationship_ids"`
	EvidenceIDs             []string `json:"evidence_ids"`
	Condition               string   `json:"condition"`
	Description             string   `json:"description"`
	Recommendation          string   `json:"recommendation"`
	Limitations             []string `json:"limitations"`
}

func EntityID(sourceID, kind, nativeID string) string {
	return stableID("entity", sourceID, kind, nativeID)
}

func RelationshipID(from, to, relationshipType, scope string) string {
	return stableID("relationship", from, to, relationshipType, scope)
}

func FindingID(ruleID, ruleVersion string, stableInputs ...string) string {
	inputs := append([]string{ruleID, ruleVersion}, stableInputs...)
	return stableID("finding", inputs...)
}

func EvidenceID(sourceID, nativeID, locator string) string {
	return stableID("evidence", sourceID, nativeID, locator)
}

func stableID(prefix string, values ...string) string {
	hasher := sha256.New()
	for index, value := range values {
		if index > 0 {
			_, _ = hasher.Write([]byte{0})
		}
		_, _ = hasher.Write([]byte(value))
	}

	return prefix + "_" + hex.EncodeToString(hasher.Sum(nil))
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}
