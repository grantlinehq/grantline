package spire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"

	"github.com/grantlinehq/grantline/internal/model"
)

// Export is an operator-controlled metadata artifact, not a signed attestation.
type Export struct {
	SchemaVersion string         `json:"schema_version"`
	SDKVersion    string         `json:"sdk_version"`
	SourceID      string         `json:"source_id"`
	Scope         string         `json:"scope"`
	TrustDomain   string         `json:"trust_domain"`
	ParentIDs     []string       `json:"parent_ids"`
	Snapshot      model.Snapshot `json:"snapshot"`
}
type WorkloadEvidence struct {
	SchemaVersion string              `json:"schema_version"`
	SourceID      string              `json:"source_id"`
	Scope         string              `json:"scope"`
	TrustDomain   string              `json:"trust_domain"`
	SPIFFEID      string              `json:"spiffe_id"`
	Issuance      model.SpireIssuance `json:"issuance"`
}

func EncodeExport(config Config, snapshot model.Snapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	value := Export{SchemaVersion: ExportSchemaVersion, SDKVersion: SDKVersion, SourceID: config.ID, Scope: config.Scope, TrustDomain: config.TrustDomain, ParentIDs: config.ParentIDs, Snapshot: snapshot}
	if !validExport(value, config) {
		return nil, fmt.Errorf("invalid SPIRE export scope")
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if len(data)+1 > MaxExportBytes {
		return nil, fmt.Errorf("SPIRE export exceeds metadata size limit")
	}
	return append(data, '\n'), err
}
func readJSON(path string, limit int, v any) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit+1)))
	if err != nil || len(data) > limit {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}
func validExport(v Export, c Config) bool {
	left, right := append([]string{}, v.ParentIDs...), append([]string{}, c.ParentIDs...)
	sort.Strings(left)
	sort.Strings(right)
	if v.SchemaVersion != ExportSchemaVersion || v.SDKVersion != SDKVersion || v.SourceID != c.ID || v.Scope != c.Scope || v.TrustDomain != c.TrustDomain || !slices.Equal(left, right) || v.Snapshot.Validate() != nil || len(v.Snapshot.Sources) != 1 {
		return false
	}
	source := v.Snapshot.Sources[0]
	if source.ID != c.ID || source.Kind != "spire" || source.Scope != c.Scope || source.Provenance != model.ProvenanceLiveAPI {
		return false
	}
	for _, e := range v.Snapshot.Entities {
		var domain, parent string
		json.Unmarshal(e.Attributes["trust_domain"], &domain)
		json.Unmarshal(e.Attributes["parent_spiffe_id"], &parent)
		if domain != c.TrustDomain || e.Provenance != model.ProvenanceLiveAPI || e.FieldStatus["x509_issuance"] != "" || e.Kind == "spire_entry" && !slices.Contains(c.ParentIDs, parent) {
			return false
		}
	}
	for _, e := range v.Snapshot.Evidence {
		if e.AssertionKind != model.AssertionConfigured {
			return false
		}
	}
	for _, e := range v.Snapshot.Relationships {
		if e.AssertionKind != model.AssertionConfigured || (e.Type != "bound_to" && e.Type != "assigned_spiffe_id") {
			return false
		}
	}
	return true
}
func (c *collection) importExport() (model.Snapshot, error) {
	c.source.Provenance = model.ProvenanceProviderExport
	var v Export
	if !readJSON(c.config.ExportPath, MaxExportBytes, &v) || !validExport(v, c.config) {
		c.fail("invalid_or_unavailable_export")
		return c.finish()
	}
	c.snapshot = v.Snapshot
	c.source = c.snapshot.Sources[0]
	c.source.Provenance = model.ProvenanceProviderExport
	c.snapshot.Entities = nil
	for _, e := range v.Snapshot.Entities {
		e.Provenance = model.ProvenanceProviderExport
		c.entities[e.ID] = &e
	}
	if c.config.WorkloadEvidencePath != "" {
		c.importWorkloadEvidence()
	}
	return c.finish()
}
func (c *collection) importWorkloadEvidence() {
	var v WorkloadEvidence
	if !readJSON(c.config.WorkloadEvidencePath, 32<<10, &v) || v.SchemaVersion != "1" || v.SourceID != c.config.ID || v.Scope != c.config.Scope || v.TrustDomain != c.config.TrustDomain || !model.SpireURIInDomain(v.SPIFFEID, c.config.TrustDomain) {
		c.fail("invalid_workload_evidence")
		return
	}
	id := model.EntityID(c.config.ID, "spiffe_identity", v.SPIFFEID)
	e := c.entities[id]
	registered := false
	for _, edge := range c.snapshot.Relationships {
		if edge.Type == "assigned_spiffe_id" && edge.To == id {
			registered = true
		}
	}
	if e == nil || !registered {
		c.fail("unmatched_workload_evidence")
		return
	}
	// Validate before recording public certificate metadata. Never import key/cert bytes.
	candidate := *e
	candidate.Attributes = map[string]json.RawMessage{}
	candidate.FieldStatus = map[string]model.FieldStatus{}
	for k, v := range e.Attributes {
		candidate.Attributes[k] = v
	}
	for k, v := range e.FieldStatus {
		candidate.FieldStatus[k] = v
	}
	set(&candidate, "x509_issuance", []model.SpireIssuance{v.Issuance})
	probe := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, CollectedAt: c.snapshot.CollectedAt, Sources: []model.Source{c.source}, Entities: []model.Entity{candidate}}
	if probe.Validate() != nil {
		c.fail("invalid_workload_evidence")
		return
	}
	c.entities[id] = &candidate
	evidence := model.Evidence{SourceID: c.config.ID, NativeID: e.NativeID, Locator: "spire/workload/x509/" + id, Fields: []string{"x509_issuance"}, AssertionKind: model.AssertionObserved, ObservedAt: v.Issuance.ObservedAt}
	evidence.ID = model.EvidenceID(evidence.SourceID, evidence.NativeID, evidence.Locator)
	c.snapshot.Evidence = append(c.snapshot.Evidence, evidence)
}
