package spire_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/analyze"
	"github.com/grantlinehq/grantline/internal/collectors/spire"
	"github.com/grantlinehq/grantline/internal/command"
	"github.com/grantlinehq/grantline/internal/model"
	"github.com/grantlinehq/grantline/internal/policy"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const root = "spiffe://example.org/spire/server"
const parent = "spiffe://example.org/ns/spire/sa/agent"
const identity = "spiffe://example.org/workload"

var now = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)

type fakeClient struct {
	entryv1.EntryClient
	list func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error)
}

func (f fakeClient) ListEntries(_ context.Context, r *entryv1.ListEntriesRequest, _ ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	return f.list(r)
}
func cfg() spire.Config {
	return spire.Config{ID: "spire-lab", Scope: "spire/lab", Options: spire.Options{TrustDomain: "example.org", ParentIDs: []string{root, parent}, SocketPath: "/tmp/spire.sock"}}
}
func sid(uri string) *types.SPIFFEID {
	return &types.SPIFFEID{TrustDomain: "example.org", Path: strings.TrimPrefix(uri, "spiffe://example.org")}
}
func entries() []*types.Entry {
	return []*types.Entry{
		{Id: "00000000-0000-0000-0000-000000000001", SpiffeId: sid(parent), ParentId: sid(root), Selectors: []*types.Selector{{Type: "k8s_psat", Value: "cluster:lab"}}},
		{Id: "00000000-0000-0000-0000-000000000002", SpiffeId: sid(identity), ParentId: sid(parent), Selectors: []*types.Selector{{Type: "k8s", Value: "ns:demo"}}, X509SvidTtl: 7200, JwtSvidTtl: 1800, Admin: true, FederatesWith: []string{"other.example"}},
		{Id: "00000000-0000-0000-0000-000000000003", SpiffeId: sid(identity), ParentId: sid(parent), Selectors: []*types.Selector{{Type: "k8s", Value: "ns:demo"}, {Type: "k8s", Value: "sa:restricted"}}, X509SvidTtl: 3600, JwtSvidTtl: 900},
	}
}
func collect(t *testing.T, records []*types.Entry) model.Snapshot {
	t.Helper()
	s, err := (spire.Collector{Config: cfg(), Now: func() time.Time { return now }, Client: fakeClient{list: func(r *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
		if r.OutputMask == nil || !r.OutputMask.Selectors || !r.OutputMask.JwtSvidTtl || r.OutputMask.Hint || r.OutputMask.DnsNames || r.PageSize != 100 {
			t.Fatal("unbounded or unexpected metadata request")
		}
		out := &entryv1.ListEntriesResponse{}
		for _, e := range records {
			if e.ParentId.Path == r.Filter.ByParentId.Path {
				out.Entries = append(out.Entries, e)
			}
		}
		return out, nil
	}}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func rules(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(`schema_version: 1
required_sources:
  - spire-lab
limits:
  max_x509_svid_ttl: 1h
  max_jwt_svid_ttl: 15m
rules:
  IL006:
    severity: high
    forbid_namespace_only: true
  IL007:
    severity: medium
`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestMetadataIdentityAndRules(t *testing.T) {
	s := collect(t, entries())
	if !s.Sources[0].Complete {
		t.Fatal(s.Sources)
	}
	identities, entryCount := 0, 0
	for _, e := range s.Entities {
		if e.Kind == "spire_entry" {
			entryCount++
		}
		if e.Kind == "spiffe_identity" && e.NativeID == identity {
			identities++
		}
		if e.FieldStatus["x509_issuance"] != "" {
			t.Fatal("configuration fabricated issuance")
		}
	}
	if entryCount != 3 || identities != 1 {
		t.Fatalf("entry/identity conflation: %d/%d", entryCount, identities)
	}
	report, err := analyze.Analyze(s, rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected selector + X509 + JWT findings, got %+v", report)
	}
	for _, r := range report.RuleResults {
		if r.Outcome != model.OutcomeFail {
			t.Fatal(r)
		}
	}
	// Equality at the threshold and multiple selectors pass; aliases are not workloads.
	records := entries()
	s = collect(t, []*types.Entry{records[0], records[2]})
	report, err = analyze.Analyze(s, rules(t))
	if err != nil || len(report.Findings) != 0 {
		t.Fatal(report, err)
	}
	for _, r := range report.RuleResults {
		if r.Outcome != model.OutcomePass {
			t.Fatal(r)
		}
	}
}
func TestUnknownAndPartialPreserveKnownFindings(t *testing.T) {
	records := entries()
	records[2].X509SvidTtl = 0
	s := collect(t, records)
	report, err := analyze.Analyze(s, rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 || report.RuleResults[1].Outcome != model.OutcomeUnknown {
		t.Fatal(report)
	}
	s.Sources[0].Complete = false
	s.Sources[0].Status = model.SourcePartial
	report, err = analyze.Analyze(s, rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 || report.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal(report)
	}
	s = collect(t, records[1:])
	report, err = analyze.Analyze(s, rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if report.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal("unresolved parent must not pass", report)
	}
}
func TestBoundedFailuresAndRedaction(t *testing.T) {
	for _, test := range []struct {
		name string
		list func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error)
	}{
		{"permission", func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "SECRET_SENTINEL")
		}},
		{"repeated token", func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
			return &entryv1.ListEntriesResponse{NextPageToken: "SECRET_SENTINEL"}, nil
		}},
		{"foreign parent", func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
			e := entries()[1]
			e.ParentId = sid("spiffe://example.org/foreign")
			return &entryv1.ListEntriesResponse{Entries: []*types.Entry{e}}, nil
		}},
		{"invalid selector", func(*entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
			e := entries()[0]
			e.Selectors[0].Value = "bad\nSECRET_SENTINEL"
			return &entryv1.ListEntriesResponse{Entries: []*types.Entry{e}}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			s, err := (spire.Collector{Config: cfg(), Client: fakeClient{list: func(r *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
				calls++
				return test.list(r)
			}}}).Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if s.Sources[0].Complete || s.Sources[0].Status != model.SourcePartial || calls > 4 {
				t.Fatal(s.Sources, calls)
			}
			data, _ := json.Marshal(s)
			if bytes.Contains(data, []byte("SECRET_SENTINEL")) {
				t.Fatal("provider error/token leaked")
			}
		})
	}
}
func TestPaginationAndDuplicates(t *testing.T) {
	c := cfg()
	c.ParentIDs = []string{parent}
	records := entries()[1:]
	calls := 0
	s, err := (spire.Collector{Config: c, Client: fakeClient{list: func(r *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
		calls++
		if r.PageToken == "" {
			return &entryv1.ListEntriesResponse{Entries: records[:1], NextPageToken: "page2"}, nil
		}
		return &entryv1.ListEntriesResponse{Entries: records[1:]}, nil
	}}}).Collect(context.Background())
	if err != nil || !s.Sources[0].Complete || calls != 2 {
		t.Fatal(s.Sources, err, calls)
	}
	s = collect(t, append(entries(), entries()[1]))
	if s.Sources[0].Complete {
		t.Fatal("duplicate registration ID accepted")
	}
}

type localServer struct {
	entryv1.UnimplementedEntryServer
}

func (localServer) ListEntries(_ context.Context, r *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
	out := &entryv1.ListEntriesResponse{}
	for _, e := range entries() {
		if e.ParentId.Path == r.Filter.ByParentId.Path {
			out.Entries = append(out.Entries, e)
		}
	}
	return out, nil
}
func TestActualUnixSocketTransport(t *testing.T) {
	dir, err := os.MkdirTemp("", "spire-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skip("Unix sockets unavailable:", err)
	}
	server := grpc.NewServer()
	entryv1.RegisterEntryServer(server, localServer{})
	go server.Serve(listener)
	defer server.Stop()
	c := cfg()
	c.SocketPath = socket
	s, err := (spire.Collector{Config: c}).Collect(context.Background())
	if err != nil || !s.Sources[0].Complete {
		t.Fatal(s.Sources, err)
	}
}
func TestControlledExportImportAndCLI(t *testing.T) {
	s := collect(t, entries())
	data, err := spire.EncodeExport(cfg(), s)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	export := filepath.Join(dir, "export.json")
	os.WriteFile(export, data, 0600)
	c := cfg()
	c.SocketPath = ""
	c.ExportPath = export
	imported, err := (spire.Collector{Config: c}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if imported.Sources[0].Provenance != model.ProvenanceProviderExport || len(imported.Entities) != len(s.Entities) || !imported.CollectedAt.Equal(s.CollectedAt) {
		t.Fatal("import lost provenance/timestamp/entities")
	}
	workload := spire.WorkloadEvidence{SchemaVersion: "1", SourceID: c.ID, Scope: c.Scope, TrustDomain: c.TrustDomain, SPIFFEID: identity, Issuance: model.SpireIssuance{ObservedAt: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), ClientReference: "test-client"}}
	evidence, _ := json.Marshal(workload)
	c.WorkloadEvidencePath = filepath.Join(dir, "workload.json")
	os.WriteFile(c.WorkloadEvidencePath, evidence, 0600)
	imported, err = (spire.Collector{Config: c}).Collect(context.Background())
	if err != nil || !imported.Sources[0].Complete {
		t.Fatal(imported.Sources, err)
	}
	report, err := analyze.Analyze(imported, rules(t))
	if err != nil || len(report.Findings) != 3 {
		t.Fatal("observed expiry must not override configured TTL", report, err)
	}
	config := filepath.Join(dir, "config.yaml")
	os.WriteFile(config, []byte(`schema_version: 1
sources:
  - id: spire-lab
    kind: spire
    scope: spire/lab
    spire:
      trust_domain: example.org
      parent_ids:
        - spiffe://example.org/spire/server
        - spiffe://example.org/ns/spire/sa/agent
      export_path: export.json
`), 0600)
	var output bytes.Buffer
	if code := command.Run([]string{"collect", "--config", config, "--out", filepath.Join(dir, "snapshot.json")}, &output, &output); code != 0 {
		t.Fatal(code, output.String())
	}
	// Invalid export still writes a valid partial snapshot and returns operational failure.
	os.WriteFile(export, []byte(`{"private_key":"SECRET_SENTINEL"}`), 0600)
	output.Reset()
	if code := command.Run([]string{"collect", "--config", config, "--out", filepath.Join(dir, "partial.json")}, &output, &output); code != 2 {
		t.Fatal(code)
	}
	partial, _ := os.ReadFile(filepath.Join(dir, "partial.json"))
	if bytes.Contains(partial, []byte("SECRET_SENTINEL")) || strings.Contains(output.String(), "SECRET_SENTINEL") {
		t.Fatal("invalid export leaked")
	}
	var partialSnapshot model.Snapshot
	if json.Unmarshal(partial, &partialSnapshot) != nil || partialSnapshot.Validate() != nil || partialSnapshot.Sources[0].Complete {
		t.Fatal("invalid partial snapshot")
	}
	for _, mutation := range []string{"source", "scope", "domain", "parents", "provenance", "partial"} {
		t.Run(mutation, func(t *testing.T) {
			var v spire.Export
			json.Unmarshal(data, &v)
			switch mutation {
			case "source":
				v.SourceID = "other"
			case "scope":
				v.Scope = "spire/other"
			case "domain":
				v.TrustDomain = "other.org"
			case "parents":
				v.ParentIDs = []string{parent}
			case "provenance":
				v.Snapshot.Sources[0].Provenance = model.ProvenanceSyntheticFixture
			case "partial":
				v.Snapshot.Sources[0].Complete = false
				v.Snapshot.Sources[0].Status = model.SourcePartial
			}
			raw, _ := json.Marshal(v)
			os.WriteFile(export, raw, 0600)
			got, err := (spire.Collector{Config: c}).Collect(context.Background())
			if err != nil || got.Sources[0].Complete {
				t.Fatal(got.Sources, err)
			}
		})
	}
}
func TestSPIREPolicyValidation(t *testing.T) {
	for _, body := range []string{"forbid_namespace_only: maybe", "forbid_namespace_only: true\n    forbid_namespace_only: false"} {
		_, err := policy.Parse([]byte(fmt.Sprintf("schema_version: 1\nrequired_sources:\n  - spire-lab\nrules:\n  IL006:\n    severity: high\n    %s\n", body)))
		if err == nil {
			t.Fatal("accepted", body)
		}
	}
	p := rules(t)
	p.MaxJWTSVIDTTL = time.Millisecond
	if p.Validate() == nil {
		t.Fatal("subsecond policy accepted")
	}
	p = rules(t)
	r := p.Rules["IL006"]
	r.ForbidNamespaceOnly = nil
	p.Rules["IL006"] = r
	if p.Validate() == nil {
		t.Fatal("missing explicit policy accepted")
	}
}

func TestUnsupportedAttestorAndMissingConfiguredEvidence(t *testing.T) {
	records := entries()
	records[0].Selectors[0].Type = "unsupported_attestor"
	s := collect(t, records)
	report, err := analyze.Analyze(s, rules(t))
	if err != nil || report.RuleResults[0].Outcome != model.OutcomeUnknown {
		t.Fatal(report, err)
	}
	for _, finding := range report.Findings {
		if finding.RuleID == "IL006" {
			t.Fatal("unsupported parent used as evidence")
		}
	}
	s = collect(t, entries())
	for i := range s.Evidence {
		s.Evidence[i].AssertionKind = model.AssertionObserved
	}
	report, err = analyze.Analyze(s, rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatal("observed assertion was substituted for registration evidence")
	}
	for _, r := range report.RuleResults {
		if r.Outcome != model.OutcomeUnknown {
			t.Fatal(r)
		}
	}
}

func TestStrictWorkloadEvidenceRejectsKeysAndWrongIdentity(t *testing.T) {
	s := collect(t, entries())
	data, err := spire.EncodeExport(cfg(), s)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	export := filepath.Join(dir, "export.json")
	if err := os.WriteFile(export, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := cfg()
	c.SocketPath = ""
	c.ExportPath = export
	c.WorkloadEvidencePath = filepath.Join(dir, "workload.json")
	base := spire.WorkloadEvidence{SchemaVersion: "1", SourceID: c.ID, Scope: c.Scope, TrustDomain: c.TrustDomain, SPIFFEID: identity, Issuance: model.SpireIssuance{ObservedAt: now, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), ClientReference: "test-client"}}
	for _, name := range []string{"private_key", "wrong_identity", "expired", "wrong_source"} {
		t.Run(name, func(t *testing.T) {
			v := base
			switch name {
			case "wrong_identity":
				v.SPIFFEID = "spiffe://example.org/unregistered"
			case "expired":
				v.Issuance.NotAfter = now
			case "wrong_source":
				v.SourceID = "other"
			}
			raw, _ := json.Marshal(v)
			if name == "private_key" {
				raw = bytes.Replace(raw, []byte(`"client_reference":"test-client"`), []byte(`"client_reference":"test-client","private_key":"SECRET_SENTINEL"`), 1)
			}
			if err := os.WriteFile(c.WorkloadEvidencePath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := (spire.Collector{Config: c}).Collect(context.Background())
			if err != nil || got.Sources[0].Complete {
				t.Fatal(got.Sources, err)
			}
			encoded, _ := json.Marshal(got)
			if bytes.Contains(encoded, []byte("SECRET_SENTINEL")) {
				t.Fatal("key material leaked")
			}
			for _, e := range got.Entities {
				if _, ok := e.Attributes["x509_issuance"]; ok {
					t.Fatal("invalid issuance was attached")
				}
			}
		})
	}
}
