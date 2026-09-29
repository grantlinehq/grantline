package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grantlinehq/grantline/internal/model"
)

func TestCollectReadsMetadataWithoutTokenOrPolicyBody(t *testing.T) {
	t.Setenv("GRANTLINE_TEST_VAULT_TOKEN", "not-for-output")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "not-for-output" {
			t.Fatal("missing Vault token")
		}
		switch request.URL.Path {
		case "/v1/auth/kubernetes/role/payments-kubernetes":
			_, _ = writer.Write([]byte(`{"data":{"bound_service_account_names":["payments"],"bound_service_account_namespaces":["demo-dev"],"token_policies":["payments-read"]}}`))
		case "/v1/sys/policies/acl/payments-read":
			_, _ = writer.Write([]byte(`{"data":{"name":"payments-read","policy":"path \"grantline-kv/data/payments/dev\" { capabilities=[\"read\"] }"}}`))
		default:
			t.Fatalf("unexpected request %s", request.URL.Path)
		}
	}))
	defer server.Close()
	snapshot, err := (Collector{Config: Config{ID: "vault-lab", Address: server.URL, TokenEnv: "GRANTLINE_TEST_VAULT_TOKEN", Scope: "vault/local", AuthRoles: []AuthRole{{Mount: "kubernetes", Name: "payments-kubernetes", Type: "kubernetes"}}, Policies: []string{"payments-read"}}, Now: func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("snapshot validation: %v", err)
	}
	data, _ := os.ReadFile(mustTempSnapshot(t, snapshot))
	if strings.Contains(string(data), "not-for-output") || strings.Contains(string(data), "grantline-kv/data/payments/dev") {
		t.Fatal("snapshot contains token or policy body")
	}
	if snapshot.Sources[0].Status != model.SourceOK || !snapshot.Sources[0].Complete {
		t.Fatalf("source=%#v", snapshot.Sources[0])
	}
}

func TestCollectForbiddenIsPartial(t *testing.T) {
	t.Setenv("GRANTLINE_TEST_VAULT_TOKEN", "token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) }))
	defer server.Close()
	snapshot, err := (Collector{Config: Config{ID: "vault-lab", Address: server.URL, TokenEnv: "GRANTLINE_TEST_VAULT_TOKEN", Scope: "vault/local", AuthRoles: []AuthRole{{Mount: "approle", Name: "jenkins-payments", Type: "approle"}}}}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Sources[0].Status != model.SourcePartial || snapshot.Sources[0].Complete {
		t.Fatalf("source=%#v", snapshot.Sources[0])
	}
}

func mustTempSnapshot(t *testing.T, snapshot model.Snapshot) string {
	t.Helper()
	file := t.TempDir() + "/snapshot.json"
	data, _ := json.Marshal(snapshot)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}
