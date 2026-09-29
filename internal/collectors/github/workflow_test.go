package github

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/grantlinehq/grantline/internal/model"
)

const parserSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const parserTenant = "11111111-1111-1111-1111-111111111111"
const parserClient = "22222222-2222-2222-2222-222222222222"
const parserPrefix = "repo:owner@12/repo@34"
const literalWorkflow = `name: Example
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v3
        with:
          tenant-id: 11111111-1111-1111-1111-111111111111
          client-id: 22222222-2222-2222-2222-222222222222
      - run: echo INLINE_SECRET_CANARY_NEVER_RETAIN
`

func TestWorkflowPermissionsContextsAndRedaction(t *testing.T) {
	cases := []struct {
		name, text, ref, permission, subject string
		count                                int
		status                               model.FieldStatus
	}{
		{"literal", literalWorkflow, "refs/heads/main", "write", parserPrefix + ":ref:refs/heads/main", 2, model.FieldKnown},
		{"job override clears inherited id-token", strings.Replace(literalWorkflow, "    runs-on:", "    permissions: {contents: read}\n    runs-on:", 1), "refs/heads/main", "none", parserPrefix + ":ref:refs/heads/main", 2, model.FieldKnown},
		{"environment precedes ref", strings.Replace(literalWorkflow, "    runs-on:", "    environment: 'prod:west'\n    runs-on:", 1), "refs/heads/main", "write", parserPrefix + ":environment:prod%3Awest", 2, model.FieldKnown},
		{"other branch only dispatch", literalWorkflow, "refs/heads/other", "write", parserPrefix + ":ref:refs/heads/other", 1, model.FieldKnown},
		{"tag dispatch", literalWorkflow, "refs/tags/v1", "write", parserPrefix + ":ref:refs/tags/v1", 1, model.FieldKnown},
		{"pull request context", strings.Replace(literalWorkflow, "  workflow_dispatch:", "  pull_request:", 1), "refs/heads/other", "write", parserPrefix + ":pull_request", 1, model.FieldKnown},
		{"unknown inherited", strings.Replace(literalWorkflow, "permissions:\n  id-token: write\n", "", 1), "refs/heads/main", "unknown", parserPrefix + ":ref:refs/heads/main", 2, model.FieldUnsupported},
		{"dynamic environment", strings.Replace(literalWorkflow, "    runs-on:", "    environment: ${{ matrix.environment }}\n    runs-on:", 1), "refs/heads/main", "write", "", 0, model.FieldUnsupported},
		{"custom template unavailable", literalWorkflow, "refs/heads/main", "write", "", 0, model.FieldKnown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := parserPrefix
			if tc.name == "custom template unavailable" {
				prefix = ""
			}
			r := parseWorkflow([]byte(tc.text), tc.ref, parserSHA, prefix)
			if r.Status != tc.status || len(r.Jobs) != 1 {
				t.Fatalf("revision status/jobs: %s/%d", r.Status, len(r.Jobs))
			}
			j := r.Jobs[0]
			if j.IDTokenPermission != tc.permission || len(j.Contexts) != tc.count {
				t.Fatalf("permission/context: %+v", j)
			}
			for _, c := range j.Contexts {
				if c.Subject != tc.subject {
					t.Fatalf("subject %s", c.Subject)
				}
			}
			if len(j.Logins) != 1 || j.Logins[0].Status != model.FieldKnown || j.Logins[0].TenantID != parserTenant || j.Logins[0].ClientID != parserClient {
				t.Fatal("literal identity lost")
			}
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), "INLINE_SECRET_CANARY") || strings.Contains(string(data), "runs-on") || strings.Contains(string(data), "echo") {
				t.Fatal("raw content retained")
			}
		})
	}
}

func TestWorkflowUnsafeAndUnsupportedInput(t *testing.T) {
	for name, text := range map[string]string{
		"duplicate key":     literalWorkflow + "permissions: {id-token: none}\n",
		"alias":             "on: &events [push]\njobs: *events\n",
		"merge":             "on: push\njobs: {deploy: {<<: {permissions: {id-token: write}}}}\n",
		"multiple docs":     literalWorkflow + "---\n" + literalWorkflow,
		"deep":              "on: push\nx: " + strings.Repeat("[", 45) + "x" + strings.Repeat("]", 45),
		"oversize":          strings.Repeat("x", (256<<10)+1),
		"glob":              strings.Replace(literalWorkflow, "branches: [main]", "branches: ['*']", 1),
		"reusable":          "on: push\npermissions: {id-token: write}\njobs: {deploy: {uses: owner/reusable/.github/workflows/shared.yml@main}}",
		"unsupported event": strings.Replace(literalWorkflow, "workflow_dispatch:", "pull_request_target:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if r := parseWorkflow([]byte(text), "refs/heads/main", parserSHA, parserPrefix); r.Status != model.FieldUnsupported {
				t.Fatal("unsupported YAML/configuration silently accepted")
			}
		})
	}
	for name, text := range map[string]string{
		"vars":                   strings.Replace(literalWorkflow, parserTenant, "${{ vars.TENANT_ID }}", 1),
		"compound expression":    strings.Replace(literalWorkflow, parserTenant, "${{ secrets.TENANT_ID || 'EXPRESSION_SECRET_CANARY' }}", 1),
		"secret auth":            strings.Replace(literalWorkflow, "          tenant-id:", "          creds: SECRET_AUTH_CANARY\n          tenant-id:", 1),
		"unknown action version": strings.Replace(literalWorkflow, "azure/login@v3", "azure/login@main", 1),
		"condition":              strings.Replace(literalWorkflow, "      - uses:", "      - if: ${{ github.ref == 'refs/heads/main' }}\n        uses:", 1),
		"non-public cloud":       strings.Replace(literalWorkflow, "          tenant-id:", "          environment: AzureUSGovernment\n          tenant-id:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			r := parseWorkflow([]byte(text), "refs/heads/main", parserSHA, parserPrefix)
			if r.Jobs[0].Logins[0].Status == model.FieldKnown {
				t.Fatal("unresolved login accepted")
			}
			data, _ := json.Marshal(r)
			if strings.Contains(string(data), "CANARY") {
				t.Fatal("sensitive expression retained")
			}
		})
	}
}

func TestIdentityDeclarationsAreExactAndPinned(t *testing.T) {
	text := strings.Replace(literalWorkflow, parserTenant, "${{ secrets.TENANT_ID }}", 1)
	base := IdentityMapping{WorkflowPath: ".github/workflows/test.yml", Ref: "refs/heads/main", CommitSHA: parserSHA, JobID: "deploy", Step: 1, Field: "tenant_id", Reference: "secrets.TENANT_ID", Value: parserTenant}
	for _, field := range []string{"valid", "ref", "commit", "path", "job", "step", "reference"} {
		t.Run(field, func(t *testing.T) {
			r := parseWorkflow([]byte(text), "refs/heads/main", parserSHA, parserPrefix)
			m := base
			switch field {
			case "ref":
				m.Ref = "refs/heads/wrong"
			case "commit":
				m.CommitSHA = strings.Repeat("b", 40)
			case "path":
				m.WorkflowPath = ".github/workflows/other.yml"
			case "job":
				m.JobID = "other"
			case "step":
				m.Step = 2
			case "reference":
				m.Reference = "vars.TENANT_ID"
			}
			used := map[int]bool{}
			applyMappings(&r, base.WorkflowPath, []IdentityMapping{m}, used)
			l := r.Jobs[0].Logins[0]
			if field == "valid" {
				if l.Status != model.FieldKnown || l.IdentityAssertion != model.AssertionDeclared || l.TenantReference != "secrets.TENANT_ID" || !used[0] {
					t.Fatal("declaration provenance/reference missing")
				}
			} else if l.Status == model.FieldKnown || len(used) != 0 {
				t.Fatal("nonexact declaration used")
			}
		})
	}
}
