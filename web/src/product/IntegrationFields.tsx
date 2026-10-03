import { useState } from "react";
import { RowsEditor, type Field } from "./FormFields";
import type { FieldIssue } from "./api";

const text = (key: string, label: string, help?: string): Field => ({
  key,
  label,
  help,
});
export function RepositoryFields({
  value,
  onChange,
  issues,
}: {
  value: any[];
  onChange: (rows: any[]) => void;
  issues: FieldIssue[];
}) {
  return (
    <RowsEditor
      label="Repositories to collect"
      path="repositories"
      value={value}
      onChange={onChange}
      max={25}
      issues={issues}
      addLabel="Add repository"
      help="Grantline reads only these repositories and refs. IDs keep scope stable if a repository is renamed."
      fields={[
        text(
          "name",
          "Repository",
          "Use owner/repository, for example acme/payments.",
        ),
        text(
          "repository_id",
          "Repository ID",
          "Use the numeric ID returned by GET /repos/OWNER/REPO or gh api repos/OWNER/REPO --jq .id.",
        ),
        {
          key: "refs",
          label: "Branch or tag refs",
          type: "lines",
          placeholder: "refs/heads/main",
          help: "One full ref per line. Use refs/heads/NAME or refs/tags/NAME.",
        },
      ]}
    >
      {(row, index, update) => (
        <details className="mapping-details">
          <summary>Optional identity declarations & run metadata</summary>
          <p>
            Declare exact tenant/client IDs only when the workflow references
            are known. This does not read secrets or prove runtime access.
          </p>
          <RowsEditor
            label="Identity declarations"
            issues={issues}
            path={`repositories.${index}.identity_mappings`}
            value={row.identity_mappings || []}
            onChange={(v) => update({ ...row, identity_mappings: v })}
            max={200}
            fields={[
              text(
                "workflow_path",
                "Workflow path",
                "For example .github/workflows/deploy.yml.",
              ),
              text(
                "ref",
                "Full ref",
                "Must also appear in this repository's refs above.",
              ),
              text(
                "commit_sha",
                "Commit SHA",
                "Full immutable 40-character commit.",
              ),
              text("job_id", "Workflow job key"),
              {
                key: "step",
                label: "Step index",
                type: "number",
                min: 1,
                max: 100,
              },
              {
                key: "field",
                label: "Identity field",
                options: [
                  { value: "tenant_id", label: "Tenant ID" },
                  { value: "client_id", label: "Client ID" },
                ],
              },
              text(
                "reference",
                "Workflow reference",
                "For example secrets.AZURE_CLIENT_ID; never its secret value.",
              ),
              text(
                "value",
                "Declared UUID",
                "The tenant or application client UUID. Never enter a client secret.",
              ),
            ]}
          />
          <RowsEditor
            label="Explicit run checks"
            issues={issues}
            path={`repositories.${index}.smoke_checks`}
            value={row.smoke_checks || []}
            onChange={(v) => update({ ...row, smoke_checks: v })}
            max={20}
            help="Read metadata for an already existing run. Grantline does not dispatch workflows."
            fields={[
              text("workflow_path", "Workflow path"),
              text("run_id", "Run ID"),
              {
                key: "attempt",
                label: "Run attempt",
                type: "number",
                min: 1,
                max: 100,
              },
              text("job_id", "Numeric job ID"),
              {
                key: "login_step_number",
                label: "Login step number",
                type: "number",
                min: 1,
                max: 1000,
              },
            ]}
          />
        </details>
      )}
    </RowsEditor>
  );
}
export function VaultRoleFields({
  value,
  onChange,
  issues,
}: {
  value: any[];
  onChange: (rows: any[]) => void;
  issues: FieldIssue[];
}) {
  return (
    <RowsEditor
      label="Auth roles"
      path="auth_roles"
      value={value}
      onChange={onChange}
      issues={issues}
      addLabel="Add auth role"
      help="Select exact role metadata; wildcard discovery is not used."
      fields={[
        text(
          "mount",
          "Auth mount",
          "Mount name without auth/, for example kubernetes or approle.",
        ),
        text("name", "Role name"),
        {
          key: "type",
          label: "Auth type",
          options: [
            { value: "kubernetes", label: "Kubernetes" },
            { value: "approle", label: "AppRole" },
          ],
        },
      ]}
    />
  );
}
export function JenkinsMappingFields({
  value,
  onChange,
  connections,
  issues,
}: {
  value: any[];
  onChange: (rows: any[]) => void;
  connections: any[];
  issues: FieldIssue[];
}) {
  return (
    <RowsEditor
      label="Jenkinsfile mappings"
      path="jenkinsfiles"
      value={value}
      onChange={onChange}
      issues={issues}
      addLabel="Add Jenkinsfile mapping"
      help="Optional. Read a pinned Jenkinsfile through an enabled GitHub connection. No scripts are executed."
      fields={[
        text(
          "job",
          "Jenkins job path",
          "Must match one of the selected job paths above.",
        ),
        {
          key: "github_source_id",
          label: "GitHub connection",
          options: connections
            .filter((c) => c.kind === "github")
            .map((c) => ({
              value: c.id,
              label: `${c.name}${c.enabled ? "" : " (paused — enable before collection)"}`,
            })),
        },
        text(
          "repository",
          "Repository",
          "Use owner/repository in the linked connection's scope.",
        ),
        text("repository_id", "Numeric repository ID"),
        text(
          "commit",
          "Full commit SHA",
          "Use all 40 characters, not a branch name.",
        ),
        text(
          "path",
          "Jenkinsfile path",
          "Relative path, for example Jenkinsfile or ci/Jenkinsfile.",
        ),
      ]}
    />
  );
}
const preparation: Record<
  string,
  { steps: string[]; reads: string; excluded: string; example?: string }
> = {
  kubernetes: {
    steps: [
      "Create a separate observer ServiceAccount using the RBAC example below; do not grant Secrets access.",
      "Issue its credential through your cluster's normal process. Build a kubeconfig with embedded CA and token or client certificate.",
      "Upload the kubeconfig and choose its context. Exec plugins and external credential-file references are rejected.",
    ],
    reads: "Namespaces, service accounts, Pods/Deployments and RBAC metadata.",
    excluded: "Secret values, exec, logs and write operations.",
    example: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: grantline-observer
rules:
  - apiGroups: [""]
    resources: ["namespaces", "serviceaccounts", "pods"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list"]
# Bind this role to your dedicated observer through your cluster change process.`,
  },
  vault: {
    steps: [
      "Create an observer policy that grants read only on the exact policy and auth-role paths you select.",
      "Issue a token for that policy; do not use a root token or grant KV secret access.",
      "Enter the HTTPS address, role names and policies. If collecting Kubernetes trust, select the related Kubernetes connection.",
    ],
    reads: "Selected auth-role definitions and ACL policy metadata.",
    excluded: "KV payloads, SecretIDs and token issuance.",
    example: `# Replace these two example paths with your explicit selection.
path "sys/policies/acl/selected-policy" { capabilities = ["read"] }
path "auth/kubernetes/role/selected-role" { capabilities = ["read"] }`,
  },
  jenkins: {
    steps: [
      "Create an observer account with Overall/Read and Job/Read on the selected jobs and ancestor folders.",
      "Create its API token and enter exact full job paths.",
      "For Jenkinsfile relationships, connect GitHub first and pin mappings to a full commit SHA.",
    ],
    reads: "Selected job/build metadata and explicitly pinned Jenkinsfiles.",
    excluded:
      "Build execution, job changes, console logs and credential values.",
  },
  entra: {
    steps: [
      "Use a dedicated collector app registration. Grant Microsoft Graph Application.Read.All under Application permissions, then grant tenant admin consent.",
      "From that app's Overview, copy Directory (tenant) ID and Application (client) ID. Create a client secret under Certificates & secrets; use its Value, not Secret ID.",
      "Select the apps to inspect by their Object ID in App registrations. Select service principals by Object ID in Enterprise applications. These are separate from the collector's client ID.",
    ],
    reads:
      "Selected app/SP metadata, credential lifetimes, owners, federation and application-role assignments.",
    excluded:
      "Secret values and permission changes. Application.Read.All consent is tenant-wide; Grantline's selected collection scope is narrower.",
  },
  github: {
    steps: [
      "Use a GitHub App installed on selected repositories, or a fine-grained token scoped to them.",
      "Grant Metadata, Contents and Actions read access. For an App, obtain its App ID, installation ID and private key.",
      "Add repositories with their numeric IDs and exact refs below. App/token expiry and installation scope remain under your control.",
    ],
    reads:
      "Repository/workflow metadata and bounded content at selected revisions.",
    excluded:
      "GitHub secret values, workflow dispatch, repository writes and administration.",
  },
  spire: {
    steps: [
      "Use a trusted operator-side exporter to produce the Grantline metadata export.",
      "Choose the exact trust domain and parent SPIFFE IDs.",
      "Upload the export or configure a mounted reference and arrange its refresh outside Grantline.",
    ],
    reads:
      "Registration, selector, parent and explicit lifetime metadata in the export.",
    excluded:
      "Live administration API access. The SPIRE admin socket must not be exposed to the web app.",
  },
};
export function ProviderPreparation({ kind }: { kind: string }) {
  const [copied, setCopied] = useState(false);
  const p = preparation[kind];
  if (!p) return null;
  return (
    <details className="provider-preparation">
      <summary>Before you connect: permissions & preparation</summary>
      <ol>
        {p.steps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <dl>
        <dt>Collected</dt>
        <dd>{p.reads}</dd>
        <dt>Boundary</dt>
        <dd>{p.excluded}</dd>
      </dl>
      {p.example && (
        <>
          <pre>{p.example}</pre>
          <button
            type="button"
            className="button"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(p.example!);
                setCopied(true);
              } catch {
                setCopied(false);
              }
            }}
          >
            {copied ? "Copied" : "Copy permission example"}
          </button>
          <p className="section-note">
            Review and adapt the example in your provider. Grantline does not
            apply permissions automatically.
          </p>
        </>
      )}
      <a href={`/docs/integrations/#${kind}`}>Full setup guide ↗</a>
    </details>
  );
}
