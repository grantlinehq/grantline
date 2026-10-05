import { useEffect, useState, type FormEvent } from "react";
import {
  ArrowRight,
  Check,
  ChevronLeft,
  Plus,
  RefreshCw,
  Settings2,
  Unplug,
} from "lucide-react";
import { Badge, Modal, SourceIcon } from "../components";
import { human, type Source } from "../types";
import { api, APIError, when, type FieldIssue, type User } from "./api";
import { FieldErrors } from "./FormFields";
import {
  JenkinsMappingFields,
  ProviderPreparation,
  RepositoryFields,
  VaultRoleFields,
} from "./IntegrationFields";
import { admin, Blank, Heading } from "./Workspace";
import { sourceCollectionMessage } from "./sourceHealth";

const providers = [
  {
    id: "kubernetes",
    name: "Kubernetes",
    detail: "Workloads, service accounts and RBAC.",
    help: "Use an observer kubeconfig with embedded CA and token or certificate. Executable authentication plugins, impersonation and file paths are rejected.",
  },
  {
    id: "vault",
    name: "HashiCorp Vault",
    detail: "Auth roles, policies and credential context.",
    help: "Create an observer token with read access to the selected auth roles and policies. Grantline never reads secret values.",
  },
  {
    id: "jenkins",
    name: "Jenkins",
    detail: "Job identities and automation relationships.",
    help: "Use an observer account with Overall/Read and Job/Read on an explicit list of jobs. Build scripts are not executed.",
  },
  {
    id: "entra",
    name: "Microsoft Entra",
    detail: "Applications, principals and federation.",
    help: "Register a separate collector application with admin-consented Application.Read.All application permission. Add explicit application and service principal object IDs.",
  },
  {
    id: "github",
    name: "GitHub",
    detail: "Repositories, workflows and trust declarations.",
    help: "Install a GitHub App or use a fine-grained token restricted to the selected repositories. Metadata, Contents and Actions read permissions are required.",
  },
  {
    id: "spire",
    name: "SPIRE",
    detail: "SPIFFE identities and registration metadata.",
    help: "Upload a Grantline metadata export from a trusted observer. The SPIRE administration socket is never exposed to this application.",
  },
];
const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean);
const prefix: Record<string, string> = {
  kubernetes: "cluster",
  vault: "vault",
  jenkins: "jenkins",
  entra: "entra",
  github: "github",
  spire: "spire",
};
export function Integrations({
  user,
  onError,
}: {
  user: User;
  onError: (s: string) => void;
}) {
  const [items, setItems] = useState<any[]>([]),
    [collection, setCollection] = useState<{
      sources: Source[];
      snapshot_collected_at?: string;
      fixture_notice?: string;
    }>({ sources: [] }),
    [loading, setLoading] = useState(true),
    [editing, setEditing] = useState<any | null>(null);
  const load = () =>
    Promise.all([api<any[]>("/integrations"), api<any>("/overview")])
      .then(([items, overview]) => {
        setItems(items);
        setCollection(
          overview.run_kind === "import" ? { sources: [] } : overview,
        );
      })
      .catch((e) => onError(e.message))
      .finally(() => setLoading(false));
  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);
  return (
    <>
      <Heading
        label="YOUR SOURCES"
        title="Built around your infrastructure."
        description="Bring the right evidence into your workspace. You control the scope."
      >
        {admin(user) && (
          <button className="primary-button" onClick={() => setEditing({})}>
            <Plus size={16} />
            Add integration
          </button>
        )}
      </Heading>
      <div className="integration-summary">
        <span>{items.filter((i) => i.enabled).length} active connections</span>
        <span>{providers.length} supported providers</span>
        <a href="/docs/integrations/">Permissions &amp; setup guides ↗</a>
      </div>
      {loading ? (
        <p role="status">Loading connections…</p>
      ) : items.length ? (
        <div className="integration-list">
          {items.map((i) => {
            const latest = collection.sources.find((s) => s.id === i.id);
            return (
              <article key={i.id}>
                <SourceIcon kind={i.kind} />
                <div className="integration-identity">
                  <h2>{i.name}</h2>
                  <small>
                    {providers.find((p) => p.id === i.kind)?.name} ·{" "}
                    <code>{i.id}</code>
                  </small>
                </div>
                <div className="integration-status">
                  <Badge value={i.enabled ? "active" : "paused"} />
                  <small>Last access test {when(i.tested_at)}</small>
                </div>
                <div className="integration-collection">
                  <span>
                    {latest
                      ? `${collection.fixture_notice ? "Sample dataset" : "Last collection"}: ${latest.complete ? "Complete" : human(latest.status)}`
                      : i.test_result?.[0]
                        ? human(i.test_result[0].status)
                        : "Access not tested"}
                  </span>
                  <small>
                    {latest
                      ? sourceCollectionMessage(latest)
                      : i.test_result?.[0]?.complete
                        ? "Selected scope collected"
                        : "Review coverage before enabling"}
                  </small>
                  {latest && (
                    <small>{when(collection.snapshot_collected_at)}</small>
                  )}
                </div>
                {admin(user) && (
                  <button
                    className="button"
                    onClick={() => setEditing(i)}
                    aria-label={`Configure ${i.name}`}
                  >
                    <Settings2 size={16} />
                    Configure
                  </button>
                )}
              </article>
            );
          })}
        </div>
      ) : (
        <Blank title="Choose your first connection">
          Each source has a scoped setup guide, an access test and a clear
          record of what was collected.
        </Blank>
      )}
      <section className="provider-catalog">
        <div className="section-heading">
          <div>
            <span className="overline">SIX SOURCES. ONE INVESTIGATION.</span>
            <h2>Where your identities live.</h2>
          </div>
        </div>
        <div className="provider-grid">
          {providers.map((p) => (
            <button
              key={p.id}
              disabled={!admin(user)}
              onClick={() => setEditing({ kind: p.id })}
            >
              <SourceIcon kind={p.id} />
              <h3>{p.name}</h3>
              <p>{p.detail}</p>
              <span>
                Connect source <ArrowRight size={15} />
              </span>
            </button>
          ))}
        </div>
      </section>
      {editing && (
        <Wizard
          initial={editing}
          connections={items}
          close={() => setEditing(null)}
          updated={load}
        />
      )}
    </>
  );
}
function Wizard({
  initial,
  connections,
  close,
  updated,
}: {
  initial: any;
  connections: any[];
  close: () => void;
  updated: () => void;
}) {
  const [kind, setKind] = useState(initial.kind || ""),
    [stage, setStage] = useState(initial.kind ? 1 : 0),
    [saved, setSaved] = useState(initial.id || ""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [result, setResult] = useState<any[] | null>(null),
    [formData, setFormData] = useState<any>(null);
  const [issues, setIssues] = useState<FieldIssue[]>([]),
    [roles, setRoles] = useState<any[]>(
      initial.config?.source?.auth_roles || [],
    ),
    [repositories, setRepositories] = useState<any[]>(
      initial.config?.source?.repositories || [],
    ),
    [jenkinsfiles, setJenkinsfiles] = useState<any[]>(
      initial.config?.jenkinsfiles || [],
    );
  const field = (name: string) => {
    const key = name.replace(/^source\.(spire\.)?/, "");
    return {
      id: `field-${key}`,
      "aria-invalid": issues.some((i) => i.field === key) || undefined,
    };
  };
  const [authMode, setAuthMode] = useState(
    initial.config?.auth_mode ||
      (initial.kind === "entra"
        ? "client_secret"
        : initial.kind === "kubernetes"
          ? "kubeconfig"
          : initial.kind === "spire"
            ? "export"
            : "token"),
  );
  const [secretRef, setSecretRef] = useState(!!initial.secret_ref),
    [upload, setUpload] = useState("");
  const credentialChanged =
    !!initial.id &&
    (authMode !== initial.config?.auth_mode ||
      (!secretRef && !!initial.secret_ref));
  const provider = providers.find((p) => p.id === kind),
    source = initial.config?.source || {};
  const choose = (id: string) => {
    setKind(id);
    setAuthMode(
      id === "entra"
        ? "client_secret"
        : id === "kubernetes"
          ? "kubeconfig"
          : id === "spire"
            ? "export"
            : "token",
    );
    setStage(1);
  };
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setIssues([]);
    const f = Object.fromEntries(new FormData(event.currentTarget)) as Record<
      string,
      string
    >;
    try {
      const source: any = { kind, scope: f.scope };
      if (["vault", "jenkins"].includes(kind)) source.address = f.address;
      if (kind === "kubernetes") source.context = f.context;
      if (kind === "vault") {
        source.policies = lines(f.policies);
        source.auth_roles = roles;
        source.kubernetes_source_id = f.kubernetes_source_id;
      }
      if (kind === "jenkins") {
        source.build_limit = Number(f.build_limit);
        source.jobs = lines(f.jobs).map((path) => ({ path, kind: "job" }));
      }
      if (kind === "entra") {
        source.tenant_id = f.tenant_id.trim().toLowerCase();
        source.scope = `tenant/${source.tenant_id}`;
        source.applications = lines(f.applications).map((v) => v.toLowerCase());
        source.service_principals = lines(f.service_principals).map((v) =>
          v.toLowerCase(),
        );
      }
      if (kind === "github")
        source.repositories = repositories.map((r) => ({
          ...r,
          refs: (r.refs || []).map((v: string) => v.trim()).filter(Boolean),
        }));
      if (kind === "spire")
        source.spire = {
          trust_domain: f.trust_domain,
          parent_ids: lines(f.parent_ids),
        };
      let credentials: Record<string, string> | undefined;
      if (!secretRef) {
        const values: Record<string, string> = {};
        for (const key of ["username", "token", "client_secret", "private_key"])
          if (f[key]) values[key] = f[key];
        if (upload) values[kind === "spire" ? "export" : "kubeconfig"] = upload;
        if (Object.keys(values).length) credentials = values;
      }
      const body = {
        name: f.name,
        config: {
          source,
          auth_mode: authMode,
          client_id: f.client_id?.trim().toLowerCase() || "",
          app_id: f.app_id || "",
          installation_id: f.installation_id || "",
          jenkinsfiles: kind === "jenkins" ? jenkinsfiles : undefined,
        },
        credentials,
        secret_ref: secretRef ? f.secret_ref : "",
        enabled: false,
        revision: initial.revision || 0,
      };
      const response = await api(
        saved ? `/integrations/${saved}` : "/integrations",
        saved ? "PUT" : "POST",
        body,
      );
      setSaved(response.id);
      setFormData({ ...body, credentials: undefined });
      setUpload("");
      setStage(2);
      updated();
    } catch (e) {
      setError((e as Error).message);
      if (e instanceof APIError) setIssues(e.fields);
    } finally {
      setBusy(false);
    }
  }
  async function test() {
    setBusy(true);
    setError("");
    try {
      setResult(await api(`/integrations/${saved}/test`, "POST", {}));
    } catch (e) {
      setResult(null);
      setError((e as Error).message);
    } finally {
      setBusy(false);
      updated();
    }
  }
  async function enable(collect: boolean) {
    setBusy(true);
    setError("");
    try {
      const all = await api<any[]>("/integrations"),
        current = all.find((i) => i.id === saved);
      await api(`/integrations/${saved}`, "PUT", {
        ...formData,
        config: current.config,
        revision: current.revision,
        enabled: true,
      });
      if (collect) await api("/runs", "POST", {});
      updated();
      setStage(3);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={initial.id ? `Configure ${initial.name}` : "Add an integration"}
      onClose={close}
      className="integration-modal"
    >
      <div className="wizard-progress" aria-label={`Step ${stage + 1} of 4`}>
        {["Provider", "Connection & scope", "Access test", "Ready"].map(
          (v, i) => (
            <span
              key={v}
              className={i <= stage ? "current" : ""}
              aria-current={i === stage ? "step" : undefined}
              aria-label={v}
            >
              <b>{i < stage ? <Check size={13} /> : i + 1}</b>
              <span className="wizard-step-label">{v}</span>
            </span>
          ),
        )}
      </div>
      {error && (
        <div className="product-error" role="alert">
          {error}
        </div>
      )}
      <FieldErrors issues={issues} />
      {stage === 0 && (
        <div className="wizard-body wizard-providers">
          {providers.map((p) => (
            <button key={p.id} onClick={() => choose(p.id)}>
              <SourceIcon kind={p.id} />
              <span>
                <strong>{p.name}</strong>
                <small>{p.detail}</small>
              </span>
              <ArrowRight size={16} />
            </button>
          ))}
        </div>
      )}
      {stage === 1 && (
        <form className="integration-form" onSubmit={save}>
          <div
            className="wizard-body integration-fields"
            id="field-config"
            tabIndex={-1}
          >
            <div className="provider-intro">
              <SourceIcon kind={kind} />
              <div>
                <h2>{provider?.name}</h2>
                <p>
                  {kind === "entra" && authMode === "token"
                    ? "Temporary access tokens expire and require manual replacement. Choose application credentials for unattended, scheduled collection."
                    : provider?.help}
                </p>
                <a href={`/docs/integrations/#${kind}`}>Permission guide ↗</a>
              </div>
            </div>
            <ProviderPreparation key={kind} kind={kind} />
            <div className="form-columns">
              <label>
                Connection name
                <input
                  name="name"
                  required
                  maxLength={100}
                  defaultValue={initial.name}
                  placeholder="Production infrastructure"
                />
              </label>
              {kind !== "entra" && (
                <label>
                  Scope name
                  <input
                    {...field("source.scope")}
                    name="scope"
                    required
                    defaultValue={source.scope || `${prefix[kind]}/production`}
                    placeholder={`${prefix[kind]}/production`}
                  />
                  <small>
                    A stable name for this source, starting with {prefix[kind]}
                    /.
                  </small>
                </label>
              )}
            </div>
            {["vault", "jenkins"].includes(kind) && (
              <label>
                API address
                <input
                  {...field("source.address")}
                  name="address"
                  type="url"
                  required
                  defaultValue={source.address}
                  placeholder={`https://${kind}.example.com`}
                />
              </label>
            )}
            {kind === "kubernetes" && (
              <label>
                Kubeconfig context
                <input
                  name="context"
                  defaultValue={source.context}
                  placeholder="Leave blank to use current-context"
                />
              </label>
            )}
            {kind === "vault" && (
              <>
                <label>
                  Policy names
                  <textarea
                    {...field("source.policies")}
                    name="policies"
                    defaultValue={source.policies?.join("\n")}
                    placeholder="One exact policy name per line"
                  />
                </label>
                <VaultRoleFields
                  value={roles}
                  onChange={setRoles}
                  issues={issues}
                />
                <label>
                  Related Kubernetes connection
                  <select
                    {...field("source.kubernetes_source_id")}
                    name="kubernetes_source_id"
                    defaultValue={source.kubernetes_source_id || ""}
                  >
                    <option value="">No Kubernetes mapping</option>
                    {connections
                      .filter((c) => c.kind === "kubernetes")
                      .map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name}
                          {c.enabled ? "" : " (paused)"}
                        </option>
                      ))}
                    {source.kubernetes_source_id &&
                      !connections.some(
                        (c) => c.id === source.kubernetes_source_id,
                      ) && (
                        <option value={source.kubernetes_source_id}>
                          Missing connection: {source.kubernetes_source_id}
                        </option>
                      )}
                  </select>
                  <small>
                    Select the cluster trusted by these Vault roles. This is an
                    explicit relationship.
                  </small>
                </label>
              </>
            )}
            {kind === "jenkins" && (
              <>
                <label>
                  Job paths
                  <textarea
                    {...field("source.jobs")}
                    name="jobs"
                    required
                    defaultValue={source.jobs
                      ?.map((j: any) => j.path)
                      .join("\n")}
                    placeholder="One full job path per line"
                  />
                </label>
                <label>
                  Build metadata limit
                  <input
                    name="build_limit"
                    type="number"
                    min={1}
                    max={20}
                    defaultValue={source.build_limit || 5}
                  />
                </label>
                <JenkinsMappingFields
                  value={jenkinsfiles}
                  onChange={setJenkinsfiles}
                  connections={connections}
                  issues={issues}
                />
              </>
            )}
            {kind === "entra" && (
              <>
                <label>
                  Authentication
                  <select
                    value={authMode}
                    onChange={(e) => {
                      setAuthMode(e.target.value);
                      setSecretRef(false);
                    }}
                  >
                    <option value="client_secret">
                      Application credentials (recommended)
                    </option>
                    <option value="token">Temporary access token</option>
                  </select>
                  <small>
                    {authMode === "client_secret"
                      ? "Uses the application's client secret to obtain access tokens automatically. Requires Application.Read.All application permission with admin consent. No user sign-in during collection."
                      : "For a one-time connection check. This token does not renew automatically."}
                  </small>
                </label>
                <div className="form-columns">
                  <label>
                    Tenant ID
                    <input
                      {...field("source.tenant_id")}
                      name="tenant_id"
                      required
                      defaultValue={source.tenant_id}
                    />
                    <small>
                      Directory (tenant) ID from the collector app’s Overview.
                      Grantline derives the tenant scope automatically.
                    </small>
                  </label>
                  <label>
                    Collector application (client) ID
                    <input
                      {...field("client_id")}
                      name="client_id"
                      required
                      defaultValue={initial.config?.client_id}
                    />
                    <small>
                      Application (client) ID of the collector app, not its
                      Object ID.
                    </small>
                  </label>
                </div>
                <label>
                  Application object IDs
                  <textarea
                    {...field("source.applications")}
                    name="applications"
                    defaultValue={source.applications?.join("\n")}
                    placeholder="One object ID per line"
                  />
                  <small>
                    App registrations → target app → Overview → Object ID. These
                    are applications to inspect; enter at least one application
                    or service principal.
                  </small>
                </label>
                <label>
                  Service principal object IDs
                  <textarea
                    {...field("source.service_principals")}
                    name="service_principals"
                    defaultValue={source.service_principals?.join("\n")}
                    placeholder="One object ID per line"
                  />
                  <small>
                    Enterprise applications → target app → Overview → Object ID.
                    This differs from the app registration’s Object ID.
                  </small>
                </label>
              </>
            )}
            {kind === "github" && (
              <>
                <label>
                  Authentication
                  <select
                    value={authMode}
                    onChange={(e) => setAuthMode(e.target.value)}
                  >
                    <option value="token">Fine-grained token</option>
                    <option value="github_app">GitHub App</option>
                  </select>
                </label>
                {authMode === "github_app" && (
                  <div className="form-columns">
                    <label>
                      App ID
                      <input
                        {...field("app_id")}
                        name="app_id"
                        required
                        defaultValue={initial.config?.app_id}
                      />
                    </label>
                    <label>
                      Installation ID
                      <input
                        {...field("installation_id")}
                        name="installation_id"
                        required
                        defaultValue={initial.config?.installation_id}
                      />
                    </label>
                  </div>
                )}
                <RepositoryFields
                  value={repositories}
                  onChange={setRepositories}
                  issues={issues}
                />
              </>
            )}
            {kind === "spire" && (
              <>
                <label>
                  Trust domain
                  <input
                    {...field("source.spire.trust_domain")}
                    name="trust_domain"
                    required
                    defaultValue={source.spire?.trust_domain}
                    placeholder="example.org"
                  />
                </label>
                <label>
                  Parent SPIFFE IDs
                  <textarea
                    {...field("source.spire.parent_ids")}
                    name="parent_ids"
                    required
                    defaultValue={source.spire?.parent_ids?.join("\n")}
                    placeholder="spiffe://example.org/spire/agent/..."
                  />
                </label>
              </>
            )}
            <fieldset className="credential-fields">
              <legend>Observer credentials</legend>
              <p>
                {credentialChanged
                  ? "Enter credentials for the selected authentication method. The previous credential cannot be reused."
                  : initial.id
                    ? "Leave credential fields empty to keep the stored value. New values replace the complete credential set."
                    : "Credentials are encrypted at rest and are never returned by the API."}
              </p>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={secretRef}
                  onChange={(e) => setSecretRef(e.target.checked)}
                />
                Use a mounted secret reference
              </label>
              {secretRef ? (
                <label>
                  Secret file name
                  <input
                    name="secret_ref"
                    required
                    defaultValue={initial.secret_ref}
                    placeholder="production-observer.json"
                  />
                  <small>
                    A JSON credential file mounted in the configured secret
                    directory.
                  </small>
                </label>
              ) : (
                <>
                  {["kubernetes", "spire"].includes(kind) ? (
                    <label>
                      {kind === "spire"
                        ? "Metadata export"
                        : "Observer kubeconfig"}
                      <input
                        type="file"
                        required={!initial.id}
                        accept={
                          kind === "spire"
                            ? ".json"
                            : ".yaml,.yml,.json,.config"
                        }
                        onChange={async (e) => {
                          const f = e.target.files?.[0];
                          if (!f) return;
                          if (f.size > 10 * 1024 * 1024) {
                            setError("File exceeds 10 MiB");
                            e.target.value = "";
                            return;
                          }
                          setUpload(await f.text());
                        }}
                      />
                    </label>
                  ) : (
                    <>
                      {kind === "jenkins" && (
                        <label>
                          Observer username
                          <input
                            name="username"
                            required={!initial.id}
                            autoComplete="off"
                          />
                        </label>
                      )}
                      {authMode === "github_app" ? (
                        <label>
                          Private key (PEM)
                          <textarea
                            name="private_key"
                            className="code-input"
                            required={!initial.id}
                            autoComplete="off"
                          />
                        </label>
                      ) : (
                        <label>
                          {authMode === "client_secret"
                            ? "Client secret"
                            : kind === "entra"
                              ? "Microsoft Graph access token"
                              : "Observer token"}
                          <input
                            key={authMode}
                            name={
                              authMode === "client_secret"
                                ? "client_secret"
                                : "token"
                            }
                            type="password"
                            required={!initial.id || credentialChanged}
                            autoComplete="new-password"
                          />
                          {authMode === "client_secret" && (
                            <small>
                              Certificates &amp; secrets → Client secrets →
                              Value. The Secret ID cannot authenticate. Store
                              the expiry in your rotation process.
                            </small>
                          )}
                        </label>
                      )}
                    </>
                  )}
                </>
              )}
            </fieldset>
            {initial.id && (
              <div className="connection-management">
                <button
                  type="button"
                  className="text-button"
                  onClick={async () => {
                    try {
                      await api(`/integrations/${initial.id}`, "PUT", {
                        name: initial.name,
                        config: initial.config,
                        secret_ref: initial.secret_ref,
                        enabled: !initial.enabled,
                        revision: initial.revision,
                      });
                      updated();
                      close();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  {initial.enabled
                    ? "Pause scheduled collection"
                    : "Resume scheduled collection"}
                </button>
                <button
                  type="button"
                  className="danger-button"
                  onClick={async () => {
                    if (
                      !confirm(
                        `Remove ${initial.name} and its stored credentials? Existing reports will be retained.`,
                      )
                    )
                      return;
                    try {
                      await api(`/integrations/${initial.id}`, "DELETE");
                      updated();
                      close();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  Remove connection
                </button>
              </div>
            )}
          </div>
          <div className="wizard-actions">
            <button
              type="button"
              className="button"
              onClick={initial.id ? close : () => setStage(0)}
            >
              {!initial.id && <ChevronLeft size={15} />}
              {initial.id ? "Cancel" : "Back"}
            </button>
            <button className="primary-button" disabled={busy}>
              {busy ? "Saving…" : "Save & continue"}
              <ArrowRight size={16} />
            </button>
          </div>
        </form>
      )}
      {stage === 2 && (
        <div className="wizard-stage">
          <div className="wizard-body wizard-test">
            <Unplug size={32} />
            <h2>Check the path to your source.</h2>
            <p>
              The access test collects the selected metadata and reports any
              gaps. Your connection is saved and paused until you enable it.
            </p>
            <button className="button" disabled={busy} onClick={test}>
              <RefreshCw size={16} />
              {busy ? "Checking access…" : "Test connection"}
            </button>
            {result?.map((s: any) => (
              <div key={s.id} className="test-result">
                <Badge value={s.status} />
                <p>
                  {s.complete
                    ? "The selected scope is available."
                    : sourceCollectionMessage(s)}
                </p>
                {s.errors?.map((e: any, i: number) => (
                  <p key={i}>
                    {typeof e === "string"
                      ? e
                      : e.code || "Source reported a coverage gap"}
                  </p>
                ))}
              </div>
            ))}
          </div>
          <div className="wizard-actions">
            <button className="button" onClick={close}>
              Keep paused
            </button>
            <button
              className="primary-button"
              disabled={busy || !result?.every((s) => s.complete)}
              onClick={() => enable(true)}
            >
              Enable & collect
              <ArrowRight size={16} />
            </button>
          </div>
        </div>
      )}
      {stage === 3 && (
        <div className="wizard-body wizard-test">
          <span className="success-mark">
            <Check size={30} />
          </span>
          <h2>Connected. Ready for context.</h2>
          <p>
            Your first collection is queued. Follow its progress in Activity;
            identities and findings appear when the report is ready.
          </p>
          <button className="primary-button" onClick={close}>
            Back to integrations
            <ArrowRight size={16} />
          </button>
        </div>
      )}
    </Modal>
  );
}
