import { useEffect, useRef, useState } from "react";
import { Check, Code2, SlidersHorizontal } from "lucide-react";
import { Badge } from "../components";
import { api, APIError, when, type FieldIssue } from "./api";
import { FieldErrors, RowsEditor, type Field } from "./FormFields";

type Rule = { Severity: string; [key: string]: any };
type PolicyForm = {
  required_sources: string[];
  limits: Record<string, string>;
  rules: Record<string, Rule>;
};
const rules = [
  [
    "IL001",
    "Broad Kubernetes permissions",
    "Kubernetes",
    "Review wildcard API groups, resources and verbs attached to service accounts.",
  ],
  [
    "IL002",
    "Unreviewed Vault subjects",
    "Vault + Kubernetes",
    "Review wildcard subject bindings and exact approved Vault-to-Kubernetes relationships.",
  ],
  [
    "IL003",
    "Long-lived client credentials",
    "Entra",
    "Compare credential metadata validity with your maximum lifetime.",
  ],
  [
    "IL004",
    "Missing application owners",
    "Entra",
    "Require owners on the exact applications or service principals you select below.",
  ],
  [
    "IL005",
    "Unreviewed application roles",
    "Entra",
    "Compare application-role assignments with exact approved grants.",
  ],
  [
    "IL006",
    "Broad workload selectors",
    "SPIRE",
    "Flag workload registrations that rely only on a namespace selector.",
  ],
  [
    "IL007",
    "Long-lived workload identities",
    "SPIRE",
    "Check explicit X.509 and JWT SVID lifetime metadata against your limits.",
  ],
  [
    "IL008",
    "Identity shared across environments",
    "Explicit business context",
    "Compare native identities across the environment pairs and context declarations you define.",
  ],
] as const;
const severityOptions = ["low", "medium", "high", "critical"];
const field = (
  key: string,
  label: string,
  extra: Partial<Field> = {},
): Field => ({ key, label, ...extra });
const kinds = ["service_account", "service_principal", "spiffe_identity"].map(
  (value) => ({ value, label: value.replaceAll("_", " ") }),
);
export function PolicyEditor({
  settings,
  updated,
}: {
  settings: any;
  updated: () => Promise<void>;
}) {
  const [editor, setEditor] = useState<any>(null),
    [sources, setSources] = useState<any[]>([]),
    [draft, setDraft] = useState<PolicyForm | null>(null);
  const [mode, setMode] = useState<"form" | "yaml">("form"),
    [defaults, setDefaults] = useState(false),
    [yaml, setYaml] = useState(""),
    [context, setContext] = useState(settings.bindings || "");
  const [review, setReview] = useState<any>(null),
    [ack, setAck] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [issues, setIssues] = useState<FieldIssue[]>([]),
    [saved, setSaved] = useState(false);
  const remembered = useRef<Record<string, Rule>>({});
  useEffect(() => {
    let active = true;
    Promise.all([api("/settings/policy"), api<any[]>("/integrations")])
      .then(([e, s]) => {
        if (!active) return;
        setEditor(e);
        setDraft(e.effective);
        remembered.current = { ...e.defaults.rules, ...e.effective.rules };
        setDefaults(e.mode === "defaults");
        setYaml(settings.policy || e.yaml);
        setContext(settings.bindings || "");
        setSources(s);
        setReview(null);
        setAck(false);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [settings.revision]);
  const invalidate = () => {
    setReview(null);
    setAck(false);
    setIssues([]);
    setSaved(false);
    setError("");
  };
  const change = (next: PolicyForm) => {
    invalidate();
    setDefaults(false);
    setDraft(next);
  };
  const updateRule = (id: string, value: Rule) => {
    if (draft) change({ ...draft, rules: { ...draft.rules, [id]: value } });
  };
  const problem = (e: unknown) => {
    setError((e as Error).message);
    setIssues(e instanceof APIError ? e.fields : []);
  };
  async function validate(preview: boolean) {
    if (!draft || !editor) return null;
    setBusy(true);
    setError("");
    setIssues([]);
    setSaved(false);
    try {
      const result = await api("/settings/policy/validate", "POST", {
        ...(defaults
          ? { policy: "" }
          : mode === "yaml"
            ? { policy: yaml }
            : { form: draft }),
        bindings: context,
        revision: editor.revision,
        preview,
      });
      setDraft(result.effective);
      setReview(preview ? result : null);
      setAck(false);
      return result;
    } catch (e) {
      setReview(null);
      problem(e);
      return null;
    } finally {
      setBusy(false);
    }
  }
  async function switchMode(next: "form" | "yaml") {
    const result = await validate(false);
    if (!result) return;
    setDraft(result.effective);
    setYaml(result.yaml);
    setMode(next);
  }
  async function save() {
    if (!review || (review.requires_acknowledgement && !ack)) return;
    setBusy(true);
    setError("");
    try {
      await api("/settings", "PUT", {
        Name: settings.name,
        schedule_minutes: settings.schedule_minutes,
        retention_days: settings.retention_days,
        Policy: review.policy,
        Bindings: context,
        Revision: editor.revision,
        acknowledge_coverage_reduction: ack,
      });
      await updated();
      setSaved(true);
      setReview(null);
    } catch (e) {
      problem(e);
    } finally {
      setBusy(false);
    }
  }
  if (!draft || !editor)
    return (
      <div role={error ? "alert" : "status"}>
        {error || "Loading effective policy…"}
      </div>
    );
  const sourceOptions = (kind?: string) =>
    sources
      .filter((s) => !kind || s.kind === kind)
      .map((s) => ({
        value: s.id,
        label: `${s.name}${s.enabled ? "" : " (paused)"}`,
      }));
  const sourceField = (key: string, label: string, kind?: string) =>
    field(key, label, { options: sourceOptions(kind) });
  const renderRows = (
    id: string,
    key: string,
    label: string,
    fields: Field[],
    help?: string,
  ) => (
    <RowsEditor
      label={label}
      path={`rules.${id}.${key}`}
      value={draft.rules[id][key] || []}
      onChange={(value) => updateRule(id, { ...draft.rules[id], [key]: value })}
      fields={fields}
      help={help}
      issues={issues}
    />
  );
  return (
    <div className="policy-workbench">
      <div className="section-heading">
        <div>
          <h2>Detection policy</h2>
          <p className="section-note">
            Choose what Grantline evaluates and review the effect before saving.
            Changes apply to the next collection.
          </p>
        </div>
        <a href="/docs/policies/">Policy guide ↗</a>
      </div>
      <div className="policy-toolbar">
        <span>
          <Badge value={defaults ? "defaults" : "custom"} /> Revision{" "}
          {editor.revision} · {Object.keys(draft.rules).length} of 8 rules
          enabled
        </span>
        <div>
          <button
            type="button"
            className="button"
            disabled={busy || mode === "form"}
            onClick={() => switchMode("form")}
          >
            <SlidersHorizontal size={15} /> Guided editor
          </button>
          <button
            type="button"
            className="button"
            disabled={busy || mode === "yaml"}
            onClick={() => switchMode("yaml")}
          >
            <Code2 size={15} /> Advanced YAML
          </button>
        </div>
      </div>
      {saved && (
        <p className="product-notice" role="status">
          <Check size={16} />
          Policy revision saved. Existing reports and triage are unchanged.
        </p>
      )}
      {error && (
        <p className="product-error" role="alert">
          {error}
        </p>
      )}
      <FieldErrors issues={issues} />
      <form
        id={mode === "form" ? "field-policy" : undefined}
        tabIndex={-1}
        onSubmit={(e) => {
          e.preventDefault();
          void validate(true);
        }}
      >
        <fieldset disabled={busy} className="policy-fields">
          <div className="policy-defaults">
            <p>
              {defaults
                ? "Using all eight built-in rules and all enabled connections. These defaults are starting points, not a universal risk standard."
                : "This custom policy replaces the defaults. Rules switched off or omitted from YAML will not run."}
            </p>
            <button
              type="button"
              className="text-button"
              onClick={() => {
                invalidate();
                setDraft(structuredClone(editor.defaults));
                setDefaults(true);
                setMode("form");
                setYaml(editor.yaml);
              }}
            >
              Use built-in defaults
            </button>
          </div>
          {mode === "yaml" ? (
            <label>
              Complete policy YAML
              <textarea
                id="field-policy"
                className="code-input policy-input"
                rows={18}
                value={yaml}
                onChange={(e) => {
                  invalidate();
                  setDefaults(false);
                  setYaml(e.target.value);
                }}
                spellCheck={false}
              />
              <small>
                Custom YAML is a complete replacement, not a patch. An omitted
                rule is disabled. Leave blank to restore defaults.
              </small>
            </label>
          ) : (
            <>
              <fieldset
                className="policy-sources"
                id="field-required_sources"
                tabIndex={-1}
              >
                <legend>Required sources</legend>
                <p className="section-note">
                  Missing or incomplete required sources prevent complete
                  coverage. Source names are not inferred environment labels.
                </p>
                {!sources.length && (
                  <p>
                    Add and enable an integration first. Defaults will include
                    it automatically.
                  </p>
                )}
                {sources.map((s) => (
                  <label className="check-label" key={s.id}>
                    <input
                      type="checkbox"
                      checked={(draft.required_sources || []).includes(s.id)}
                      onChange={(e) =>
                        change({
                          ...draft,
                          required_sources: e.target.checked
                            ? [...(draft.required_sources || []), s.id]
                            : draft.required_sources.filter(
                                (id) => id !== s.id,
                              ),
                        })
                      }
                    />
                    <span>
                      {s.name}
                      <small>
                        {s.kind} ·{" "}
                        {s.enabled ? "Enabled" : "Paused — not collected"}
                      </small>
                    </span>
                  </label>
                ))}
                {(draft.required_sources || [])
                  .filter((id) => !sources.some((s) => s.id === id))
                  .map((id) => (
                    <label className="check-label" key={id}>
                      <input
                        type="checkbox"
                        checked
                        onChange={() =>
                          change({
                            ...draft,
                            required_sources: draft.required_sources.filter(
                              (v) => v !== id,
                            ),
                          })
                        }
                      />
                      <span>
                        {id}
                        <small>
                          Connection is no longer present; keeping it required
                          preserves UNKNOWN coverage.
                        </small>
                      </span>
                    </label>
                  ))}
              </fieldset>
              <div className="policy-rule-list">
                {rules.map(([id, title, provider, description]) => {
                  const rule = draft.rules[id];
                  return (
                    <section
                      className={`policy-rule ${rule ? "" : "policy-rule-off"}`}
                      key={id}
                    >
                      <div className="policy-rule-head">
                        <label className="check-label">
                          <input
                            type="checkbox"
                            checked={!!rule}
                            onChange={(e) => {
                              const next = { ...draft.rules };
                              if (e.target.checked)
                                next[id] =
                                  remembered.current[id] ||
                                  editor.defaults.rules[id];
                              else {
                                remembered.current[id] = next[id];
                                delete next[id];
                              }
                              change({ ...draft, rules: next });
                            }}
                          />
                          <span>
                            <strong>
                              {id} · {title}
                            </strong>
                            <small>{provider}</small>
                          </span>
                        </label>
                        <span>
                          {rule ? "Enabled" : "Disabled — not evaluated"}
                        </span>
                      </div>
                      <p>{description}</p>
                      {rule && (
                        <div className="policy-rule-options">
                          <label>
                            Severity
                            <select
                              value={rule.Severity}
                              onChange={(e) =>
                                updateRule(id, {
                                  ...rule,
                                  Severity: e.target.value,
                                })
                              }
                            >
                              {severityOptions.map((v) => (
                                <option key={v}>{v}</option>
                              ))}
                            </select>
                          </label>
                          {(id === "IL003" || id === "IL007") &&
                            (id === "IL003"
                              ? ["max_client_secret_validity"]
                              : ["max_x509_svid_ttl", "max_jwt_svid_ttl"]
                            ).map((key) => (
                              <label key={key}>
                                {key === "max_client_secret_validity"
                                  ? "Maximum client secret validity"
                                  : key === "max_x509_svid_ttl"
                                    ? "Maximum X.509 SVID lifetime"
                                    : "Maximum JWT SVID lifetime"}
                                <input
                                  id={`field-limits.${key}`}
                                  aria-invalid={
                                    issues.some(
                                      (i) => i.field === `limits.${key}`,
                                    ) || undefined
                                  }
                                  aria-describedby={`help-limits.${key}`}
                                  required
                                  value={draft.limits[key] || ""}
                                  placeholder="24h"
                                  onChange={(e) =>
                                    change({
                                      ...draft,
                                      limits: {
                                        ...draft.limits,
                                        [key]: e.target.value,
                                      },
                                    })
                                  }
                                />
                                <small
                                  id={`help-limits.${key}`}
                                  className={
                                    issues.some(
                                      (i) => i.field === `limits.${key}`,
                                    )
                                      ? "field-error"
                                      : ""
                                  }
                                >
                                  {issues.find(
                                    (i) => i.field === `limits.${key}`,
                                  )?.message ||
                                    "Use hours or minutes, such as 168h (7 days), 24h or 15m."}
                                </small>
                              </label>
                            ))}
                          {id === "IL006" && (
                            <label className="check-label">
                              <input
                                type="checkbox"
                                checked={!!rule.ForbidNamespaceOnly}
                                onChange={(e) =>
                                  updateRule(id, {
                                    ...rule,
                                    ForbidNamespaceOnly: e.target.checked,
                                  })
                                }
                              />
                              Forbid namespace-only workload selectors
                            </label>
                          )}
                        </div>
                      )}
                      {rule && (
                        <details className="policy-rule-details">
                          <summary>
                            {id === "IL004"
                              ? `${rule.RequireOwnersFor?.length || 0} owner targets — select exact objects`
                              : id === "IL008"
                                ? "Environment separation & approved exceptions"
                                : "Exact exceptions and scope"}
                          </summary>
                          {id === "IL001" &&
                            renderRows(
                              id,
                              "AllowedGrants",
                              "Approved RBAC grants",
                              [
                                sourceField(
                                  "SourceID",
                                  "Kubernetes connection",
                                  "kubernetes",
                                ),
                                field("RoleNativeID", "Role native ID"),
                                field(
                                  "ServiceAccountNativeID",
                                  "Service account native ID",
                                ),
                                field("Scope", "Exact scope"),
                              ],
                            )}
                          {id === "IL002" &&
                            renderRows(
                              id,
                              "AllowedVaultKubernetesBindings",
                              "Approved Vault subjects",
                              [
                                sourceField(
                                  "VaultSourceID",
                                  "Vault connection",
                                  "vault",
                                ),
                                field("RoleNativeID", "Vault role native ID"),
                                sourceField(
                                  "KubernetesSourceID",
                                  "Kubernetes connection",
                                  "kubernetes",
                                ),
                                field(
                                  "ServiceAccountID",
                                  "Service account native ID",
                                ),
                              ],
                            )}
                          {id === "IL004" &&
                            renderRows(
                              id,
                              "RequireOwnersFor",
                              "Objects requiring owners",
                              [
                                sourceField(
                                  "SourceID",
                                  "Entra connection",
                                  "entra",
                                ),
                                field("ObjectID", "Object ID"),
                                field("ObjectKind", "Object type", {
                                  options: [
                                    {
                                      value: "application_registration",
                                      label: "Application registration",
                                    },
                                    {
                                      value: "service_principal",
                                      label: "Service principal",
                                    },
                                  ],
                                }),
                              ],
                              "Only these exact targets require owners. An empty list does not require owners on every object.",
                            )}
                          {id === "IL005" &&
                            renderRows(
                              id,
                              "AllowedAppRoles",
                              "Approved application roles",
                              [
                                sourceField(
                                  "SourceID",
                                  "Entra connection",
                                  "entra",
                                ),
                                field(
                                  "PrincipalObjectID",
                                  "Principal object ID",
                                ),
                                field("ResourceObjectID", "Resource object ID"),
                                field("AppRoleID", "App role ID"),
                              ],
                            )}
                          {id === "IL008" && (
                            <>
                              {renderRows(
                                id,
                                "SeparatedEnvironments",
                                "Separated environments",
                                [
                                  field("First", "First environment"),
                                  field("Second", "Second environment"),
                                ],
                                "Exact names must match your context declarations below.",
                              )}
                              {renderRows(
                                id,
                                "AllowedSharedIdentities",
                                "Approved shared identities",
                                [
                                  field("First", "First environment"),
                                  field("Second", "Second environment"),
                                  sourceField("SourceID", "Connection"),
                                  field("Kind", "Identity kind", {
                                    options: kinds,
                                  }),
                                  field("NativeID", "Native identity ID"),
                                  field("Reason", "Approval reason"),
                                ],
                              )}
                            </>
                          )}
                          {["IL003", "IL006", "IL007"].includes(id) && (
                            <p>
                              Configure this rule using the controls above. It
                              has no per-object exception list.
                            </p>
                          )}
                        </details>
                      )}
                    </section>
                  );
                })}
              </div>
            </>
          )}
          <details className="policy-context">
            <summary>
              Advanced business context & relationship declarations
            </summary>
            <p>
              Environment separation requires explicit application members and
              environment names. Names alone do not prove a shared identity.{" "}
              <a href="/docs/policies/#context-declarations">
                See the complete context example ↗
              </a>
            </p>
            <label>
              Context YAML
              <textarea
                id="field-bindings"
                className="code-input policy-input"
                rows={12}
                value={context}
                onChange={(e) => {
                  invalidate();
                  setContext(e.target.value);
                }}
                spellCheck={false}
                placeholder="Optional explicit context bindings"
              />
            </label>
          </details>
          <div className="wizard-actions">
            <button className="primary-button" disabled={busy}>
              {busy ? "Checking…" : "Validate & preview"}
            </button>
          </div>
        </fieldset>
      </form>
      {review && (
        <section className="policy-review" aria-live="polite">
          <h3>Review this change</h3>
          <p>
            Enabled: {Object.keys(review.effective.rules).join(", ")}. Disabled:{" "}
            {review.disabled_rules.join(", ") || "none"}.
          </p>
          {review.warnings.length > 0 && (
            <ul className="coverage-warnings">
              {review.warnings.map((v: string, i: number) => (
                <li key={i}>{v}</li>
              ))}
            </ul>
          )}
          {review.preview &&
            (review.preview.available ? (
              <>
                <p>
                  Saved report from {when(review.preview.observed_at)} ·{" "}
                  {review.preview.run_kind === "import"
                    ? "Imported report"
                    : "Collected report"}
                  {review.preview.fixture_notice ? " · Synthetic data" : ""}.{" "}
                  {review.preview.message}
                </p>
                <p>
                  <strong>
                    {review.preview.before} → {review.preview.after} findings
                  </strong>{" "}
                  · {review.preview.added} new matches ·{" "}
                  {review.preview.no_longer_reported} no longer reported.
                </p>
                <div className="product-table-wrap">
                  <table className="product-table">
                    <thead>
                      <tr>
                        <th>Rule</th>
                        <th>Saved result</th>
                        <th>Preview result</th>
                        <th>Findings before → after</th>
                      </tr>
                    </thead>
                    <tbody>
                      {review.preview.rules.map((r: any) => (
                        <tr key={r.id}>
                          <td>{r.id}</td>
                          <td>{r.before_outcome || "Disabled"}</td>
                          <td>{r.after_outcome || "Disabled"}</td>
                          <td>
                            {r.before} → {r.after}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {review.preview.binding_issues?.length > 0 && (
                  <p role="status">
                    Some context references could not be resolved in this
                    snapshot. Collect fresh evidence after reviewing your
                    declarations.
                  </p>
                )}
              </>
            ) : (
              <p>{review.preview.message}</p>
            ))}
          {review.requires_acknowledgement && (
            <label className="check-label coverage-ack">
              <input
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.target.checked)}
              />
              I understand that this disables rules or reduces required-source
              coverage. Fewer findings do not mean the risks were fixed.
            </label>
          )}
          <button
            type="button"
            className="primary-button"
            disabled={busy || (review.requires_acknowledgement && !ack)}
            onClick={save}
          >
            Save new revision
          </button>
        </section>
      )}
    </div>
  );
}
