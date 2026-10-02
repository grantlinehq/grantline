// Separate development-only entry. Vite's production input is index.html;
// this module and its synthetic API are never imported by the shipped application.
import { createRoot } from "react-dom/client";
import { Product } from "./Workspace";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "../styles.css";
import "./product.css";

if (!import.meta.env.DEV) throw new Error("Design preview is development-only");
const at = new Date().toISOString();
const kinds = ["kubernetes", "vault", "jenkins", "entra", "github", "spire"];
const sources = kinds.map((kind, i) => ({
  id: `${kind}-production`,
  kind,
  scope: `${kind}/production`,
  status: i === 1 ? "partial" : "ok",
  complete: i !== 1,
  pagination_complete: true,
  provenance: "synthetic_fixture",
  warnings: i === 1 ? ["One policy is outside the observer scope."] : [],
  permissions_observed: [],
}));
const entities = [
  ["release-controller", "service_account", "kubernetes"],
  ["payments-api", "service_account", "kubernetes"],
  ["inventory-worker", "service_account", "kubernetes"],
  ["payments-federation", "service_principal", "entra"],
  ["deployment-automation", "service_principal", "entra"],
  ["reporting-sync", "service_principal", "entra"],
  ["payments/api", "spiffe_identity", "spire"],
  ["inventory/worker", "spiffe_identity", "spire"],
  ["platform/gateway", "spiffe_identity", "spire"],
  ["release-pipeline", "job", "jenkins"],
  ["deploy-production", "workflow", "github"],
  ["payments-observer", "auth_role", "vault"],
].map(([name, kind, provider], i) => ({
  id: `sample-identity-${i}`,
  name,
  kind,
  native_id:
    i === 3
      ? "00000000-0000-4000-8000-000000000001/servicePrincipals/00000000-0000-4000-8000-0000000000cf/appRoleAssignments/00000000-0000-4000-8000-0000000002c3"
      : `${provider}://${name}`,
  source_id: `${provider}-production`,
  scope: `${provider}/production`,
  observed_at: at,
  provenance: "synthetic_fixture",
  attributes: {
    environment: "production",
    team: i < 3 ? "Platform engineering" : "Payments",
    description: "Fictional identity for visual review",
  },
  field_status: {},
}));
const evidence = entities.map((e, i) => ({
  id: `sample-evidence-${i}`,
  source_id: e.source_id,
  native_id: e.native_id,
  locator:
    i < 3
      ? `clusterroles/${e.name}`
      : `synthetic/demo-catalog/role_binding/${e.native_id}`,
  fields:
    i < 3
      ? ["rules.apiGroups", "rules.resources", "rules.verbs"]
      : ["id", "displayName", "configuration"],
  observed_at: at,
  assertion_kind: "synthetic_fixture",
}));
const findings = [
  {
    id: "sample-finding-long",
    rule_id: "IL005",
    severity: "critical",
    condition: "Unreviewed application role",
    description:
      'Service principal "00000000-0000-4000-8000-0000000000cf" is assigned role "00000000-0000-4000-8000-00000000025f" on resource service principal "00000000-0000-4000-8000-000000002328".',
    recommendation:
      "Review the actual app-role assignment and add an exact exception only when approved.",
    affected_entity_ids: [entities[3].id],
    evidence_ids: [evidence[3].id, evidence[4].id],
    limitations: [],
    affected_relationship_ids: [],
  },
  {
    id: "sample-finding-1",
    rule_id: "IL001",
    severity: "high",
    condition: "Wildcard permissions",
    description:
      "The release-controller service account is bound to a role that permits broad access across API groups and resources.",
    recommendation:
      "Review the release workflow's required operations. Replace wildcard grants with an explicit resource and verb allowlist.",
    affected_entity_ids: [entities[0].id],
    evidence_ids: [evidence[0].id],
    limitations: [],
    affected_relationship_ids: ["sample-edge-0"],
  },
  {
    id: "sample-finding-2",
    rule_id: "IL003",
    severity: "medium",
    condition: "Long-lived credential",
    description:
      "The deployment-automation application has a client credential whose configured validity exceeds the workspace policy.",
    recommendation:
      "Review the credential lifetime and prefer a scoped federated identity where supported.",
    affected_entity_ids: [entities[4].id],
    evidence_ids: [evidence[4].id],
    limitations: [
      "Configured validity does not establish whether this credential was used.",
    ],
    affected_relationship_ids: [],
  },
  {
    id: "sample-finding-3",
    rule_id: "IL004",
    severity: "medium",
    condition: "No application owner",
    description:
      "The reporting-sync application has no owner recorded in the selected directory scope.",
    recommendation:
      "Confirm responsibility with the application team and assign an accountable owner in the source directory.",
    affected_entity_ids: [entities[5].id],
    evidence_ids: [evidence[5].id],
    limitations: [],
    affected_relationship_ids: [],
  },
];
const edges = [0, 1, 2, 3, 4, 6, 7, 8].map((n, i) => ({
  id: `sample-edge-${i}`,
  from: entities[n].id,
  to: entities[(n + 3) % entities.length].id,
  type: i % 2 ? "uses_identity" : "can_assume",
  scope: "production",
  assertion_kind: "synthetic_fixture",
  evidence_ids: [evidence[n].id],
  observed_at: at,
}));
const user = {
  id: "sample-owner",
  name: "Alex Morgan",
  email: "alex@example.test",
  role: "owner",
  mfa_pending: false,
  disabled: false,
  mfa_enabled: true,
};
const users = [
  user,
  {
    ...user,
    id: "sample-analyst",
    name: "Taylor Reed",
    email: "taylor@example.test",
    role: "analyst",
  },
  {
    ...user,
    id: "sample-viewer",
    name: "Sam Lee",
    email: "sam@example.test",
    role: "viewer",
  },
];
const status = {
  mode: "server",
  setup_required: false,
  organization: "Northstar",
  oidc_enabled: false,
};
let integrations = sources.map((s, i) => ({
  id: s.id,
  name: [
    "Production cluster",
    "Workload credentials",
    "Release automation",
    "Corporate directory",
    "Platform repositories",
    "Workload identities",
  ][i],
  kind: s.kind,
  enabled: true,
  revision: 1,
  configured: true,
  tested_at: at,
  updated_at: at,
  test_result: [s],
  secret_ref: "",
  config: {
    source: { ...s },
    auth_mode:
      s.kind === "kubernetes"
        ? "kubeconfig"
        : s.kind === "spire"
          ? "export"
          : "token",
  },
}));
let settings = {
  name: "Northstar",
  revision: 1,
  schedule_minutes: 60,
  retention_days: 30,
  next_run: new Date(Date.now() + 3600000).toISOString(),
  policy: "",
  bindings: "",
};
let runs = [
  {
    id: "sample-run",
    kind: "collection",
    state: "partial",
    created_at: at,
    error_code: "",
  },
];
const reviews: Record<string, any> = {},
  comments: Record<string, any[]> = {};
const activity = [
  {
    id: 1,
    name: "System",
    action: "collection.finished",
    subject: "sample-run",
    created_at: at,
  },
  {
    id: 2,
    name: "Taylor Reed",
    action: "triage.updated",
    subject: "sample-finding-1",
    created_at: at,
  },
  {
    id: 3,
    name: "Alex Morgan",
    action: "integration.saved",
    subject: "kubernetes-production",
    created_at: at,
  },
];
const realFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const url = new URL(String(input), location.origin);
  if (!url.pathname.startsWith("/api/v1/")) return realFetch(input, init);
  const path = url.pathname.slice(7),
    method = init?.method || "GET",
    body = init?.body ? JSON.parse(String(init.body)) : {};
  let output: any = {},
    code = 200;
  if (path === "/status") output = status;
  else if (path === "/auth/session")
    output = { user, csrf: "synthetic-preview" };
  else if (path === "/settings/sso")
    output = {
      issuer: "",
      client_id: "",
      enabled: false,
      secret_configured: false,
      revision: 0,
      redirect_uri: `${location.origin}/api/v1/auth/oidc/callback`,
    };
  else if (path === "/auth/sessions")
    output = [
      {
        created_at: at,
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        current: true,
        mfa_pending: false,
      },
    ];
  else if (path === "/settings/versions") output = [];
  else if (path === "/overview")
    output = {
      run_id: "sample-run",
      snapshot_collected_at: at,
      identities: 9,
      findings: 3,
      sources,
      rule_results: Array.from({ length: 8 }, (_, i) => {
        const rule_id = `IL00${i + 1}`;
        return {
          rule_id,
          outcome:
            i === 1 || i === 6
              ? "UNKNOWN"
              : findings.some((f) => f.rule_id === rule_id)
                ? "FAIL"
                : "PASS",
          finding_ids: findings
            .filter((f) => f.rule_id === rule_id)
            .map((f) => f.id),
        };
      }),
    };
  else if (path.startsWith("/objects/")) {
    const [, , category, id] = path.split("/");
    const all: any[] =
      category === "identities"
        ? entities
        : category === "findings"
          ? findings
          : edges;
    if (id) {
      const item = all.find((v) => v.id === id);
      output = {
        item,
        evidence: evidence.filter(
          (e) =>
            item.evidence_ids?.includes(e.id) || e.native_id === item.native_id,
        ),
        entities: entities.filter((e) =>
          item.affected_entity_ids?.includes(e.id),
        ),
        triage: reviews[id] || { state: "open", revision: 0 },
        comments: comments[id] || [],
      };
    } else {
      const q = (url.searchParams.get("q") || "").toLowerCase(),
        source = url.searchParams.get("source"),
        kind = url.searchParams.get("kind"),
        state = url.searchParams.get("state");
      const filtered = all.filter(
        (v) =>
          (!q || JSON.stringify(v).toLowerCase().includes(q)) &&
          (!source ||
            v.source_id === source ||
            entities.some(
              (e) =>
                e.source_id === source && v.affected_entity_ids?.includes(e.id),
            )) &&
          (!kind || [v.kind, v.rule_id, v.type].includes(kind)) &&
          (!state ||
            state === (reviews[v.id]?.state || "open") ||
            (state === "active" &&
              ["open", "in_review"].includes(
                reviews[v.id]?.state || "open",
              ))) &&
          (url.searchParams.get("native") !== "true" ||
            [
              "service_account",
              "service_principal",
              "spiffe_identity",
            ].includes(v.kind)),
      );
      output = {
        items: filtered.map((v) =>
          category === "findings"
            ? { ...v, triage_state: reviews[v.id]?.state || "open" }
            : v,
        ),
        total: filtered.length,
        page: 0,
        page_size: 50,
        run_id: "sample-run",
      };
    }
  } else if (path === "/users") output = users;
  else if (path === "/runs") {
    if (method === "POST")
      runs = [
        {
          id: `sample-run-${runs.length}`,
          kind: "collection",
          state: "completed",
          created_at: new Date().toISOString(),
          error_code: "",
        },
        ...runs,
      ];
    output = method === "POST" ? { run_id: runs[0].id } : runs;
  } else if (path === "/activity") output = activity;
  else if (path === "/settings") {
    if (method === "PUT")
      settings = {
        ...settings,
        name: body.Name,
        schedule_minutes: body.schedule_minutes,
        retention_days: body.retention_days,
        policy: body.Policy,
        bindings: body.Bindings,
        revision: settings.revision + 1,
      };
    output = settings;
  } else if (path.startsWith("/triage/")) {
    const id = path.split("/").at(-1)!;
    reviews[id] = {
      state: body.State,
      assignee_id: body.Assignee,
      reason: body.Reason,
      expires_at: body.expires_at,
      revision: body.Revision + 1,
    };
  } else if (path.startsWith("/comments/")) {
    const id = path.split("/").at(-1)!;
    comments[id] = [
      ...(comments[id] || []),
      {
        id: Date.now(),
        name: user.name,
        body: body.Body,
        created_at: new Date().toISOString(),
      },
    ];
  } else if (path === "/graph")
    output = {
      nodes: entities,
      edges: edges.filter(
        (e) =>
          e.from === url.searchParams.get("entity") ||
          e.to === url.searchParams.get("entity"),
      ),
      truncated: false,
    };
  else if (path === "/integrations" && method === "GET") output = integrations;
  else if (path.startsWith("/integrations") && path.endsWith("/test"))
    output = [{ id: "sample-test", status: "ok", complete: true }];
  else if (
    path.startsWith("/integrations") &&
    ["POST", "PUT"].includes(method)
  ) {
    const id = path.split("/")[2] || `sample-connection-${integrations.length}`;
    const clean = {
      ...body,
      credentials: undefined,
      id,
      kind: body.config.source.kind,
      revision: (body.revision || 0) + 1,
      configured: true,
      test_result: [],
      updated_at: at,
      tested_at: at,
    };
    integrations = [...integrations.filter((i) => i.id !== id), clean];
    output = { id };
  } else {
    code = 400;
    output = {
      error:
        "This action is available in the installed application. Preview changes are temporary.",
    };
  }
  return new Response(JSON.stringify(output), {
    status: code,
    headers: { "Content-Type": "application/json" },
  });
};
createRoot(document.getElementById("root")!).render(
  <>
    <div className="design-preview-note">
      DESIGN PREVIEW · Fictional data · Do not enter real credentials
    </div>
    <Product initial={status} />
  </>,
);
