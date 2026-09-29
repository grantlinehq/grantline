export type Entity = {
  id: string;
  kind: string;
  name: string;
  native_id: string;
  source_id: string;
  scope: string;
  observed_at: string;
  provenance: string;
  attributes: Record<string, unknown>;
  field_status: Record<string, string>;
};
export type Edge = {
  id: string;
  from: string;
  to: string;
  type: string;
  scope: string;
  assertion_kind: string;
  evidence_ids: string[];
  observed_at: string;
};
export type Evidence = {
  id: string;
  source_id: string;
  native_id: string;
  locator: string;
  fields: string[];
  observed_at: string;
  assertion_kind: string;
};
export type Source = {
  id: string;
  kind: string;
  scope: string;
  status: string;
  complete: boolean;
  pagination_complete: boolean;
  provenance: string;
  warnings: string[];
  permissions_observed: string[];
  error_code?: string;
};
export type Finding = {
  id: string;
  rule_id: string;
  severity: string;
  condition: string;
  description: string;
  recommendation: string;
  affected_entity_ids: string[];
  affected_relationship_ids: string[];
  evidence_ids: string[];
  limitations: string[];
};
export type Context = {
  entity_id: string;
  application_id: string;
  application_name: string;
  environment: string;
  owner_hint?: string;
  evidence_ids: string[];
};
export type Report = {
  generated_at: string;
  snapshot_collected_at: string;
  fixture_notice?: string;
  input_provenances: string[];
  snapshot: {
    entities: Entity[];
    relationships: Edge[];
    sources: Source[];
    evidence: Evidence[];
  };
  evidence: Evidence[];
  findings: Finding[];
  rule_results: {
    rule_id: string;
    outcome: string;
    finding_ids: string[];
    limitations?: string[];
  }[];
  contexts?: Context[];
  binding_issues?: string[];
  policy_exceptions?: {
    rule_id: string;
    entity_id: string;
    environments: string[];
    reason: string;
  }[];
  completeness: {
    complete: boolean;
    required_sources: {
      source_id: string;
      satisfies_required_coverage: boolean;
      limitations?: string[];
    }[];
  };
};
export type Selection = {
  type: "entity" | "finding" | "edge" | "source";
  id: string;
} | null;
export const ruleNames: Record<string, string> = {
  IL001: "Broad Kubernetes permissions",
  IL002: "Unreviewed Vault subjects",
  IL003: "Long-lived client credentials",
  IL004: "Missing application owners",
  IL005: "Unreviewed application roles",
  IL006: "Broad workload selectors",
  IL007: "Long-lived workload identities",
  IL008: "Identity shared across environments",
};
const labels: Record<string, string> = {
  live_api: "Live API",
  provider_export: "Provider export",
  synthetic_fixture: "Synthetic fixture",
  spiffe_identity: "SPIFFE identity",
  spire_entry: "SPIRE registration",
  assigned_spiffe_id: "Assigned SPIFFE ID",
  NOT_APPLICABLE: "Not applicable",
};
export const human = (value: string) =>
  labels[value] ??
  value.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
export const date = (value: string) =>
  new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(new Date(value));
export const shortDate = (value: string) =>
  new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
export const rank: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};
export const isPrincipal = (e: Entity) =>
  ["service_account", "service_principal", "spiffe_identity"].includes(e.kind);
export const sourceName: Record<string, string> = {
  kubernetes: "Kubernetes",
  vault: "HashiCorp Vault",
  jenkins: "Jenkins",
  entra: "Microsoft Entra",
  github: "GitHub",
  spire: "SPIRE",
};
