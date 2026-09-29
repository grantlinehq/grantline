import { useEffect, useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Database,
  Filter,
  Fingerprint,
  Network,
  Search,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import {
  Badge,
  CopyButton,
  Empty,
  EntityIcon,
  EntityLabel,
  EvidenceList,
  Modal,
  PageHead,
  PanelTitle,
  SourceIcon,
} from "./components";
import {
  date,
  human,
  isPrincipal,
  rank,
  ruleNames,
  shortDate,
  sourceName,
  type Report,
  type Selection,
} from "./types";

type Props = { report: Report; onSelect: (s: Selection) => void };
function SearchInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <label className="filter-search">
      <Search size={16} />
      <input
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}
export function Inventory({
  report,
  onSelect,
  source,
  setSource,
  principals,
  setPrincipals,
}: Props & {
  source: string;
  setSource: (s: string) => void;
  principals: boolean;
  setPrincipals: (v: boolean) => void;
}) {
  const [query, setQuery] = useState(""),
    [kind, setKind] = useState(""),
    [environment, setEnvironment] = useState(""),
    [application, setApplication] = useState(""),
    [page, setPage] = useState(0),
    [ascending, setAscending] = useState(true);
  const contexts = report.contexts ?? [];
  const environments = [...new Set(contexts.map((c) => c.environment))].sort(),
    apps = [
      ...new Map(
        contexts.map((c) => [c.application_id, c.application_name]),
      ).entries(),
    ];
  const entities = useMemo(
    () =>
      report.snapshot.entities
        .filter(
          (e) =>
            (!source || e.source_id === source) &&
            (!kind || e.kind === kind) &&
            (!principals || isPrincipal(e)) &&
            `${e.name} ${e.native_id} ${e.scope}`
              .toLowerCase()
              .includes(query.toLowerCase()) &&
            (!environment ||
              contexts.some(
                (c) => c.entity_id === e.id && c.environment === environment,
              )) &&
            (!application ||
              contexts.some(
                (c) => c.entity_id === e.id && c.application_id === application,
              )),
        )
        .sort(
          (a, b) =>
            (a.name.localeCompare(b.name) || a.id.localeCompare(b.id)) *
            (ascending ? 1 : -1),
        ),
    [
      report,
      source,
      kind,
      principals,
      query,
      environment,
      application,
      ascending,
    ],
  );
  useEffect(
    () => setPage(0),
    [source, kind, principals, query, environment, application],
  );
  const visible = entities.slice(page * 25, page * 25 + 25);
  function reset() {
    setSource("");
    setKind("");
    setEnvironment("");
    setApplication("");
    setQuery("");
    setPrincipals(false);
  }
  return (
    <>
      <PageHead
        eyebrow="INVENTORY"
        title="Identity inventory"
        description="Collected principals and the workloads, registrations, and policies around them."
      />
      <div className="inventory-summary">
        <Fingerprint size={18} />
        <strong>
          {report.snapshot.entities.filter(isPrincipal).length} native
          identities
        </strong>
        <span>across {report.snapshot.entities.length} collected objects</span>
        <label className="toggle-label">
          <input
            type="checkbox"
            checked={principals}
            onChange={(e) => setPrincipals(e.target.checked)}
          />
          Native identities only
        </label>
      </div>
      <div className="panel">
        <div className="filter-bar">
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Search names, native IDs, or scopes…"
          />
          <select
            aria-label="Filter source"
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="">All sources</option>
            {report.snapshot.sources.map((s) => (
              <option value={s.id} key={s.id}>
                {s.id}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter kind"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="">All kinds</option>
            {[...new Set(report.snapshot.entities.map((e) => e.kind))]
              .sort()
              .map((k) => (
                <option key={k} value={k}>
                  {human(k)}
                </option>
              ))}
          </select>
          <select
            aria-label="Filter environment"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          >
            <option value="">All environments</option>
            {environments.map((e) => (
              <option key={e}>{e}</option>
            ))}
          </select>
          <select
            aria-label="Filter application"
            value={application}
            onChange={(e) => setApplication(e.target.value)}
          >
            <option value="">All applications</option>
            {apps.map(([id, name]) => (
              <option value={id} key={id}>
                {name}
              </option>
            ))}
          </select>
        </div>
        <div className="table-meta">
          <span>
            {entities.length} objects
            {(environment || application) && " · Operator-declared context"}
          </span>
          <button className="text-button" onClick={reset}>
            Clear filters
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>
                  <button
                    className="sort-button"
                    onClick={() => setAscending(!ascending)}
                  >
                    Identity / object{" "}
                    <ArrowDown
                      size={13}
                      className={ascending ? "" : "rotate"}
                    />
                  </button>
                </th>
                <th>Source</th>
                <th>Environment</th>
                <th>Findings</th>
                <th>Last observed</th>
                <th>
                  <span className="sr-only">Inspect</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => {
                const entityContexts = contexts.filter(
                    (c) => c.entity_id === e.id,
                  ),
                  count = report.findings.filter((f) =>
                    f.affected_entity_ids.includes(e.id),
                  ).length;
                return (
                  <tr key={e.id}>
                    <td>
                      <EntityLabel
                        entity={e}
                        onClick={() => onSelect({ type: "entity", id: e.id })}
                      />
                    </td>
                    <td>
                      <span className="cell-source">{e.source_id}</span>
                      <small>{human(e.provenance)}</small>
                    </td>
                    <td>
                      {entityContexts.length ? (
                        <div className="tag-list">
                          {[
                            ...new Set(
                              entityContexts.map((c) => c.environment),
                            ),
                          ].map((env) => (
                            <span className="tag" key={env}>
                              {env}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="muted">Unassigned</span>
                      )}
                    </td>
                    <td>
                      {count ? (
                        <span className="finding-count">{count} findings</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="nowrap">{shortDate(e.observed_at)}</td>
                    <td>
                      <button
                        className="icon-button"
                        aria-label={`Inspect ${e.name}`}
                        onClick={() => onSelect({ type: "entity", id: e.id })}
                      >
                        <ChevronRight size={16} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!entities.length && (
          <Empty title="No objects match these filters">
            Try a broader search or clear the filters.
          </Empty>
        )}
        <div className="pagination">
          <span>
            {entities.length
              ? `${page * 25 + 1}–${Math.min((page + 1) * 25, entities.length)}`
              : "0"}{" "}
            of {entities.length} objects
          </span>
          <div>
            <span>25 per page</span>
            <button
              className="icon-button"
              aria-label="Previous page"
              disabled={!page}
              onClick={() => setPage(page - 1)}
            >
              <ChevronLeft size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Next page"
              disabled={(page + 1) * 25 >= entities.length}
              onClick={() => setPage(page + 1)}
            >
              <ChevronRight size={17} />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
export function Findings({
  report,
  onSelect,
  rule,
  setRule,
}: Props & { rule: string; setRule: (r: string) => void }) {
  const [query, setQuery] = useState(""),
    [severity, setSeverity] = useState("");
  const filtered = report.findings
    .filter(
      (f) =>
        (!rule || f.rule_id === rule) &&
        (!severity || f.severity === severity) &&
        `${f.description} ${f.condition} ${f.rule_id} ${ruleNames[f.rule_id]}`
          .toLowerCase()
          .includes(query.toLowerCase()),
    )
    .sort(
      (a, b) => rank[b.severity] - rank[a.severity] || a.id.localeCompare(b.id),
    );
  const results = report.rule_results.filter(
    (r) => !rule || r.rule_id === rule,
  );
  return (
    <>
      <PageHead
        eyebrow="POLICY REVIEW"
        title="Findings & policy checks"
        description="Every finding carries its condition, affected identities, and evidence."
      />
      <div className="finding-severity-tabs">
        <button
          className={!severity ? "selected" : ""}
          onClick={() => setSeverity("")}
        >
          All severities <b>{report.findings.length}</b>
        </button>
        {["critical", "high", "medium", "low"].map((s) => (
          <button
            key={s}
            className={severity === s ? "selected" : ""}
            onClick={() => setSeverity(s)}
          >
            <span className={`severity-dot marker-${s}`} />
            {human(s)}
            <b>{report.findings.filter((f) => f.severity === s).length}</b>
          </button>
        ))}
      </div>
      <div className="panel">
        <div className="filter-bar">
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Search findings and conditions…"
          />
          <select
            aria-label="Filter rule"
            value={rule}
            onChange={(e) => setRule(e.target.value)}
          >
            <option value="">All policy rules</option>
            {report.rule_results.map((r) => (
              <option key={r.rule_id} value={r.rule_id}>
                {r.rule_id} · {ruleNames[r.rule_id]}
              </option>
            ))}
          </select>
          <button
            className="text-button"
            onClick={() => {
              setRule("");
              setQuery("");
              setSeverity("");
            }}
          >
            Clear filters
          </button>
        </div>
        {filtered.map((f) => (
          <button
            className="finding-row"
            key={f.id}
            onClick={() => onSelect({ type: "finding", id: f.id })}
          >
            <div className="finding-row-top">
              <Badge value={f.severity} />
              <code>{f.rule_id}</code>
              <span>{f.evidence_ids.length} evidence records</span>
              <ChevronRight size={16} />
            </div>
            <h3>{ruleNames[f.rule_id] ?? f.condition}</h3>
            <p>{f.description}</p>
            <div className="finding-identities">
              {f.affected_entity_ids.slice(0, 3).map((id) => {
                const e = report.snapshot.entities.find((e) => e.id === id);
                return (
                  <span key={id}>
                    <Fingerprint size={13} />
                    {e?.name ?? id}
                  </span>
                );
              })}
            </div>
          </button>
        ))}
        {!filtered.length && (
          <Empty title="No findings in this view">
            A result without findings may still be unknown. Review the rule
            outcomes below.
          </Empty>
        )}
      </div>
      <div className="panel outcome-panel">
        <PanelTitle
          title="Rule outcomes & limitations"
          description="Findings remain visible even when a check has incomplete evidence."
        />
        <div className="outcomes">
          {results.map((r) => (
            <div className="outcome" key={r.rule_id}>
              <div>
                <code>{r.rule_id}</code>
                <strong>{ruleNames[r.rule_id]}</strong>
                <Badge value={r.outcome} />
              </div>
              {r.limitations?.map((l, i) => (
                <p key={i}>{l}</p>
              ))}
            </div>
          ))}
        </div>
      </div>
      {!!report.policy_exceptions?.length && (
        <div className="panel outcome-panel">
          <PanelTitle
            title="Documented shared-service exceptions"
            description="Exact native identity and environment pairs; coverage limitations still apply."
          />
          {report.policy_exceptions.map((e, i) => (
            <div className="exception" key={i}>
              <button
                className="text-button"
                onClick={() => onSelect({ type: "entity", id: e.entity_id })}
              >
                {
                  report.snapshot.entities.find((x) => x.id === e.entity_id)
                    ?.name
                }
              </button>
              <Badge value="declared">Exception</Badge>
              <p>
                {e.environments.join(" ↔ ")} · {e.reason}
              </p>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
export function Sources({
  report,
  onSelect,
  onInventory,
}: Props & { onInventory: (s: string) => void }) {
  return (
    <>
      <PageHead
        eyebrow="COLLECTION COVERAGE"
        title="Source coverage"
        description="This is a saved report. Status describes collection coverage, not current service health."
      />
      <div
        className={`notice ${report.completeness.complete ? "notice-green" : ""}`}
      >
        <Database size={18} />
        <span>
          <strong>
            {report.completeness.complete
              ? "All required sources were collected."
              : "Required source coverage is incomplete."}
          </strong>{" "}
          Object timestamps may differ across source collections. Check each
          source before comparing environments.
        </span>
      </div>
      <div className="sources-grid">
        {report.snapshot.sources.map((s) => {
          const entities = report.snapshot.entities.filter(
            (e) => e.source_id === s.id,
          );
          const times = entities.map((e) => e.observed_at).sort();
          return (
            <div className="panel source-card" key={s.id}>
              <div className="source-card-head">
                <SourceIcon kind={s.kind} />
                <div>
                  <h2>{sourceName[s.kind]}</h2>
                  <p>{s.id}</p>
                </div>
                <Badge
                  value={
                    s.complete && s.pagination_complete && s.status === "ok"
                      ? "complete"
                      : "partial"
                  }
                />
              </div>
              <dl>
                <dt>Collection transport</dt>
                <dd>{human(s.provenance)}</dd>
                <dt>Source scope</dt>
                <dd className="mono">{s.scope}</dd>
                <dt>Latest object evidence</dt>
                <dd>
                  {times.length ? date(times.at(-1)!) : "No object timestamps"}
                </dd>
                <dt>Pagination</dt>
                <dd>{s.pagination_complete ? "Complete" : "Incomplete"}</dd>
              </dl>
              <div className="source-card-counts">
                <div>
                  <strong>{entities.length}</strong>
                  <span>objects</span>
                </div>
                <div>
                  <strong>
                    {report.evidence.filter((e) => e.source_id === s.id).length}
                  </strong>
                  <span>evidence records</span>
                </div>
                <div>
                  <strong>{s.warnings?.length ?? 0}</strong>
                  <span>warnings</span>
                </div>
              </div>
              <div className="source-card-actions">
                <button
                  className="text-button"
                  onClick={() => onSelect({ type: "source", id: s.id })}
                >
                  Inspect source
                  <ArrowRight size={15} />
                </button>
                <button
                  className="small-button"
                  onClick={() => onInventory(s.id)}
                >
                  View inventory
                </button>
              </div>
            </div>
          );
        })}
      </div>
      {!!report.binding_issues?.length && (
        <div className="panel outcome-panel">
          <PanelTitle
            title="Unresolved declarations"
            description="No live objects or relationships are invented for missing references."
          />
          {report.binding_issues.map((issue, i) => (
            <p className="binding-issue" key={i}>
              <ShieldAlert size={16} />
              {issue}
            </p>
          ))}
        </div>
      )}
    </>
  );
}

export function Detail({
  report,
  selection,
  onSelect,
  onClose,
  onGraph,
}: Props & {
  selection: NonNullable<Selection>;
  onClose: () => void;
  onGraph: (id: string) => void;
}) {
  useEffect(() => {
    document.querySelector<HTMLElement>(".drawer")?.scrollTo(0, 0);
  }, [selection.id]);
  const { entities, relationships, sources } = report.snapshot;
  const selectedEntity =
    selection.type === "entity"
      ? entities.find((e) => e.id === selection.id)
      : undefined;
  const finding =
    selection.type === "finding"
      ? report.findings.find((f) => f.id === selection.id)
      : undefined;
  const edge =
    selection.type === "edge"
      ? relationships.find((e) => e.id === selection.id)
      : undefined;
  const source =
    selection.type === "source"
      ? sources.find((s) => s.id === selection.id)
      : undefined;
  const related = selectedEntity
    ? relationships.filter(
        (e) => e.from === selectedEntity.id || e.to === selectedEntity.id,
      )
    : [];
  const contexts = (report.contexts ?? []).filter(
    (c) => c.entity_id === selectedEntity?.id,
  );
  const evidenceIDs = selectedEntity
    ? report.evidence
        .filter(
          (e) =>
            e.source_id === selectedEntity.source_id &&
            e.native_id === selectedEntity.native_id,
        )
        .map((e) => e.id)
    : (finding?.evidence_ids ??
      edge?.evidence_ids ??
      (source
        ? report.evidence
            .filter((e) => e.source_id === source.id)
            .map((e) => e.id)
        : []));
  const title =
    selectedEntity?.name ??
    (finding ? ruleNames[finding.rule_id] : undefined) ??
    (edge ? human(edge.type) : undefined) ??
    (source ? sourceName[source.kind] : "Details");
  function entity(id: string) {
    const e = entities.find((e) => e.id === id);
    return e ? (
      <EntityLabel
        key={id}
        entity={e}
        onClick={() => onSelect({ type: "entity", id })}
      />
    ) : null;
  }
  return (
    <Modal title={human(selection.type) + " details"} onClose={onClose} drawer>
      <div className="detail-body">
        <div className="detail-eyebrow">
          {selectedEntity
            ? human(selectedEntity.kind)
            : (finding?.rule_id ??
              source?.id ??
              "EVIDENCE-BACKED RELATIONSHIP")}
        </div>
        <h2 className="detail-title">{title}</h2>
        <div className="detail-badges">
          {selectedEntity && <Badge value={selectedEntity.provenance} />}{" "}
          {finding && <Badge value={finding.severity} />}{" "}
          {edge && <Badge value={edge.assertion_kind} />}{" "}
          {source && <Badge value={source.status} />}
        </div>
        {selectedEntity && (
          <>
            <button
              className="primary-button graph-button"
              onClick={() => onGraph(selectedEntity.id)}
            >
              <Network size={16} />
              Explore relationships
              <ArrowRight size={16} />
            </button>
            <div className="detail-section">
              <h3>Identity record</h3>
              <dl>
                <dt>Native ID</dt>
                <dd className="mono">
                  {selectedEntity.native_id}
                  <CopyButton value={selectedEntity.native_id} />
                </dd>
                <dt>Source</dt>
                <dd>
                  <button
                    className="text-button"
                    onClick={() =>
                      onSelect({ type: "source", id: selectedEntity.source_id })
                    }
                  >
                    {selectedEntity.source_id}
                    <ArrowRight size={13} />
                  </button>
                </dd>
                <dt>Scope</dt>
                <dd className="mono">{selectedEntity.scope}</dd>
                <dt>Observed</dt>
                <dd>{date(selectedEntity.observed_at)}</dd>
              </dl>
            </div>
            <div className="detail-section">
              <h3>
                Business context <Badge value="declared" />
              </h3>
              {contexts.length ? (
                contexts.map((c, i) => (
                  <div className="context-card" key={i}>
                    <strong>{c.application_name}</strong>
                    <span className="tag">{c.environment}</span>
                    <p>Owner hint: {c.owner_hint || "Not assigned"}</p>
                  </div>
                ))
              ) : (
                <p className="muted">
                  No explicit application or environment binding.
                </p>
              )}
              <p className="field-note">
                Owner hints are operator declarations, not provider ownership
                records.
              </p>
            </div>
            <div className="detail-section">
              <h3>Collected metadata</h3>
              {Object.entries(selectedEntity.field_status ?? {}).length ===
              0 ? (
                <p className="muted">
                  This object has no additional metadata fields.
                </p>
              ) : (
                Object.entries(selectedEntity.field_status).map(
                  ([k, status]) => (
                    <details className="attribute" key={k}>
                      <summary>
                        <span>{human(k)}</span>
                        <Badge value={status} />
                      </summary>
                      <pre>
                        {JSON.stringify(
                          selectedEntity.attributes?.[k] ?? null,
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  ),
                )
              )}
            </div>
            <div className="detail-section">
              <h3>Associated findings</h3>
              {report.findings
                .filter((f) =>
                  f.affected_entity_ids.includes(selectedEntity.id),
                )
                .map((f) => (
                  <button
                    className="detail-finding"
                    key={f.id}
                    onClick={() => onSelect({ type: "finding", id: f.id })}
                  >
                    <Badge value={f.severity} />
                    <span>{ruleNames[f.rule_id]}</span>
                    <ChevronRight size={16} />
                  </button>
                ))}
              {!report.findings.some((f) =>
                f.affected_entity_ids.includes(selectedEntity.id),
              ) && (
                <p className="muted">
                  No findings directly reference this object.
                </p>
              )}
            </div>
            <div className="detail-section">
              <h3>
                Relationships{" "}
                <span className="count-pill">{related.length}</span>
              </h3>
              {related.map((e) => (
                <button
                  className="related-row"
                  key={e.id}
                  onClick={() => onSelect({ type: "edge", id: e.id })}
                >
                  <span>
                    <small>
                      {human(e.type)} ·{" "}
                      {e.from === selectedEntity.id ? "Outgoing" : "Incoming"}
                    </small>
                    <strong>
                      {
                        entities.find(
                          (x) =>
                            x.id ===
                            (e.from === selectedEntity.id ? e.to : e.from),
                        )?.name
                      }
                    </strong>
                  </span>
                  <Badge value={e.assertion_kind} />
                  <ChevronRight size={15} />
                </button>
              ))}
              {!related.length && (
                <p className="muted">
                  No collected relationships for this object.
                </p>
              )}
            </div>
          </>
        )}
        {finding && (
          <>
            <div className="detail-section">
              <h3>Condition</h3>
              <p>{finding.condition}</p>
              <p>{finding.description}</p>
            </div>
            <div className="recommendation">
              <ShieldAlert size={19} />
              <div>
                <h3>Recommended review</h3>
                <p>{finding.recommendation}</p>
              </div>
            </div>
            <div className="detail-section">
              <h3>Affected identities</h3>
              {finding.affected_entity_ids.map(entity)}
            </div>
            {!!finding.affected_relationship_ids?.length && (
              <div className="detail-section">
                <h3>Affected relationships</h3>
                {finding.affected_relationship_ids.map((id) => (
                  <button
                    className="related-row"
                    key={id}
                    onClick={() => onSelect({ type: "edge", id })}
                  >
                    {human(
                      relationships.find((e) => e.id === id)?.type ??
                        "relationship",
                    )}
                    <ChevronRight size={15} />
                  </button>
                ))}
              </div>
            )}
            <div className="detail-section">
              <h3>Limits of this finding</h3>
              {finding.limitations?.map((l, i) => (
                <p className="field-note" key={i}>
                  {l}
                </p>
              ))}
            </div>
          </>
        )}
        {edge && (
          <>
            <div className="relationship-detail">
              <span>FROM</span>
              {entity(edge.from)}
              <div className="edge-connector">
                <ArrowDown size={18} />
                {human(edge.type)}
                <Badge value={edge.assertion_kind} />
              </div>
              <span>TO</span>
              {entity(edge.to)}
            </div>
            <div className="detail-section">
              <h3>Relationship record</h3>
              <dl>
                <dt>Scope</dt>
                <dd>{edge.scope}</dd>
                <dt>Observed</dt>
                <dd>{date(edge.observed_at)}</dd>
                <dt>Assertion</dt>
                <dd>{human(edge.assertion_kind)}</dd>
              </dl>
              <p className="field-note">
                {edge.assertion_kind === "declared"
                  ? "This connection includes an explicit operator declaration."
                  : "This assertion describes the collected metadata."}{" "}
                A relationship does not prove effective permissions or runtime
                authentication.
              </p>
            </div>
            <button
              className="primary-button"
              onClick={() => onGraph(edge.from)}
            >
              <Network size={16} />
              Explore this neighborhood
            </button>
          </>
        )}
        {source && (
          <>
            <div className="detail-section">
              <h3>Collection record</h3>
              <dl>
                <dt>Source scope</dt>
                <dd>{source.scope}</dd>
                <dt>Transport</dt>
                <dd>{human(source.provenance)}</dd>
                <dt>Coverage</dt>
                <dd>{source.complete ? "Complete" : "Incomplete"}</dd>
                <dt>Pagination</dt>
                <dd>
                  {source.pagination_complete ? "Complete" : "Incomplete"}
                </dd>
                <dt>Error code</dt>
                <dd>{source.error_code ?? "None reported"}</dd>
              </dl>
            </div>
            <div className="detail-section">
              <h3>Observed permissions</h3>
              <div className="permission-list">
                {source.permissions_observed?.map((p) => (
                  <code key={p}>{p}</code>
                ))}
              </div>
            </div>
            <div className="detail-section">
              <h3>Collection warnings</h3>
              {source.warnings?.length ? (
                source.warnings.map((w, i) => <p key={i}>{w}</p>)
              ) : (
                <p className="muted">No source warnings recorded.</p>
              )}
              <p className="field-note">
                This does not check whether the source is available now.
              </p>
            </div>
          </>
        )}
        <div className="detail-section">
          <h3>
            Supporting evidence{" "}
            <span className="count-pill">{evidenceIDs.length}</span>
          </h3>
          <EvidenceList ids={evidenceIDs} evidence={report.evidence} />
        </div>
      </div>
    </Modal>
  );
}
