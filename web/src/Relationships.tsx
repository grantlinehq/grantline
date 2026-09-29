import { useEffect, useMemo, useState, useRef, useLayoutEffect } from "react";
import {
  ArrowRight,
  Crosshair,
  Expand,
  Minus,
  Network,
  Plus,
  Search,
} from "lucide-react";
import { Badge, Empty, EntityIcon, PageHead } from "./components";
import {
  human,
  type Edge,
  type Entity,
  type Report,
  type Selection,
} from "./types";

type Neighborhood = {
  nodes: Entity[];
  edges: Edge[];
  truncated: boolean;
  limit: number;
};
export default function Relationships({
  report,
  focus,
  setFocus,
  onSelect,
  active,
}: {
  report: Report;
  focus: string;
  setFocus: (id: string) => void;
  onSelect: (s: Selection) => void;
  active: boolean;
}) {
  const [search, setSearch] = useState(""),
    [depth, setDepth] = useState("1"),
    [assertion, setAssertion] = useState(""),
    [type, setType] = useState(""),
    [data, setData] = useState<Neighborhood | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false),
    [zoom, setZoom] = useState(1);
  const canvas = useRef<HTMLDivElement>(null);
  const focusEntity = report.snapshot.entities.find((e) => e.id === focus);
  const candidates = report.snapshot.entities
    .filter((e) =>
      `${e.name} ${e.source_id} ${e.kind} ${e.native_id}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    )
    .slice(0, 8);
  useEffect(() => {
    if (!focus || !active) return;
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setData(null);
    fetch(
      "/api/graph?" +
        new URLSearchParams({ entity: focus, depth, assertion, type }),
      { signal: controller.signal },
    )
      .then(async (r) => {
        if (!r.ok)
          throw new Error(
            r.status === 401
              ? "Session expired. Lock and reopen the workspace."
              : "Could not load relationships.",
          );
        setData(await r.json());
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [focus, depth, assertion, type, active]);
  useEffect(() => setZoom(1), [focus, depth]);
  const positions = useMemo(() => {
    const nodes = data?.nodes ?? [];
    const map: Record<string, { x: number; y: number }> = {};
    if (!nodes.length) return map;
    map[nodes[0].id] = { x: 450, y: 300 };
    nodes.slice(1).forEach((node, index) => {
      const total = nodes.length - 1;
      const ring = Math.floor(index / 12),
        n = Math.min(12, total - ring * 12);
      const angle = ((index % 12) / n) * 2 * Math.PI - Math.PI / 2;
      const radius = 235 + ring * 185;
      map[node.id] = {
        x: 450 + Math.cos(angle) * radius * 1.35,
        y: 300 + Math.sin(angle) * radius,
      };
    });
    return map;
  }, [data]);
  const ringCount = Math.ceil(Math.max(0, (data?.nodes.length ?? 1) - 1) / 12);
  const canvasWidth = ringCount <= 1 ? 900 : 900 + (ringCount - 1) * 500,
    canvasHeight = ringCount <= 1 ? 600 : 600 + (ringCount - 1) * 400;
  useLayoutEffect(() => {
    const el = canvas.current;
    if (el) {
      el.scrollLeft = (el.scrollWidth - el.clientWidth) / 2;
      el.scrollTop = (el.scrollHeight - el.clientHeight) / 2;
    }
  }, [data, zoom]);
  function fit() {
    const el = canvas.current;
    if (el)
      setZoom(Math.min(1, el.clientWidth / canvasWidth, 540 / canvasHeight));
  }
  const roots = report.snapshot.entities
    .filter((e) =>
      report.findings.some((f) => f.affected_entity_ids.includes(e.id)),
    )
    .slice(0, 4);
  return (
    <>
      <PageHead
        eyebrow="RELATIONSHIP EXPLORER"
        title="Relationship explorer"
        description="Explore an identity’s immediate neighborhood. Every edge retains its original assertion and evidence."
      />
      <div className="graph-layout">
        <aside className="panel graph-picker">
          <div className="graph-picker-head">
            <h2>Choose a starting point</h2>
            <p>Search the collected inventory.</p>
          </div>
          <label className="graph-search">
            <Search size={16} />
            <input
              aria-label="Search graph identities"
              placeholder="Name or native ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <div className="graph-candidates">
            {candidates.map((e) => (
              <button
                className={e.id === focus ? "selected" : ""}
                key={e.id}
                onClick={() => setFocus(e.id)}
              >
                <EntityIcon kind={e.kind} />
                <span>
                  <strong>{e.name}</strong>
                  <small>
                    {human(e.kind)} · {e.source_id}
                  </small>
                </span>
              </button>
            ))}
            {candidates.length === 0 && (
              <p className="muted">No matching objects.</p>
            )}
          </div>
          <div className="graph-picker-options">
            <label>
              Neighborhood depth
              <select value={depth} onChange={(e) => setDepth(e.target.value)}>
                <option value="1">1 connection</option>
                <option value="2">2 connections</option>
              </select>
            </label>
            <label>
              Assertion
              <select
                value={assertion}
                onChange={(e) => setAssertion(e.target.value)}
              >
                <option value="">All assertions</option>
                {["observed", "configured", "declared", "inferred"].map((a) => (
                  <option key={a}>{a}</option>
                ))}
              </select>
            </label>
            <label>
              Relationship type
              <select value={type} onChange={(e) => setType(e.target.value)}>
                <option value="">All relationship types</option>
                {[...new Set(report.snapshot.relationships.map((e) => e.type))]
                  .sort()
                  .map((t) => (
                    <option key={t} value={t}>
                      {human(t)}
                    </option>
                  ))}
              </select>
            </label>
            <button
              className="text-button"
              onClick={() => {
                setDepth("1");
                setAssertion("");
                setType("");
                setSearch("");
              }}
            >
              Reset filters
            </button>
          </div>
          <div className="graph-legend">
            <h3>READING THE GRAPH</h3>
            <span>
              <i className="legend-observed" />
              Observed / configured
            </span>
            <span>
              <i className="legend-declared" />
              Declared
            </span>
            <span>
              <i className="legend-inferred" />
              Inferred
            </span>
            <p>
              Direction follows the stored relationship. No transitive access is
              assumed.
            </p>
          </div>
        </aside>
        <div className="panel graph-panel">
          <div className="graph-header">
            <div>
              <Network size={18} />
              <strong>{focusEntity?.name ?? "Identity neighborhood"}</strong>
            </div>
            {data && (
              <span>
                {data.nodes.length} nodes · {data.edges.length} edges
              </span>
            )}
          </div>
          {!focus ? (
            <div className="graph-welcome">
              <div className="graph-illustration">
                <span />
                <Network size={50} />
                <span />
              </div>
              <div className="eyebrow">START WITH AN IDENTITY</div>
              <h2>A useful graph starts with a question.</h2>
              <p>
                Choose an object from the inventory, or begin with an identity
                that has a finding.
              </p>
              <div className="graph-suggestions">
                {roots.map((e) => (
                  <button key={e.id} onClick={() => setFocus(e.id)}>
                    {e.name}
                    <ArrowRight size={15} />
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <>
              {data?.truncated && (
                <div className="notice">
                  This neighborhood exceeds 75 nodes. Results are truncated;
                  narrow the assertion or relationship filter.
                </div>
              )}
              {error && (
                <div className="error-box" role="alert">
                  {error}
                </div>
              )}
              {loading && (
                <div className="empty" role="status">
                  Loading this neighborhood…
                </div>
              )}
              {data && (
                <>
                  <div className="graph-toolbar">
                    <Badge value="configured">Saved metadata</Badge>
                    <div>
                      <button
                        className="icon-button"
                        aria-label="Zoom out"
                        onClick={() => setZoom(Math.max(0.1, zoom - 0.2))}
                      >
                        <Minus size={17} />
                      </button>
                      <span>{Math.round(zoom * 100)}%</span>
                      <button
                        className="icon-button"
                        aria-label="Zoom in"
                        onClick={() => setZoom(Math.min(2, zoom + 0.2))}
                      >
                        <Plus size={17} />
                      </button>
                      <button
                        className="icon-button"
                        aria-label="Fit graph"
                        onClick={fit}
                      >
                        <Expand size={17} />
                      </button>
                      <button
                        className="small-button"
                        onClick={() => onSelect({ type: "entity", id: focus })}
                      >
                        Inspect identity
                      </button>
                    </div>
                  </div>
                  <div
                    className="graph-canvas"
                    ref={canvas}
                    tabIndex={0}
                    aria-label="Scrollable relationship graph"
                  >
                    <svg
                      width={canvasWidth * zoom}
                      height={canvasHeight * zoom}
                      viewBox={`${450 - canvasWidth / 2} ${300 - canvasHeight / 2} ${canvasWidth} ${canvasHeight}`}
                      role="group"
                      aria-label="Identity relationship graph"
                    >
                      <defs>
                        <marker
                          id="edge-arrow"
                          viewBox="0 0 10 10"
                          refX="9"
                          refY="5"
                          markerWidth="5"
                          markerHeight="5"
                          orient="auto"
                        >
                          <path d="M 0 0 L 10 5 L 0 10 z" fill="#92a5a0" />
                        </marker>
                      </defs>
                      {data.edges.map((e) => {
                        const a = positions[e.from],
                          b = positions[e.to];
                        if (!a || !b) return null;
                        const dx = b.x - a.x,
                          dy = b.y - a.y,
                          len = Math.hypot(dx, dy) || 1;
                        return (
                          <g
                            key={e.id}
                            className={`graph-edge assertion-${e.assertion_kind}`}
                            role="button"
                            tabIndex={0}
                            aria-label={`${human(e.type)}: ${report.snapshot.entities.find((n) => n.id === e.from)?.name} to ${report.snapshot.entities.find((n) => n.id === e.to)?.name}; ${e.assertion_kind}`}
                            onClick={() => onSelect({ type: "edge", id: e.id })}
                            onKeyDown={(ev) => {
                              if (ev.key === "Enter" || ev.key === " ") {
                                ev.preventDefault();
                                onSelect({ type: "edge", id: e.id });
                              }
                            }}
                          >
                            <line
                              className="edge-hit"
                              x1={a.x}
                              y1={a.y}
                              x2={b.x}
                              y2={b.y}
                            />
                            <line
                              className="edge-line"
                              x1={a.x + (dx / len) * 60}
                              y1={a.y + (dy / len) * 35}
                              x2={b.x - (dx / len) * 90}
                              y2={b.y - (dy / len) * 36}
                              markerEnd="url(#edge-arrow)"
                            />
                            <text
                              x={(a.x + b.x) / 2}
                              y={(a.y + b.y) / 2 - 10}
                              textAnchor="middle"
                            >
                              {human(e.type)}
                            </text>
                          </g>
                        );
                      })}
                      {data.nodes.map((e) => {
                        const p = positions[e.id];
                        return (
                          <g
                            key={e.id}
                            transform={`translate(${p.x},${p.y})`}
                            className={`graph-node ${e.id === focus ? "root-node" : ""}`}
                            role="button"
                            tabIndex={0}
                            aria-label={`Inspect ${e.name}`}
                            onClick={() =>
                              onSelect({ type: "entity", id: e.id })
                            }
                            onKeyDown={(ev) => {
                              if (ev.key === "Enter" || ev.key === " ") {
                                ev.preventDefault();
                                onSelect({ type: "entity", id: e.id });
                              }
                            }}
                          >
                            <title>
                              {e.name} · {e.native_id}
                            </title>
                            <rect
                              x={-100}
                              y={-33}
                              width={200}
                              height={66}
                              rx={10}
                            />
                            <circle cx={-81} cy={-7} r={4} />
                            <text x={-68} y={-3} className="node-name">
                              {e.name.length > 22
                                ? e.name.slice(0, 21) + "…"
                                : e.name}
                            </text>
                            <text x={-81} y={18} className="node-kind">
                              {human(e.kind)}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                  <div className="graph-bottom">
                    <Crosshair size={15} />
                    <span>
                      Select a node or edge to inspect its evidence. Scroll to
                      move around a zoomed graph.
                    </span>
                  </div>
                  {data.nodes.length === 1 && (
                    <div className="notice">
                      No relationships match the current filters for this
                      object.
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
