import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Command,
  Fingerprint,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Network,
  Search,
  ShieldCheck,
  ShieldAlert,
  SlidersHorizontal,
  Unplug,
  X,
} from "lucide-react";
import {
  Badge,
  Empty,
  EntityLabel,
  Mark,
  Modal,
  PageHead,
  PanelTitle,
  SourceIcon,
  LinkButton,
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
import { Inventory, Findings, Sources, Detail } from "./views";
import Relationships from "./Relationships";

const pages = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "identities", label: "Identities", icon: Fingerprint },
  { id: "findings", label: "Findings", icon: ShieldAlert },
  { id: "relationships", label: "Relationships", icon: Network },
  { id: "sources", label: "Sources", icon: Unplug },
];
export default function App() {
  const [report, setReport] = useState<Report | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [token, setToken] = useState(""),
    [busy, setBusy] = useState(false);
  const [page, setPage] = useState(() =>
      pages.some((p) => p.id === location.hash.slice(1))
        ? location.hash.slice(1)
        : "overview",
    ),
    [selection, setSelection] = useState<Selection>(null),
    [searchOpen, setSearchOpen] = useState(false),
    [search, setSearch] = useState(""),
    [mobile, setMobile] = useState(false),
    [focus, setFocus] = useState("");
  const [inventorySource, setInventorySource] = useState(""),
    [findingRule, setFindingRule] = useState("");
  const [narrow, setNarrow] = useState(
    () => window.matchMedia("(max-width: 760px)").matches,
  );
  useEffect(() => {
    const media = window.matchMedia("(max-width: 760px)");
    const update = () => setNarrow(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!mobile || !narrow) return;
    const root = document.querySelector<HTMLElement>(".sidebar")!;
    const items = Array.from(
      root.querySelectorAll<HTMLElement>("a[href],button"),
    );
    items[0]?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMobile(false);
        e.preventDefault();
      }
      if (e.key === "Tab") {
        const first = items[0],
          last = items.at(-1);
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      document.querySelector<HTMLButtonElement>(".mobile-toggle")?.focus();
    };
  }, [mobile, narrow]);
  const [inventoryReset, setInventoryReset] = useState(0),
    [nativeOnly, setNativeOnly] = useState(false);
  async function load() {
    setLoading(true);
    try {
      const response = await fetch("/api/report");
      if (response.status === 401) {
        setReport(null);
        return;
      }
      if (!response.ok)
        throw new Error(
          "The report could not be loaded. Check that the report viewer is still running.",
        );
      const data = await response.json();
      data.findings ??= [];
      data.rule_results ??= [];
      for (const field of ["entities", "relationships", "sources", "evidence"])
        data.snapshot[field] ??= [];
      setReport(data);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);
  useEffect(() => {
    const fn = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (report) setSearchOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", fn);
    return () => window.removeEventListener("keydown", fn);
  }, [report]);
  useEffect(() => {
    const fn = () => {
      const value = location.hash.slice(1);
      if (pages.some((p) => p.id === value)) setPage(value);
    };
    window.addEventListener("hashchange", fn);
    return () => window.removeEventListener("hashchange", fn);
  }, []);
  function navigate(next: string) {
    setPage(next);
    location.hash = next;
    setMobile(false);
    document.getElementById("main")?.scrollTo(0, 0);
  }
  function graph(id: string) {
    setFocus(id);
    setSelection(null);
    navigate("relationships");
  }
  async function login(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const r = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token.trim() }),
      });
      setToken("");
      if (!r.ok)
        throw new Error(
          r.status === 429
            ? "Too many attempts. Wait 30 seconds and try again."
            : "Access code not accepted. Use the code file from this viewer process.",
        );
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function logout() {
    try {
      const response = await fetch("/api/logout", { method: "POST" });
      if (!response.ok && response.status !== 401)
        throw new Error("Could not lock the session.");
      setReport(null);
      setSelection(null);
      setSearchOpen(false);
      setToken("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const searchResults = useMemo(
    () =>
      report?.snapshot.entities
        .filter((e) =>
          `${e.name} ${e.native_id} ${e.kind} ${e.source_id}`
            .toLowerCase()
            .includes(search.toLowerCase()),
        )
        .slice(0, 25) ?? [],
    [report, search],
  );
  if (!report)
    return (
      <div className="unlock-layout">
        <div className="unlock-brand">
          <Mark />
          <strong>grantline</strong>
          <span>Identity security, in context.</span>
        </div>
        <div className="unlock-card">
          <div className="unlock-icon">
            <LockKeyhole size={25} />
          </div>
          <div className="eyebrow">GRANTLINE REPORT VIEWER</div>
          <h1>
            Your evidence.
            <br />A clearer picture.
          </h1>
          <p>
            Unlock this report to explore your non-human identities, review
            findings, and follow the evidence.
          </p>
          {loading ? (
            <div className="loading" role="status">
              Opening the report viewer…
            </div>
          ) : (
            <form onSubmit={login}>
              <label htmlFor="access">Report access code</label>
              <input
                id="access"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste the code from your private file"
                autoComplete="off"
                required
                spellCheck={false}
              />
              <p className="input-help">
                The terminal shows the access-code file path when you run{" "}
                <code>grantline serve</code>.
              </p>
              <button
                className="primary-button"
                disabled={busy || !token.trim()}
              >
                {busy ? "Unlocking…" : "Open workspace"}
                <ArrowRight size={16} />
              </button>
            </form>
          )}
          {error && (
            <div className="error-box" role="alert">
              {error}
              <button className="text-button" onClick={load}>
                Reconnect
              </button>
            </div>
          )}
          <div className="unlock-note">
            <ShieldCheck size={16} />
            Review identities and follow their evidence.
          </div>
        </div>
        <div className="unlock-footer">
          GRANTLINE / NON-HUMAN IDENTITY INTELLIGENCE
        </div>
      </div>
    );
  const { entities, sources } = report.snapshot;
  const unknown = report.rule_results.filter(
    (r) => r.outcome === "UNKNOWN",
  ).length;
  const current = pages.find((p) => p.id === page)!;
  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      {mobile && (
        <button
          aria-label="Close navigation"
          className="sidebar-scrim"
          onClick={() => setMobile(false)}
        />
      )}
      <aside
        id="workspace-navigation"
        className={`sidebar ${mobile ? "open" : ""}`}
        inert={narrow && !mobile}
        role={narrow && mobile ? "dialog" : undefined}
        aria-modal={narrow && mobile ? true : undefined}
        aria-label="Workspace navigation"
      >
        <a
          href="#overview"
          onClick={() => navigate("overview")}
          className="brand"
        >
          <Mark />
          <span>
            grantline<span className="brand-period">.</span>
          </span>
        </a>
        <div className="workspace-switch">
          <span className="workspace-initial">
            <Mark />
          </span>
          <div>
            <strong>Security workspace</strong>
            <small>Saved report</small>
          </div>
          <LockKeyhole size={14} />
        </div>
        <div className="nav-label">INVESTIGATE</div>
        <nav aria-label="Main navigation">
          {pages.map((p) => (
            <button
              key={p.id}
              className={`nav-item ${p.id === page ? "active" : ""}`}
              aria-current={p.id === page ? "page" : undefined}
              onClick={() => navigate(p.id)}
            >
              <p.icon size={19} />
              <span>{p.label}</span>
              {p.id === "findings" && report.findings.length > 0 && (
                <span className="nav-count">{report.findings.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <p>
            Viewing a saved report. Observation times and coverage are shown
            with the evidence.
          </p>
          <div className="sidebar-version">
            <span>Grantline</span>
            <span>Report viewer</span>
          </div>
        </div>
      </aside>
      <div className="workspace" inert={narrow && mobile}>
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-toggle"
              aria-controls="workspace-navigation"
              aria-expanded={mobile}
              aria-label="Open navigation"
              onClick={() => setMobile(true)}
            >
              <Menu size={22} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{current.label}</strong>
          </div>
          <div className="topbar-actions">
            <button
              className="global-search"
              aria-label="Find an identity"
              onClick={() => setSearchOpen(true)}
            >
              <Search size={16} />
              <span>Find an identity…</span>
              <kbd>Ctrl K</kbd>
            </button>
            <span className="session-indicator">
              <span />
              Report session
            </span>
            <button
              className="icon-button"
              onClick={logout}
              aria-label="Lock workspace"
              title="Lock workspace"
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          {error && (
            <div className="error-box" role="alert">
              {error}
            </div>
          )}
          {report.fixture_notice && (
            <div className="notice fixture-notice">
              <ShieldAlert size={17} />
              <span>
                <strong>Synthetic fixture.</strong> {report.fixture_notice}
              </span>
            </div>
          )}
          <section hidden={page !== "overview"}>
            <PageHead
              eyebrow="IDENTITY SECURITY"
              title="Identity overview"
              description="Understand what exists, what needs attention, and the evidence behind it."
            >
              <a href="/api/report/download" className="button">
                <ArrowDownToLine size={16} />
                Export report
              </a>
            </PageHead>
            <div className="snapshot-strip">
              <Clock3 size={15} />
              <span>
                Snapshot assembled{" "}
                <strong>{shortDate(report.snapshot_collected_at)}</strong>
              </span>
              <span className="strip-divider" />
              <span>
                6-source model · {sources.length} sources in this report
              </span>
              <span className="snapshot-label">SAVED SNAPSHOT</span>
            </div>
            <div className="metrics">
              <button
                onClick={() => {
                  setInventorySource("");
                  setNativeOnly(true);
                  setInventoryReset((v) => v + 1);
                  navigate("identities");
                }}
                className="metric"
              >
                <span>
                  Native identities
                  <Fingerprint size={17} />
                </span>
                <strong>{entities.filter(isPrincipal).length}</strong>
                <small>
                  Service accounts, principals & SPIFFE IDs
                  <ChevronRight size={14} />
                </small>
              </button>
              <button
                onClick={() => {
                  setFindingRule("");
                  navigate("findings");
                }}
                className="metric"
              >
                <span>
                  Policy findings
                  <ShieldAlert size={17} />
                </span>
                <strong>
                  {report.findings.length}
                  <em>
                    {
                      report.findings.filter((f) => rank[f.severity] >= 3)
                        .length
                    }{" "}
                    high or critical
                  </em>
                </strong>
                <small>
                  Evidence-backed conditions to review
                  <ChevronRight size={14} />
                </small>
              </button>
              <button onClick={() => navigate("sources")} className="metric">
                <span>
                  Source coverage
                  <Unplug size={17} />
                </span>
                <strong>
                  {
                    sources.filter(
                      (s) =>
                        s.complete &&
                        s.pagination_complete &&
                        s.status === "ok",
                    ).length
                  }
                  <i>/ {sources.length}</i>
                </strong>
                <small>
                  {report.completeness.complete
                    ? "Required sources complete at collection"
                    : "Required source coverage is incomplete"}
                  <ChevronRight size={14} />
                </small>
              </button>
              <button
                onClick={() =>
                  document
                    .getElementById("rule-coverage")
                    ?.scrollIntoView({ behavior: "smooth" })
                }
                className="metric"
              >
                <span>
                  Checks needing context
                  <SlidersHorizontal size={17} />
                </span>
                <strong>
                  {unknown}
                  <i>/ {report.rule_results.length}</i>
                </strong>
                <small>
                  Unknown outcomes remain visible
                  <ChevronRight size={14} />
                </small>
              </button>
            </div>
            <div className="overview-grid">
              <div className="panel attention-panel">
                <PanelTitle
                  title="Your review queue"
                  description="Findings ordered by severity, with their supporting identities."
                >
                  <LinkButton
                    onClick={() => {
                      setFindingRule("");
                      navigate("findings");
                    }}
                  >
                    All findings
                  </LinkButton>
                </PanelTitle>
                {report.findings.length === 0 ? (
                  <Empty title="No policy findings">
                    Check rule outcomes and source coverage before drawing a
                    conclusion.
                  </Empty>
                ) : (
                  <div className="queue">
                    {[...report.findings]
                      .sort(
                        (a, b) =>
                          rank[b.severity] - rank[a.severity] ||
                          a.id.localeCompare(b.id),
                      )
                      .slice(0, 5)
                      .map((f) => {
                        const e = entities.find(
                          (e) => e.id === f.affected_entity_ids[0],
                        );
                        return (
                          <button
                            className="queue-row"
                            key={f.id}
                            onClick={() =>
                              setSelection({ type: "finding", id: f.id })
                            }
                          >
                            <span
                              className={`queue-marker marker-${f.severity}`}
                            >
                              <ShieldAlert size={17} />
                            </span>
                            <span className="queue-content">
                              <span>
                                <strong>
                                  {ruleNames[f.rule_id] ?? f.condition}
                                </strong>
                                <span className="rule-id">{f.rule_id}</span>
                              </span>
                              <small>
                                {e?.name ?? "Unresolved identity"}{" "}
                                <span>· {e?.source_id}</span>
                              </small>
                            </span>
                            <Badge value={f.severity} />
                            <ChevronRight size={16} />
                          </button>
                        );
                      })}
                  </div>
                )}
                <div className="panel-foot">
                  <ShieldCheck size={15} />
                  <span>
                    Configuration findings describe metadata, not effective
                    access.
                  </span>
                </div>
              </div>
              <div className="panel">
                <PanelTitle
                  title="Connected evidence"
                  description="Coverage at the time of collection."
                >
                  <LinkButton onClick={() => navigate("sources")}>
                    Sources
                  </LinkButton>
                </PanelTitle>
                <div className="source-summary">
                  {sources.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => setSelection({ type: "source", id: s.id })}
                    >
                      <SourceIcon kind={s.kind} />
                      <span>
                        <strong>{sourceName[s.kind]}</strong>
                        <small>{s.id}</small>
                      </span>
                      <span
                        className={`source-status ${s.complete && s.pagination_complete && s.status === "ok" ? "complete" : "partial"}`}
                      >
                        {s.complete &&
                        s.pagination_complete &&
                        s.status === "ok" ? (
                          <CheckCircle2 size={15} />
                        ) : (
                          <ShieldAlert size={15} />
                        )}
                      </span>
                    </button>
                  ))}
                </div>
                <div className="panel-foot">
                  <Clock3 size={15} /> Saved data; not a live connection
                  monitor.
                </div>
              </div>
            </div>
            <div className="panel rules-panel" id="rule-coverage">
              <PanelTitle
                title="Policy coverage"
                description="A passed check and an unknown result mean different things."
              />
              <div className="rules-grid">
                {report.rule_results.map((r) => (
                  <button
                    className="rule-card"
                    key={r.rule_id}
                    onClick={() => {
                      setFindingRule(r.rule_id);
                      navigate("findings");
                    }}
                  >
                    <span className="rule-card-top">
                      <code>{r.rule_id}</code>
                      <Badge value={r.outcome} />
                    </span>
                    <strong>{ruleNames[r.rule_id] ?? r.rule_id}</strong>
                    <small>
                      {r.finding_ids?.length ?? 0} findings
                      {r.limitations?.length
                        ? ` · ${r.limitations.length} limitations`
                        : ""}
                      <ArrowRight size={14} />
                    </small>
                  </button>
                ))}
              </div>
            </div>
            <div className="bottom-note">
              <ShieldCheck size={16} />
              <span>
                {entities.filter((e) => e.kind === "spire_entry").length} SPIRE
                registrations are counted separately from{" "}
                {entities.filter((e) => e.kind === "spiffe_identity").length}{" "}
                SPIFFE identities. Roles, policies, and human owners are
                excluded from the native identity count.
              </span>
            </div>
          </section>
          <section hidden={page !== "identities"}>
            <Inventory
              key={inventoryReset}
              principals={nativeOnly}
              setPrincipals={setNativeOnly}
              report={report}
              onSelect={setSelection}
              source={inventorySource}
              setSource={setInventorySource}
            />
          </section>
          <section hidden={page !== "findings"}>
            <Findings
              report={report}
              onSelect={setSelection}
              rule={findingRule}
              setRule={setFindingRule}
            />
          </section>
          <section hidden={page !== "relationships"}>
            <Relationships
              report={report}
              focus={focus}
              setFocus={setFocus}
              onSelect={setSelection}
              active={page === "relationships"}
            />
          </section>
          <section hidden={page !== "sources"}>
            <Sources
              report={report}
              onSelect={setSelection}
              onInventory={(id) => {
                setInventorySource(id);
                navigate("identities");
              }}
            />
          </section>
          <footer className="page-footer">
            <span>
              GRANTLINE <span>/</span> Evidence before assumptions.
            </span>
            <span>Report generated {shortDate(report.generated_at)}</span>
          </footer>
        </main>
      </div>
      {selection && (
        <Detail
          selection={selection}
          report={report}
          onSelect={setSelection}
          onClose={() => setSelection(null)}
          onGraph={graph}
        />
      )}
      {searchOpen && (
        <Modal title="Find an identity" onClose={() => setSearchOpen(false)}>
          <div className="command-input">
            <Search size={20} />
            <input
              autoFocus
              aria-label="Search all identities"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Name, native ID, source, or kind…"
            />
          </div>
          <div className="command-results">
            {searchResults.map((e) => (
              <EntityLabel
                key={e.id}
                entity={e}
                onClick={() => {
                  setSelection({ type: "entity", id: e.id });
                  setSearchOpen(false);
                }}
              />
            ))}
          </div>
          {searchResults.length === 0 && (
            <Empty title="No matching identities">
              Try a name, source ID, or native identifier.
            </Empty>
          )}
          <div className="command-foot">
            <Command size={14} />
            <span>Showing up to 25 matches · Esc to close</span>
          </div>
        </Modal>
      )}
    </div>
  );
}
