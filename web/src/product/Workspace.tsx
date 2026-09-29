import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  BookOpen,
  ChevronRight,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  Unplug,
  X,
} from "lucide-react";
import { Badge, EvidenceList, Mark, Modal, SourceIcon } from "../components";
import {
  ruleNames,
  human,
  type Entity,
  type Finding,
  type Evidence,
  type Edge,
} from "../types";
import { api, APIError, setCSRF, when, type Status, type User } from "./api";
import { Auth } from "./Auth";
import { Integrations } from "./Integrations";
import { Settings } from "./Settings";

export const admin = (u: User) => ["owner", "admin"].includes(u.role);
const selectedRun = () =>
  new URLSearchParams(location.hash.split("?")[1] || "").get("run") || "";
const navigation = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "identities", label: "Identities", icon: Fingerprint },
  { id: "findings", label: "Findings", icon: ShieldAlert },
  { id: "relationships", label: "Relationships", icon: Network },
  { id: "integrations", label: "Integrations", icon: Unplug },
  { id: "activity", label: "Activity", icon: Activity },
];
export function Heading({
  label,
  title,
  description,
  children,
}: {
  label?: string;
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <header className="product-heading">
      <div>
        {label && <span className="overline">{label}</span>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      <div className="heading-actions">{children}</div>
    </header>
  );
}
export function Blank({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="product-blank">
      <span className="blank-mark">
        <Mark />
      </span>
      <h2>{title}</h2>
      <p>{children}</p>
    </div>
  );
}
export function Product({ initial }: { initial: Status }) {
  const [status, setStatus] = useState(initial),
    [user, setUser] = useState<User | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  const [route, setRoute] = useState(location.hash.slice(1) || "overview"),
    [mobile, setMobile] = useState(false),
    [epoch, setEpoch] = useState(0);
  const [narrow, setNarrow] = useState(
    () => window.matchMedia("(max-width: 700px)").matches,
  );
  useEffect(() => {
    const media = window.matchMedia("(max-width: 700px)");
    const update = () => {
      setNarrow(media.matches);
      if (!media.matches) setMobile(false);
    };
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    if (!mobile || !narrow) return;
    const root = document.getElementById("product-navigation");
    if (!root) return;
    const before = document.activeElement as HTMLElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const items = Array.from(
      root.querySelectorAll<HTMLElement>("a[href],button:not([disabled])"),
    );
    items[0]?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        setMobile(false);
      }
      if (e.key === "Tab") {
        if (e.shiftKey && document.activeElement === items[0]) {
          e.preventDefault();
          items.at(-1)?.focus();
        } else if (!e.shiftKey && document.activeElement === items.at(-1)) {
          e.preventDefault();
          items[0]?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      document.body.style.overflow = overflow;
      if (before?.isConnected) before.focus();
    };
  }, [mobile, narrow]);
  const page = route.split("?")[0].split("/")[0],
    selected = route.split("?")[0].split("/")[1];
  async function refresh() {
    try {
      setStatus(await api("/status"));
      const s = await api<{ user: User; csrf: string }>("/auth/session");
      setCSRF(s.csrf);
      setUser(s.user);
    } catch (e) {
      if (e instanceof APIError && e.status === 401) {
        setUser(null);
        setCSRF("");
      } else {
        setError((e as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    refresh();
    const h = () => {
      setRoute(location.hash.slice(1) || "overview");
      setMobile(false);
    };
    window.addEventListener("hashchange", h);
    return () => window.removeEventListener("hashchange", h);
  }, []);
  const go = (next: string) => {
    const query = location.hash.split("?")[1];
    location.hash =
      next +
      (query && next.split("/")[0] === page
        ? `?${query}`
        : selectedRun()
          ? `?run=${encodeURIComponent(selectedRun())}`
          : "");
  };
  const changed = () => setEpoch((v) => v + 1);
  if (loading)
    return (
      <div className="product-loading" role="status">
        Opening Grantline…
      </div>
    );
  if (!user && error)
    return (
      <div className="product-loading" role="alert">
        <p>{error}</p>
        <button className="button" onClick={() => location.reload()}>
          Retry
        </button>
      </div>
    );
  if (!user || user.mfa_pending)
    return <Auth status={status} user={user} refresh={refresh} />;
  const active = navigation.find((n) => n.id === page)?.label || "Settings";
  return (
    <div className="product-shell">
      <a
        href="#product-main"
        className="skip-link"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("product-main")?.focus();
        }}
      >
        Skip to content
      </a>
      {mobile && narrow && (
        <button
          className="product-scrim"
          aria-label="Close navigation"
          aria-hidden="true"
          tabIndex={-1}
          onClick={() => setMobile(false)}
        />
      )}
      <aside
        id="product-navigation"
        className={`product-sidebar ${mobile ? "is-open" : ""}`}
        inert={narrow && !mobile}
        role={narrow && mobile ? "dialog" : undefined}
        aria-modal={narrow && mobile ? true : undefined}
        aria-label="Workspace navigation"
      >
        {narrow && mobile && (
          <button
            className="product-nav-close icon-button"
            aria-label="Close navigation"
            onClick={() => setMobile(false)}
          >
            <X size={18} />
          </button>
        )}
        <a href="#overview" className="product-brand">
          <Mark />
          <span>grantline</span>
        </a>
        <div className="organization-label">
          <span>{status.organization}</span>
          <small>Security workspace</small>
        </div>
        <div className="overline sidebar-section">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map((n) => (
            <a
              key={n.id}
              href={`#${n.id}${selectedRun() && ["overview", "identities", "findings", "relationships"].includes(n.id) ? `?run=${encodeURIComponent(selectedRun())}` : ""}`}
              aria-current={page === n.id ? "page" : undefined}
            >
              <n.icon size={18} />
              {n.label}
            </a>
          ))}
        </nav>
        <div className="product-sidebar-bottom">
          <a href="#settings">
            <Settings2 size={18} />
            Settings
          </a>
          <a href="/docs/">
            <BookOpen size={18} />
            Documentation
            <ArrowRight size={14} />
          </a>
          <div className="signed-in">
            <span className="user-avatar">
              {user.name.slice(0, 1).toUpperCase()}
            </span>
            <span>
              <strong>{user.name}</strong>
              <small>{human(user.role)}</small>
            </span>
            <button
              aria-label="Sign out"
              onClick={async () => {
                try {
                  await api("/auth/logout", "POST");
                  await refresh();
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="product-workspace" inert={narrow && mobile}>
        <header className="product-topbar">
          <div>
            <button
              className="product-mobile"
              aria-label="Open navigation"
              aria-controls="product-navigation"
              aria-expanded={mobile}
              onClick={() => setMobile(true)}
            >
              <Menu size={20} />
            </button>
            <span>{status.organization}</span>
            <ChevronRight size={14} />
            <strong>{active}</strong>
          </div>
          <a href="#identities" className="product-search">
            <Search size={16} />
            <span>Find an identity</span>
            <kbd>↗</kbd>
          </a>
        </header>
        <main id="product-main" tabIndex={-1}>
          {error && (
            <div className="product-error" role="alert">
              {error}
              <button onClick={() => setError("")} aria-label="Dismiss error">
                <X size={16} />
              </button>
            </div>
          )}
          {page === "overview" && (
            <Overview
              key={`${epoch}:${selectedRun()}`}
              user={user}
              go={go}
              changed={changed}
              onError={setError}
            />
          )}
          {["identities", "findings", "relationships"].includes(page) && (
            <Records key={page + epoch} category={page} go={go} />
          )}
          {page === "integrations" && (
            <Integrations user={user} onError={setError} />
          )}
          {page === "activity" && <ActivityView user={user} />}
          {page === "settings" && (
            <Settings user={user} onError={setError} refresh={refresh} />
          )}
        </main>
        <footer className="product-footer">
          <span>GRANTLINE</span>
          <span>Identity, with context.</span>
          <a href="/docs/">Help &amp; documentation ↗</a>
        </footer>
      </div>
      {selected &&
        ["identities", "findings", "relationships"].includes(page) && (
          <RecordDetail
            category={page}
            id={selected}
            user={user}
            close={() => go(page)}
            go={go}
            changed={changed}
          />
        )}
    </div>
  );
}
function Overview({
  user,
  go,
  changed,
  onError,
}: {
  user: User;
  go: (s: string) => void;
  changed: () => void;
  onError: (s: string) => void;
}) {
  const [data, setData] = useState<any>(null),
    [queue, setQueue] = useState<Finding[]>([]),
    [runs, setRuns] = useState<any[]>([]),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    const load = () =>
      Promise.all([
        api(`/overview?run=${encodeURIComponent(selectedRun())}`),
        api(
          `/objects/findings?state=active&run=${encodeURIComponent(selectedRun())}`,
        ),
        api("/runs"),
      ])
        .then(([d, f, r]) => {
          if (!active) return;
          setData(d);
          setQueue(f.items.slice(0, 5));
          setRuns(r.slice(0, 4));
        })
        .catch((e) => active && onError(e.message));
    load();
    const timer = setInterval(load, 15000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  async function collect() {
    setBusy(true);
    try {
      await api("/runs", "POST", {});
      changed();
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Heading
        label="THE WORKSPACE"
        title="A clearer view of access."
        description="Follow what needs attention, with the evidence close at hand."
      >
        {user.role !== "viewer" && (
          <button className="button" disabled={busy} onClick={collect}>
            <RefreshCw size={15} />
            Collect now
          </button>
        )}
        {admin(user) && (
          <a href="#integrations" className="primary-button">
            <Plus size={16} />
            Add integration
          </a>
        )}
      </Heading>
      {!data ? (
        <p role="status">Loading your workspace…</p>
      ) : (
        <>
          <div className="overview-ledger">
            <button onClick={() => go("identities")}>
              <span>Native identities</span>
              <strong>{data.identities.toLocaleString()}</strong>
              <small>Accounts, principals &amp; SPIFFE IDs</small>
            </button>
            <button onClick={() => go("findings")}>
              <span>Policy findings</span>
              <strong>{data.findings.toLocaleString()}</strong>
              <small>Conditions worth a closer look</small>
            </button>
            <button onClick={() => go("integrations")}>
              <span>Source coverage</span>
              <strong>
                {data.sources.filter((s: any) => s.complete).length}
                <i> / {data.sources.length}</i>
              </strong>
              <small>Complete at collection</small>
            </button>
            <div className="last-observation">
              <span className="overline">LAST OBSERVATION</span>
              <strong>{when(data.snapshot_collected_at)}</strong>
              {data.run_id ? (
                <a href={`/api/v1/report?run=${data.run_id}`}>
                  <ArrowDownToLine size={14} />
                  Export report
                </a>
              ) : (
                <span>Connect a source to begin</span>
              )}
            </div>
          </div>
          {(data.run_kind === "import" || selectedRun()) && (
            <div className="product-notice" role="status">
              {data.run_kind === "import"
                ? "Imported report · Original observation time and evidence preserved. This does not establish a live connection."
                : "Historical collection · Viewing the evidence as it was collected."}{" "}
              {selectedRun() && <a href="#overview">Return to latest</a>}
            </div>
          )}
          <p className="section-note">
            Last successful collection: {when(data.last_success)}
            {runs[0] && (
              <>
                {" "}
                · Last attempt: {when(runs[0].created_at)} (
                {human(runs[0].state)})
              </>
            )}
          </p>
          {data.fixture_notice && (
            <div className="product-notice">
              Synthetic fixture · {data.fixture_notice}
            </div>
          )}
          {!data.run_id ? (
            <Blank title="Start with what you run.">
              Connect your first source to bring identities, permissions and
              evidence into one workspace.{" "}
              <a href="#integrations">Explore integrations →</a>
              {admin(user) && (
                <label className="import-report">
                  Or import an existing Grantline report
                  <input
                    type="file"
                    accept="application/json,.json"
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      try {
                        if (f.size > 64 * 1024 * 1024)
                          throw new Error("Report exceeds 64 MiB");
                        await api(
                          "/reports/import",
                          "POST",
                          JSON.parse(await f.text()),
                        );
                        changed();
                      } catch (e) {
                        onError((e as Error).message);
                      }
                    }}
                  />
                </label>
              )}
            </Blank>
          ) : (
            <div className="overview-columns">
              <section className="review-queue">
                <div className="section-heading">
                  <div>
                    <span className="overline">01 / PRIORITIES</span>
                    <h2>Your review queue</h2>
                  </div>
                  <a href="#findings">
                    All findings <ArrowRight size={15} />
                  </a>
                </div>
                {queue.length ? (
                  queue.map((f, i) => (
                    <button
                      key={f.id}
                      className="review-row"
                      onClick={() => go(`findings/${f.id}`)}
                    >
                      <span className="row-number">0{i + 1}</span>
                      <div>
                        <strong>{ruleNames[f.rule_id] || f.condition}</strong>
                        <small>
                          {f.rule_id} · {f.affected_entity_ids.length} affected
                          identities
                        </small>
                      </div>
                      <Badge value={f.severity} />
                      <ArrowRight size={16} />
                    </button>
                  ))
                ) : (
                  <Blank title="Nothing in the queue">
                    No findings were reported. Check source coverage before
                    drawing conclusions.
                  </Blank>
                )}
              </section>
              <section className="source-register">
                <div className="section-heading">
                  <div>
                    <span className="overline">02 / COVERAGE</span>
                    <h2>Connected evidence</h2>
                  </div>
                </div>
                {data.sources.map((s: any) => (
                  <a key={s.id} href="#integrations">
                    <SourceIcon kind={s.kind} />
                    <span>
                      <strong>{human(s.kind)}</strong>
                      <small>{s.id}</small>
                    </span>
                    <Badge value={s.status} />
                  </a>
                ))}
                <p className="section-note">
                  Coverage reflects the selected collection, including any gaps.
                </p>
              </section>
            </div>
          )}
          <section className="policy-register">
            <div className="section-heading">
              <div>
                <span className="overline">03 / POLICY</span>
                <h2>Checks, with their context.</h2>
              </div>
            </div>
            <div className="policy-lines">
              {data.rule_results.map((r: any) => (
                <a href="#findings" key={r.rule_id}>
                  <code>{r.rule_id}</code>
                  <span>{ruleNames[r.rule_id]}</span>
                  <small>{r.finding_ids?.length || 0} findings</small>
                  <Badge value={r.outcome} />
                </a>
              ))}
            </div>
          </section>
          {runs.length > 0 && (
            <section>
              <div className="section-heading">
                <h2>Recent collections</h2>
                <a href="#activity">View activity →</a>
              </div>
              {runs.map((r) => (
                <div className="run-row" key={r.id}>
                  <span>{human(r.kind)}</span>
                  <small>{when(r.created_at)}</small>
                  <Badge value={r.state} />
                  {r.error_code && <small>{human(r.error_code)}</small>}
                </div>
              ))}
            </section>
          )}
        </>
      )}
    </>
  );
}
function Records({
  category,
  go,
}: {
  category: string;
  go: (v: string) => void;
}) {
  const parameters = () =>
    new URLSearchParams(location.hash.split("?")[1] || "");
  const run = selectedRun();
  const [q, setQ] = useState(parameters().get("q") || ""),
    [source, setSource] = useState(parameters().get("source") || ""),
    [kind, setKind] = useState(parameters().get("kind") || ""),
    [state, setState] = useState(parameters().get("state") || ""),
    [page, setPage] = useState(
      Math.max(0, Number(parameters().get("page")) || 0),
    ),
    [data, setData] = useState<any>(null),
    [error, setError] = useState("");
  useEffect(() => {
    const read = () => {
      const p = parameters();
      setQ(p.get("q") || "");
      setSource(p.get("source") || "");
      setKind(p.get("kind") || "");
      setState(p.get("state") || "");
      setPage(Math.max(0, Number(p.get("page")) || 0));
    };
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);
  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      const filters = new URLSearchParams();
      if (run) filters.set("run", run);
      for (const [key, value] of Object.entries({
        q,
        source,
        kind,
        state,
        page: page ? String(page) : "",
      }))
        if (value) filters.set(key, value);
      const current = location.hash.split("?")[0];
      history.replaceState(
        null,
        "",
        `${location.pathname}${location.search}${current}${filters.size ? `?${filters}` : ""}`,
      );
      api(
        `/objects/${category}?${new URLSearchParams({ q, source, kind, state, run, page: String(page), native: category === "identities" ? "true" : "false" })}`,
      )
        .then((d) => {
          if (active) {
            setData(d);
            setError("");
          }
        })
        .catch((e) => active && setError(e.message));
    }, 180);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [category, q, source, kind, state, page, run]);
  return (
    <>
      <Heading
        label="INVESTIGATE"
        title={human(category)}
        description={
          category === "identities"
            ? "Know the identities behind your infrastructure."
            : category === "findings"
              ? "Review the condition. Follow the evidence. Record your decision."
              : "Configured and observed connections, with their provenance."
        }
      />
      <div className="record-toolbar">
        <label className="record-search">
          <Search size={17} />
          <input
            aria-label="Search records"
            maxLength={256}
            placeholder="Search by name or native ID…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(0);
            }}
          />
        </label>
        <input
          aria-label="Filter by source ID"
          placeholder="Source ID"
          value={source}
          onChange={(e) => {
            setSource(e.target.value);
            setPage(0);
          }}
        />
        <input
          aria-label="Filter by kind or rule"
          placeholder={category === "findings" ? "Rule, e.g. IL001" : "Kind"}
          value={kind}
          onChange={(e) => {
            setKind(e.target.value);
            setPage(0);
          }}
        />
      </div>
      {category === "findings" && (
        <label className="review-filter">
          Review status{" "}
          <select
            aria-label="Filter by review status"
            value={state}
            onChange={(e) => {
              setState(e.target.value);
              setPage(0);
            }}
          >
            <option value="">All reviews</option>
            <option value="active">Needs attention</option>
            <option value="open">Open</option>
            <option value="in_review">In review</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
      )}
      {error && (
        <div className="product-error" role="alert">
          {error}
        </div>
      )}
      {!data ? (
        <p role="status">Loading records…</p>
      ) : data.items.length === 0 ? (
        <Blank title="No matching records">
          Try another filter, or collect a source to get started.
        </Blank>
      ) : (
        <div className="product-table-wrap">
          <table className="product-table">
            <thead>
              <tr>
                <th>
                  {category === "findings"
                    ? "Finding"
                    : "Identity / relationship"}
                </th>
                <th>{category === "findings" ? "Severity" : "Type"}</th>
                <th>
                  {category === "findings" ? "Rule" : "Source / assertion"}
                </th>
                {category === "findings" && <th>Review</th>}
                <th>
                  <span className="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((item: any) => (
                <tr key={item.id}>
                  <td>
                    <button onClick={() => go(`${category}/${item.id}`)}>
                      <strong>
                        {item.name ||
                          ruleNames[item.rule_id] ||
                          human(item.type || item.condition)}
                      </strong>
                      <small>
                        {item.native_id || item.description || item.scope}
                      </small>
                    </button>
                  </td>
                  <td>
                    {item.severity ? (
                      <Badge value={item.severity} />
                    ) : (
                      human(item.kind || item.type || "")
                    )}
                  </td>
                  <td>
                    <code>
                      {item.source_id || item.rule_id || item.assertion_kind}
                    </code>
                  </td>
                  {category === "findings" && (
                    <td>
                      <Badge value={item.triage_state || "open"} />
                    </td>
                  )}
                  <td>
                    <button
                      aria-label={`Open ${item.name || item.rule_id || item.type}`}
                      onClick={() => go(`${category}/${item.id}`)}
                    >
                      <ArrowRight size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && (
        <div className="pagination">
          <span>
            {data.total.toLocaleString()} records · Page {page + 1}
          </span>
          <button
            className="button"
            disabled={page === 0}
            onClick={() => setPage((v) => v - 1)}
          >
            Previous
          </button>
          <button
            className="button"
            disabled={(page + 1) * 50 >= data.total}
            onClick={() => setPage((v) => v + 1)}
          >
            Next
          </button>
        </div>
      )}
    </>
  );
}
function RecordDetail({
  category,
  id,
  user,
  close,
  go,
  changed,
}: {
  category: string;
  id: string;
  user: User;
  close: () => void;
  go: (v: string) => void;
  changed: () => void;
}) {
  const [data, setData] = useState<any>(null),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false),
    [saving, setSaving] = useState(false),
    [members, setMembers] = useState<User[]>([]),
    [graph, setGraph] = useState<{
      nodes: Entity[];
      edges: Edge[];
      truncated: boolean;
    } | null>(null);
  const run = selectedRun();
  const load = () =>
    api(`/objects/${category}/${id}?run=${encodeURIComponent(run)}`)
      .then(setData)
      .catch((e) => setError(e.message));
  useEffect(() => {
    setData(null);
    setGraph(null);
    setSaved(false);
    load();
    if (category === "findings")
      api<User[]>("/users")
        .then(setMembers)
        .catch(() => {});
  }, [id, category, run]);
  async function save(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (saving) return;
    const f = Object.fromEntries(new FormData(e.currentTarget));
    setSaving(true);
    setSaved(false);
    try {
      await api(`/triage/${id}`, "PUT", {
        State: f.state,
        Assignee: f.assignee,
        Reason: f.reason,
        expires_at: f.expiry ? new Date(String(f.expiry)).toISOString() : null,
        Revision: data.triage.revision,
      });
      await load();
      setError("");
      setSaved(true);
      changed();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }
  return (
    <Modal
      title={
        data?.item.name || ruleNames[data?.item.rule_id] || "Evidence detail"
      }
      onClose={close}
      drawer
    >
      {error && (
        <div className="product-error" role="alert">
          {error}
        </div>
      )}
      {!data ? (
        <p role="status">Loading evidence…</p>
      ) : (
        <div className="product-detail">
          <span className="overline">{human(category)}</span>
          <h2>
            {data.item.name ||
              ruleNames[data.item.rule_id] ||
              human(data.item.type)}
          </h2>
          <p>
            {data.item.description || data.item.native_id || data.item.scope}
          </p>
          <div className="detail-badges">
            {data.item.severity && <Badge value={data.item.severity} />}
            <Badge
              value={
                data.item.provenance ||
                data.item.assertion_kind ||
                data.item.rule_id
              }
            />
          </div>
          {data.item.recommendation && (
            <section>
              <h3>Recommended next step</h3>
              <p>{data.item.recommendation}</p>
            </section>
          )}
          {data.entities?.length > 0 && (
            <section>
              <h3>Affected identities</h3>
              {data.entities_truncated && (
                <p>
                  Showing the first 100 identities. Export the report for the
                  complete set.
                </p>
              )}
              {data.entities.map((e: Entity) => (
                <button
                  className="detail-entity"
                  key={e.id}
                  onClick={() => go(`identities/${e.id}`)}
                >
                  {e.name || e.native_id}
                  <ArrowRight size={15} />
                </button>
              ))}
            </section>
          )}
          {category === "identities" && (
            <>
              <button
                className="button"
                onClick={() =>
                  api(
                    `/graph?entity=${id}&depth=1&run=${encodeURIComponent(run)}`,
                  )
                    .then(setGraph)
                    .catch((e) => setError(e.message))
                }
              >
                <Network size={16} />
                Explore connections
              </button>
              {graph && (
                <section>
                  <h3>{graph.edges.length} evidence-backed connections</h3>
                  {graph.edges.map((e) => (
                    <button
                      className="connection-line"
                      key={e.id}
                      onClick={() => go(`relationships/${e.id}`)}
                    >
                      <span>
                        {graph.nodes.find((n) => n.id === e.from)?.name ||
                          e.from}
                      </span>
                      <small>{human(e.type)} →</small>
                      <span>
                        {graph.nodes.find((n) => n.id === e.to)?.name || e.to}
                      </span>
                    </button>
                  ))}
                  {graph.truncated && (
                    <p>Showing the first 75 connected objects.</p>
                  )}
                </section>
              )}
              <details>
                <summary>Identity metadata</summary>
                <pre>{JSON.stringify(data.item.attributes, null, 2)}</pre>
              </details>
            </>
          )}
          {category === "relationships" && (
            <section>
              <h3>Endpoints</h3>
              {[data.item.from, data.item.to].map((v) => (
                <button
                  key={v}
                  className="detail-entity"
                  onClick={() => go(`identities/${v}`)}
                >
                  <code>{v}</code>
                  <ArrowRight size={16} />
                </button>
              ))}
            </section>
          )}
          <section>
            <h3>Supporting evidence</h3>
            {data.evidence_truncated && (
              <p>
                Showing the first 100 evidence records. Export the report for
                the complete set.
              </p>
            )}
            <EvidenceList
              ids={(data.evidence as Evidence[]).map((e) => e.id)}
              evidence={data.evidence}
            />
          </section>
          {data.item.limitations?.length > 0 && (
            <section>
              <h3>What remains uncertain</h3>
              {data.item.limitations.map((l: string) => (
                <p key={l}>{l}</p>
              ))}
            </section>
          )}
          {category === "findings" && (
            <section>
              <h3>Review decision</h3>
              {user.role !== "viewer" ? (
                <form onSubmit={save} key={id} onChange={() => setSaved(false)}>
                  <label>
                    Status
                    <select name="state" defaultValue={data.triage.state}>
                      {["open", "in_review", "accepted_risk", "resolved"].map(
                        (s) => (
                          <option key={s} value={s}>
                            {human(s)}
                          </option>
                        ),
                      )}
                    </select>
                  </label>
                  <label>
                    Assignee
                    <select
                      name="assignee"
                      defaultValue={data.triage.assignee_id || ""}
                    >
                      <option value="">Unassigned</option>
                      {members
                        .filter((m) => !m.disabled)
                        .map((m) => (
                          <option value={m.id} key={m.id}>
                            {m.name}
                          </option>
                        ))}
                    </select>
                  </label>
                  <label>
                    Reason
                    <textarea
                      name="reason"
                      maxLength={4000}
                      defaultValue={data.triage.reason}
                    />
                  </label>
                  <label>
                    Risk acceptance expires
                    <input
                      name="expiry"
                      type="datetime-local"
                      defaultValue={
                        data.triage.expires_at
                          ? new Date(
                              new Date(data.triage.expires_at).getTime() -
                                new Date().getTimezoneOffset() * 60000,
                            )
                              .toISOString()
                              .slice(0, 16)
                          : ""
                      }
                    />
                  </label>
                  <button
                    className="primary-button"
                    aria-disabled={saving}
                    aria-busy={saving}
                  >
                    {saving ? "Saving…" : "Save review"}
                  </button>
                  {saved && <p role="status">Review saved.</p>}
                  <small>
                    Review decisions do not change the underlying policy result.
                  </small>
                </form>
              ) : (
                <Badge value={data.triage.state} />
              )}
              <h3>Discussion</h3>
              {data.comments_truncated && (
                <p>Showing the 100 most recent comments.</p>
              )}
              {data.comments.map((c: any) => (
                <article className="comment" key={c.id}>
                  <strong>{c.name}</strong>
                  <small>{when(c.created_at)}</small>
                  <p>{c.body}</p>
                </article>
              ))}
              {user.role !== "viewer" && (
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    const form = e.currentTarget;
                    const Body = new FormData(form).get("body");
                    try {
                      await api(`/comments/${id}`, "POST", { Body });
                      form.reset();
                      await load();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  <label>
                    Add a comment
                    <textarea name="body" required maxLength={4000} />
                  </label>
                  <button className="button">Post comment</button>
                </form>
              )}
            </section>
          )}
        </div>
      )}
    </Modal>
  );
}
function ActivityView({ user }: { user: User }) {
  const [items, setItems] = useState<any[]>([]),
    [runs, setRuns] = useState<any[]>([]),
    [error, setError] = useState("");
  useEffect(() => {
    Promise.all([api("/activity"), api("/runs")])
      .then(([a, r]) => {
        setItems(a);
        setRuns(r);
      })
      .catch((e) => setError(e.message));
  }, []);
  return (
    <>
      <Heading
        label="THE RECORD"
        title="Activity"
        description="The decisions and collections behind your workspace."
      />
      {error && (
        <div role="alert" className="product-error">
          {error}
        </div>
      )}
      <section>
        <h2>Collection history</h2>
        {runs.map((r) => (
          <div key={r.id} className="run-row">
            <span>{human(r.kind)}</span>
            <small>{when(r.created_at)}</small>
            <Badge value={r.state} />
            {["completed", "partial"].includes(r.state) && (
              <>
                <a href={`#overview?run=${r.id}`}>Review</a>
                <a href={`/api/v1/report?run=${r.id}`}>Export ↗</a>
              </>
            )}
            {user.role !== "viewer" &&
              ["queued", "running"].includes(r.state) && (
                <button
                  onClick={() =>
                    api(`/runs/${r.id}/cancel`, "POST", {})
                      .then(() => location.reload())
                      .catch((e) => setError(e.message))
                  }
                >
                  Cancel
                </button>
              )}
          </div>
        ))}
      </section>
      <section className="audit-log">
        <h2>Workspace history</h2>
        {items.map((v) => (
          <div key={v.id}>
            <span className="audit-point" />
            <strong>{v.name}</strong>
            <span>{v.action.replaceAll(".", " ")}</span>
            <code>{v.subject}</code>
            <time>{when(v.created_at)}</time>
          </div>
        ))}
      </section>
    </>
  );
}
