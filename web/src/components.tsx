import { useEffect, useRef, type ReactNode } from "react";
import {
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Database,
  GitBranch,
  KeyRound,
  Shield,
  X,
} from "lucide-react";
import { human, sourceName, type Entity, type Evidence } from "./types";

export function Mark() {
  return (
    <svg
      viewBox="0 0 40 40"
      width="32"
      height="32"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M6 12h17a7 7 0 0 1 7 7v9M34 28H17a7 7 0 0 1-7-7v-9"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path d="M16 20h8" stroke="currentColor" strokeWidth="3" />
      <circle cx="20" cy="20" r="3" fill="currentColor" />
    </svg>
  );
}
export function Badge({
  value,
  children,
}: {
  value: string;
  children?: ReactNode;
}) {
  return (
    <span className={`badge tone-${value.toLowerCase().replaceAll("_", "-")}`}>
      <span className="badge-dot" />
      {children ?? human(value)}
    </span>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <CircleHelp size={28} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function EntityIcon({ kind }: { kind: string }) {
  return (
    <span className={`entity-icon kind-${kind}`}>
      {kind === "service_account" || kind === "service_principal" ? (
        <KeyRound size={17} />
      ) : kind === "spiffe_identity" || kind === "spire_entry" ? (
        <Shield size={17} />
      ) : kind === "job" || kind === "workflow" ? (
        <GitBranch size={17} />
      ) : (
        <Database size={17} />
      )}
    </span>
  );
}
export function EntityLabel({
  entity,
  onClick,
  subtitle = true,
}: {
  entity: Entity;
  onClick: () => void;
  subtitle?: boolean;
}) {
  return (
    <button className="entity-link" onClick={onClick}>
      <EntityIcon kind={entity.kind} />
      <span>
        <strong>{entity.name || entity.native_id}</strong>
        {subtitle && <small>{human(entity.kind)}</small>}
      </span>
      <ChevronRight size={15} />
    </button>
  );
}
export function SourceIcon({ kind }: { kind: string }) {
  const text: Record<string, string> = {
    kubernetes: "K8",
    vault: "V",
    jenkins: "J",
    entra: "E",
    github: "GH",
    spire: "S",
  };
  return (
    <span className={`source-icon source-${kind}`} title={sourceName[kind]}>
      {text[kind] ?? kind.slice(0, 2).toUpperCase()}
    </span>
  );
}
export function PanelTitle({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <div className="panel-title">
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {children}
    </div>
  );
}
export function EvidenceList({
  ids,
  evidence,
  compact = false,
}: {
  ids: string[];
  evidence: Evidence[];
  compact?: boolean;
}) {
  const selected = new Set(ids);
  const items = evidence.filter((e) => selected.has(e.id));
  return (
    <div className={`evidence-list${compact ? " evidence-list-compact" : ""}`}>
      {items.length === 0 ? (
        <p className="muted">No evidence attached.</p>
      ) : (
        items.map((e) => (
          <details key={e.id}>
            <summary>
              <Database size={15} />
              {compact ? (
                <span className="evidence-summary-text">
                  <strong>{e.source_id}</strong>
                  <small>{e.native_id}</small>
                </span>
              ) : (
                <span>{e.locator}</span>
              )}
              <Badge value={e.assertion_kind} />
              {compact && (
                <ChevronRight
                  className="evidence-chevron"
                  size={16}
                  aria-hidden="true"
                />
              )}
            </summary>
            <div className="evidence-content">
              <dl>
                {compact && (
                  <>
                    <dt>Locator</dt>
                    <dd className="mono">{e.locator}</dd>
                  </>
                )}
                <dt>Source</dt>
                <dd>{e.source_id}</dd>
                <dt>Native object</dt>
                <dd className="mono">{e.native_id}</dd>
                <dt>Observed</dt>
                <dd>{new Date(e.observed_at).toLocaleString()}</dd>
                <dt>Fields</dt>
                <dd>{(e.fields ?? []).join(", ")}</dd>
                <dt>Evidence ID</dt>
                <dd className="mono">{e.id}</dd>
              </dl>
            </div>
          </details>
        ))
      )}
    </div>
  );
}
export function Modal({
  title,
  onClose,
  children,
  drawer = false,
  className = "",
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  drawer?: boolean;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const before = document.activeElement as HTMLElement;
    const root = ref.current!;
    root.focus();
    const bodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        closeRef.current();
      }
      if (e.key === "Tab") {
        const items = Array.from(
          root.querySelectorAll<HTMLElement>(
            'button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,a[href],[tabindex="0"]',
          ),
        ).filter((el) => el.getClientRects().length);
        if (!items.length) {
          e.preventDefault();
          return;
        }
        const first = items[0],
          last = items.at(-1)!;
        if (
          e.shiftKey &&
          (document.activeElement === first || document.activeElement === root)
        ) {
          e.preventDefault();
          last.focus();
        } else if (
          !e.shiftKey &&
          (document.activeElement === last || document.activeElement === root)
        ) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      document.body.style.overflow = bodyOverflow;
      if (before?.isConnected) before.focus();
      else document.querySelector<HTMLElement>("main[tabindex]")?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`${drawer ? "drawer" : "modal"} ${className}`.trim()}
      >
        <div className="modal-head">
          <span>{title}</span>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close details"
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
export function PageHead({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}
export function LinkButton({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-button" onClick={onClick}>
      {children}
      <ArrowUpRight size={15} />
    </button>
  );
}
export function CopyButton({ value }: { value: string }) {
  const ref = useRef<HTMLButtonElement>(null);
  return (
    <button
      className="small-button"
      ref={ref}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          ref.current!.textContent = "Copied";
        } catch {
          ref.current!.textContent = "Select and copy the value";
        }
      }}
    >
      <Check size={13} />
      Copy ID
    </button>
  );
}
