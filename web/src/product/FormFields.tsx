import { Plus, Trash2 } from "lucide-react";
import type { ReactNode } from "react";
import type { FieldIssue } from "./api";

export type Field = {
  key: string;
  label: string;
  help?: string;
  placeholder?: string;
  type?: "text" | "number" | "lines";
  required?: boolean;
  min?: number;
  max?: number;
  options?: { value: string; label: string }[];
};
export function FieldErrors({ issues }: { issues: FieldIssue[] }) {
  if (!issues.length) return null;
  return (
    <div className="field-errors" role="alert">
      <strong>Check these fields</strong>
      <ul>
        {issues.map((v, i) => (
          <li key={i}>
            <a
              href={`#field-${v.field}`}
              onClick={(e) => {
                e.preventDefault();
                const input =
                  document.getElementById(`field-${v.field}`) ||
                  document.getElementById("field-policy") ||
                  document.getElementById("field-config");
                let parent = input?.parentElement;
                while (parent) {
                  if (parent instanceof HTMLDetailsElement) parent.open = true;
                  parent = parent.parentElement;
                }
                input?.focus();
                input?.scrollIntoView({ block: "center" });
              }}
            >
              {v.field}
              {v.line ? ` · line ${v.line}` : ""}
            </a>
            : {v.message}
          </li>
        ))}
      </ul>
    </div>
  );
}
export function RowsEditor({
  label,
  value,
  onChange,
  fields,
  path,
  addLabel = "Add row",
  max = 100,
  help,
  issues = [],
  children,
}: {
  label: string;
  value: Record<string, any>[];
  onChange: (value: Record<string, any>[]) => void;
  fields: Field[];
  path: string;
  addLabel?: string;
  max?: number;
  help?: string;
  issues?: FieldIssue[];
  children?: (
    row: Record<string, any>,
    index: number,
    update: (next: Record<string, any>) => void,
  ) => ReactNode;
}) {
  return (
    <fieldset className="rows-editor" id={`field-${path}`} tabIndex={-1}>
      <legend>
        {label} <span className="count-pill">{value.length}</span>
      </legend>
      {help && <p className="section-note">{help}</p>}
      {value.length === 0 && (
        <p className="empty-rows">No entries configured.</p>
      )}
      {value.map((row, index) => {
        const update = (next: Record<string, any>) =>
          onChange(value.map((v, i) => (i === index ? next : v)));
        return (
          <div
            className="editor-row"
            key={index}
            id={`field-${path}.${index}`}
            tabIndex={-1}
          >
            <div className="editor-row-heading">
              <strong>{index + 1}</strong>
              <button
                type="button"
                className="text-button"
                onClick={() => onChange(value.filter((_, i) => i !== index))}
                aria-label={`Remove ${label} row ${index + 1}`}
              >
                <Trash2 size={14} /> Remove
              </button>
            </div>
            <div className="editor-row-fields">
              {fields.map((f) => {
                const id = `${path}.${index}.${f.key}`,
                  problem = issues.find((v) => v.field === id);
                const common = {
                  id: `field-${id}`,
                  "aria-invalid": !!problem,
                  "aria-describedby":
                    f.help || problem ? `help-${id}` : undefined,
                  required: f.required !== false,
                };
                return (
                  <label key={f.key}>
                    {f.label}
                    {f.options ? (
                      <select
                        {...common}
                        value={row[f.key] ?? ""}
                        onChange={(e) =>
                          update({ ...row, [f.key]: e.target.value })
                        }
                      >
                        <option value="">Choose…</option>
                        {row[f.key] &&
                          !f.options.some((o) => o.value === row[f.key]) && (
                            <option value={row[f.key]}>
                              Unavailable: {row[f.key]}
                            </option>
                          )}
                        {f.options.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    ) : f.type === "lines" ? (
                      <textarea
                        {...common}
                        rows={2}
                        value={(row[f.key] || []).join("\n")}
                        placeholder={f.placeholder}
                        onChange={(e) =>
                          update({
                            ...row,
                            [f.key]: e.target.value.split("\n"),
                          })
                        }
                      />
                    ) : (
                      <input
                        {...common}
                        type={f.type || "text"}
                        min={f.min}
                        max={f.max}
                        value={row[f.key] ?? ""}
                        placeholder={f.placeholder}
                        onChange={(e) =>
                          update({
                            ...row,
                            [f.key]:
                              f.type === "number"
                                ? e.target.value === ""
                                  ? ""
                                  : Number(e.target.value)
                                : e.target.value,
                          })
                        }
                      />
                    )}
                    {(f.help || problem) && (
                      <small
                        id={`help-${id}`}
                        className={problem ? "field-error" : ""}
                      >
                        {problem?.message || f.help}
                      </small>
                    )}
                  </label>
                );
              })}
            </div>
            {children?.(row, index, update)}
          </div>
        );
      })}
      <button
        type="button"
        className="button"
        disabled={value.length >= max}
        onClick={() =>
          onChange([
            ...value,
            Object.fromEntries(
              fields.map((f) => [
                f.key,
                f.type === "lines"
                  ? []
                  : f.type === "number"
                    ? (f.min ?? 1)
                    : "",
              ]),
            ),
          ])
        }
      >
        <Plus size={14} />
        {addLabel}
      </button>
    </fieldset>
  );
}
