import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy, Plus, ShieldCheck } from "lucide-react";
import { Badge, Modal } from "../components";
import { human } from "../types";
import { api, when, type User } from "./api";
import { SessionSettings, SSOSettings } from "./SecuritySettings";
import { Heading } from "./Workspace";

export function Settings({
  user,
  onError,
  refresh,
}: {
  user: User;
  onError: (s: string) => void;
  refresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState(
      ["owner", "admin"].includes(user.role) ? "workspace" : "account",
    ),
    [settings, setSettings] = useState<any>(null),
    [users, setUsers] = useState<any[]>([]),
    [message, setMessage] = useState(""),
    [invite, setInvite] = useState(false),
    [link, setLink] = useState<any>(null),
    [busy, setBusy] = useState(false);
  const load = () =>
    Promise.all([
      ["owner", "admin"].includes(user.role)
        ? api("/settings")
        : Promise.resolve(null),
      ["owner", "admin"].includes(user.role)
        ? api("/users")
        : Promise.resolve([]),
    ])
      .then(([s, u]) => {
        setSettings(s);
        setUsers(u);
      })
      .catch((e) => onError(e.message));
  useEffect(() => {
    load();
  }, []);
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    const f = Object.fromEntries(new FormData(e.currentTarget));
    try {
      await api("/settings", "PUT", {
        Name: f.name ?? settings.name,
        schedule_minutes: Number(f.schedule ?? settings.schedule_minutes),
        retention_days: Number(f.retention ?? settings.retention_days),
        Policy: f.policy ?? settings.policy,
        Bindings: f.bindings ?? settings.bindings,
        Revision: settings.revision,
      });
      await load();
      await refresh();
      setMessage("Workspace settings saved.");
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function updateUser(member: any, role: string, disabled: boolean) {
    try {
      await api(`/users/${member.id}`, "PATCH", {
        Role: role,
        Disabled: disabled,
      });
      await load();
      setMessage("Account updated. Its existing sessions were revoked.");
      if (member.id === user.id) await refresh();
    } catch (e) {
      onError((e as Error).message);
    }
  }
  return (
    <>
      <Heading
        label="MAKE IT YOURS"
        title="Workspace settings"
        description="People, collection policies and the decisions that shape your workspace."
      />
      <nav className="settings-tabs" aria-label="Settings sections">
        {(["owner", "admin"].includes(user.role)
          ? [
              "workspace",
              "people",
              "policies",
              ...(user.role === "owner" ? ["sso"] : []),
              "account",
            ]
          : ["account"]
        ).map((t) => (
          <button
            key={t}
            aria-current={tab === t ? "page" : undefined}
            onClick={() => {
              setTab(t);
              setMessage("");
            }}
          >
            {human(t)}
          </button>
        ))}
      </nav>
      {message && (
        <div className="product-notice" role="status">
          <Check size={16} />
          {message}
        </div>
      )}
      {settings && tab === "workspace" && (
        <form onSubmit={save} className="settings-form">
          <div className="settings-section">
            <div>
              <h2>Organization</h2>
              <p>A shared name for your security workspace.</p>
            </div>
            <label>
              Workspace name
              <input
                name="name"
                readOnly={user.role !== "owner"}
                required
                maxLength={100}
                defaultValue={settings.name}
              />
            </label>
          </div>
          <div className="settings-section">
            <div>
              <h2>Collection schedule</h2>
              <p>
                Only enabled connections are collected. Overlapping jobs are
                coalesced into one active collection.
              </p>
            </div>
            <label>
              Interval in minutes
              <input
                name="schedule"
                type="number"
                min={15}
                max={10080}
                required
                defaultValue={settings.schedule_minutes}
              />
            </label>
          </div>
          <div className="settings-section">
            <div>
              <h2>Report retention</h2>
              <p>
                Older reports are removed automatically. Review decisions and
                audit records are preserved.
              </p>
            </div>
            <label>
              Days to retain
              <input
                name="retention"
                type="number"
                min={1}
                max={365}
                required
                defaultValue={settings.retention_days}
              />
            </label>
          </div>
          <div className="wizard-actions">
            <button className="primary-button" disabled={busy}>
              Save settings
            </button>
          </div>
          <p className="section-note">
            Configuration revision {settings.revision} · Next scheduled
            collection {when(settings.next_run)}
          </p>
        </form>
      )}
      {tab === "people" && (
        <>
          <div className="section-heading">
            <h2>
              People with access <small>{users.length}</small>
            </h2>
            <button
              className="primary-button"
              onClick={() => {
                setLink(null);
                setInvite(true);
              }}
            >
              <Plus size={16} />
              Invite member
            </button>
          </div>
          <div className="product-table-wrap">
            <table className="product-table">
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Role</th>
                  <th>Account</th>
                  <th>Manage</th>
                </tr>
              </thead>
              <tbody>
                {users.map((member) => (
                  <tr key={member.id}>
                    <td>
                      <strong>{member.name}</strong>
                      <small>{member.email}</small>
                    </td>
                    <td>
                      <select
                        aria-label={`Role for ${member.name}`}
                        disabled={
                          member.role === "owner" && user.role !== "owner"
                        }
                        value={member.role}
                        onChange={(e) =>
                          updateUser(member, e.target.value, member.disabled)
                        }
                      >
                        {[
                          ...(user.role === "owner" ? ["owner"] : []),
                          "admin",
                          "analyst",
                          "viewer",
                        ].map((role) => (
                          <option key={role} value={role}>
                            {human(role)}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <Badge value={member.disabled ? "disabled" : "active"} />
                      <small>
                        {member.mfa_enabled
                          ? "Authenticator enrolled"
                          : "No local authenticator"}
                      </small>
                    </td>
                    <td>
                      <div className="member-actions">
                        <button
                          className="text-button"
                          disabled={
                            member.role === "owner" && user.role !== "owner"
                          }
                          onClick={() =>
                            updateUser(member, member.role, !member.disabled)
                          }
                        >
                          {member.disabled ? "Enable" : "Disable"}
                        </button>
                        <button
                          className="text-button"
                          disabled={
                            member.role === "owner" && user.role !== "owner"
                          }
                          onClick={async () => {
                            try {
                              setLink(
                                await api("/recovery", "POST", {
                                  Email: member.email,
                                }),
                              );
                              setInvite(true);
                            } catch (e) {
                              onError((e as Error).message);
                            }
                          }}
                        >
                          Recovery link
                        </button>
                        <button
                          className="text-button"
                          disabled={
                            member.role === "owner" && user.role !== "owner"
                          }
                          onClick={async () => {
                            try {
                              await api(
                                `/users/${member.id}/sessions/revoke`,
                                "POST",
                                {},
                              );
                              setMessage("Active sessions revoked.");
                              if (member.id === user.id) await refresh();
                            } catch (e) {
                              onError((e as Error).message);
                            }
                          }}
                        >
                          Revoke sessions
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="section-note">
            Owner manages organization and SSO. Admin manages connections and
            people. Analyst investigates. Viewer reads. The final active Owner
            cannot be removed.
          </p>
        </>
      )}
      {settings && tab === "policies" && (
        <form onSubmit={save} className="settings-form">
          <div className="section-heading">
            <div>
              <h2>Policy &amp; explicit context</h2>
              <p className="section-note">
                Changes are validated and versioned. They apply to the next
                collection; existing reports remain unchanged.
              </p>
            </div>
            <a href="/docs/policies/">Configuration reference ↗</a>
          </div>
          <label>
            IL001–IL008 policy configuration
            <textarea
              name="policy"
              className="code-input policy-input"
              defaultValue={settings.policy}
              placeholder="Leave blank to use the documented defaults"
            />
          </label>
          <label>
            Environment, business context &amp; relationship declarations
            <textarea
              name="bindings"
              className="code-input policy-input"
              defaultValue={settings.bindings}
              placeholder="Optional strict YAML context bindings"
            />
          </label>
          <div className="wizard-actions">
            <button className="primary-button" disabled={busy}>
              Save new revision
            </button>
          </div>
        </form>
      )}
      {tab === "sso" && user.role === "owner" && (
        <SSOSettings onError={onError} />
      )}
      {tab === "account" && (
        <div className="settings-form">
          <SessionSettings onError={onError} />
          <section className="settings-section">
            <div>
              <ShieldCheck size={25} />
              <h2>Your account</h2>
              <p>{user.email}</p>
            </div>
            <div>
              <h3>Organization sign-in</h3>
              <p>
                Link an organization identity while signed in. Accounts are
                never merged automatically by email.
              </p>
              <button
                className="button"
                onClick={async () => {
                  try {
                    const r = await api("/auth/oidc/link", "POST", {});
                    location.assign(r.url);
                  } catch (e) {
                    onError((e as Error).message);
                  }
                }}
              >
                Link SSO identity
              </button>
              <a className="section-note" href="/docs/authentication/">
                SSO configuration guide ↗
              </a>
            </div>
          </section>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              const f = Object.fromEntries(new FormData(e.currentTarget));
              try {
                await api("/auth/password", "POST", {
                  Current: f.current,
                  Password: f.password,
                });
                await refresh();
              } catch (e) {
                onError((e as Error).message);
              }
            }}
          >
            <h2>Change password</h2>
            <p className="section-note">
              Changing your password signs out all sessions, including this one.
            </p>
            <label>
              Current password
              <input
                name="current"
                type="password"
                required
                autoComplete="current-password"
              />
            </label>
            <label>
              New password
              <input
                name="password"
                type="password"
                required
                minLength={15}
                maxLength={256}
                autoComplete="new-password"
              />
            </label>
            <button className="primary-button">Update password</button>
          </form>
        </div>
      )}
      {invite && (
        <Modal
          title={link ? "Secure account link" : "Invite a member"}
          onClose={() => setInvite(false)}
        >
          {link ? (
            <div className="invite-result">
              <p>
                {link.email_queued
                  ? "Email delivery is queued. You can also share this link directly."
                  : "Share this link directly with the intended person."}{" "}
                It can be used once and expires {when(link.expires_at)}.
              </p>
              <textarea
                readOnly
                value={link.url}
                aria-label="Single-use account link"
              />
              <button
                className="button"
                onClick={async () => {
                  await navigator.clipboard.writeText(link.url);
                  setMessage("Link copied.");
                }}
              >
                <Copy size={16} />
                Copy link
              </button>
            </div>
          ) : (
            <form
              className="integration-form"
              onSubmit={async (e) => {
                e.preventDefault();
                const f = Object.fromEntries(new FormData(e.currentTarget));
                try {
                  setLink(
                    await api("/invitations", "POST", {
                      Email: f.email,
                      Role: f.role,
                      send_email: f.send_email === "on",
                    }),
                  );
                } catch (e) {
                  onError((e as Error).message);
                }
              }}
            >
              <label>
                Email address
                <input name="email" type="email" required />
              </label>
              <label>
                Role
                <select name="role" defaultValue="analyst">
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
              <p className="section-note">
                The invitation expires in 24 hours. Privileged local accounts
                must enroll an authenticator before accessing the workspace.
              </p>
              <label className="check-label">
                <input name="send_email" type="checkbox" />
                Send via configured SMTP
              </label>
              <button className="primary-button">Create invitation</button>
            </form>
          )}
        </Modal>
      )}
    </>
  );
}
