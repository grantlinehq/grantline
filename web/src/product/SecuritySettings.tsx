import { useEffect, useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { api, when } from "./api";

export function SSOSettings({ onError }: { onError: (s: string) => void }) {
  const [value, setValue] = useState<any>(null),
    [saved, setSaved] = useState(false);
  const load = () =>
    api("/settings/sso")
      .then(setValue)
      .catch((e) => onError(e.message));
  useEffect(() => {
    load();
  }, []);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaved(false);
    const f = Object.fromEntries(new FormData(e.currentTarget));
    try {
      await api("/settings/sso", "PUT", {
        issuer: f.issuer,
        client_id: f.client_id,
        client_secret: f.client_secret,
        enabled: f.enabled === "on",
        revision: value.revision,
      });
      await load();
      setSaved(true);
    } catch (e) {
      onError((e as Error).message);
    }
  }
  if (!value) return <p role="status">Loading sign-in configuration…</p>;
  return (
    <form className="settings-form" onSubmit={submit} key={value.revision}>
      <div className="provider-intro">
        <ShieldCheck size={27} />
        <div>
          <h2>Organization sign-in</h2>
          <p>
            Configure an OIDC application for Grantline. Collector applications
            are managed separately under Integrations.
          </p>
          <a href="/docs/authentication/">SSO and MFA requirements ↗</a>
        </div>
      </div>
      {saved && (
        <div className="product-notice" role="status">
          Sign-in configuration saved. Test a new sign-in before relying on this
          provider.
        </div>
      )}
      <label className="check-label">
        <input type="checkbox" name="enabled" defaultChecked={value.enabled} />
        Enable organization sign-in
      </label>
      <label>
        Issuer URL
        <input
          name="issuer"
          type="url"
          defaultValue={value.issuer}
          placeholder="https://identity.example.com/tenant"
        />
      </label>
      <label>
        Client ID
        <input name="client_id" defaultValue={value.client_id} />
      </label>
      <label>
        Client secret
        <input
          name="client_secret"
          type="password"
          autoComplete="new-password"
          placeholder={
            value.secret_configured
              ? "Saved · leave blank to keep"
              : "Enter the sign-in application's secret"
          }
        />
      </label>
      <label>
        Redirect URI
        <input
          readOnly
          value={value.redirect_uri}
          onFocus={(e) => e.currentTarget.select()}
        />
      </label>
      <p className="section-note">
        Only invited users can join. Existing accounts require explicit identity
        linking. Owner/Admin sign-in requires your provider to assert MFA.
        Disabling SSO removes the stored client secret; local accounts remain
        available.
      </p>
      <div className="wizard-actions">
        <button className="primary-button">Save sign-in settings</button>
      </div>
    </form>
  );
}

export function SessionSettings({ onError }: { onError: (s: string) => void }) {
  const [sessions, setSessions] = useState<any[]>([]),
    [message, setMessage] = useState("");
  const load = () =>
    api<any[]>("/auth/sessions")
      .then(setSessions)
      .catch((e) => onError(e.message));
  useEffect(() => {
    load();
  }, []);
  return (
    <section>
      <h2>Active sessions</h2>
      <p className="section-note">
        End other sign-ins while keeping this session active.
      </p>
      {sessions.map((s, i) => (
        <div className="run-row" key={i}>
          <span>
            {s.current
              ? "This session"
              : s.mfa_pending
                ? "Awaiting authenticator"
                : "Signed-in session"}
          </span>
          <small>Started {when(s.created_at)}</small>
          <small>Expires {when(s.expires_at)}</small>
        </div>
      ))}
      <button
        className="button"
        onClick={async () => {
          try {
            await api("/auth/sessions/revoke", "POST", {});
            await load();
            setMessage("Other sessions ended.");
          } catch (e) {
            onError((e as Error).message);
          }
        }}
      >
        Sign out other sessions
      </button>
      {message && (
        <p className="section-note" role="status">
          {message}
        </p>
      )}
    </section>
  );
}
