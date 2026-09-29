import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, Check, KeyRound } from "lucide-react";
import { Mark } from "../components";
import { api, type Status, type User } from "./api";

export function Auth({
  status,
  user,
  refresh,
}: {
  status: Status;
  user: User | null;
  refresh: () => Promise<void>;
}) {
  const invitation = location.hash.startsWith("#accept/")
    ? location.hash.slice(8)
    : "";
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [accepted, setAccepted] = useState(false);
  const [forgot, setForgot] = useState(false),
    [recoverySent, setRecoverySent] = useState(false);
  const [mfa, setMfa] = useState<{ enrolled: boolean; secret?: string } | null>(
    null,
  );
  const setup = status.setup_required,
    pending = user?.mfa_pending;
  useEffect(() => {
    if (pending)
      api("/auth/mfa")
        .then(setMfa)
        .catch((e) => setError(e.message));
  }, [pending]);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = Object.fromEntries(new FormData(e.currentTarget));
    try {
      if (forgot) {
        await api("/auth/forgot", "POST", { Email: f.email });
        setRecoverySent(true);
        return;
      }
      if (pending) await api("/auth/mfa", "POST", { Code: f.code });
      else if (setup)
        await api("/auth/setup", "POST", {
          Token: f.token,
          Organization: f.organization,
          Email: f.email,
          Name: f.name,
          Password: f.password,
        });
      else if (invitation && !accepted) {
        await api("/auth/accept", "POST", {
          Token: invitation,
          Name: f.name,
          Password: f.password,
        });
        history.replaceState(null, "", "/#overview");
        setAccepted(true);
      } else
        await api("/auth/login", "POST", {
          Email: f.email,
          Password: f.password,
        });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function sso() {
    setBusy(true);
    setError("");
    try {
      const r = await api("/auth/oidc/start", "POST", {
        Invitation: invitation,
      });
      location.assign(r.url);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  }
  return (
    <div className="product-auth">
      <aside className="auth-story">
        <a className="product-brand" href="/">
          <Mark />
          <span>grantline</span>
        </a>
        <div className="auth-statement">
          <span className="overline">KNOW WHAT CONNECTS.</span>
          <h1>
            Every identity.
            <br />A line of evidence.
          </h1>
          <p>
            A considered view of the accounts, workloads and permissions that
            keep your organization running.
          </p>
          <div className="brand-lines" aria-hidden="true">
            <i />
            <i />
            <i />
            <b />
          </div>
        </div>
        <span className="auth-caption">IDENTITY SECURITY / GRANTLINE</span>
      </aside>
      <main className="auth-main">
        <div className="auth-box">
          <span className="overline">
            {setup
              ? "YOUR WORKSPACE STARTS HERE"
              : pending
                ? "ONE MORE STEP"
                : "WELCOME TO GRANTLINE"}
          </span>
          <h2>
            {forgot
              ? "Recover your account"
              : pending
                ? mfa?.enrolled
                  ? "Verify your sign-in"
                  : "Protect your account"
                : setup
                  ? "Make it your workspace"
                  : invitation && !accepted
                    ? "Join your team"
                    : "Good to have you back."}
          </h2>
          <p>
            {forgot
              ? "Enter your email to request a single-use recovery link."
              : pending
                ? "Use your authenticator app to continue."
                : setup
                  ? "Create your organization and its first owner."
                  : invitation && !accepted
                    ? "Set your name and password to accept this invitation."
                    : "Sign in to follow the evidence."}
          </p>
          {accepted && (
            <div className="product-notice">
              <Check size={16} /> Your password is ready. Sign in to continue.
            </div>
          )}
          {recoverySent && (
            <div className="product-notice" role="status">
              If this account can receive recovery mail, a single-use link has
              been queued. Check your inbox or contact your administrator.
            </div>
          )}
          {pending && mfa?.secret && (
            <div className="mfa-setup">
              <KeyRound size={22} />
              <strong>Add an authenticator account</strong>
              <p>
                Choose a time-based, 6-digit account and enter this setup key.
                Keep it private.
              </p>
              <code>{mfa.secret}</code>
            </div>
          )}
          <form onSubmit={submit}>
            {forgot ? (
              <label>
                Email address
                <input
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                />
              </label>
            ) : pending ? (
              <label>
                Authentication code
                <input
                  name="code"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  autoComplete="one-time-code"
                  required
                  autoFocus
                />
              </label>
            ) : (
              <>
                {setup && (
                  <>
                    <label>
                      Setup token
                      <input
                        name="token"
                        type="password"
                        required
                        autoComplete="off"
                      />
                    </label>
                    <label>
                      Organization
                      <input
                        name="organization"
                        maxLength={100}
                        placeholder="Your organization"
                        required
                      />
                    </label>
                  </>
                )}
                {(setup || (invitation && !accepted)) && (
                  <label>
                    Your name
                    <input
                      name="name"
                      maxLength={100}
                      autoComplete="name"
                      required
                    />
                  </label>
                )}
                {(!invitation || accepted || setup) && (
                  <label>
                    Email address
                    <input
                      name="email"
                      type="email"
                      autoComplete="username"
                      placeholder="you@company.com"
                      required
                    />
                  </label>
                )}
                <label>
                  Password
                  <input
                    name="password"
                    type="password"
                    minLength={setup || (invitation && !accepted) ? 15 : 1}
                    maxLength={256}
                    autoComplete={
                      setup || (invitation && !accepted)
                        ? "new-password"
                        : "current-password"
                    }
                    required
                  />
                </label>
                {(setup || (invitation && !accepted)) && (
                  <small>
                    Use at least 15 characters. A memorable passphrase works
                    well.
                  </small>
                )}
              </>
            )}
            {error && (
              <div className="product-error" role="alert">
                {error}
              </div>
            )}
            <button className="primary-button" disabled={busy}>
              {busy
                ? "Please wait…"
                : forgot
                  ? "Send recovery link"
                  : pending
                    ? "Verify and continue"
                    : setup
                      ? "Create workspace"
                      : invitation && !accepted
                        ? "Set password"
                        : "Sign in"}
              <ArrowRight size={17} />
            </button>
          </form>
          {!setup && !pending && !forgot && status.oidc_enabled && (
            <button className="sso-button" disabled={busy} onClick={sso}>
              Continue with your organization
            </button>
          )}
          {!setup &&
            !pending &&
            !invitation &&
            (status.email_enabled || forgot) && (
              <button
                className="text-button"
                disabled={busy}
                onClick={() => {
                  setForgot(!forgot);
                  setRecoverySent(false);
                  setError("");
                }}
              >
                {forgot ? "Back to sign in" : "Forgot your password?"}
              </button>
            )}
          {!setup && !pending && (
            <p className="auth-help">
              Need access or a password reset? Contact your workspace
              administrator.
            </p>
          )}
          {pending && (
            <button
              className="text-button"
              onClick={async () => {
                await api("/auth/logout", "POST");
                await refresh();
              }}
            >
              Use another account
            </button>
          )}
        </div>
        <a href="/docs/" className="auth-docs">
          Installation &amp; account help ↗
        </a>
      </main>
    </div>
  );
}
