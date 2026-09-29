CREATE TABLE IF NOT EXISTS workspace (
 id integer PRIMARY KEY CHECK (id=1), name text NOT NULL,
 schedule_minutes integer NOT NULL DEFAULT 60 CHECK(schedule_minutes BETWEEN 15 AND 10080),
 retention_days integer NOT NULL DEFAULT 30 CHECK(retention_days BETWEEN 1 AND 365),
 policy text NOT NULL DEFAULT '', bindings text NOT NULL DEFAULT '', revision integer NOT NULL DEFAULT 1,
 next_run timestamptz NOT NULL DEFAULT now()+interval '1 hour'
);
CREATE TABLE IF NOT EXISTS users (
 id text PRIMARY KEY, email text NOT NULL UNIQUE, name text NOT NULL,
 role text NOT NULL CHECK(role IN ('owner','admin','analyst','viewer')),
 password text NOT NULL DEFAULT '', disabled boolean NOT NULL DEFAULT false,
 totp_secret bytea, totp_enabled boolean NOT NULL DEFAULT false, totp_step bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
 digest text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 mfa_pending boolean NOT NULL DEFAULT false, expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tickets (
 digest text PRIMARY KEY, kind text NOT NULL CHECK(kind IN ('invite','recovery','oidc')),
 email text NOT NULL, role text NOT NULL DEFAULT 'viewer', payload bytea,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oidc_links (
 issuer text NOT NULL, subject text NOT NULL, user_id text NOT NULL REFERENCES users(id),
 PRIMARY KEY(issuer,subject)
);
CREATE TABLE IF NOT EXISTS integrations (
 id text PRIMARY KEY, name text NOT NULL, kind text NOT NULL,
 config jsonb NOT NULL, credentials bytea, secret_ref text NOT NULL DEFAULT '',
 enabled boolean NOT NULL DEFAULT true, revision integer NOT NULL DEFAULT 1,
 tested_at timestamptz, test_result jsonb,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS runs (
 id text PRIMARY KEY, kind text NOT NULL CHECK(kind IN ('collection','import')),
 state text NOT NULL CHECK(state IN ('queued','running','completed','partial','failed','cancelled','interrupted')),
 actor_id text, started_at timestamptz, finished_at timestamptz,
 cancel_requested boolean NOT NULL DEFAULT false, error_code text NOT NULL DEFAULT '',
 config_revision integer, attempts integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_collection ON runs ((kind)) WHERE kind='collection' AND state IN ('queued','running');
CREATE TABLE IF NOT EXISTS reports (
 run_id text PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE, report jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS objects (
 run_id text NOT NULL REFERENCES reports(run_id) ON DELETE CASCADE,
 category text NOT NULL, id text NOT NULL, source_id text NOT NULL DEFAULT '',
 name text NOT NULL DEFAULT '', kind text NOT NULL DEFAULT '', severity integer NOT NULL DEFAULT 0,
 body jsonb NOT NULL, PRIMARY KEY(run_id,category,id)
);
CREATE INDEX IF NOT EXISTS objects_list ON objects(run_id,category,kind,source_id,severity DESC,name,id);
CREATE TABLE IF NOT EXISTS triage (
 finding_id text PRIMARY KEY, state text NOT NULL CHECK(state IN ('open','in_review','accepted_risk','resolved')),
 assignee_id text REFERENCES users(id), reason text NOT NULL DEFAULT '', expires_at timestamptz,
 revision integer NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS comments (
 id text PRIMARY KEY, finding_id text NOT NULL, actor_id text NOT NULL REFERENCES users(id),
 body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor_id text, action text NOT NULL,
 subject text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_attempts (
 bucket text PRIMARY KEY, failures integer NOT NULL DEFAULT 0, until_at timestamptz NOT NULL
);
