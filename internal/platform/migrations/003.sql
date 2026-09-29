CREATE TABLE email_jobs (
 id text PRIMARY KEY, encrypted bytea NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sent','failed')),
 attempts integer NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz
);
