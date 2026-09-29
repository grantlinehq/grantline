CREATE TABLE system_settings (
 name text PRIMARY KEY, encrypted bytea NOT NULL, revision integer NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE configuration_versions (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 kind text NOT NULL, subject text NOT NULL, revision integer NOT NULL,
 configuration jsonb NOT NULL, actor_id text, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(kind,subject,revision)
);
ALTER TABLE runs ADD COLUMN configuration jsonb;
CREATE INDEX comments_finding ON comments(finding_id,created_at DESC);
CREATE INDEX reports_recent ON reports(created_at DESC,run_id DESC);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX objects_identity_evidence ON objects(run_id,category,source_id,(body->>'native_id'));
