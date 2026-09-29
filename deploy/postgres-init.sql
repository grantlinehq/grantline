-- The bootstrap role cannot be demoted. Create a separate application owner.
-- psql quotes the file value as a literal; credentials never enter shell arguments.
\set app_password `cat /run/secrets/postgres-password`
BEGIN;
CREATE ROLE grantline LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
  PASSWORD :'app_password';
ALTER DATABASE grantline OWNER TO grantline;
-- Administration remains available via the container's local Unix socket.
-- With no password the bootstrap account cannot use network password auth.
ALTER ROLE postgres PASSWORD NULL;
COMMIT;
\unset app_password
