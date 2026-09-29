# Backup and restore

A usable backup includes PostgreSQL data **and the matching encryption key**.
Without the key, saved observer credentials and TOTP secrets cannot be decrypted.
Store the key separately in a protected secret manager or offline recovery medium.
Also preserve deployment values, custom CA certificates and mounted observer files.

## PostgreSQL backup

Use your managed database backup facilities, or `pg_dump -Fc` with a dedicated
backup role. Verify the exit status and size, and encrypt backups at rest. For the
evaluation Compose database:

```sh
docker compose exec -T postgres pg_dump -U grantline -d grantline -Fc > grantline.dump
```

Run shell binary redirection only in a shell that preserves binary output (modern
PowerShell 7.4+, bash). Older Windows PowerShell can corrupt binary redirects;
write the dump inside the container and use `docker cp` instead.

## Restore rehearsal

1. Stop the application so no worker or new write competes with the restore.
2. Restore into a new, empty database using `pg_restore --no-owner` and the correct
   application owner role. Do not overwrite the only working database.
3. Supply the encryption key that belongs to that backup, plus matching external
   secret references and CA configuration.
4. Start the application version compatible with the restored schema. Run its
   migration command, then verify readiness and sign in using a recovery account.
5. Confirm counts, a historical report, decryptable connections, TOTP sign-in and
   a fresh collection. Revoke sessions as part of an incident recovery procedure.

Keep the original database and key until the rehearsal passes. A restored database
may include unexpired sessions and invitation links from the backup. Treat backups
as credentials as well as business data.

## Encryption-key rotation

Stop the application before rotation and take a database backup with its current
key. Generate and persist a separate new key file (32 random bytes encoded as
standard base64 without padding). Keep the normal database and **old** encryption
key configuration available to the CLI, then run:

```sh
grantline rotate-key --new-key-file /private/grantline/new-encryption-key
```

Rotation takes the worker lock and re-encrypts connections, TOTP, SSO settings and
queued mail in one transaction. An incorrect old key aborts it. All sessions and
pending OIDC exchanges are revoked. After success, switch the deployment key file
or Secret and start the application. Startup rejects a key that does not match the
database. Keep the old key with its matching historical backups. Helm never rotates keys.

Report retention defaults to 30 days and is configurable. Backups have their own
retention policy; deleting a report from the live database does not erase old backups.
