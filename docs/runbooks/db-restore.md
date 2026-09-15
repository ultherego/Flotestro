# Database restore

## Purpose

Bring the control plane back on a PostgreSQL snapshot, knowing what the snapshot does and
does not contain, and settle the work that was in flight when it was taken. PostgreSQL is the
only source of truth: hosts, certificates, jobs and attempts, campaigns, budgets, secrets
(encrypted), the outbox and its consumer cursor, the audit trail, monitoring samples and
rollups all live in the database named by `FLOTESTRO_DATABASE_URL`.

Not in the database, and therefore part of every backup set:

- `FLOTESTRO_STATE_DIR` (default `/var/lib/flotestro`): `ca.pem`, `ca.key`, `ca-pending.pem`,
  `ca-pending.key`, `ca-pending.at`, `ca-retired/<serial>.pem` (the fleet CA; without `ca.key`
  no host can renew or enroll), `secrets.key` (or the file named by `FLOTESTRO_SECRETS_KEY_FILE`;
  without it every row of the secret store is unreadable), `bootstrap-token` (first start only).
- `/etc/flotestro/control-plane.env`.
- The package repositories: the panel only knows `FLOTESTRO_PACKAGE_REPOSITORY_URL`; the
  signed apt, dnf and pacman repositories from `packaging/sign-repo.sh` live wherever you serve them.

There is no built-in dump or restore: `flotestro-control-plane` has flags only, and no API
route exports the database. Backups are taken with the PostgreSQL tools.

## Signals

- `GET /healthz` answers `503 database_unavailable` while the pool cannot ping the database,
  `{"status":"ok","active_sessions":N}` otherwise.
- The log line "the database schema is current" at start; `GET /api/v1/settings` (permission
  `settings.read`) reports the highest applied row of `schema_migrations`.
- After a restore to an older point: attempts closed as `lease_expired`, results answered with
  `superseded_by_result`, agents reporting `outcome_unknown`.

## Preconditions

- PostgreSQL 13 or newer on the target (`gen_random_uuid()` is used as a core function; no
  `CREATE EXTENSION` runs except a best-effort `pg_trgm` that may fail without harm).
- The same database role as in `FLOTESTRO_DATABASE_URL` owns the restored objects; the
  migrations create no roles and grant nothing.
- A copy of `FLOTESTRO_STATE_DIR` taken together with the dump. A dump restored next to a
  different `ca.key` or `secrets.key` produces a fleet that cannot renew and secrets that
  cannot be decrypted.

## Procedure

### Backup (routine)

1. `pg_dump --format=custom --no-owner --no-privileges --file=flotestro-$(date -u +%Y%m%dT%H%MZ).dump "$FLOTESTRO_DATABASE_URL"`
   from a host that can reach the database; the custom format allows a selective restore.
2. `tar -C / -czf flotestro-state-$(date -u +%Y%m%dT%H%MZ).tgz var/lib/flotestro etc/flotestro/control-plane.env`
   (adjust for a non-default `FLOTESTRO_STATE_DIR`), stored with the same care as the CA key.
3. Export the audit trail alongside: `GET /api/v1/audit/export` (filters `since`, `until`,
   `actor`, `action`, `outcome`, `target_type`, `target_id`) returns NDJSON with a `prev_sha256`
   per line and a trailer `{"count": N, "sha256_chain": "<hex>"}`. The export itself is audited as `audit.export`.

### Restore (drill or incident)

1. `systemctl stop flotestro-control-plane`. Agents keep their sessions closed and retry the
   gateway with backoff; a relay buffers its site's messages in memory up to `buffer_max_bytes`.
2. Restore the state directory first, permissions intact (`ca.key` and `secrets.key` are 0600,
   owned by the service user): `tar -C / -xzf flotestro-state-<stamp>.tgz`.
3. Create an empty database and restore into it:
   `createdb flotestro && pg_restore --no-owner --no-privileges --dbname=flotestro flotestro-<stamp>.dump`.
   A restore over a live schema is not needed; the service applies any migration newer than the
   dump at start, under the advisory lock `0x464c4f54`, one file per transaction.
4. Point `FLOTESTRO_DATABASE_URL` at the restored database and `systemctl start flotestro-control-plane`.
   Watch for "the database schema is current" and, if the dump predates a release, one line per migration.
5. Let the scheduler settle the in-flight work. Nothing is done by hand here:
   - Every 30 seconds `ReclaimExpiredLeases` closes attempts whose `lease_expires_at` has passed
     (the execution lease is 5 minutes, fixed in `cmd/control-plane`) as `lease_expired`, returns the
     job to `queued`, and releases its budget tokens. After a restore this catches every job the
     snapshot shows as `leased`, `dispatched` or `running`.
   - A result that arrives for an attempt already closed as `lease_expired` is accepted and
     settles the job; other open attempts of the job close as `superseded_by_result`. A result
     for a terminal job is kept for diagnostics and not applied.
   - A job the agent already finished and the panel dispatches again is answered from the
     agent's idempotency journal (kept 24 hours) or, if the agent restarted mid-operation, with
     `outcome_unknown`; the agent never repeats the operation on its own.
   - `ExpireOverdue` marks tasks past their time to live as `expired`.
   - The outbox consumer resumes from `outbox_consumers.last_id` as restored; webhook events
     after that point are delivered again. The receiver deduplicates by event id.
6. Read the job list for what needs a decision: `GET /api/v1/jobs?state=failed` and, per
   campaign, `GET /api/v1/campaigns/{id}/targets`; follow the guide (`GET /api/v1/errors`) for
   `lease_expired` and `outcome_unknown`: read the host (`packages.list`, `unit.status`) before
   ordering a destructive step again.

## Verification

1. `GET /healthz` is `200`; `GET /api/v1/settings` shows the expected schema version.
2. `GET /api/v1/fleet/summary` and the dashboard: hosts come back online as their agents
   reconnect (`flotestro_hosts_lifecycle{lifecycle_state}` on `GET /metrics`).
3. Certificates and secrets: `GET /api/v1/pki` lists the same active CA as before;
   `flotestro_agent_renewal_total{outcome="failed"}` is not climbing; `GET /api/v1/secrets` lists
   the store and a host operation that needs a secret does not end in `secret_unavailable`.
4. Audit chain: `GET /api/v1/audit/export > audit.jsonl` then `flotestro-auditverify audit.jsonl`.
   Exit `0` prints `OK, N events` and the `sha256_chain`; exit `1` prints `BROKEN` with the
   number of events verified before the break; exit `2` is a usage or read error. Compare the
   chain value with the export taken at backup time: a restore cannot recreate events lost
   between the snapshot and the outage; the trail restarts from the snapshot and the
   `audit_events` table is append-only by trigger.
5. Queue: `flotestro_job_queue_age_seconds` falls, `flotestro_jobs{state}` shows no job stuck
   in `leased` longer than the lease.

## Rollback/Recovery

- A restore that turns out wrong (wrong dump, wrong state directory): stop the service, keep the
  restored database for analysis, restore again from the intended pair. Do not run the service
  against a database whose `secrets.key` or `ca.key` does not match; renewals fail with
  `unknown_certificate` and secrets with `secret_unavailable` until the pair is right.
- Hosts that renewed their certificate after the snapshot present a certificate the restored
  database does not know (`unknown_certificate` in the connection refusal on the host page).
  Recover each with `POST /api/v1/hosts/{id}/identity-recovery` and
  `flotestro-agentctl identity reset --confirm <hostname>` (see `quarantine.md`).

## Related codes

From the error guide: `lease_expired` (reconcile, read state), `superseded_by_result`
(reconcile, never retry), `outcome_unknown` (agent, read state), `expired` (dispatch),
`secret_unavailable` (dispatch, automatic retry). Outside the guide: `database_unavailable`
(`/healthz`, 503); `unknown_certificate`, `revoked_certificate`, `identity_mismatch` in the
gateway's connection refusals.
