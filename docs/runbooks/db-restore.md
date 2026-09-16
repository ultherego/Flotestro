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
  no host can renew or enroll), `keys/<key-id>.key` (the key encryption keys of the secret store;
  without the active one every row of the store is unreadable), `secrets.key` (or the file named
  by `FLOTESTRO_SECRETS_KEY_FILE`; the key of an installation from before the `keys/` directory,
  adopted as `keys/legacy.key` at the first start after the upgrade and still needed by the rows
  that the background rewrap has not reached), `bootstrap-token` (first start only).
  A key kept as a systemd credential (`FLOTESTRO_SECRETS_KEY_CREDENTIAL`) lives wherever the
  unit's `LoadCredential=` points, and that place is part of the backup set instead.
- `/etc/flotestro/control-plane.env`.
- The package repositories: the panel only knows `FLOTESTRO_PACKAGE_REPOSITORY_URL`; the
  signed apt, dnf and pacman repositories from `packaging/sign-repo.sh` live wherever you serve them.

There is no built-in dump or restore: `flotestro-control-plane` has flags only, and no API
route exports the database. Backups are taken with the PostgreSQL tools.

## Signals

- `GET /healthz` answers `503 database_unavailable` while the pool cannot ping the database,
  `{"status":"ok","active_sessions":N}` otherwise.
- `GET /api/v1/status`, block `crypto`: `ok` with `installation_id`, `active_key_id`, `issuer_id`,
  `keys` and `pending_rewrap`; the block repeats the self-test of the start on every read.
- A start that stops with `the control plane refuses to start: the cryptographic state of the
  installation is not usable` and a `code` of `secrets_key_unavailable`, `issuer_key_unavailable`,
  `pki_state_mismatch` or `crypto_state_ambiguous`: see "Cryptographic state at start" below.
- The log line "the database schema is current" at start; `GET /api/v1/settings` (permission
  `settings.read`) reports the highest applied row of `schema_migrations`.
- After a restore to an older point: attempts closed as `lease_expired`, results answered with
  `superseded_by_result`, agents reporting `outcome_unknown`.

## Cryptographic state at start

The database carries one row, `crypto_installation_state`, that names the installation, the
key of the secret store that is active, the CA that issues the agent certificates, and a
sentinel sealed under that key. At every start, before anything touches the secret store or
the CA, the panel takes an advisory lock (`0x46435259`), reads the row and checks the state
directory against it. What it finds decides what happens:

| Found at start | What the panel does |
|---|---|
| No row, empty database, no files | Initialises: a new key under `keys/k-<random>.key`, a new CA, the row. Logged as "the installation was initialised". |
| No row, existing database, `secrets.key` and the CA present | Adopts: `secrets.key` is copied to `keys/legacy.key` and becomes the active key `legacy`, the CA is opened and verified, the row is written. Logged as "the existing installation was adopted". No downtime beyond the start itself; the rows of the store are rewrapped in the background. |
| Row present, key present and it opens the sentinel, CA matches the row | Starts. |
| Row present, key missing or a different key under the same name | Stops: `secrets_key_unavailable`. Nothing is generated. |
| CA certificate present, `ca.key` missing | Stops: `issuer_key_unavailable`. Nothing is generated. |
| `ca.key` without `ca.pem`, a key that does not match the certificate, a CA other than the recorded one, an unreadable file | Stops: `pki_state_mismatch`. |
| No row, database with secrets, no `secrets.key` | Stops: `secrets_key_unavailable`. |
| No row, database with hosts, no CA at all; or several keys under `keys/` and nothing says which is active | Stops: `crypto_state_ambiguous`. |
| A second panel of the same installation starting at the same time | Waits on the lock, then reads the row the first one wrote. Two panels never make two installations. |

Every stop is logged with `code`, `reason`, `detail` and `hint`; the process exits 1 and
systemd restarts it every 5 seconds until the state is right. The same codes are in the error
guide (`GET /api/v1/errors`, stage `startup`).

What to do, by code:

- `secrets_key_unavailable`: put the key back from the backup of the state directory - the
  file named in the reason (`keys/<key-id>.key`, or `secrets.key` for an installation from
  before the upgrade), owned by the service user, mode 0600. Do not generate a key: a fresh
  key of the right size passes nothing (the sentinel does not open) and would only hide which
  file is missing. If the key is truly lost, the secret store is lost with it: retire every
  secret and enter the values again after the panel is up (see "Recovering from a lost key").
- `issuer_key_unavailable`: put `ca.key` back from the backup, next to `ca.pem`. A new CA in its
  place would cut every host off, because the hosts trust the certificate that is there.
- `pki_state_mismatch`: restore the whole state directory from the backup taken with the dump.
  The reason names what does not fit (a key without its certificate, a pair that does not
  match, a CA other than the recorded one). Do not mix the files of two installations.
- `crypto_state_ambiguous`: the reason says what was found. A database with hosts and no CA is a
  restore that forgot the state directory - restore it. Several keys under `keys/` without a row
  are the leftover of an abandoned installation on an empty database - remove the ones that
  are not wanted, or restore the row with the dump.

### First start after the upgrade (adoption)

Nothing to prepare. On the first start with the new release the migration `0090` adds the row's
table and the columns, and the guard finds no row: it adopts `secrets.key` as `keys/legacy.key`,
opens the existing CA, writes the row and starts. The log shows "the existing installation was
adopted" with the counts of secret versions and hosts, then "the issuer identifier of the agent
certificates was filled in". The secret versions written before the upgrade keep working as they
are and are rewrapped, two hundred at a time, into envelopes under `legacy` ("the secret store
was rewrapped onto the active key"). `GET /api/v1/status` shows `active_key_id: legacy`,
`adopted: true` and `pending_rewrap: 0` once the rewrap is through. Keep `secrets.key` in the
backup set until it is retired; the status block lists it under `keys`.

### Rotating the key of the secret store

1. Set `FLOTESTRO_SECRETS_KEY_ROTATE_TO=k-<name>` and restart. The panel creates
   `keys/k-<name>.key`, reseals the sentinel under it, moves the row and starts; the versions of
   the store are rewrapped in the background. The log says "the secret store switched to a new
   key". The setting is a no-op once that key is active, so it may stay in the environment.
2. Watch `pending_rewrap` in the `crypto` block fall to 0. A rewrap interrupted by a restart
   resumes at the next start; the rows are chosen by the key they are on, not by a cursor.
3. Only then, and after a backup drill with the new key, remove the old key file (`keys/<old>.key`;
   for `legacy` remove `secrets.key` as well, or the guard adopts it again). The status block
   names the keys that no version uses any more. A key removed too early makes the versions
   still on it unreadable, which the fetch reports as `secrets_key_unavailable`.

A key may be moved out of the state directory into a systemd credential: put the file under
`/etc/credstore/` (mode 0600, root), add `LoadCredential=<key-id>:/etc/credstore/<file>` to the
unit's drop-in, set `FLOTESTRO_SECRETS_KEY_CREDENTIAL=<key-id>` and remove `keys/<key-id>.key`.
The panel registers the credential under the key id and never writes it.

### Recovering from a lost key

When the active key is gone from every backup, the values of the secret store cannot be
recovered; the metadata and the fleet can. With the service stopped:

1. Destroy every version, so that no row depends on the lost key any more:
   `update secret_versions set ciphertext = '\x', nonce = '\x', wrapped_dek = null, destroyed_at = now() where destroyed_at is null`.
2. Delete the installation row: `delete from crypto_installation_state`.
3. Remove `keys/` and `secrets.key` from the state directory. Keep the CA files.
4. Start the service. The guard finds no row, no live secret versions and the CA present: it
   makes a new key, writes a new row and starts; the fleet keeps its CA and its certificates.
5. Rotate every secret through the API (`POST /api/v1/secrets/{name}/rotate`) with the values
   entered again. The audit trail keeps the history of the destroyed versions.

## Preconditions

- PostgreSQL 13 or newer on the target (`gen_random_uuid()` is used as a core function; no
  `CREATE EXTENSION` runs except a best-effort `pg_trgm` that may fail without harm).
- The same database role as in `FLOTESTRO_DATABASE_URL` owns the restored objects; the
  migrations create no roles and grant nothing.
- A copy of `FLOTESTRO_STATE_DIR` taken together with the dump. A dump restored next to a
  different `ca.key` or another `keys/` directory does not start: the guard reports
  `pki_state_mismatch` or `secrets_key_unavailable` rather than serving a fleet that cannot
  renew and secrets that cannot be decrypted.

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
2. Restore the state directory first, permissions intact (`ca.key`, `keys/*.key` and
   `secrets.key` are 0600, owned by the service user): `tar -C / -xzf flotestro-state-<stamp>.tgz`.
3. Create an empty database and restore into it:
   `createdb flotestro && pg_restore --no-owner --no-privileges --dbname=flotestro flotestro-<stamp>.dump`.
   A restore over a live schema is not needed; the service applies any migration newer than the
   dump at start, under the advisory lock `0x464c4f54`, one file per transaction.
4. Point `FLOTESTRO_DATABASE_URL` at the restored database and `systemctl start flotestro-control-plane`.
   Watch for "the database schema is current" and, if the dump predates a release, one line per
   migration, then "the cryptographic state of the installation was verified" with the
   `installation_id` of the dump. A dump from before the upgrade restored next to its own state
   directory is adopted the way a first start is (see above).
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
  restored database for analysis, restore again from the intended pair. The service does not
  run against a database whose keys or `ca.key` do not match: the start stops with
  `secrets_key_unavailable` or `pki_state_mismatch` until the pair is right.
- Hosts that renewed their certificate after the snapshot present a certificate the restored
  database does not know (`unknown_certificate` in the connection refusal on the host page).
  Recover each with `POST /api/v1/hosts/{id}/identity-recovery` and
  `flotestro-agentctl identity reset --confirm <hostname>` (see `quarantine.md`).

## Related codes

From the error guide: `lease_expired` (reconcile, read state), `superseded_by_result`
(reconcile, never retry), `outcome_unknown` (agent, read state), `expired` (dispatch),
`secret_unavailable` (dispatch, automatic retry); `secrets_key_unavailable`,
`issuer_key_unavailable`, `pki_state_mismatch`, `crypto_state_ambiguous` (startup, after a
change). Outside the guide: `database_unavailable` (`/healthz`, 503); `unknown_certificate`,
`revoked_certificate`, `identity_mismatch` in the gateway's connection refusals.
