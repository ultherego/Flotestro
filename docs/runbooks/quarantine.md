# Quarantine, identity recovery and decommission

## Purpose

Cut a host off from the fleet, bring it back, replace its identity, or retire it. The
lifecycle states are `active`, `quarantined`, `recovery`, `retiring`, `retired`; a transition
from any other state than the ones it allows is refused with `409 lifecycle_conflict`, and
every change carries a reason.

## Signals

- Host page (`/hosts/<id>/overview`): the lifecycle card with state, since, reason and meaning
  ("The host is cut off: no operations, no secrets, no session. Release it once the incident is
  assessed."), and the connection refusal notice with the gateway's code (`lifecycle_quarantined`,
  `unknown_certificate`, `revoked_certificate`, `identity_mismatch`, `certificate_expired`).
- Dashboard (`GET /api/v1/fleet/summary`): `quarantined_hosts`, `duplicate_identities_24h`;
  `GET /metrics`: `flotestro_hosts_lifecycle{lifecycle_state}`, `flotestro_duplicate_identity_total{gateway}`.
- Audit (`GET /api/v1/hosts/{id}/audit`): `security.duplicate_identity` (outcome `denied`, with
  `previous_session`, `previous_boot_id`, `previous_addr`, `remote_addr`, `policy`, `quarantined`),
  `host.quarantine`, `host.quarantine.release`, `host.identity.recovery`,
  `host.identity.recovery.lapsed`, `host.retiring`, `host.decommission`, `host.certificate.revoke`.
- Operations refused with `409 host_quarantined`; campaign targets `ineligible` with `quarantined`.

## Preconditions

- Permissions `host.quarantine`, `host.quarantine.release`, `host.identity.replace`,
  `host.decommission` in the host's scope; all four routes are step-up operations (`reason` of
  at least 8 characters, `FLOTESTRO_STEPUP_MAX_AGE`, `FLOTESTRO_STEPUP_TOKENS`).
- `FLOTESTRO_CLONE_POLICY` is `quarantine` (the default) or `report`. A clone is the same
  certificate alive on a different boot id and address while the previous session still
  heartbeats; a reconnect from the same address is not one.
- All four are on the host page, in the lifecycle card of the overview ("Quarantine host…",
  "Release from quarantine…", "Order identity recovery…", "Decommission host…"); each asks for
  the reason, the typed hostname and, when the session is stale, a fresh sign-in. The API calls
  below are what those buttons send.

## Procedure

### Enter quarantine

1. `POST /api/v1/hosts/{id}/quarantine` with `{"reason": "...", "revoke_certificates": false}`,
   from `active`, `recovery` or `quarantined`. Set `revoke_certificates` only on a suspected key
   leak: a revoked certificate cannot be released, only recovered. Without it the key stays
   valid and the database state alone blocks the host.
2. In the same transaction, undelivered jobs (`planned`, `awaiting_approval`, `queued`, `leased`)
   become `canceled` with `cancel_reason` `host.quarantine` (`duplicate_identity` under the clone
   policy), their budget tokens are released and the session is closed. A task already
   `dispatched` or `running` is not interrupted; its result is recorded on arrival.
3. The gateway then refuses the host's connection (`lifecycle_quarantined`): no heartbeat,
   inventory or sample arrives; secret leases and renewal are refused; new operations answer
   `409 host_quarantined`.
4. Under the clone policy `quarantine`, both sessions end with `duplicate_identity` and the
   host is quarantined with that reason; under `report` the newer session stands. The audit
   entry and `flotestro_duplicate_identity_total` are written under both.

### Release

1. Decide which machine is the host; under a duplicate identity, wipe or reinstall the other
   machine first, or the release produces the next duplicate.
2. `POST /api/v1/hosts/{id}/quarantine/release` with `{"reason": "..."}`, from `quarantined`
   only; refused with `409 identity_revoked` when the host has no live (unrevoked, unexpired)
   certificate. The host returns to `active`; the agent reconnects by itself within its retry
   backoff (up to 5 minutes), or at once after `systemctl restart flotestro-agent`.

### Identity recovery (new key, same host record)

1. `POST /api/v1/hosts/{id}/identity-recovery` with
   `{"reason": "...", "revoke_old_immediately": false, "ttl_seconds": 900}` (refused with
   `409 host_retired` for `retiring` or `retired`). The response is a one-use enrollment request
   of purpose `replace_identity` with the clear `token` (shown once) and `expires_at` (default
   15 minutes, at most 24 hours). An `active` host moves to `recovery` and its undelivered jobs
   are cancelled; a `quarantined` host stays quarantined. `revoke_old_immediately` revokes the
   old certificates now and ends the session with `identity_recovery`; otherwise the old
   certificate may still connect for 24 hours.
2. On the host, with the token in a file the service user can read:
   `sudo -u flotestro-agent flotestro-agentctl identity reset --confirm <hostname> --token-file /run/token`
   (`--confirm` must equal the machine's hostname, else `confirmation_mismatch`; `--timeout`
   default 2m; `--discard-pending` abandons an unfinished attempt). The tool writes a new
   generation under `/var/lib/flotestro-agent/identity/generations/<serial>/`, verifies it
   against the gateway and only then switches `identity/current`. Output: `Replaced: host/<id>`.
3. `systemctl restart flotestro-agent`: the running daemon keeps its old session otherwise.
4. The first session of the new certificate takes the host from `recovery` back to `active`;
   the record, history and tasks are the same host, rebound to the new machine id. An order
   that expires unused is lapsed hourly back to `active` (`host.identity.recovery.lapsed`).

### Decommission

1. `POST /api/v1/hosts/{id}/decommission` with `{"reason": "...", "typed_confirmation": "<hostname>",
   "local_identity_wipe": true, "revoke_immediately_if_offline": true}`. Allowed from `active`,
   `quarantined`, `recovery`, `retiring`; a wrong confirmation is `400 confirmation_mismatch`.
2. The host goes `retiring` at once (`host.retiring`), undelivered jobs are cancelled with
   `host.decommission`, nothing new starts. With a session, the gateway sends the final task
   (90 seconds of grace), waits up to 2 minutes for the agent's readiness, revokes the
   certificates, sends the commit (identity and journal wiped, service disabled) and gives the
   session 15 seconds to close. Without a session, or on a timeout, the host is retired anyway
   with `remote_cleanup_unconfirmed` (phase `no_session`, `timeout` or `committed` in the audit).
3. The row stays `retired`; the machine id is withheld from new enrollments for 30 days, then
   released under `retired:<id>:<machine_id>` so the machine can enroll as a new host.

### A machine enrolled as a new host

The root helper keeps its own view of who the host is: the host identifier and the panel's
capability keys, handed to it in a bundle the panel signs at enrollment and at every session.
Once it holds them, only that panel can change them. A machine that is enrolled anew - after a
decommission, after a `purge` of the agent package on another system than Debian, or with a
panel rebuilt without its state directory - therefore answers the new bundle with
`trust_bundle_untrusted` in the helper's journal, and the panel's `job.dispatch` events for the
host carry a capability the helper will refuse. As root, before or right after the enrollment:

1. `flotestro-agentctl helper-trust show`: the identity, the keys and the mode.
2. `flotestro-agentctl helper-trust reset --confirm <hostname>`: forgets both; the next session
   of the agent hands the helper the current panel's bundle, which is taken on trust.

A Debian `apt purge` of `flotestro-agent` does this on its own, together with the agent's
identity.

## Verification

- `GET /api/v1/hosts/{id}`: `lifecycle_state` as intended, `connection_state` `online` after a
  release or recovery; `flotestro-agentctl status` shows the session, `diagnose` no `fail`.
- A read (`POST /api/v1/hosts/{id}/operations`, action `packages.list`) is accepted rather
  than refused with `host_quarantined`.

## Rollback/Recovery

- A quarantine by mistake: release it. If `revoke_certificates` was set, order an identity
  recovery instead; nothing un-revokes a certificate.
- A recovery order given in error: `POST /api/v1/enrollment-requests/{id}/revoke`; the host
  lapses back to `active` on the next hourly sweep, its old key valid unless revoked.
- Decommission cannot be undone; enroll the machine as a new host after the 30-day retention.

## Related codes

From the error guide: `quarantined`, `recovery`, `retiring`, `retired` (preflight),
`host_retiring` (agent), `remote_cleanup_unconfirmed` (reconcile), `canceled` (dispatch).
Outside the guide: `host_quarantined`, `host_retired`, `lifecycle_conflict`, `identity_revoked`,
`confirmation_mismatch` (HTTP problems); `lifecycle_<state>`, `unknown_certificate`,
`revoked_certificate`, `identity_mismatch`, `certificate_expired` (gateway refusals);
`duplicate_identity`, `identity_recovery` (session end reasons).
