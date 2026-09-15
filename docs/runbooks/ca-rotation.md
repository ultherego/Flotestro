# CA rotation

## Purpose

Replace the fleet CA without a window in which a host distrusts the panel or the panel
distrusts a host. The rotation is staged: a new CA is *prepared* (trusted, distributed,
not signing), *activated* (signs new certificates; the old one becomes *retired*), and the
old one is *retired* out of the trust set once no host uses it. Every stage is a step-up
operation under `pki.rotate`, held by `platform_admin` only.

## Signals

- `flotestro_ca_certificate_expires_in_seconds` (the signing CA) and
  `flotestro_trust_authority_expires_in_seconds{state,serial}` (every CA in the set) on `GET /metrics`.
- `GET /api/v1/pki` lists every authority with `state` (`active`, `pending`, `retired`),
  `hosts_using`, and for a pending CA `prepared_at`, `hosts_missing`, `ready_to_activate`.
- Panel: Access, tab "Fleet CA" (`/access`, needs `principal.manage`); Certificates (`/certificates`)
  shows the fleet's leaf certificates and the "Trusted authorities" card from `GET /api/v1/certificates/trust`.

## Preconditions

- A session or token with `pki.read` and `pki.rotate`. If `FLOTESTRO_STEPUP_TOKENS=refuse`, an
  API token gets `reauthentication_required`; use a browser session younger than
  `FLOTESTRO_STEPUP_MAX_AGE` (default `5m`) and, if set, at `FLOTESTRO_STEPUP_ACR`.
- Every `reason` is at least 8 characters, or the request is refused with `reason_required`.
- The CA files live in `FLOTESTRO_STATE_DIR` (default `/var/lib/flotestro`): `ca.pem`, `ca.key`,
  `ca-pending.pem`, `ca-pending.key`, `ca-pending.at`, `ca-retired/<serial>.pem`. Back the
  directory up before the first step; they are not in the database (see `db-restore.md`).
- No host you need is `quarantined`, `retiring` or in `recovery`: renewal refuses such a host
  (`lifecycle_<state>` in the denial audit), and it will keep `hosts_missing` above zero.

## Procedure

1. Read the current trust set: `GET /api/v1/pki`. Exactly one `active` authority, no `pending`.
2. Prepare the new CA:
   `POST /api/v1/pki/prepare` with `{"reason": "<why, 8+ chars>"}`. Response: the new authority
   with `state: "pending"`. Audit action `pki.ca.prepare`. A second prepare is refused with
   `prepare_failed` while one is pending.
3. Let the fleet learn the new CA. There is no push: the bundle (active + pending + retired PEM)
   travels only in the enrollment and certificate renewal responses. An agent renews by itself
   when less than a third of its certificate lifetime remains (`FLOTESTRO_AGENT_CERT_TTL`, default
   `720h`, so roughly the last 10 days), checking at most every 6 hours and retrying every 30
   minutes after a failure. To finish sooner, force a renewal on each host:
   `sudo -u flotestro-agent flotestro-agentctl renew` (flags `-config`, `-timeout`, default 2m).
   Forced renewals are throttled to one per 10 minutes (exit 2 when too soon). The running daemon
   keeps its old session; `systemctl restart flotestro-agent.service` switches it.
4. Watch `GET /api/v1/pki`: the pending entry's `hosts_missing` counts hosts with no unrevoked
   certificate issued since `prepared_at`; retired hosts are left out, quarantined and
   recovering ones are not - release or recover them, or the count never reaches zero.
   `flotestro_agent_renewal_total{outcome}` shows the renewals.
5. Activate once `ready_to_activate` is `true`:
   `POST /api/v1/pki/activate` with `{"reason": "..."}`. With `hosts_missing > 0` the call is
   refused with `409 hosts_missing_ca` and audited as denied. On success the new CA signs, the
   old one is `retired` (still trusted for verification), and the log says
   "the new fleet CA took over signing".
6. Restart the control plane: `systemctl restart flotestro-control-plane`. The gateway server
   certificate is issued at start from the active CA; until then it still comes from the old one.
   Both are in every agent's bundle, so either order works.
7. Wait for `hosts_using` of the retired CA to reach 0. Certificates are reissued only by
   renewal (step 3 applies again), so this takes up to one certificate lifetime unless forced.
8. Retire the old CA out of the set:
   `DELETE /api/v1/pki/{fingerprint}?reason=<why>` (the reason is a query parameter here).
   With `hosts_using > 0` it is refused with `409 ca_in_use`; so is the active CA ("the CA that
   signs new certificates cannot be removed"). Success is `204`. The panel offers "Remove from
   trust set" only for a retired CA with 0 hosts.

### Host trust anchors (optional, for anchors on the hosts' own trust stores)

Flotestro's mTLS does not use the OS trust store; the agent keeps its bundle in its identity.
If the fleet CA is also installed as a system anchor, roll it with a campaign
(`POST /api/v1/campaigns`, `"action"` and `"payload": {"anchor_id": ..., "certificate": "<PEM>"}`):
`certificate.trust.plan` (read, `certificate.trust.plan` permission), then
`certificate.trust.ensure` (critical, lock class certificates, `plan_hash` from the plan), and
last `certificate.trust.remove` for the old anchor. Removal requires full coverage: while any
host's readiness is uncertain the order is refused with `400 incomplete_coverage`; a host-side
plan refuses removal of an anchor that still signs a certificate the host uses. Coverage is
read on `/certificates` ("covered" means `hosts >= hosts_total` and `hosts_unknown = 0`).

## Verification

- `GET /api/v1/pki`: one `active` authority (the new serial), no `pending`, the old one gone or
  `retired` with `hosts_using: 0`.
- `flotestro_agent_certificate_expiry_seconds_min` and `flotestro_agent_certificates_expiring{within}`
  show renewed leaves; `flotestro_agent_renewal_total{outcome="refused"}` is not climbing.
- On a host: `flotestro-agentctl status` and `flotestro-agentctl diagnose` report a valid identity
  and an open session; `/certificates` shows no host without certificates.
- Audit (`GET /api/v1/audit?action=pki.ca.activate`) carries the step-up evidence.

## Rollback

- Before activation: abandon the pending CA with `DELETE /api/v1/pki/{fingerprint}` on the
  pending fingerprint. It deletes `ca-pending.*`; nothing was signed with it. Agents drop it from
  their bundle at their next renewal. The panel has no button for this; it is API only.
- After activation there is no route that makes the old CA sign again. The old CA stays trusted
  as `retired`, so nothing breaks; to go back, prepare and activate again (a fresh key each
  time, `Prepare` always generates one). Restoring `ca.pem`/`ca.key` from a file backup is not a
  supported path and is not described here.
- A host that missed the rotation and no longer connects: `flotestro-agentctl diagnose`, then
  re-enroll it (`identity-recovery`, see `quarantine.md`).

## Related codes

`incomplete_coverage` (materialize, retry after change) is the only entry in the error guide
(`GET /api/v1/errors`). The PKI routes answer with their own problem codes, not in the guide:
`pki_unavailable` (501), `prepare_failed`, `no_pending_ca`, `hosts_missing_ca`, `activate_failed`,
`ca_in_use` (all 409), `invalid_body` (400), `reason_required` (400), `reauthentication_required` (401).
