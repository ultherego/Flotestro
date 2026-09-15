# Runbooks

Procedures for the operations the panel does not do by itself. Each one names the signals
that call for it, the preconditions, the exact requests and commands, how to verify the
result, and how to go back; the codes at the end are the entries of the error guide
(`GET /api/v1/errors`) that the procedure produces or reads. Where the product offers no
route or command for a step, the runbook says so rather than describing one.

- [CA rotation](ca-rotation.md): prepare, activate and retire a fleet CA; the trust-anchor
  campaign for hosts' own trust stores; rollback of a prepared CA.
- [Database restore](db-restore.md): what the database holds and what lives in
  `FLOTESTRO_STATE_DIR`, backup with `pg_dump`, the restore drill, in-flight jobs after a restore,
  the audit chain check with `flotestro-auditverify`.
- [Queue backlog](queue-backlog.md): budgets, the dispatch rate, lock waits and offline hosts;
  raising a budget under `If-Match`; pausing and cancelling a campaign.
- [Relay buffer full and relay disk full](relay-disk-full.md): the in-memory buffer and
  `buffer_max_bytes`, what is dropped, `flotestro-relayctl`, re-enrollment of a relay.
- [Quarantine, identity recovery and decommission](quarantine.md): the host lifecycle, the
  clone policy, release, `flotestro-agentctl identity reset`, the decommission handshake.
