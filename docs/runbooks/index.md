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
- [Samples stop arriving, or a chart has a hole](metrics-gap.md): the agent's spool, a
  delivery refused as too late, a rollup that has stopped, the lease of the alert
  evaluator, the daily partitions of the raw samples.
- [Quarantine, identity recovery and decommission](quarantine.md): the host lifecycle, the
  clone policy, release, `flotestro-agentctl identity reset`, the decommission handshake.
- [Support bundle](support-bundle.md): what a bundle carries and what it never carries,
  making one, `--verify` before sending it, and what to do when the scanner refuses to make one.
- [Golden image and cloud-init](golden-image.md): what an image may and must not carry, the
  sanitisation before sealing, the first-boot enrollment through `flotestro-enroll.service`
  and its credential file, the Ansible alternative, what a clone does to the fleet.

The checks a change has to pass before it reaches `main`, what each one proves and
what to do when one of them fails, are in [the continuous integration reference](../ci.md).
