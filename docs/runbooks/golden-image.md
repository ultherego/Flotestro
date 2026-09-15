# Golden image and cloud-init

## Purpose

Build a machine image that carries the agent but no identity, so that every machine started
from it enrolls as a host of its own on its first boot. The same procedure sanitises a
snapshot taken from a running host before it becomes a template. What an image must not carry
follows from what the panel binds a host to:

- The host row is keyed by `machine_id` (unique index; `Upsert` in `internal/hosts` updates
  the row on conflict rather than creating a second one). The agent reads it at enrollment
  from `/etc/machine-id`, and when that file is missing or empty from
  `/var/lib/dbus/machine-id` (`MachineID` in `internal/agent/facts.go`); it goes into the
  enrollment request as `machine_id`, and an order with `expected_machine_id` matches no other.
- The identity of the host is one generation under
  `/var/lib/flotestro-agent/identity/generations/<serial>/` (`agent.key`, `agent.pem`,
  `trust-bundle.pem`) pointed at by `identity/current`. The daemon starts only when
  `identity/current/agent.pem` exists (`ConditionPathExists` in `flotestro-agent.service`),
  and `flotestro-enroll.service` runs only when it does not.
- A session is recognised by the certificate fingerprint. A clone is that fingerprint alive on
  another boot id from another address while the first session still heartbeats
  (`detectDuplicateIdentity` in `internal/gateway/agent_service.go`).

## Signals

- Dashboard (`GET /api/v1/fleet/summary`): `duplicate_identities_24h` ("a cloned machine or
  image"); `GET /metrics`: `flotestro_duplicate_identity_total{gateway}`.
- Audit: `security.duplicate_identity` (outcome `denied`, target the host, with
  `previous_boot_id`, `previous_addr`, `remote_addr`, `policy`, `quarantined`) for a copied
  identity; `host.enroll` with outcome `denied` and reason `duplicate_machine_id` or
  `machine_id_mismatch` for a copied machine id.
- The installation screen of an order: the certificate step with `error_code`
  `duplicate_machine_id` ("The machine is already in the fleet under another host; a new-host
  token does not fit it."); the token step with `machine_id_mismatch`.
- A host that went into quarantine by itself: `lifecycle_reason` "duplicate identity: the same
  certificate was alive on two boots at once", and `last_connection_refusal.code`
  `lifecycle_quarantined` on `GET /api/v1/hosts/{id}` (`hosts.last_connection_refusal_code`;
  `GET /api/v1/hosts?connection_refusal=lifecycle_quarantined` lists them).

## What a clone does to the fleet

| The image carried | On the second boot from it | Where it shows |
| --- | --- | --- |
| Nothing of the below | Two hosts, two keys, two certificate serials, one order with `uses` 2 | Two rows on the fleet list |
| `/etc/machine-id` (no identity) | The first clone enrolls and takes the machine id; the next is refused with `duplicate_machine_id` (`checkPurpose` in `internal/gateway/enrollment_service.go`: a new-host token does not fit a known, unretired machine). With `expected_machine_id` on a per-machine order the other clone is refused with `machine_id_mismatch` instead. | The order's certificate step; audit `host.enroll` denied; the token is not used up (the transaction rolls back) |
| `identity/**` | Two machines with one certificate: the second session is a duplicate identity. Under `FLOTESTRO_CLONE_POLICY` `quarantine` (the default) both sessions end and the host is quarantined; under `report` the newer session stands and the older is closed | `security.duplicate_identity`, the dashboard counter, the host's lifecycle card |
| `identity/pending.json` | The clone repeats the attempt of the template with the template's key and request id, and the panel answers with the certificate already issued for that attempt (`replay` in `internal/enrollment`: same `client_request_id` or same CSR digest); the result is the row above | As above |
| An enrollment token | Any machine with the image enrolls as long as the order lives (`max_uses`, `ttl_minutes`, at most 24 hours) | `host.enroll` from machines nobody ordered |

## Preconditions

- The image is built on a machine that has never enrolled, or on a host that is sanitised
  as below. `flotestro-agentctl identity reset` is not a sanitiser: it replaces the identity
  with a recovery token issued by the panel for one existing host (`cmd/agentctl/identity.go`)
  and leaves a working identity behind; do not run it on a template.
- The fleet CA bundle (`GET /api/v1/installation-profiles?kind=agent`, field `ca.pem`, or the
  `flotestro-ca.pem` next to the package repository) and the addresses for `agent.yaml`
  (`connection.enrollment_url`, `connection.gateway_urls`).
- For the cloud-init variant: a way to give every instance its own one-use token, or one batch
  order with `max_uses` set to the number of instances (an order with `max_uses` above 1 is a
  step-up operation with a `reason`). A token in user-data is a token in the platform's
  metadata and logs for good; the product has no attestation exchange, so the trusted fetch
  of the token is the platform's, not the agent's.

## Procedure

### What may be in the image

- The package: `/usr/bin/flotestro-agent`, `/usr/bin/flotestro-agentctl`, the units
  (`flotestro-agent.service`, `flotestro-enroll.service`, `flotestro-helper.socket`,
  `flotestro-helper.service`), sysusers and tmpfiles. The package enables
  `flotestro-agent.service` and `flotestro-helper.socket`; both may stay enabled, the agent
  does not start without an identity.
- `/etc/flotestro/agent.yaml` (`root:flotestro-agent`, `0640`) with `schema_version`,
  `connection.enrollment_url`, `connection.gateway_urls`, `connection.bootstrap_ca_file`,
  `agent.state_dir`, `agent.mode`. The site, environment and owner are not in the file: they
  come from the order.
- `/var/lib/flotestro-agent/ca.pem`: the fleet CA bundle (public), readable by
  `flotestro-agent`; the path in `bootstrap_ca_file` must be an ordinary file, not a symlink
  into a directory writable by others (`CheckBootstrapCA`).

### What must not be in the image

- `/var/lib/flotestro-agent/identity/` in full: `current`, `generations/*`, `pending.json`,
  `.current-next`, `.new-*`.
- The legacy layout from before the generation store: `/var/lib/flotestro-agent/agent.key`,
  `agent.pem` (the daemon accepts `agent.pem` there as an identity too).
- `/var/lib/flotestro-agent/tasks/` (the idempotency journal of executed tasks),
  `status.json` (the session record `flotestro-agentctl status` reads), `run/`.
- `/run/flotestro-bootstrap/enrollment-token` or a token in any other file, in `agent.env`
  or in user-data. `/etc/flotestro/agent.env` is optional and read for overrides only.
- A populated `/etc/machine-id`; `/var/lib/dbus/machine-id` when it is a file rather than a
  symlink, since the agent falls back to it.

### Sanitise before sealing

On the template machine, as root:

```sh
systemctl stop flotestro-agent.service flotestro-enroll.service
rm -rf /var/lib/flotestro-agent/identity \
       /var/lib/flotestro-agent/tasks \
       /var/lib/flotestro-agent/run \
       /var/lib/flotestro-agent/status.json \
       /var/lib/flotestro-agent/agent.key \
       /var/lib/flotestro-agent/agent.pem
rm -rf /run/flotestro-bootstrap
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id && ln -s /etc/machine-id /var/lib/dbus/machine-id
cloud-init clean --logs 2>/dev/null || true
```

`/var/lib/flotestro-agent/ca.pem` and `/etc/flotestro/agent.yaml` stay. The state directory
itself stays owned by `flotestro-agent` (`StateDirectory=` recreates it either way; the
enrollment refuses a state directory owned by anybody else). An empty `/etc/machine-id` is
what systemd fills in on the next boot; a distribution that wants the file absent instead
(`rm -f /etc/machine-id`) gets the same result. The product does not regenerate the machine
id and has no check of its own that it changed: that is the platform's first-boot work.

Check before the snapshot: `flotestro-agentctl status` prints `Identity: missing
(identity_missing)` and no `Pending:` line; `ls /var/lib/flotestro-agent` lists `ca.pem` and
nothing else. If the template was a host in the fleet, decommission it
(`POST /api/v1/hosts/{id}/decommission`, see the quarantine runbook): its machine id is
withheld from new enrollments for 30 days, and a clone that regenerated its own is unaffected.

### First boot with cloud-init

The enrollment unit reads the token as a systemd credential:
`LoadCredential=enrollment-token:/run/flotestro-bootstrap/enrollment-token`, and runs
`flotestro-agentctl enroll --config /etc/flotestro/agent.yaml --token-file
$CREDENTIALS_DIRECTORY/enrollment-token` as `flotestro-agent`. The file is read by systemd,
so it may stay `root:root 0600`; nothing in the package creates `/run/flotestro-bootstrap`, the
first-boot automation does. The unit has no `[Install]` section and is started explicitly.
In the example below `fetch-token` stands for the platform's trusted fetch of a one-use token
(a secret manager, an instance-identity exchange); the product ships no such command. Putting
the token into `write_files` works too, and leaves it in the instance's user-data.

```yaml
#cloud-config
# agent.yaml and ca.pem are in the image; this file only brings the token
# and starts the two services in the right order. A machine that already
# has an identity is guarded by the units themselves: the enroll unit does
# not start when identity/current/agent.pem exists, and the agent starts
# only when it does.
runcmd:
  - [install, -d, -m, '0700', /run/flotestro-bootstrap]
  # The platform's trusted fetch of a one-use token into the credential
  # file; "fetch-token" stands for it.
  - [sh, -c, 'umask 077 && fetch-token > /run/flotestro-bootstrap/enrollment-token']
  - [systemctl, start, flotestro-enroll.service]
  - [rm, -rf, /run/flotestro-bootstrap]
  - [systemctl, enable, --now, flotestro-helper.socket, flotestro-agent.service]
```

`flotestro-agentctl enroll` refuses a machine that already has a valid identity
(`machine_already_enrolled`) and repeats an unfinished attempt recorded in `pending.json`
rather than starting a new one; on success it prints `Registered: host/<id>` and the agent
service, whose condition now holds, starts. A refused token fails the unit with
`enrollment_token_invalid` in its output; the reason is on the order in the panel, not on
the machine.

### The Ansible alternative

`deploy/ansible/roles/flotestro_agent` does the same without cloud-init: it installs the
package, writes `ca.pem` and `agent.yaml`, and only when
`/var/lib/flotestro-agent/identity/current/agent.pem` is absent orders a token bound to the
machine (`expected_machine_id` read from `/etc/machine-id`, `max_uses: 1`,
`flotestro_enrollment_ttl_minutes`) and passes it to `flotestro-agentctl enroll` over
standard input, then enables and starts the agent. A clone that kept the template's machine
id gets a per-machine order that the panel refuses with `duplicate_machine_id` (the machine
is another host's), so the run fails on that machine rather than adopting it.

## Verification

- Start two instances from the image. `GET /api/v1/hosts` shows two rows with different
  `id`, `hostname` and `machine_id`; the order shows `uses` 2 and both `host.enroll` events
  carry different `cert_serial`.
- `GET /api/v1/fleet/summary`: `duplicate_identities_24h` did not grow; no
  `security.duplicate_identity` in `GET /api/v1/audit?action=security.duplicate_identity`.
- On an instance: `flotestro-agentctl status` shows `Identity: host/<id>` and a session;
  `flotestro-agentctl diagnose` no `fail`.
- The integration test `TestTwoClonesOfOneImageGetDistinctIdentities`
  (`tests/integration/clone_image_test.go`) enrolls two synthetic machines from one order and
  a third with the first one's machine id, and asserts the outcomes above; run it in CI after
  a change to the enrollment or the image build.

## Rollback/Recovery

- Two instances came up as one host (the image carried an identity): the host is quarantined
  under the default clone policy. Wipe the identity on both (the `rm` list above), decide
  which machine keeps the row, order an identity recovery for it and enroll the other as a new
  host; then rebuild the image. Under `report` only the audit entry and the counter say so,
  and the older session was closed by the epoch rule.
- A clone was refused with `duplicate_machine_id` (the image carried the machine id): the
  earlier clone owns the row. Regenerate the machine id on the refused one (the two commands
  above, then a reboot) and enroll it with a new order; nothing in the panel needs undoing,
  the refused order was not used up.
- A token leaked with the image: `POST /api/v1/enrollment-requests/{id}/revoke`; hosts already
  enrolled with it stay, and each is to be assessed. The order's `enrolled_host_id` names
  only the last of them; the audit trail read by `target_id` of the order names every use.

## Related codes

From the error guide: none of its own; `quarantined` (preflight) once a clone has put a host
into quarantine. Outside the guide: `duplicate_machine_id`, `machine_id_mismatch`,
`machine_id_retired`, `token_expired`, `token_revoked`, `enrollment_request_reused` (refusals
recorded on the order); `enrollment_token_invalid`, `machine_already_enrolled`,
`identity_missing` (the agent's tools); `security.duplicate_identity` (audit action);
`duplicate_identity` (session end reason and cancel reason); `lifecycle_quarantined` (gateway
refusal).
