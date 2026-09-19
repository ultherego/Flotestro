# Configuration reference

Every setting of a Flotestro binary is an environment variable read at
start, with a command-line flag of the same meaning that overrides it. The
packages put the variables in `/etc/flotestro/control-plane.env` for the
control plane and `/etc/flotestro/agent.env` for the agent; the hosts are
described by `/etc/flotestro/agent.yaml`, the relays by
`/etc/flotestro/relay.yaml`, and the variables of those two binaries are
overrides for an image or a test.

A change of any variable takes effect at the next start of the service:
nothing here is re-read while the process runs. The settings screen of the
panel shows the effective values with the secrets masked; the status screen
shows what the loops set up by them are doing.

Durations are written the way Go reads them: `30s`, `5m`, `8h`, `720h`. An
unreadable duration keeps the default rather than switching a safeguard
off.

## Control plane (`flotestro-control-plane`)

### Database and listeners

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_DATABASE_URL` | none, required | The PostgreSQL DSN. The database is the only source of truth. | yes | Carries the database password; the file is readable by root and the service account alone. |
| `FLOTESTRO_STATE_DIR` | `/var/lib/flotestro` | The state directory: the fleet CA, the keys of the secret store under `keys/`, the bootstrap token file. Checked against the installation record at every start; a missing key or a missing part of the CA stops the start with a named state instead of a fresh key or CA (see `docs/runbooks/db-restore.md`). | yes | Holds the CA key and the store keys; nothing else may read it. |
| `FLOTESTRO_ADMIN_ADDR` | `127.0.0.1:8080` | The REST API and the web panel. | yes | Plain HTTP; expose it through a reverse proxy with TLS. |
| `FLOTESTRO_GATEWAY_ADDR` | `:8443` | The agent gateway (mTLS). | yes | |
| `FLOTESTRO_ENROLLMENT_ADDR` | `:8444` | The enrollment endpoint (TLS, no client certificate). | yes | Answers strangers; a request is bounded to 256 KiB. |
| `FLOTESTRO_ADVERTISE` | `127.0.0.1` | The addresses and names the agents see the panel under, comma separated. They enter the gateway certificate and are reserved: no relay may carry one of them. | yes | A panel left at the loopback serves no fleet and says so at start. |
| `FLOTESTRO_PUBLIC_URL` | empty | The panel address as the browser sees it; the OIDC redirect and the Secure flag of the cookies follow from it. | yes | |
| `FLOTESTRO_PACKAGE_REPOSITORY_URL` | empty | The base address of the signed package repository the "Add host" instructions point at; in an isolated site, the package-repository image of the air-gapped profile. It is the address the hosts reach, not a Compose service name. | yes | |
| `FLOTESTRO_WEB_ROOT` | empty | The directory with the built panel; empty serves the API alone. | yes | |
| `FLOTESTRO_GATEWAY_ID` | the hostname | The name of this gateway in a multi-gateway installation; sessions and leases are tagged with it. | yes | |

### Agents

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_HEARTBEAT_SECONDS` | `60` | The base heartbeat interval handed to the agents. | yes | |
| `FLOTESTRO_HEARTBEAT_JITTER` | `30` | The random spread added to the heartbeat. A host is stale after three missed heartbeats of the sum. | yes | |
| `FLOTESTRO_AGENT_CERT_TTL` | `720h` | The lifetime of an agent certificate; the agent renews after two thirds. | yes | A shorter term narrows the window of a stolen key. |
| `FLOTESTRO_DISPATCH_RATE` | `100` | Task envelopes sent per second, with a burst of one second's worth; `0` sends every leased task at once. Held-back tasks are counted in `flotestro_dispatch_throttled_total`. | yes | |
| `FLOTESTRO_CLONE_POLICY` | `quarantine` | What the gateway does with the same identity alive on two boots: `quarantine` ends both sessions and quarantines the host, `report` records the incident and lets the newer session stand. Any other word refuses to start. | yes | `report` lets a cloned key act until somebody looks. |
| `FLOTESTRO_RELAY_IDENTITY` | `prefer` | What the gateway does with a session through a relay in which the host did not sign its own identity envelope (`relay.identity` v2). A signed envelope is verified under every mode - relay, host, certificate by serial, site and environment, payload digest, signature, sequence - and marks the host `relay_identity: end_to_end` (`flotestro_relay_session_identity_total{strength="end_to_end"}`, `auth_strength: end_to_end` on the session); a bad envelope is refused under every mode with `relay_envelope_invalid`, `relay_body_hash_mismatch`, `relay_sequence_replayed` or `relay_host_signature_invalid` on the host. Without an envelope, `observe` and `prefer` let the session in on the relay's attestation (`attested`) or word alone (`weak`), counted under those strengths and recorded as `auth_strength: relay_only`. `enforce` refuses a relay that names the host alone with `relay_identity_missing`, and an agent that does not sign behind a relay that attests with `blocked_upgrade_required`. A renewal or a secret fetch through a relay requires the envelope under every mode. Any other word refuses to start. | yes | Upgrade the panel, then the relays, then the agents; set `enforce` once `weak` and `relay_only` sessions are at zero. |

### Lifecycle orders between instances

A host is connected to exactly one control-plane instance, and an operator's
request lands on whichever instance answered the browser. Most decisions are
rows and travel by themselves; the work that needs the host's open stream -
the final task of a decommission, the end of a session at a quarantine or an
identity recovery - does not. That work is written as an order in
`gateway_commands`, addressed to the session `host_session_owners` names at
the moment of the decision and to the fencing token of that claim, and the
instance holding exactly that session carries it out. An instance that has
since lost the host claims nothing, and an order whose session is gone is
never carried out: it says so, and the panel falls back to what it does for
a host nobody holds - retiring it with `remote_cleanup_unconfirmed`.

The loop runs on every instance and is woken by the trail, so an order
normally reaches its owner within a round trip; the settings below are the
floor under that. An installation with one instance never writes an order at
all and is unaffected by them.

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_COMMAND_POLL` | `5s` | How often an instance looks for orders addressed to the sessions it holds when the trail's notification did not reach it. The same tick settles the orders that expired. | yes | |
| `FLOTESTRO_COMMAND_EXPIRY` | `5m` | How long an unclaimed order stands. Longer than the lease of an ownership claim, so an instance that is merely slow still takes it; past it the order is settled as `expired` and nothing was done to the host. A decision acted on long after it was taken is worse than one repeated by the operator. | yes | Shortening it below the ownership lease (45s) would retire hosts as unreachable while their instance is still talking to them. |

The request that gave the order waits up to 60 seconds for the answer. A
decommission the owner has not finished by then is answered with phase
`handover_pending`: the host stands in `retiring`, the owning instance
finishes the handshake, and the decision is never taken twice.

### Local accounts and their SSH keys

One list of privileged groups is read by every binary that judges a local
account - the control plane, the agent and the helper - so that the panel
calls privileged exactly what the host does. The same goes for the UID
range that tells a person's account from a service's: it comes from the
host's `/etc/login.defs` and is not a setting of the panel.

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_ACCOUNTS_PRIVILEGED_GROUPS` | `sudo,wheel,docker,lxd` | The groups whose membership is root by another name: sudo and wheel give root directly, docker and lxd through the engine socket. An order that creates an account in one of them, or moves an account into one, ranks critical: it needs the permission `accounts.privileged_groups` in the host's scope beside the operation's own, fresh authentication with a reason, and an approval. The names are separated by commas or spaces, lowercased and deduplicated; an empty value leaves the default, because an installation that set nothing did not mean that no group is privileged. | yes | Taking a group off the list does not take away the rights it grants - it takes away the gate in front of granting them. Add the groups your installation uses (`admin`, `adm`, `systemd-journal`) rather than shortening the list. The permission itself is the platform administrator's alone: the identity administrator makes accounts and keys, and putting one into a privileged group is the other half of the decision. |

The keys of an account are edited one key at a time - an add appends, a
removal names fingerprints, a replace carries the list the operator saw and
is refused as stale when the account has changed in between - and each
order edits one file. By default that is the user's own
`~/.ssh/authorized_keys`, which is also where a key of a newly created
account goes.

An order may instead name the panel's managed file,
`/etc/ssh/authorized_keys.d/<account>/60-flotestro.keys`: root-owned,
world-readable, and beyond the reach of the user, so the panel's keys stay
apart from the ones the user wrote and a replace there touches nothing
anybody else put on the host. The file is only written when sshd says it
reads it: the effective configuration (`sshd -T`) has to carry
`/etc/ssh/authorized_keys.d/%u/60-flotestro.keys` in `AuthorizedKeysFile`,
otherwise such an order is refused with `managed_file_not_read` rather than
writing keys that open nothing. The panel shows, for every key, which of
the two files it came from.

### Identity provider and browser sessions

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_OIDC_ISSUER` | empty | The OIDC issuer, e.g. `https://ipa:8081/realms/flotestro`. Empty disables browser login; the panel then works on API tokens. | yes | |
| `FLOTESTRO_OIDC_CLIENT_ID` | `flotestro-panel` | The OIDC client identifier. | yes | |
| `FLOTESTRO_OIDC_CLIENT_SECRET` | empty | The OIDC client secret. | yes | Secret; the settings screen shows only whether it is set. |
| `FLOTESTRO_OIDC_GROUPS_CLAIM` | `groups` | The field of the token with the list of groups the role mappings read. | yes | |
| `FLOTESTRO_OIDC_ADMIN_LOGOUT` | `false` | Also end a disabled user's sessions at the provider through the Keycloak admin API; needs a service account with `view-users` and `manage-users`. | yes | The local denial holds without it. |
| `FLOTESTRO_SESSION_IDLE` | `8h` | How long a browser session survives without a request; between `1m` and the absolute limit of 24 hours. | yes | |
| `FLOTESTRO_SESSION_GROUP_REFRESH` | `5m` | How often the groups of a live session are confirmed with the provider; `0` turns it off, otherwise between `1m` and 24 hours. | yes | Off, a membership taken away reaches the session only at its next login. |
| `FLOTESTRO_STEPUP_MAX_AGE` | `5m` | The acceptable age of an authentication for the operations of the greatest impact. | yes | |
| `FLOTESTRO_STEPUP_ACR` | empty | The required authentication level (acr) for those operations; empty leaves only the freshness condition. | yes | |
| `FLOTESTRO_STEPUP_TOKENS` | `allow` | Whether an API token may carry those operations out: `allow` or `refuse`. | yes | `refuse` puts a person with fresh authentication behind every such change. |
| `FLOTESTRO_PRODUCTION_ENVIRONMENTS` | `prod,production` | The environments where a change needs a second person's approval. | yes | |

### Directory connector (FreeIPA)

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_IPA_URL` | empty | The FreeIPA server, e.g. `https://ipa.example.org`. Empty disables the directory module. `FLOTESTRO_IPA_SERVER` is read as a fallback. | yes | |
| `FLOTESTRO_IPA_PRINCIPAL` | empty | The service principal of the connector; the connector starts only with both the server and the principal. | yes | |
| `FLOTESTRO_IPA_KEYTAB` | `/etc/flotestro/ipa.keytab` | The keytab of the connector. | yes | Must be mode 600 and owned by root or the service user, or the panel refuses to start. |
| `FLOTESTRO_IPA_CA_CERT` | `/etc/flotestro/ipa-ca.crt` | The CA certificate the connector verifies the server with. | yes | |
| `FLOTESTRO_IPA_REALM` | empty | The Kerberos realm of the directory. | yes | |
| `FLOTESTRO_DIRECTORY_WRITE` | `false` | Enables directory changes from the panel; by default it only reads. | yes | |

### Notifications (webhook)

The webhook of the environment file is the implicit channel of the
installation: one address, every event of the durable trail, configured
here rather than in the panel. The channels an administrator writes in
the panel are a second consumer of the same trail, with a cursor of their
own, and are not configured by variables at all - an address, the
subjects it carries and the part of the fleet it speaks for are records
of the panel, written with a reason and kept in the audit trail.

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_WEBHOOK_URL` | empty | Where the events of the durable trail are posted in batches; empty disables the webhook. | yes | |
| `FLOTESTRO_WEBHOOK_SECRET` | empty | The HMAC-SHA256 secret the deliveries are signed with. | yes | Secret; without it the deliveries are not verifiable and the panel warns at start. |
| `FLOTESTRO_WEBHOOK_EVENTS` | empty | The prefixes of the event types to deliver, comma separated, e.g. `campaign.`; empty delivers every event. | yes | |

### Notification queue

A message to a channel is a durable row, not a call. The router writes
one row per event and channel in the transaction of the event; the worker
of every panel instance claims the rows that are due, sends them under a
lease and settles them. A receiver that is down therefore delays a
message rather than losing it: the row waits, the attempts are counted on
it, and a row whose attempts ran out - or whose receiver refused the
credentials - becomes a dead letter an operator sends again from the
panel. Two instances never send the same row at once, and a row whose
worker died is reclaimed when its lease runs out.

The settings below tune that worker. They are the same on every instance;
raising the batch or lowering the poll makes the queue quicker and the
database busier, and a fleet with few channels has no reason to touch
them.

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_NOTIFY_POLL` | `2s` | How often a worker looks for rows that are due when nothing woke it. A row written by the router, and a dead letter an operator put back, wake the worker of that instance at once, so this is the floor for the other instances rather than the usual delay. | yes | |
| `FLOTESTRO_NOTIFY_BATCH` | `50` | How many rows one claim takes. A round that fills its batch is followed by another at once, so this bounds one transaction rather than the pace. | yes | |
| `FLOTESTRO_NOTIFY_MAX_ATTEMPTS` | `20` | How many attempts a row gets before it is a dead letter. With the backoff below that is about a day of a receiver being down. A 401 or 403 from the receiver, and a mail relay that refuses the login, are dead letters at the first attempt whatever this says: another attempt with the same credential cannot help. | yes | |
| `FLOTESTRO_NOTIFY_BACKOFF_BASE` | `30s` | The pause before the second attempt. Each attempt after it doubles the pause, drawn with full jitter - a uniform draw between nothing and the doubled pause - so a thousand rows that failed together do not come back together. | yes | |
| `FLOTESTRO_NOTIFY_BACKOFF_MAX` | `1h` | The ceiling of that pause. | yes | |
| `FLOTESTRO_NOTIFY_LEASE` | `30s` | How long a claimed row is one worker's. The lease is renewed while a send runs, so a slow receiver does not hand the row to a second worker; a worker that died holds its rows only until the lease runs out. | yes | |

Settled rows - delivered and suppressed - are swept after thirty days. A
row that still waits is never swept: a dead letter is an operator's to
settle, however old.

### Notification channel credentials

A credential never lies in a channel record. The address of an incoming
webhook (it carries the token that lets anybody post to the room), the
key a webhook is signed with and the password of a mailbox are versions
of the panel's secret store, named `panel.notification.<channel id>`.
They go there the moment they are typed, are read only at the moment of
sending, and the API answers with `secret_configured` and
`secret_last_rotated_at` in their place - never the value, not even to a
platform administrator.

What follows from that, on the API and on the screen:

- An edit that leaves the secret field empty keeps the stored credential;
  the form says which channels have one and when it was last replaced. A
  webhook's signing key is cleared by asking for it explicitly, and an
  incoming webhook cannot be left without an address at all.
- `GET /api/v1/notifications/channels/{id}` carries no address for an
  incoming webhook. Beside the configuration it carries `public_config`,
  a summary with the host of the address and nothing of the path, so a
  mistyped receiver is told from the right one without showing the token.
- The scheduler refuses to issue a secret under the
  `panel.notification.` prefix to a host: a credential of the panel is
  not a task's to carry.
- Channels written by a release before this one kept their credentials in
  the configuration column. They are moved into the secret store once, at
  the first start of the panel after the upgrade, and the move is
  recorded with its count; it is idempotent, so a second start moves
  nothing. A panel of the previous release started against the same
  database still reads the configuration column and sends nothing for a
  moved channel - which is the intent: a credential is not left where the
  older release could read it.

### Vulnerability feeds

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_VULN_ENABLED` | `true` | Enables the correlator based on the distribution trackers. | yes | |
| `FLOTESTRO_VULN_SYNC_INTERVAL` | `30m` | How often the panel asks the trackers about changes. | yes | |
| `FLOTESTRO_VULN_MAX_SNAPSHOT_AGE` | `6h` | The age above which a feed is described as stale next to every assessment. | yes | |
| `FLOTESTRO_VULN_DEBIAN_URL` | `https://security-tracker.debian.org/tracker/data/json` | The Debian tracker dump (`https://` or `file://`); empty disables the source. | yes | |
| `FLOTESTRO_VULN_UBUNTU_URL` | `https://security-metadata.canonical.com/oval/` | The directory with the OVAL data of Canonical (`https://` or `file://`); empty disables the source. | yes | |
| `FLOTESTRO_VULN_REDHAT_URL` | `https://security.access.redhat.com/data/csaf/v2/vex/` | The directory with the CSAF/VEX data of Red Hat (`https://` or `file://`); empty disables the source. | yes | |
| `FLOTESTRO_VULN_REDHAT_CACHE` | `/var/lib/flotestro/vuln/redhat` | Where the Red Hat findings read so far are kept between cycles. | yes | |
| `FLOTESTRO_VULN_NVD_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | The NVD API for the descriptions and scores; empty disables the enrichment, which is what an isolated site sets - NVD has no offline form. NVD settles nothing about a host. | yes | |
| `FLOTESTRO_VULN_NVD_KEY` | empty | The NVD API key; without it the first read takes around twenty minutes. | yes | Secret; the settings screen shows only whether it is set. |
| `FLOTESTRO_VULN_NVD_INTERVAL` | `6h` | How often the descriptions are refreshed. | yes | |
| `FLOTESTRO_VULN_SHRINK_SHARE` | `0.4` | How much of the snapshot in force a fetch may lose and still be activated. A fetch that loses more, or that stops covering a release the snapshot in force covered, is not activated: it is kept as a candidate with the reason `feed_shrank` or `feed_release_missing`, the previous snapshot stays in force and ages into stale, and an operator accepts the candidate deliberately from the Vulnerabilities screen (`POST /api/v1/vulnerabilities/snapshots/{id}/accept`, with a reason and on the audit trail). A value outside `0 < share < 1` falls back to the default, so a mistyped setting cannot switch the gate off; `0` means the default. | yes | Towards `0` the gate refuses ordinary movement at the vendor and trains the operator to accept without reading; towards `1` only an empty feed is refused. |

### Monitoring and retention

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_METRICS_RETENTION_RAW` | `168h` (7 days) | How long the raw resource samples of the hosts are kept. The raw samples live in one partition per day and the retention drops whole partitions, so a longer window costs storage rather than a sweep that holds the database. A partition that still owes a rollup is kept past its day; the status block counts what is owed. | yes | |
| `FLOTESTRO_METRICS_RETENTION_ROLLUP` | `2160h` (90 days) | How long the quarter-hour rollups are kept. This is the window a capacity trend is read over. | yes | |
| `FLOTESTRO_RELAY_BUFFER_RETENTION_RAW` | `168h` (7 days) | How long the raw buffer reports of the relays are kept. A relay reports once a minute, so this is the window that answers "was this site cut off last night" minute by minute. Plain rows with a delete sweep, not daily partitions: a fleet of relays is three orders of magnitude smaller than a fleet of hosts. `0` means the default. | yes | |
| `FLOTESTRO_RELAY_BUFFER_RETENTION_ROLLUP` | `2160h` (90 days) | How long the quarter-hour rollups of the relay buffer reports are kept. This is the window that answers "has this spool been filling for a month", and it also bounds how long a resolved relay buffer alert stays as history. `0` means the default. | yes | |
| `FLOTESTRO_METRICS_MAX_LATENESS` | `24h` | How long after it was taken a sample may still arrive and be stored. A relay whose link to the centre was down drains its spool and every reading lands in the chart it belongs to; anything older is answered `metric_sample_too_old`, is not stored, and leaves a gap with a reason instead of a line drawn through it. The agent drops such a sample from its own spool. | yes | |
| `FLOTESTRO_METRICS_QUERY_WINDOW` | `24h` | How far back the panel promises full resolution. It is what the retention is validated against, not a limit on the chart ranges. | yes | |
| `FLOTESTRO_METRICS_CLOCK_SKEW` | `5m` | How far ahead of the panel a host's clock may be before its sample is stamped with the panel's time. Only the future direction is corrected: a sample from the past may simply have waited in a spool, and restamping it would turn a relay's backlog into a wall of identical points. A sample is identified by its boot and its sequence, never by its clock, so a correction here changes where a point is drawn and never which sample it is. | yes | |
| `FLOTESTRO_METRICS_PARTITIONS_AHEAD` | `3` | How many days of raw partitions exist ahead of today. An insert into a day no partition covers is an error, so this is how many days the maintenance loop may fail to run without a fleet losing its samples. At most 60. | yes | |
| `FLOTESTRO_METRICS_EVALUATOR_LEASE` | `45s` | How long one control-plane instance holds the right to evaluate the alert rules. An instance that finds the lease held evaluates nothing; one that loses it mid-pass stops where it is (`alert_evaluator_lease_lost`) and the new holder carries on from the open episodes. Three renewals fit in the term. | yes | |
| `FLOTESTRO_AUDIT_RETENTION` | `0` | How long the audit trail is kept; `0` keeps it forever. The trail is evidence: deleting it is a decision of the installation. | yes | Set it only when the trail is kept elsewhere. |
| `FLOTESTRO_JOB_RETENTION` | `2160h` (90 days) | How long finished jobs are kept with their attempts. A job of a campaign stays as long as the campaign; a job under way is never deleted. `0` means the default. | yes | |
| `FLOTESTRO_CAMPAIGN_RETENTION` | `8760h` (a year) | How long finished campaigns are kept with their targets, steps, plans and approvals. A campaign under way, or one another campaign retries or compensates, is never deleted. `0` means the default. | yes | |
| `FLOTESTRO_OUTBOX_RETENTION` | `720h` (30 days) | How long the delivered events of the durable trail are kept. An event a webhook consumer has not taken yet stays whatever its age. `0` means the default. | yes | |
| `FLOTESTRO_SECRETS_KEY_FILE` | `<state dir>/secrets.key` | The key file of a secret store from before the key provider. At the first start after the upgrade it is adopted as `keys/legacy.key` and becomes the active key `legacy`; a new installation never has one. | yes | Keep it in the backup set until the key `legacy` is retired. The panel never generates it. |
| `FLOTESTRO_SECRETS_KEY_CREDENTIAL` | empty | The name of a systemd credential (`LoadCredential=<name>:<file>` in the unit) that holds a key of the secret store under that key id; read from `$CREDENTIALS_DIRECTORY`, never written. | yes | A credential is narrower than a file of the state directory: no other process sees it. |
| `FLOTESTRO_SECRETS_KEY_ROTATE_TO` | empty | The id of the key the secret store switches to at this start (`k-...`, lowercase letters, digits, dashes). Created under `keys/` when missing; the versions of the store are rewrapped in the background and the old key stays until none of them names it. A no-op once that key is active. | yes | Remove the old key only when the status block shows `pending_rewrap: 0`. |

The sweep runs once an hour, five thousand rows of a kind at a time, and
the ended agent sessions are swept after thirty days regardless of any
setting.

**The panel refuses to start** when `FLOTESTRO_METRICS_RETENTION_RAW` is shorter than
`FLOTESTRO_METRICS_QUERY_WINDOW` plus `FLOTESTRO_METRICS_MAX_LATENESS`
(`metrics_retention_too_short`). Such a configuration deletes a reading a relay is still
carrying, by definition and without anybody ordering it; raise the retention or lower the
window or the lateness.

The agent keeps the samples the panel has not acknowledged in
`<state dir>/metrics-spool`: at most 240 of them, four hours at one a minute, one small file
each. A sample is written there before it is sent and deleted only when the panel answers
that very sample; on reconnect the agent sends what was never answered, oldest first. Past
the bound the oldest is dropped - a panel that has been away for a week costs the host four
hours of readings, not a week of them. There is no setting: the bound is what the agent may
cost a host.

## Agent (`flotestro-agent`)

The host is described by `/etc/flotestro/agent.yaml`. The variables below
override the file when set; leave them empty for the file to decide. The
daemon does not enroll: `FLOTESTRO_ENROLLMENT_TOKEN` in its environment is
ignored and reported at every start until it is removed.

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_AGENT_CONFIG` | `/etc/flotestro/agent.yaml` | The configuration file of the agent. | yes | |
| `FLOTESTRO_AGENT_STATE_DIR` | `/var/lib/flotestro-agent` | The state directory: the identity, the certificate, the result buffer. | yes | Holds the host key. |
| `FLOTESTRO_ENROLLMENT_URL` | from the file | The enrollment endpoint of the panel or of a relay. | yes | |
| `FLOTESTRO_GATEWAY_URL` | from the file | The agent gateway; it replaces the whole list of the file. | yes | |
| `FLOTESTRO_CA_FILE` | from the file | The CA bundle for bootstrapping the trust. | yes | |
| `FLOTESTRO_INVENTORY_MINUTES` | `15` | The interval of a full inventory. | yes | |
| `FLOTESTRO_MAX_CONCURRENT_TASKS` | `2` | The limit of concurrent jobs on the host. | yes | |
| `FLOTESTRO_HELPER_SOCKET` | `/run/flotestro/helper.sock` | The socket of the root helper. | yes | |
| `FLOTESTRO_AGENT_MODE` | from the file | `full` or `read_only`. | yes | A read-only agent reports and changes nothing. |

`flotestro-agentctl enroll` reads `FLOTESTRO_ENROLLMENT_TOKEN`,
`FLOTESTRO_ENROLLMENT_URL`, `FLOTESTRO_GATEWAY_URL` and `FLOTESTRO_CA_FILE`
from the agent environment file when migrating a host set up before
`agent.yaml`; the token is a one-time secret and belongs in the operator's
command or a file with narrow permissions, not in a file that survives
package updates.

## Agent helper (`flotestro-agent-helper`)

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_HELPER_SOCKET` | `/run/flotestro/helper.sock` | The socket path when there is no socket activation. | yes | |
| `FLOTESTRO_AGENT_USER` | `flotestro-agent` | The user allowed to issue commands over the socket. | yes | Anybody else on the socket is refused. |
| `FLOTESTRO_HELPER_IDLE_SECONDS` | `300` | The idle time after which the helper exits; systemd starts it again on the next command. | yes | |
| `FLOTESTRO_HELPER_CONFIG` | `/etc/flotestro/helper.yaml` | The helper's own file, optional: `capabilities.mode`, `capabilities.trusted_keys_dir`, `capabilities.replay_dir`, `identity.host_id_file`. The file belongs to root, so a compromised agent cannot lower what it says. | yes | |
| `FLOTESTRO_HELPER_CAPABILITY_MODE` | `prefer` | What the helper does with a request that changes the host. Every such request is meant to carry a capability the panel signed for exactly this host, task, action and payload. `observe` runs a request without one or with a bad one and logs it; `prefer` runs a request without one (an agent from before the capability) but refuses a bad one; `enforce` refuses a request without one with `capability_required`. Reads never need a capability. | yes | Set `enforce` on every host once the panel's `flotestro_helper_capability_total{outcome="legacy_agent"}` stays at zero. |
| `FLOTESTRO_HELPER_TRUST_DIR` | `/etc/flotestro/helper-trust.d` | The panel's capability keys, one `<key_id>.pub` each, root-owned. Filled from the panel's signed bundle at enrollment and at every session; the first bundle is taken on trust only while the helper has neither a key nor a host identity. | yes | A key file that is not root's or is writable by others is not a key. |
| `FLOTESTRO_HELPER_REPLAY_DIR` | `/var/lib/flotestro-helper/replay` | Where the helper remembers the nonce of every capability it ran, so the same capability cannot run twice. | yes | |
| `FLOTESTRO_HELPER_FILE_VERSION_DIR` | `/var/lib/flotestro-helper/files` | Where the host keeps the content of a managed configuration file from before each write, so a return to a version has something exact to put back. One directory per file, named by the digest of its path. | yes | Root's own directory, 0700, every copy 0600: a copy holds what the file held, including a value that came from the secret store, so it is readable by exactly whom the file was readable by. |
| `FLOTESTRO_HELPER_FILE_VERSIONS` | `10` | How many copies of one file the host keeps. The oldest goes when the next is made. | yes | |
| `FLOTESTRO_HELPER_FILE_VERSION_BYTES` | `33554432` | The size of the whole store in bytes. Above it the oldest copies go, across all files - one file rewritten with megabytes stays inside its own count and would still fill the partition the helper's state lives on. | yes | |
| `FLOTESTRO_HELPER_HOST_ID_FILE` | `/var/lib/flotestro-helper/host-id` | The host identifier the helper answers to; a capability for another host is refused. `flotestro-agentctl helper-trust show` prints it with the keys, and `helper-trust reset --confirm <hostname>` (as root) forgets both for a host enrolled anew with a panel the helper does not know. | yes | |

The store of file versions is what `file.rollback` restores from. A write
copies the content it is about to replace into it before the rename, and a
write that cannot make that copy - a full partition, a file larger than the
module's one-megabyte boundary - refuses with `file_version_not_kept`
instead of making a change nothing can undo. The host reports what it keeps
with the files fragment of the inventory, so the panel offers a content to
go back to rather than asking for a checksum; a copy whose content came
from the secret store is reported without its checksum and therefore cannot
be ordered back from the panel, because naming it would put a fingerprint
of a secret value in the panel's database. A return names one version by
its checksum: a checksum this host never kept is refused with
`file_version_unknown` rather than answered with the newest copy, and the
restored content goes through the same staging and the same validator as
any other write - a version the service no longer accepts is refused, not
written back.

## Relay (`flotestro-relay`)

The relay is described by `/etc/flotestro/relay.yaml`; `flotestro-relay
config show` prints what follows from it. One variable is read, by the
`enroll` command alone:

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_ENROLLMENT_TOKEN` | empty | The enrollment token, when neither `--token-file` nor the standard input carries it. | not applicable | A one-time secret: pass it by file or stdin rather than leave it in the environment. |
