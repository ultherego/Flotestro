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
| `FLOTESTRO_STATE_DIR` | `/var/lib/flotestro` | The state directory: the fleet CA, the secret store key, the bootstrap token file. | yes | Holds the CA key; nothing else may read it. |
| `FLOTESTRO_ADMIN_ADDR` | `127.0.0.1:8080` | The REST API and the web panel. | yes | Plain HTTP; expose it through a reverse proxy with TLS. |
| `FLOTESTRO_GATEWAY_ADDR` | `:8443` | The agent gateway (mTLS). | yes | |
| `FLOTESTRO_ENROLLMENT_ADDR` | `:8444` | The enrollment endpoint (TLS, no client certificate). | yes | Answers strangers; a request is bounded to 256 KiB. |
| `FLOTESTRO_ADVERTISE` | `127.0.0.1` | The addresses and names the agents see the panel under, comma separated. They enter the gateway certificate and are reserved: no relay may carry one of them. | yes | A panel left at the loopback serves no fleet and says so at start. |
| `FLOTESTRO_PUBLIC_URL` | empty | The panel address as the browser sees it; the OIDC redirect and the Secure flag of the cookies follow from it. | yes | |
| `FLOTESTRO_PACKAGE_REPOSITORY_URL` | empty | The base address of the signed package repository the "Add host" instructions point at. | yes | |
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

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_WEBHOOK_URL` | empty | Where the events of the durable trail are posted in batches; empty disables the webhook. | yes | |
| `FLOTESTRO_WEBHOOK_SECRET` | empty | The HMAC-SHA256 secret the deliveries are signed with. | yes | Secret; without it the deliveries are not verifiable and the panel warns at start. |
| `FLOTESTRO_WEBHOOK_EVENTS` | empty | The prefixes of the event types to deliver, comma separated, e.g. `campaign.`; empty delivers every event. | yes | |

### Vulnerability feeds

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_VULN_ENABLED` | `true` | Enables the correlator based on the distribution trackers. | yes | |
| `FLOTESTRO_VULN_SYNC_INTERVAL` | `30m` | How often the panel asks the trackers about changes. | yes | |
| `FLOTESTRO_VULN_MAX_SNAPSHOT_AGE` | `6h` | The age above which a feed is described as stale next to every assessment. | yes | |
| `FLOTESTRO_VULN_DEBIAN_URL` | `https://security-tracker.debian.org/tracker/data/json` | The Debian tracker dump (`https://` or `file://`); empty disables the source. | yes | |
| `FLOTESTRO_VULN_UBUNTU_URL` | `https://security-metadata.canonical.com/oval/` | The directory with the OVAL data of Canonical; empty disables the source. | yes | |
| `FLOTESTRO_VULN_REDHAT_URL` | `https://security.access.redhat.com/data/csaf/v2/vex/` | The directory with the CSAF/VEX data of Red Hat; empty disables the source. | yes | |
| `FLOTESTRO_VULN_REDHAT_CACHE` | `/var/lib/flotestro/vuln/redhat` | Where the Red Hat findings read so far are kept between cycles. | yes | |
| `FLOTESTRO_VULN_NVD_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | The NVD API for the descriptions and scores; empty disables the enrichment. NVD settles nothing about a host. | yes | |
| `FLOTESTRO_VULN_NVD_KEY` | empty | The NVD API key; without it the first read takes around twenty minutes. | yes | Secret; the settings screen shows only whether it is set. |
| `FLOTESTRO_VULN_NVD_INTERVAL` | `6h` | How often the descriptions are refreshed. | yes | |

### Monitoring and retention

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_METRICS_RETENTION_RAW` | `48h` | How long the raw resource samples of the hosts are kept. | yes | |
| `FLOTESTRO_METRICS_RETENTION_ROLLUP` | `720h` | How long the quarter-hour rollups are kept. | yes | |
| `FLOTESTRO_AUDIT_RETENTION` | `0` | How long the audit trail is kept; `0` keeps it forever. The trail is evidence: deleting it is a decision of the installation. | yes | Set it only when the trail is kept elsewhere. |
| `FLOTESTRO_JOB_RETENTION` | `2160h` (90 days) | How long finished jobs are kept with their attempts. A job of a campaign stays as long as the campaign; a job under way is never deleted. `0` means the default. | yes | |
| `FLOTESTRO_CAMPAIGN_RETENTION` | `8760h` (a year) | How long finished campaigns are kept with their targets, steps, plans and approvals. A campaign under way, or one another campaign retries or compensates, is never deleted. `0` means the default. | yes | |
| `FLOTESTRO_OUTBOX_RETENTION` | `720h` (30 days) | How long the delivered events of the durable trail are kept. An event a webhook consumer has not taken yet stays whatever its age. `0` means the default. | yes | |
| `FLOTESTRO_SECRETS_KEY_FILE` | `<state dir>/secrets.key` | The key of the secret store. | yes | Without a copy of the file the secrets cannot be recovered; the panel generates one at first start and warns. |

The sweep runs once an hour, five thousand rows of a kind at a time, and
the ended agent sessions are swept after thirty days regardless of any
setting.

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

## Relay (`flotestro-relay`)

The relay is described by `/etc/flotestro/relay.yaml`; `flotestro-relay
config show` prints what follows from it. One variable is read, by the
`enroll` command alone:

| Variable | Default | Meaning | Restart | Security |
|---|---|---|---|---|
| `FLOTESTRO_ENROLLMENT_TOKEN` | empty | The enrollment token, when neither `--token-file` nor the standard input carries it. | not applicable | A one-time secret: pass it by file or stdin rather than leave it in the environment. |
