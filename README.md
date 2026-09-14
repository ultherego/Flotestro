# Flotestro

Flotestro is a control plane for fleets of Linux servers. It consists of a central
service written in Go, a web panel written in TypeScript and React, an unprivileged
agent with a root helper on every managed host, and an optional relay for sites without
a direct route to the centre. Changes are expressed as typed operations, planned on the
host, approved in the panel, carried across the fleet in waves, verified afterwards and
recorded in an append-only, hash-chained audit trail.

## Overview

Flotestro addresses the operation of Linux hosts under change control: an organisation
that has to know, for every host, what was changed, by whom, on whose approval and with
what result. It is intended for platform and operations teams that run Debian, RHEL and
Arch families across several sites and environments.

The panel never runs a shell on a host: every operation is a typed, versioned contract
with its own permission, risk class, lock class and campaign policy. A change is planned
on the host, the plan is what an approver reads, and the host refuses a plan whose
content differs from the approved one. Facts are shown as the host reported them, and an
unknown fact is shown as unknown rather than as a default.

## Architecture

| Component | Binary | Runs as | Role |
|---|---|---|---|
| Control plane | `flotestro-control-plane` | service on the panel server | REST API, web panel, agent gateway, enrollment endpoint, scheduler, campaign engine, PKI, PostgreSQL store |
| Agent | `flotestro-agent` | `flotestro-agent`, unprivileged | Holds one mTLS session to a gateway, reports inventory and metrics, plans changes, hands privileged steps to the helper |
| Helper | `flotestro-agent-helper` | root, socket-activated by systemd | Executes the fixed set of privileged operations received over a local Unix socket; never opens a network connection |
| Relay | `flotestro-relay` | `flotestro-relay`, unprivileged | Terminates agent sessions of one site and forwards them to the centre; buffers results during an upstream outage |
| Tooling | `flotestro-agentctl`, `flotestro-relayctl`, `flotestro-auditverify`, `flotestro-sbom` | operator | Enrollment, renewal, status and diagnosis on the host; offline audit verification; bill of materials of a binary |

Trust boundaries. Browsers and API clients reach the control plane over HTTP on an
administrative address that listens on the loopback by default and is meant to sit
behind a TLS reverse proxy. Agents reach the gateway over mutual TLS with certificates
from the fleet CA; the host identity is a URI SAN in the certificate, never a field of
the request. The agent is the only process on the host that talks to the network and it
holds no root; the helper is the only privileged process, accepts requests from the
agent user alone and runs tools in transient systemd scopes. The relay has its own
identity and attests to the centre which host a forwarded session belongs to.

Data flow. The scheduler dispatches an order to the agent session; the agent validates
the payload with the same code the panel used, checks the plan and asks the helper for
each privileged step. Results, inventory and monitoring samples return over the same
session, through the relay where one is in the path.

## Capabilities

- Packages: plan, upgrade, install, remove, hold, repair, repository sources; per-host plans with an approval bound to the plan digest; a separate operation for upgrading the agent itself.
- Services: start, stop, restart, reload, reset-failed, enable, mask; status and health; journal read and bounded follow; log files from an allowlist.
- Files: managed files with plan, ensure, remove and rollback to a kept version; version history in the panel.
- Network and firewall: profiles, routes and MTU through NetworkManager, nmstate or netplan with a connectivity watchdog and local rollback; rules, zones, ports and services through firewalld, nftables or UFW; resolver configuration and resolution tests.
- Storage: mounts, filesystem creation, check and resize, LVM extension, device wipe, SMART reading; storage topology in the inventory.
- Containers: Docker container lifecycle, image pull, targeted prune, engine events and container logs; Compose projects planned and deployed against a specific plan, with manifest versions kept.
- Kernel and security: sysctl, module load and blacklist, SELinux mode, audit rule reload; security scans with compliance verdicts formed in the panel and remediation as campaigns of typed steps.
- Time: chrony and systemd-timesyncd configuration, time zone, and a synchronisation test that queries the candidate server before a working one is removed.
- Identity: FreeIPA directory read-through (users, groups, hosts, host groups, HBAC and sudo rules, DNS), access simulation, approved directory changes, host enrollment into the domain with preflight; local accounts with keys, groups, expiry, lock and deletion.
- Certificates: scanning of declared files, trust anchor rotation in stages, deployment with the private key fetched by the host, renewal through certmonger.
- Backups: restic and borg definitions, runs, verification and restore; data flows between host and repository, the panel sees metadata.
- Scheduled jobs: cron entries and systemd timers as managed target state, with preview and run-now.
- Monitoring: agents sample CPU, memory, swap, filesystem and inode usage and uptime every minute; the panel stores raw samples and quarter-hour rollups, evaluates alert rules, keeps alerts and silences. No external metrics system is required.
- Vulnerabilities: package lists correlated in the panel against Debian, Ubuntu, Red Hat and NVD feeds, or against mirrored copies.
- Campaigns: canary, waves, manual or automatic gates, failure and connectivity-loss thresholds, maintenance windows, reboot policy, offline policy, per-site and per-channel budgets, exclusions with reasons, compensating campaigns linked to the original.
- Audit: every order, approval and result in an append-only trail; hash-chained export; signed webhook delivery of the event trail.

## Supported platforms

The agent derives the family from `ID` and `ID_LIKE` in `/etc/os-release`. systemd is
required on every managed host.

| Family | Package manager | Packages published for |
|---|---|---|
| Debian, Ubuntu | apt | agent, relay, control plane (`.deb`, amd64 and arm64) |
| Fedora, RHEL, CentOS | dnf | agent, relay, control plane (`.rpm`) |
| Arch Linux | pacman | agent, relay (pacman package) |

A host of another family is inventoried but reports its package manager as unsupported.
Tool-specific adapters are used where the tool is present and reported as absent otherwise.

## Security

Host identity. The control plane runs an internal CA. At enrollment the agent generates
a key pair and submits a CSR; the private key never leaves the host. Agent certificates
are valid for 30 days and are renewed over the existing mTLS session without a token; a
superseded certificate is revoked once the new one has opened a session. The CA is
rotated in stages (prepare, activate, retire). A host can be quarantined, released and
decommissioned; a lost identity is restored by an explicit recovery order.

Enrollment tokens. An enrollment request records who ordered the installation, for what
purpose, in what scope and how it ended. The token is a one-time secret with the prefix
`flt_`; only its digest is stored, the agent receives the same refusal whatever the
reason, and on the host it arrives as a systemd credential or a file, never as an
argument or an environment variable.

Authorisation. A permission is the pair of an operation and a scope (site and
environment). The roles are `viewer`, `auditor`, `operator`, `approver`, `identity_admin`
and `platform_admin`; operator and approver are disjoint, so the person who orders a
change does not approve it. Roles come from OpenID Connect group mappings or direct
grants; API tokens are issued per principal.

Step-up and second person. Operations of critical risk and changes to access rules
require authentication fresher than `FLOTESTRO_STEPUP_MAX_AGE`, optionally with a given
`acr`; `FLOTESTRO_STEPUP_TOKENS` decides whether API tokens may perform them at all. In
environments listed in `FLOTESTRO_PRODUCTION_ENVIRONMENTS` a change is approved by a
person other than its author. Destructive operations require the target name to be
typed and are excluded from campaigns by contract.

Secrets. Values are encrypted at rest under a key in the state directory and bound to
their row and version. A task carries a reference; the host fetches the value under a
lease valid for five minutes from delivery. The value appears neither in the task, nor
in the audit trail, nor in the inventory.

Audit chain. Events are appended, never updated. An export is a file of JSON lines, each
carrying the digest of the previous one, closed by a trailer with the count and the
final digest; `flotestro-auditverify` checks it without the panel. Webhook deliveries
are signed with HMAC-SHA256 over a timestamp and the body.

## Installation

Control plane (requires PostgreSQL; the schema is created and migrated at start):

```
apt install flotestro-control-plane            # or dnf
$EDITOR /etc/flotestro/control-plane.env
systemctl enable --now flotestro-control-plane
```

Keys in `/etc/flotestro/control-plane.env` an installation sets: `FLOTESTRO_DATABASE_URL`,
`FLOTESTRO_ADMIN_ADDR` (default `127.0.0.1:8080`), `FLOTESTRO_GATEWAY_ADDR` (`:8443`),
`FLOTESTRO_ENROLLMENT_ADDR` (`:8444`), `FLOTESTRO_ADVERTISE` (names entered into the
gateway certificate), `FLOTESTRO_PUBLIC_URL`, `FLOTESTRO_PACKAGE_REPOSITORY_URL`, the
`FLOTESTRO_OIDC_*` and `FLOTESTRO_IPA_*` keys, `FLOTESTRO_WEBHOOK_URL`, the retention
keys, `FLOTESTRO_STATE_DIR` and `FLOTESTRO_WEB_ROOT`; the file documents every key. The
first start writes a bootstrap API token to `/var/lib/flotestro/bootstrap-token`, used to
create the group mappings and deleted once proper accounts exist. Without an OIDC issuer
the panel works on API tokens alone.

Host agent (the package installs the agent, the helper with its socket unit and `flotestro-agentctl`):

```
apt install flotestro-agent                    # or dnf, pacman
$EDITOR /etc/flotestro/agent.yaml              # enrollment_url, gateway_urls, bootstrap_ca_file
sudo -u flotestro-agent flotestro-agentctl enroll --token-file /path/to/token
systemctl enable --now flotestro-agent
```

The token comes from an enrollment request created in the panel or through the API.
Agent state lives in `/var/lib/flotestro-agent`; the helper listens on
`/run/flotestro/helper.sock`. `agent.yaml` also sets the inventory interval, the task
concurrency and the mode (`full` or `read_only`).

Relay. The relay package installs `flotestro-relay` and `flotestro-relayctl`.
`/etc/flotestro/relay.yaml` names the relay, its site, its listening address (default
`0.0.0.0:8453`), the names it advertises to site agents, the result buffer limit and the
upstream gateways. The relay enrolls with its own one-time token.

Ansible. `deploy/ansible/site.yml` applies the role `flotestro_agent` to the inventory
group `flotestro_agents`: it configures the signed repository for the host family,
installs the package, writes `agent.yaml`, creates a one-time enrollment request through
the API and enrolls the host. It requires `flotestro_api_url`, `flotestro_agent_enrollment_url`,
`flotestro_agent_gateway_urls`, `flotestro_repo_url` and `flotestro_automation_api_token`.

Ports: 8080 administrative API and panel (HTTP, behind a TLS proxy), 8443 agent gateway
(mTLS), 8444 enrollment (TLS), 8453 relay (mTLS, site side).

## Operation

A change begins as an order for one operation on one host or, as a campaign, on a
selected set. An operation whose contract requires a plan runs only against one: the
host computes the difference between its state and the requested target, and the plan
digest is what the approver signs off. The scheduler dispatches the approved order under the operation's lock class,
the host reports the result with a stable error code where it failed, and verification
follows the contract: unit health, connectivity, a recomputed plan with no difference,
or a module-specific check. Every step is an audit event with the actor, the request
identifier and the authentication it rested on.

A campaign runs one operation over a snapshot of targets: it plans on every host, waits
for approval, runs the canary, stops at a manual gate if one was asked for, and proceeds
in waves under the failure threshold, the maintenance window, the budgets and the offline
policy. Every target keeps its own record of steps; a finished campaign can be compensated
by a second one linked to it.

## Building and testing

Go 1.25 and protoc with the Go and Connect plugins for the services, Node.js for the panel.

```
make build            # control plane, auditverify and agent for the host platform
make build-agent      # static agent for linux/amd64
make generate         # regenerate Go code from api/proto
make test             # unit tests
make lint             # gofmt and go vet
make test-integration # integration tests against a live fleet (build tag: integration)
make package-deb COMPONENT=agent            # requires dpkg-deb
make package-rpm COMPONENT=control-plane    # requires rpmbuild
```

The panel is built with `npm ci && npm run build` in `web/`; `npm test` runs its unit
tests and `npm run test:e2e` the Playwright suite. The control plane serves it from
`FLOTESTRO_WEB_ROOT`.

`packaging/build-release.sh <binaries|packages|all> <version> <dir> [arch ...]` builds
the binaries for amd64 and arm64 with version and commit stamped in, writes a CycloneDX
1.5 bill of materials per binary, packs the `.deb`, `.rpm` and pacman packages and writes
`SHA256SUMS`; it signs nothing. `packaging/sign-repo.sh <release-dir> <gpg-key> <repo-dir>`
composes the signed apt, dnf and pacman repositories, keeping earlier versions in the index.

## Repository layout

```
api/proto/    protobuf contracts of the agent gateway and the helper socket
cmd/          entry points: control-plane, agent, agent-helper, relay, agentctl, relayctl, auditverify, sbom
internal/     opspec (operation registry), scheduler, campaigns, budgets, gateway, relay, adminapi,
              authz, pki, enrollment, secrets, audit, monitoring, vuln, freeipa, packages, modules/, helper
db/migrations PostgreSQL schema, applied by the control plane at start
web/          the panel: fleet pages and per-host module pages
packaging/    systemd units, configuration templates, package scripts, release and repository signing
deploy/       Ansible playbook and the flotestro_agent role
tests/        integration tests against a running fleet
```
