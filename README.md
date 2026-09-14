# Flotestro

Flotestro is a control plane for fleets of Linux servers. One panel plans,
approves and carries changes across hundreds or thousands of hosts — packages,
services, files, firewall, network, storage, containers, time, identity — and
keeps a record of who ordered what, who approved it and what every host
answered.

It is built for organisations that run mixed fleets under change control: the
panel shows facts as the hosts report them, refuses to guess where it does not
know, and never runs a shell on a host.

## How it works

| Component | Runs on | Role |
|---|---|---|
| `flotestro-control-plane` | the panel server | REST API and web panel, scheduler, campaign engine, PostgreSQL store, package repository client, identity connector |
| `flotestro-agent` | every managed host, unprivileged | keeps a mutual-TLS session to the panel, reports inventory and metrics, carries typed operations |
| `flotestro-helper` | every managed host, root, socket-activated | the only privileged process; accepts a fixed set of operations from the agent over a local socket and runs them in resource scopes |
| `flotestro-relay` | one per isolated site | forwards agent sessions and enrollment from a site that cannot reach the panel directly |

Every operation is a typed, versioned contract: what it changes, what it
locks, what its risk class is, whether it needs approval, how it can be
cancelled and what way back exists. A change is planned on the host first,
the plan is what gets approved, and the host refuses to apply anything whose
content differs from the approved plan.

Campaigns take an operation across a selected set of hosts in waves — canary,
manual or automatic gates, failure thresholds, maintenance windows, budgets per
site and per package backend, offline policy per host — with a durable record
of every target's steps.

## Supported hosts

Debian and Ubuntu (apt), Fedora and RHEL family (dnf), Arch Linux (pacman);
systemd is required. Docker and Compose, chrony and systemd-timesyncd,
NetworkManager, nmstate and netplan, firewalld, nftables and UFW, restic
backups, FreeIPA joins are handled where present and reported as absent
where not.

## Security model

- Hosts hold a certificate issued by the fleet CA at enrollment; the agent
  renews it itself and the panel revokes a superseded one.
- Enrollment is by one-time token, bound to a purpose and optionally to a
  machine identity; a lost identity is recovered by an explicit order in the
  panel, never by re-registering as a new host.
- Users sign in through OpenID Connect; roles come from group mappings, scoped
  by site and environment. Sensitive actions require step-up authentication
  and, in production environments, a second person.
- Secrets never travel inside a task: a host receives a lease and fetches the
  value itself.
- The audit trail is append-only and hash-chained; `flotestro-auditverify`
  checks it offline.

## Installation

Packages are published from a signed repository for every supported family
(`packaging/`). On the panel server:

```
apt install flotestro-control-plane        # or dnf / pacman
$EDITOR /etc/flotestro/control-plane.env   # database, public URL, OIDC issuer, directory connector
systemctl enable --now flotestro-control-plane
```

The first start writes a bootstrap API token to `/var/lib/flotestro/`; use it
to map identity-provider groups to roles, after which people sign in through
the identity provider.

On a host:

```
apt install flotestro-agent                # or dnf / pacman
$EDITOR /etc/flotestro/agent.yaml          # enrollment and gateway addresses
echo "$TOKEN" | flotestro-agentctl enroll  # token from an enrollment order in the panel
systemctl enable --now flotestro-agent
```

`deploy/ansible` carries a role that does the same for a whole inventory,
ordering a one-time token per host as it goes. `flotestro-agentctl diagnose`
explains a host that does not appear in the panel.

Ports: `8080` API and panel (put a TLS proxy in front), `8443` agent gateway,
`8444` enrollment, `8453` relay.

## Building from source

Go 1.25 for the services, Node.js for the panel.

```
make build            # control plane and agent for the host platform
make generate         # regenerate code from the protobuf contract
make test             # unit tests
(cd web && npm ci && npm run build)      # the panel, served by the control plane
make package-deb COMPONENT=agent
make package-rpm COMPONENT=control-plane
```

`packaging/build-release.sh` builds every package of a release with a
CycloneDX bill of materials and signs the repositories.

## Layout

```
api/          protobuf contracts between panel, agent, helper and relay
cmd/          entry points: control-plane, agent, agent-helper, relay, agentctl, relayctl, auditverify, sbom
internal/     the product: opspec (operation registry), scheduler, campaigns, modules, gateway, adminapi, ...
db/           PostgreSQL migrations
web/          the panel (React, TypeScript)
packaging/    systemd units, configuration templates, package and repository builds
deploy/       Ansible role for host rollout
tests/        integration tests against a live fleet
```
