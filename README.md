<div align="center">

![Flotestro](docs/logo.webp)

</div>

<p align="center">
  Fleet management for Linux servers.<br>
  One panel that plans, approves, carries and records changes across Debian, Ubuntu, Fedora, RHEL and Arch hosts.
</p>

<p align="center">
  <a href="#why-flotestro">Why</a> ·
  <a href="#features">Features</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#how-a-change-happens">How it works</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#building">Building</a>
</p>

## Why Flotestro

- **Typed operations only.** Every action is a versioned contract with its own permission, risk level, lock class and campaign mode. There is no "run a command" type; the panel never runs a shell on a host.
- **Plans approved by digest.** The host computes the plan, an approver reads it, and the host applies it only if the content still matches the approved digest.
- **Unknown is shown as unknown.** A fact the agent could not determine is empty, not zero; a missing declaration means a refusal, not consent.
- **Evidence, not logs.** Every order, approval and result is an event in a hash-chained audit trail that `auditverify` checks offline, without the database.
- **No external monitoring stack.** Agents sample their host, the panel keeps the samples and rollups, evaluates rules, and holds alerts and silences.

## Features

| Area | Operations |
|---|---|
| Packages | plan, upgrade, install, remove, hold, repair; per-host plans approved by digest; agent upgrades |
| Services and processes | start, stop, restart, reload, enable, mask, reset-failed; unit detail; process tree; signals |
| Files and schedules | managed files with versions and rollback; cron entries and systemd timers |
| Network and firewall | NetworkManager, nmstate, netplan with a connectivity watchdog; firewalld, nftables, UFW; resolver |
| Storage | mounts, filesystem check and resize, LVM, SMART, device wipe |
| Containers | Docker containers, images, prune, events, logs; Compose projects deployed against a plan |
| Kernel and security | sysctl, modules, SELinux mode, audit rules; security checks with fleet-wide remediation |
| Time | chrony and timesyncd, time zone, source test before a source is replaced |
| Identity | FreeIPA users, groups, HBAC and sudo rules, access simulation, domain joins; local accounts and keys |
| Certificates and backups | scanning, trust-anchor rotation, certmonger renewal; restic and borg runs, verification, restore |
| Monitoring | CPU, memory, swap, filesystems, inodes, uptime sampled by the agent; alert rules and silences in the panel |
| Vulnerabilities | package lists correlated against Debian, Ubuntu, Red Hat and NVD feeds; the panel reads the feeds, never the hosts |
| Campaigns | canary, waves, manual or automatic gates, failure thresholds, maintenance windows, per-site budgets, offline policy per host |
| Notifications | durable trail posted to a webhook in batches, signed with HMAC-SHA256, delivered at least once and in order |

## Screenshots

<p align="center"><img src="docs/screenshots/dashboard.png" alt="Fleet dashboard" width="900"></p>

<table>
  <tr>
    <td><img src="docs/screenshots/hosts.png" alt="Hosts" width="440"></td>
    <td><img src="docs/screenshots/host-overview.png" alt="Host overview" width="440"></td>
  </tr>
  <tr>
    <td>Hosts with state, site, environment and what needs attention.</td>
    <td>One page per module with the facts as the agent reported them.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/host-packages.png" alt="Packages of a host" width="440"></td>
    <td><img src="docs/screenshots/campaign.png" alt="Campaign" width="440"></td>
  </tr>
  <tr>
    <td>Packages of a host: the plan, its digest and the actions the operator may take.</td>
    <td>A campaign across the fleet: canary, waves, gates and thresholds.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/security.png" alt="Security" width="440"></td>
    <td><img src="docs/screenshots/monitoring.png" alt="Monitoring" width="440"></td>
  </tr>
  <tr>
    <td>Versioned security checks judged in the panel; a fix for many hosts is one campaign with one approval.</td>
    <td>Built-in monitoring: raw samples, rollups, rules, alerts and silences.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/audit.png" alt="Audit" width="440"></td>
    <td></td>
  </tr>
  <tr>
    <td>Audit trail: the actor, the request and the authentication it rested on.</td>
    <td></td>
  </tr>
</table>

## How a change happens

<div align="center">

![How Flotestro works](docs/flow.svg)

</div>

1. The host computes a plan of the change and reports its digest.
2. An approver reads the plan; in production a second person approves.
3. The host applies the change only if its content still matches the approved digest.
4. The result, the verification and every step are written to a hash-chained audit trail.

Across a fleet the same change runs as a campaign: canary, waves, manual or automatic
gates, failure thresholds, maintenance windows, per-site budgets, offline policy per host.

## Architecture

| Component | Runs as | Role |
|---|---|---|
| `flotestro-control-plane` | service on the panel server | API, web panel, agent gateway, enrollment, scheduler, campaign engine, PKI, PostgreSQL |
| `flotestro-agent` | unprivileged user on every host | one mTLS session to the gateway; inventory, metrics, plans; hands privileged steps to the helper |
| `flotestro-agent-helper` | root, socket-activated | executes the fixed set of privileged operations over a local socket; no network |
| `flotestro-relay` | unprivileged, one per isolated site | terminates agent sessions of a site and forwards them; buffers results during an outage |

Hosts hold a certificate from the fleet CA, issued at enrollment from a key that never
leaves the host, renewed by the agent itself, revoked when superseded. Enrollment tokens
are one-time and stored as digests. Users sign in through OpenID Connect; roles come from
group mappings scoped by site and environment; sensitive actions need step-up
authentication. Secrets are fetched by the host under a short lease and never travel in a
task. PostgreSQL is the only source of truth; the panel keeps the fleet state nowhere else.

## Quick start

Nothing to build and nothing to clone. The panel runs from a published image;
the hosts take a package from the project's signed repository.

**The panel**, with a database of its own:

```
curl -fsSLO https://raw.githubusercontent.com/ultherego/Flotestro/main/deploy/compose.yaml
printf '%s\n' FLOTESTRO_VERSION=0.60.0 FLOTESTRO_GATEWAY_ID=cp-01 \
  FLOTESTRO_ADVERTISE=panel.example.org FLOTESTRO_PUBLIC_URL=http://panel.example.org:8080 > .env
mkdir -p secrets && chmod 700 secrets
printf '%s' 'a-long-random-password' > secrets/postgres-password
printf '%s' 'postgresql://flotestro:a-long-random-password@postgres:5432/flotestro?sslmode=disable' > secrets/database-url
sudo chown 65532:65532 secrets/* && chmod 400 secrets/*
docker compose --profile quickstart up -d
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token .
```

`FLOTESTRO_ADVERTISE` is the name the fleet really reaches this panel at: it
enters the agent gateway's certificate. The bootstrap token is the first sign-in;
map the identity provider's groups to roles, then delete it.

Against a database you already run, leave the profile out and point
`secrets/database-url` at it. Under rootless Podman add
`-f compose.podman.yaml`. On a host with SELinux,
`chcon -Rt container_file_t secrets`. The rest - the backup pair, an isolated
site, pinning a digest, upgrading - is in [deploy/README.md](deploy/README.md).

**A host**, from the package repository:

```
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsS https://ultherego.github.io/Flotestro/packages/flotestro-repo.asc | sudo tee /etc/apt/keyrings/flotestro.asc >/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/flotestro.asc] https://ultherego.github.io/Flotestro/packages/deb stable main' | sudo tee /etc/apt/sources.list.d/flotestro.list >/dev/null
sudo apt update && sudo apt install flotestro-agent
```

Every index in it is signed by the release key, and there is no version in any
of those lines: `apt update` is how a host learns a newer version exists and
`apt upgrade` is what moves it. A pre-release goes to a `testing` channel that
a host asking for `stable` never reads. `dnf` and `pacman` read the same tree
under `rpm/stable` and `arch/stable`; the panel writes all three for its own
repository address under **Add host**.

Without a route out, a package is fetched on a connected machine and carried
in. The file name carries the version, so there is no `latest` URL to quote -
`gh` resolves the newest stable release itself, and pre-releases are not in it:

```
curl -fsS https://ultherego.github.io/Flotestro/packages/flotestro-repo.asc | gpg --import
gh release download --repo ultherego/Flotestro --pattern 'flotestro-agent_*_amd64.deb' --pattern 'SHA256SUMS*'
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./flotestro-agent_*_amd64.deb
```

`.rpm` and `.pkg.tar.zst` are there too. Every asset carries a build
attestation, so where it came from is a question with an answer:

```
gh attestation verify flotestro-agent_1.2.3_amd64.deb --repo ultherego/Flotestro
```

Then enroll the host. The panel writes the exact commands for its own
addresses under **Add host**; the shape is:

```
sudo tee /var/lib/flotestro-agent/ca.pem >/dev/null   # the fleet CA, fingerprint shown in the panel
sudo sed -i -e 's|^  enrollment_url: .*|  enrollment_url: "https://panel.example.org:8444"|' \
            -e 's|^  gateway_urls: .*|  gateway_urls: ["https://panel.example.org:8443"]|' /etc/flotestro/agent.yaml
echo "$TOKEN" | sudo -u flotestro-agent flotestro-agentctl enroll   # one-time, from the panel
sudo systemctl enable --now flotestro-agent
flotestro-agentctl diagnose                                        # explains a host that does not show up
```

For a whole inventory at once there is an Ansible role in
[deploy/ansible](deploy/ansible); for a site behind a relay,
`deploy/compose.relay.yaml`. Installing from nothing, end to end, is
[docs/runbooks/install.md](docs/runbooks/install.md); every environment
variable of every binary is in [docs/configuration.md](docs/configuration.md).

| Port | Service |
|---|---|
| 8080 | panel and API; loopback by default, put behind a TLS proxy |
| 8443 | agent gateway (mTLS) |
| 8444 | enrollment (TLS) |
| 8453 | relay |

## Building

Go 1.25 for the services, Node.js for the panel.

```
make build                                   # control plane, agent, auditverify
make generate                                # code from api/proto
make test                                    # unit tests
make lint                                    # gofmt and go vet
(cd web && npm ci && npm run build)          # the panel
packaging/build-release.sh all 1.0.0 dist    # packages for amd64 and arm64 with a CycloneDX SBOM
packaging/sign-repo.sh dist <gpg-key> repo 1.0.0  # adds the release to the signed apt, dnf and pacman repositories
```

GitHub Actions in `.github/workflows` run the same checks, the vulnerability scan and the fuzz targets on every push, and build the packages of a `v*` tag.

## Repository layout

```
api/proto/    protobuf contracts       internal/     the product      web/        the panel
cmd/          entry points             db/           migrations       packaging/  units, templates, package builds
deploy/       Ansible role             tests/        integration tests against a live fleet
```
