<div align="center">

![Flotestro](docs/logo.webp)

**Run your Linux fleet from one panel.**

Debian · Ubuntu · Fedora · RHEL · Arch — packages, services, files, firewall,
storage, containers, certificates and monitoring, on every host, from one place.

[Documentation](https://ultherego.github.io/Flotestro/docs/) ·
[Install](#install) ·
[Screenshots](#screenshots)

</div>

---

## Why you would want it

**One panel instead of five tools.** Inventory, packages, services, files,
network, firewall, storage, containers, accounts, certificates, backups,
monitoring, alerting, CVEs and compliance — the same fleet, the same
permissions, the same audit trail.

**No shell on your servers.** There is no "run this command" action. Every
change is a typed operation with its own permission and risk level, so a
mistake is refused instead of executed.

**See the plan before it happens.** The host works out what would change, you
read it, you approve it — and the host applies it only if what it found still
matches what you approved.

**Nothing pretends to be fine.** A fact the agent could not read is shown as
unknown, never as zero. A host that cannot answer is a host that cannot answer.

**No monitoring stack to run.** Agents sample their own host, the panel keeps
the samples, evaluates the rules and sends the alerts. No Prometheus, no Loki,
no Alertmanager.

**Proof, not logs.** Every order, approval and result is an event in a
hash-chained trail that `flotestro-auditverify` checks offline, without the
database.

## Install

**The panel**, with a database of its own:

```bash
curl -fsSLO https://raw.githubusercontent.com/ultherego/Flotestro/main/deploy/compose.yaml
printf '%s\n' FLOTESTRO_VERSION=latest FLOTESTRO_GATEWAY_ID=cp-01 \
  FLOTESTRO_ADVERTISE=panel.example.org FLOTESTRO_PUBLIC_URL=http://panel.example.org:8080 > .env
mkdir -p secrets && chmod 700 secrets
printf '%s' 'a-long-random-password' > secrets/postgres-password
printf '%s' 'postgresql://flotestro:a-long-random-password@postgres:5432/flotestro?sslmode=disable' > secrets/database-url
sudo chown 65532:65532 secrets/* && chmod 400 secrets/*
docker compose --profile quickstart up -d
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token .
```

Open the panel, sign in with the token, and add your first host.

**A host:**

```bash
curl -fsS https://ultherego.github.io/Flotestro/packages/flotestro-repo.asc | sudo tee /etc/apt/keyrings/flotestro.asc >/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/flotestro.asc] https://ultherego.github.io/Flotestro/packages/deb stable main' | sudo tee /etc/apt/sources.list.d/flotestro.list >/dev/null
sudo apt update && sudo apt install flotestro-agent
```

`dnf` and `pacman` are in the [documentation](https://ultherego.github.io/Flotestro/docs/installation.html).
The panel writes the enrollment command for each host under **Add host**.

Everything else — an external database, a relay for a remote site, an
air-gapped installation, backups, upgrades — is in the
[documentation](https://ultherego.github.io/Flotestro/docs/).

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

## Built from

Go for the control plane, the agent, the root helper and the relay; React and
TypeScript for the panel; PostgreSQL for everything it remembers. The agent and
its helper are native packages, not containers, because a host agent has to see
the real `/proc`, the real disks and the real systemd.

Images are published to
[GHCR](https://github.com/ultherego/Flotestro/pkgs/container/flotestro-control-plane)
and packages to the signed
[apt, dnf and pacman repository](https://ultherego.github.io/Flotestro/packages/),
each with a build attestation that says which run produced it.

Contributing, building from source and the repository layout are in the
[documentation](https://ultherego.github.io/Flotestro/docs/).
