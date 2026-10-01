# Installing Flotestro from nothing

## Purpose

Bring up an installation that does not exist yet: the control plane from its image, the
first administrator, the backup pair, and the first hosts from signed packages. It is the
path a customer takes, and it ends with a fleet the panel can see and order work on.

The server runs in a container; the hosts do not. The agent and its helper are native
packages, because a host agent that has to see the real `/proc`, the real disks and the
real systemd is a `--privileged` container with nothing isolated about it
(`docker/README.md`, ADR-OCI-01).

## Preconditions

- A PostgreSQL 16 or newer the installation will own, reachable from the panel's host, or
  the quick-start profile that brings one up beside it.
- A container runtime: Docker Engine with the Compose plugin, or Podman - see the Podman
  section of `docker/README.md` for what differs.
- DNS that resolves the names the panel will advertise, from the hosts and from the
  operator's browser. They enter the agent gateway's certificate, so they are the names
  the fleet really reaches, never a Compose service name. A laboratory needs none of it:
  an address serves where a name would, and the panel offers the ones it finds.
- Ports: 8080 for the panel and its API, published on every address of its host; 8443 and
  8444 reached by the fleet directly - their TLS is end to end and must not be terminated
  by an HTTP proxy. An installation with a reverse proxy in front narrows 8080 back to the
  loopback with `FLOTESTRO_API_PUBLISH`.
- A signed package repository the hosts can reach. The release produces one; an isolated
  site uses the package-repository image of the air-gapped profile.

## Procedure

### 0. The whole of it, for a laboratory

Six steps, no file edited and nothing else installed:

```
curl -fsSLO https://raw.githubusercontent.com/ultherego/Flotestro/main/docker/compose.yaml
docker compose up -d
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token .
```

Then open `http://<the panel host's address>:8080` from another machine, sign in with that
token, confirm the address the agents dial on the first-run screen, and install an agent on
a separate host with the commands "Add host" prints. The database, the initialisation and
the migration happen on their own; no domain, no certificate, no tunnel, no OIDC issuer and
no FreeIPA are involved, and the first-run checklist counts an installation that
deliberately has none of them as complete rather than as unfinished.

**That is plain HTTP: the bootstrap token and every administrative request travel in clear
on the network.** For a laboratory that is accepted. A company running a real fleet from
this panel puts TLS in front of it - a reverse proxy, a certificate, a domain - and narrows
`FLOTESTRO_API_PUBLISH` to the loopback when it does. The fleet's own traffic never
depended on it: the enrollment on 8444 and the agents' mTLS on 8443 terminate their own TLS
against Flotestro's PKI.

The rest of this runbook is the installation that carries a company's fleet.

### 1. The control plane

Follow "The first start" in `docker/README.md`, which carries the exact files. Three things
that are easy to get wrong and cost an hour each:

- **The DSN is a file you write, and nothing else.** `./secrets/database-url`, mode 0600,
  owned by you. The `init` service copies it into the runtime and gives the copy to the
  account the panel runs as, so neither the uid nor the SELinux label is yours to get right.
- **The quickstart writes its own.** With no `./secrets/database-url` to import, init makes
  a password for the local database. An installation that meant to use an external one
  stops, writes the DSN and starts again.
- **Pin the digest in production.** The example shows a tag because a tag is readable; a tag
  can be rewritten by whoever publishes it and a digest cannot.

The panel does not migrate: `FLOTESTRO_AUTO_MIGRATE` is false in the deployment and the
`migrate` service settles the schema before any replica serves. A panel started against a
schema it does not expect refuses with `schema_behind` rather than serving half a product.
Ask the binary the deployment points at, then the panel itself:

```
docker compose --profile check run --rm schema-check   # exit 0 and the level it found
curl -fsS http://127.0.0.1:8080/readyz
```

`/readyz` and not `/healthz`: the latter says the process is alive, which it is even when
the database is unreachable or has become a read-only standby.

### 2. The first administrator

An installation with no identities writes a bootstrap token into its state. Take it, sign
in with it, connect the identity provider, map its groups to roles, and then delete it -
the control plane warns at every start while it is still valid, and a group from a token
grants nothing by itself until a mapping says so.

An installation that names no identity provider signs its operators in with API tokens
instead, and that is a shape the panel supports rather than a step left half done: the
checklist marks the provider and the group mapping optional and counts neither. What still
has to happen is the handover - issue an API token of your own with `platform_admin`, sign
in with it, and only then revoke the bootstrap one.

```
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token ./bootstrap-token
```

### 3. Back up before anything else

The database and the state directory are one pair: the state holds the fleet CA, the keys
of the secret store and the helper's signing key, and a database restored beside a
different state is an installation that cannot talk to its own fleet. Take the pair now,
while the CA is minutes old, and prove the restore before the fleet depends on it -
"The database and the state are one backup pair" in `docker/README.md`.

### 4. The hosts

The panel generates the commands per host and per family under "Add host": the repository,
the package, the fleet CA with its fingerprint to check, the enrollment and the start. Use
those rather than the shapes below - they carry this installation's own addresses, the one
-time token and the CA the fleet really uses. What they do, so an operator knows what is
being run:

| Step | What it does |
| --- | --- |
| repository | Adds the signed repository and its key to apt, dnf or pacman |
| package | Installs `flotestro-agent`, which brings the helper with it |
| CA | Writes the fleet CA where the agent reads it, and prints its fingerprint to compare |
| enroll | Spends the one-time token and takes the host's own certificate |
| start | `systemctl enable --now flotestro-agent` |

The token is one-time and short-lived. Pass it by file or on standard input, never in the
environment. The command runs as `flotestro-agent`, so a file written by root is a file it
cannot open - give it to that account and nobody else:

```bash
printf '%s' "$TOKEN" | sudo install -m 0400 -o flotestro-agent -g flotestro-agent /dev/stdin /run/token
sudo -u flotestro-agent flotestro-agentctl enroll --token-file /run/token
sudo rm -f /run/token
```

One command writes the file, because a file created first and written afterwards is a file
the writer no longer owns: 0400 to `flotestro-agent` leaves the operator unable to fill it.

Standard input avoids the file altogether, which is the shorter way when the token is
already in the shell: `printf '%s' "$TOKEN" | sudo -u flotestro-agent flotestro-agentctl
enroll`. Either way the token is gone afterwards - a one-time secret left in a file is a
one-time secret only by courtesy.

A host whose identity already exists keeps it: a package upgrade does not re-enroll, which
is why installing onto a host that carried a previous installation needs its identity
removed explicitly - a new fleet CA does not recognise certificates the previous one issued.

### 5. A site behind a relay, if there is one

Create `relay.yaml` and `relay-ca.pem` next to `compose.relay.yaml` before the first start -
a bind mount whose source does not exist becomes a directory - then register the relay with
a one-time token from the panel. The relay's spool is on disk and survives its restart, so
give it room: `docker/README.md` and `docs/runbooks/relay-disk-full.md`.

## Verification

- `GET /api/v1/status`: the schema is current, the database answers, the instance claims its
  gateway identity.
- `GET /api/v1/hosts`: every host enrolled is `online` and reports its distribution and its
  agent version.
- One operation end to end on one host - a read is enough - reaches a terminal state with a
  result, not a refusal.
- The panel shows no bootstrap token warning, and `./bootstrap-token` is deleted.
- The backup pair exists and has been restored once, somewhere that is not production.

## Rollback

Nothing here is irreversible until hosts are enrolled. Before that, `docker compose down -v`
and an empty database put the machine back. After that, a host is removed with
`docs/runbooks/golden-image.md`'s sanitisation - the identity, the task state and the
firewall registry - and the panel decommissions its record; removing the installation
itself is "Removing an installation" in `docker/README.md`.

## Codes

`installation_state_mismatch` and `gateway_id_in_use` refuse a control plane pointed at a
database that belongs to another installation, or a second instance claiming a gateway
identity that is already held. `machine_already_enrolled` refuses an enrollment on a host
that still holds an identity. The enrollment refusals and the agent's own codes are in the
error guide (`GET /api/v1/errors`).
