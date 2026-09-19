# Installing Flotestro from nothing

## Purpose

Bring up an installation that does not exist yet: the control plane from its image, the
first administrator, the backup pair, and the first hosts from signed packages. It is the
path a customer takes, and it ends with a fleet the panel can see and order work on.

The server runs in a container; the hosts do not. The agent and its helper are native
packages, because a host agent that has to see the real `/proc`, the real disks and the
real systemd is a `--privileged` container with nothing isolated about it
(`deploy/README.md`, ADR-OCI-01).

## Preconditions

- A PostgreSQL 16 or newer the installation will own, reachable from the panel's host, or
  the quick-start profile that brings one up beside it.
- A container runtime: Docker Engine with the Compose plugin, or Podman - see the Podman
  section of `deploy/README.md` for what differs.
- DNS that resolves the names the panel will advertise, from the hosts and from the
  operator's browser. They enter the agent gateway's certificate, so they are the names
  the fleet really reaches, never a Compose service name.
- Ports: 8080 for the panel behind a reverse proxy, 8443 and 8444 reached by the fleet
  directly - their TLS is end to end and must not be terminated by an HTTP proxy.
- A signed package repository the hosts can reach. The release produces one; an isolated
  site uses the package-repository image of the air-gapped profile.

## Procedure

### 1. The control plane

Follow "The first start" in `deploy/README.md`, which carries the exact files. Three things
that are easy to get wrong and cost an hour each:

- **The secret files belong to the account the container runs as.** A Compose secret is a
  bind mount that keeps its ownership, and the control plane runs as 65532. Under Docker:
  `chown 65532:65532 secrets/*` and `chmod 0400`. Under rootless Podman that uid is outside
  the account's subuid range, so use `compose.podman.yaml`, which maps the other way round
  and leaves the files owned by the deploying account.
- **On a host with SELinux the secret also needs the container label**, or the read fails
  with a plain "permission denied" that names nothing:
  `chcon -Rt container_file_t ./secrets`.
- **Pin the digest in production.** The example shows a tag because a tag is readable; a tag
  can be rewritten by whoever publishes it and a digest cannot.

The panel migrates its own schema before it listens. Wait for it:

```
docker compose logs -f control-plane        # "the database schema is current"
curl -fsS http://127.0.0.1:8080/healthz
```

### 2. The first administrator

An installation with no identities writes a bootstrap token into its state. Take it, sign
in with it, connect the identity provider, map its groups to roles, and then delete it -
the control plane warns at every start while it is still valid, and a group from a token
grants nothing by itself until a mapping says so.

```
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token ./bootstrap-token
```

### 3. Back up before anything else

The database and the state directory are one pair: the state holds the fleet CA, the keys
of the secret store and the helper's signing key, and a database restored beside a
different state is an installation that cannot talk to its own fleet. Take the pair now,
while the CA is minutes old, and prove the restore before the fleet depends on it -
"The database and the state are one backup pair" in `deploy/README.md`.

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
environment: `sudo -u flotestro-agent flotestro-agentctl enroll --token-file /run/token`,
and delete the file afterwards.

A host whose identity already exists keeps it: a package upgrade does not re-enroll, which
is why installing onto a host that carried a previous installation needs its identity
removed explicitly - a new fleet CA does not recognise certificates the previous one issued.

### 5. A site behind a relay, if there is one

Create `relay.yaml` and `relay-ca.pem` next to `compose.relay.yaml` before the first start -
a bind mount whose source does not exist becomes a directory - then register the relay with
a one-time token from the panel. The relay's spool is on disk and survives its restart, so
give it room: `deploy/README.md` and `docs/runbooks/relay-disk-full.md`.

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
itself is "Removing an installation" in `deploy/README.md`.

## Codes

`installation_state_mismatch` and `gateway_id_in_use` refuse a control plane pointed at a
database that belongs to another installation, or a second instance claiming a gateway
identity that is already held. `machine_already_enrolled` refuses an enrollment on a host
that still holds an identity. The enrollment refusals and the agent's own codes are in the
error guide (`GET /api/v1/errors`).
