# Container deployment

The images and the Compose files of the Flotestro control plane and relay.
The agent and its helper are not here: they manage the host itself - its
PID 1, its devices, its package database - and are installed natively from
the signed repository.

| File | Role |
|---|---|
| `Containerfile` | Both images: the control plane (target `control-plane`) and the relay (target `relay`). |
| `compose.yaml` | The control plane alone, against a database somebody else runs. |
| `compose.local-db.yaml` | The overlay that adds a local PostgreSQL for a laboratory or a small fleet. |
| `compose.relay.yaml` | The relay of one site, run on the site host as its own project. |
| `../.dockerignore` | The allowlist of the build context; it lies at the repository root because that is the context the build runs with. |

## The three profiles

**Quick start** - the control plane and a PostgreSQL of its own, one host,
local backup. For a laboratory, a demonstration and a small installation.

```
docker compose -f compose.yaml -f compose.local-db.yaml up -d
```

**Production basic** - one control plane against an external, backed-up
PostgreSQL. This is the default for a company; the database keeps its own
lifecycle, its own tuning and its own high availability.

```
docker compose up -d
```

**Production relay** - the same, plus one relay per site, each on its own
host next to the agents it serves.

```
docker compose -f compose.relay.yaml --profile enroll run --rm relay-enroll
docker compose -f compose.relay.yaml up -d
```

`compose.yaml` never names a database service, a host called `postgres` or a
database volume. An installation that points at an external database
therefore cannot start a second, empty one beside it and write half of its
truth there.

## Building the images

```
docker buildx build -f deploy/Containerfile --target control-plane \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.54.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-control-plane:0.54.0 --push .

docker buildx build -f deploy/Containerfile --target relay \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.54.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-relay:0.54.0 --push .
```

The build arguments are written into the binaries as `buildinfo.Version`,
`buildinfo.Commit` and `buildinfo.Date` - the same symbols the release script
stamps - so a container answers "which commit is this" the way a package
does. The build runs from the repository root.

The examples pin images by tag because a tag is readable. Production pins the
digest as well, `image:tag@sha256:...`, for the base images in the
`Containerfile` and for the images in the Compose files: a tag can be
rewritten by whoever publishes it, a digest cannot.

### What the images deliberately do not contain

No PostgreSQL, no shell, no package manager, no curl or wget, no Docker CLI
and no Docker socket. The runtime is distroless: the binaries, the system
certificate store and the built panel. The health check is a static client of
our own (`cmd/container-healthcheck`) precisely because there is nothing in
the image to call an endpoint with; debugging is done with a support bundle
or a separate tools image, never by installing something into a running
container.

## The mounts

| Mount | Why |
|---|---|
| `flotestro-state` → `/var/lib/flotestro` | The identity of the installation: the fleet CA (`ca.key`, `ca.pem`), the keys of the secret store under `keys/`, the helper signing key, the bootstrap token, the feed cache. Read and written by the control plane alone. |
| `/run/secrets/*` (read-only) | One file per secret; see below. |
| `/tmp` (tmpfs) | The only other writable path. The root filesystem is read-only. |
| `flotestro-relay-state` → `/var/lib/flotestro-relay` | The relay identity, its certificate and the durable spool: the results of the site the centre has not acknowledged yet. |
| `./relay.yaml` → `/etc/flotestro/relay.yaml` (read-only) | The relay is configured by a file, not by the environment: its name, site, listen address, advertised names and upstream gateways. |
| `./relay-ca.pem` → `/etc/flotestro/ca.pem` (read-only) | The fleet CA for the relay's first connection, before it has a copy of its own. |

The volumes are named explicitly. A renamed Compose project would otherwise
create a new, empty state next to the existing database - and an empty state
means an installation whose CA is gone.

The directory in the image is created at build time as `0700`, owned by
`65532:65532`, and a named volume inherits that. Nothing is ever started as
root to chown its own state; a bind mount instead of a volume has to be
created with that owner and mode before the first start.

## Secrets

Secrets are passed as files and read once at start. Every variable has a
`_FILE` form that names a path; the value form and the `_FILE` form must not
both be set, and an empty file, a symlink, a directory or a file readable by
anyone else is refused.

| Secret | Variable | Mount |
|---|---|---|
| Database DSN | `FLOTESTRO_DATABASE_URL_FILE` | `/run/secrets/database_url` |
| OIDC client secret | `FLOTESTRO_OIDC_CLIENT_SECRET_FILE` | `/run/secrets/oidc_client_secret` |
| Webhook HMAC key | `FLOTESTRO_WEBHOOK_SECRET_FILE` | `/run/secrets/webhook_secret` |
| NVD API key | `FLOTESTRO_VULN_NVD_KEY_FILE` | `/run/secrets/nvd_key` |
| FreeIPA keytab | `FLOTESTRO_IPA_KEYTAB` (already a path) | `/run/secrets/ipa.keytab` |
| PostgreSQL password (local profile) | `POSTGRES_PASSWORD_FILE` | `/run/secrets/postgres_password` |

The files live in `./secrets/`, which is not tracked by Git and is readable
only by the account that runs the deployment. `./.env` holds non-secret
values alone - the version, the gateway identifier, the advertised addresses
and the public URL.

Nothing secret goes into a command line, a label, a log line or the settings
screen: an environment variable is visible in `docker inspect` and in the
process list of the host, which is why the DSN travels as a path.

## The first start

Production basic, from an empty directory:

```
cd deploy

# 1. The non-secret settings.
cat > .env <<'SETTINGS'
FLOTESTRO_VERSION=0.54.0
FLOTESTRO_GATEWAY_ID=cp-prod-01
FLOTESTRO_ADVERTISE=panel.example.org
FLOTESTRO_PUBLIC_URL=https://panel.example.org
SETTINGS

# 2. The database DSN, as a file and with no trailing surprises.
mkdir -p secrets && chmod 700 secrets
printf '%s' 'postgresql://flotestro:PASSWORD@db.example.org:5432/flotestro?sslmode=verify-full&application_name=flotestro-control-plane' > secrets/database-url
chmod 600 secrets/database-url

# 3. Start. The panel migrates the schema itself before it listens.
docker compose up -d
docker compose logs -f control-plane        # wait for "the database schema is current"

# 4. The first administrator. The control plane writes a bootstrap token into
#    its state when the installation has no identities yet.
docker compose cp control-plane:/var/lib/flotestro/bootstrap-token ./bootstrap-token

# 5. Back up the database and the state volume together, now - the CA was
#    just created.
```

Delete `./bootstrap-token` and the token in the panel once the real accounts
exist; the control plane warns at every start while it is still valid.

For the quick start profile, write `secrets/postgres-password` first, point
the DSN at the local database, and start both files together:

```
printf '%s' 'a-long-random-password' > secrets/postgres-password && chmod 600 secrets/postgres-password
printf '%s' 'postgresql://flotestro:a-long-random-password@postgres:5432/flotestro?sslmode=disable&application_name=flotestro-control-plane' > secrets/database-url
docker compose -f compose.yaml -f compose.local-db.yaml up -d
```

`sslmode=disable` is acceptable only here, on one host with an internal
network; an external database requires `verify-full`.

For a relay, create `relay.yaml` and `relay-ca.pem` next to
`compose.relay.yaml` before the first start - a bind mount whose source does
not exist becomes a directory - then register the relay with a one-time token
from the panel and start it. The token file is deleted afterwards.

## The database and the state are one backup pair

The database holds the hosts, the tasks, the campaigns, the audit trail, the
monitoring and the encrypted secrets. The state directory holds the keys
those ciphertexts open with and the CA the fleet certificates were issued
by. Neither is a backup of the other and neither is usable without the other:

- Back them up together and restore them together, from the same point in
  time.
- A foreign state next to an existing database stops the start, fail-closed,
  with the state named. Nothing is ever created anew in place of what is
  missing - a regenerated CA would silently cut off every host in the fleet.
- Two control plane instances must not run with separate state directories
  against one database.
- Both belong on encrypted storage. File-based secrets are not disk
  encryption.
