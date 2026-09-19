# Container deployment

The images and the Compose files of the Flotestro control plane and relay.
The agent and its helper are not here: they manage the host itself - its
PID 1, its devices, its package database - and are installed natively from
the signed repository.

| File | Role |
|---|---|
| `Containerfile` | All three images: the control plane (target `control-plane`), the relay (target `relay`) and the administration tools (target `admin-tools`). |
| `compose.yaml` | The control plane alone, against a database somebody else runs. |
| `compose.local-db.yaml` | The overlay that adds a local PostgreSQL for a laboratory or a small fleet. |
| `compose.relay.yaml` | The relay of one site, run on the site host as its own project. |
| `compose.tools.yaml` | The overlay with the backup and the restore, behind the profiles `tools` and `restore`. It adds nothing to `up`. |
| `../.dockerignore` | The allowlist of the build context; it lies at the repository root because that is the context the build runs with. |
| `../.github/workflows/images.yml` | What builds, publishes, describes and signs the three images, and what a pull request runs to prove the files above still work. |

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

The backup and the restore are not a fourth profile of a deployment: they are
two one-shot services behind the profiles `tools` and `restore` in
`compose.tools.yaml`, which adds nothing to `up`. See "Taking the pair".

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

docker buildx build -f deploy/Containerfile --target admin-tools \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.54.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-admin-tools:0.54.0 --push .
```

These are the commands by hand, for a laboratory. A release runs all three
from `.github/workflows/images.yml`, which also attaches the bills of
materials and the provenance, signs the result and prints the digests; see
"The supply chain" below.

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
or the tools image, never by installing something into a running container.

The tools image is the one exception, and only where it has to be. It is
built on the image of the PostgreSQL server, because a dump is written by
the client of the server and that client is a C program with a distribution
under it - `pg_dump` links against libpq, OpenSSL, ICU, LDAP and GSSAPI and
reads the locale tables of the system, none of which exist on a static
distroless image, and a client older than the server refuses to dump at all.
What it still does not carry: no Docker socket, no Docker CLI, no route to a
managed host, no daemon and no port. It runs one command and ends.

## The supply chain

`.github/workflows/images.yml` is what publishes the images. It runs on two
occasions and they are deliberately different:

| Trigger | What runs |
|---|---|
| A tag `v*` | The build context is checked, every Compose combination is parsed, the three images are built for `linux/amd64` and `linux/arm64` and **pushed** to GHCR, each with a bill of materials and a provenance statement attached, signed with cosign when the run has an identity, and the digests are printed. |
| A pull request touching `deploy/`, `cmd/`, `internal/`, `db/`, `web/`, `go.mod`, `go.sum` or `.dockerignore` | The same checks and the same build for both platforms, and **nothing is pushed**: a Containerfile that no longer builds is found while there is still a branch to fix it on. |
| `workflow_dispatch` | A dry run of the above on a branch. It pushes nothing either. |

What the release publishes for each image is two tags: the full version,
`0.56.0`, which is never rewritten, and `sha-<twelve characters of the
commit>` for diagnostics. No moving alias - no `latest`, no `stable`, no
`0.56` - is published: an alias that can be repointed is a convenience of a
test bench, and the run refuses outright to build a version tag that already
exists in the registry.

Three things the run checks that an operator would otherwise find the hard
way: that the build context carries no `.env`, no key material, no `secrets/`
and no `state/` (it builds the context and looks at what came out, rather
than reading the ignore file and believing it); that every documented Compose
combination parses; and that every service of ours in them runs as
`65532:65532`, read-only, without capabilities and without new privileges.

### Pinning a digest

The run ends by printing the three digests, and attaches a ready
`compose.pins.yaml` to itself. The short form, for `./.env`:

```
FLOTESTRO_VERSION=0.56.0
FLOTESTRO_TOOLS_DIGEST=sha256:...
```

and the whole references, for a manifest that pins them directly:

```
ghcr.io/ultherego/flotestro-control-plane:0.56.0@sha256:...
ghcr.io/ultherego/flotestro-relay:0.56.0@sha256:...
ghcr.io/ultherego/flotestro-admin-tools:0.56.0@sha256:...
```

The tag stays in the reference because it is what a human reads; the digest
is what is deployed. Load the override last:

```
docker compose -f compose.yaml -f compose.pins.yaml up -d
```

### Verifying what you are about to run

The signature is keyless: it was made against the identity of the workflow
and recorded in the public transparency log, so there is no key to be stolen
and none to distribute.

```
cosign verify \
  --certificate-identity-regexp '^https://github\.com/ultherego/Flotestro/\.github/workflows/images\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/ultherego/flotestro-control-plane:0.56.0@sha256:...
```

The identity is checked, not merely the presence of a signature: an image
signed by somebody else is an image signed by somebody else. The bill of
materials and the provenance are read the same way:

```
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/ultherego/Flotestro/\.github/workflows/images\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/ultherego/flotestro-control-plane:0.56.0@sha256:...

docker buildx imagetools inspect --format '{{ json .Provenance }}' \
  ghcr.io/ultherego/flotestro-control-plane:0.56.0@sha256:...

docker buildx imagetools inspect --format '{{ json .SBOM }}' \
  ghcr.io/ultherego/flotestro-control-plane:0.56.0@sha256:...
```

A run that receives no OIDC identity publishes the image unsigned and says so
in its log and in the checks list. It does not make up a key so that a step
can be green, and `cosign verify` on such an image fails - which is the
correct answer, not a malfunction.

There are three bills for a release, because one of them cannot see what the
other two do. The attestation attached to the image is the filesystem of the
image itself, packages of the distribution included. The CycloneDX bills
produced by `cmd/sbom` are read out of the built binaries, module by module,
and are attached to the platform manifest they describe. The bill of the
panel is taken from the lock file the image was built from, because the panel
ships as a bundle and nothing in the image resembles a dependency any more.
All three are also attached to the run as artefacts.

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
#    just created. See "Taking the pair" below.
mkdir -p backups && chown 65532:65532 backups && chmod 700 backups
docker compose -f compose.yaml -f compose.tools.yaml \
  --profile tools run --rm admin-tools backup
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

### Taking the pair

`compose.tools.yaml` is the overlay that takes it, and `flotestro-admin-tools`
is the image that does the work - so that the host which runs the panel never
needs a PostgreSQL client, a `pg_dump` of the wrong major version or a cron
job written by hand.

Once, before the first backup:

```
mkdir -p backups && chown 65532:65532 backups && chmod 700 backups
```

Then, with the control plane stopped - or at the very least with the rotation
of the CA and of the key encryption keys held for the duration:

```
docker compose -f compose.yaml -f compose.tools.yaml \
  --profile tools run --rm admin-tools backup
```

It writes `./backups/<backup-id>/` and nothing outside it:

| File | What it is |
|---|---|
| `database.dump` | `pg_dump --format=custom`, without owners and without privileges: the restore is done by whoever owns the empty database it goes into. |
| `state.tar.zst` | The state directory, with numeric owners and the original modes - the state is `0700` and the keys in it are `0600`. |
| `manifest.json` | What ties the two halves together: the backup identifier, the moment, the version and commit of the image, the installation identifier, the active key and issuer identifiers, the digests of both files and the digest of the image, when the deployment pins one. |
| `SHA256SUMS` | The digests of the two archives, checked before every restore. |

The manifest carries no DSN, no password and no secret value. The archives
do: the backup belongs on encrypted storage, away from the host it was taken
from, and it is worth restoring it into an isolated environment now and again
to find out whether it actually works.

Writing `COMPOSE_FILE=compose.yaml:compose.tools.yaml` into `./.env` shortens
all of this to `docker compose --profile tools run --rm admin-tools backup`.
With the quick start profile the local database is on an internal network, so
add `-f compose.local-db.yaml` as well.

### Putting it back

The restore is a second profile, because it is the one operation that mounts
the state writable:

```
docker compose -f compose.yaml -f compose.tools.yaml \
  --profile restore run --rm admin-restore restore 20260919T101500Z
```

It refuses to start unless the checksums match, the state volume is empty and
the target database has no tables in its `public` schema: a restore puts an
installation back where there is none, it never writes over the identity of
one that is still there. A pair can be checked without restoring anything:

```
docker compose -f compose.yaml -f compose.tools.yaml \
  --profile tools run --rm admin-tools verify 20260919T101500Z
```

The whole procedure, in order: stop every control plane; pick the database
and the state of one backup identifier; restore the pair with the command
above; start one control plane, which runs the migrator itself; check that
the installation identifier, the CA and the key identifiers are the ones the
manifest names, that the agents reconnect and that the audit trail still
verifies; only then start the rest.

The image carries the same `auditverify` the packages ship, so an export can
be checked where it lies:

```
docker compose -f compose.yaml -f compose.tools.yaml \
  --profile tools run --rm admin-tools auditverify /backups/audit-20260901.jsonl
```

Anything else it is asked to run, it runs: `psql`, `pg_dump` and `pg_restore`
are there for the hour when the documented commands are not the ones needed.
What is not there is a way out of the container - no Docker socket, no Docker
CLI, no route to a managed host - and the DSN never reaches an argument: the
tool lifts the password out of it and passes it to libpq through the
environment, so a dump that runs for an hour does not stand in the process
list of the host with a password in it for that hour.
