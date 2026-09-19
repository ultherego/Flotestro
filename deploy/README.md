# Container deployment

The images and the Compose files of the Flotestro control plane and relay.
The agent and its helper are not here: they manage the host itself - its
PID 1, its devices, its package database - and are installed natively from
the signed repository.

| File | Role |
|---|---|
| `Containerfile` | All four images: the control plane (target `control-plane`), the relay (target `relay`), the administration tools (target `admin-tools`) and the package repository of an isolated site (target `package-repository`). |
| `compose.yaml` | The control plane alone, against a database somebody else runs. |
| `compose.local-db.yaml` | The overlay that adds a local PostgreSQL for a laboratory or a small fleet. |
| `compose.relay.yaml` | The relay of one site, run on the site host as its own project. |
| `compose.airgap.yaml` | The overlay that puts the signed package repository of the release beside the control plane, for a site with no route out. |
| `compose.tools.yaml` | The overlay with the backup and the restore, behind the profiles `tools` and `restore`. It adds nothing to `up`. |
| `../.dockerignore` | The allowlist of the build context; it lies at the repository root because that is the context the build runs with. |
| `../.github/workflows/images.yml` | What builds, publishes, describes and signs the three service images, and what a pull request runs to prove the files above still work. |

## The four profiles

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

**Air-gapped** - any of the three above, plus the package repository of the
release on the network the managed hosts reach. The site receives the images
on media and installs its agents from the fourth one; nothing reaches the
Internet.

```
docker compose -f compose.yaml -f compose.airgap.yaml up -d
```

The backup and the restore are not a profile of a deployment: they are two
one-shot services behind the profiles `tools` and `restore` in
`compose.tools.yaml`, which adds nothing to `up`. See "Taking the pair".

`compose.yaml` never names a database service, a host called `postgres` or a
database volume. An installation that points at an external database
therefore cannot start a second, empty one beside it and write half of its
truth there.

## Podman

The images build and run under Podman, and the published ones are ordinary OCI
images that `podman pull` takes like any other. Two differences are worth
knowing before an installation is planned around it.

**`HEALTHCHECK` is a Docker-format extension.** Podman builds OCI-format images
by default and says so during the build - "HEALTHCHECK is not supported for OCI
image format and will be ignored". The image-level check is then simply not
there. It costs nothing here, because `compose.yaml` declares the same check
itself and Podman honours a Compose healthcheck whatever the image format; a
deployment that runs the image with a bare `podman run` gets none and should
either add `--health-cmd /usr/local/bin/flotestro-healthcheck` or build with
`--format docker`.

**The secrets need one more thing than the file mode.** A Compose secret is a
bind mount of a file the deploying account owns, and the container runs as
65532. Under Docker, give the file to that account: `chown 65532:65532
./secrets/*` and `chmod 0400`. Rootless Podman cannot use that - host uid 65532
is outside the account's subuid range, so the container would see the file as
nobody's - so `compose.podman.yaml` turns the mapping round instead with
`keep-id`, and the files stay owned by the deploying account at mode 0600. On a
host with SELinux the file also needs the container label, or the read fails
with a plain "permission denied" that says nothing about SELinux:

    chcon -Rt container_file_t ./secrets

**Rootless is the sensible way to run it,** and the images are built for it:
they run as 65532, drop every capability and write only to their volume and to
`/tmp`. The account that runs the deployment needs subuid and subgid ranges
(`usermod --add-subuids 200000-265535 --add-subgids 200000-265535 <account>`)
and `loginctl enable-linger <account>`, or the panel stops with the session
that started it. Every port the panel publishes is above 1024, so rootless
needs no change there.

`podman-compose` reads the rest of the files as written: `secrets:`,
`read_only`, `tmpfs`, `cap_drop`, `security_opt`, `pids_limit`, `ulimits` and
`stop_grace_period`. Two options had to change to be portable at all, and both
changed in the shipped files rather than in an overlay: the tmpfs is declared
with `mode=1777` instead of `uid=`/`gid=`, which Podman refuses, and the log
driver is `json-file` instead of Docker's `local`, which Podman does not know.
Rotation is the same either way.

## Building the images

```
docker buildx build -f deploy/Containerfile --target control-plane \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.59.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-control-plane:0.59.0 --push .

docker buildx build -f deploy/Containerfile --target relay \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.59.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-relay:0.59.0 --push .

docker buildx build -f deploy/Containerfile --target admin-tools \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.59.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-admin-tools:0.59.0 --push .
```

The fourth image is built from something the source tree does not contain: a
repository that is already built and already signed. `packaging/build-release.sh`
makes the packages, `packaging/sign-repo.sh` signs them into a tree, and that
tree enters the build as a named context. The signing key stays on the machine
that used it and never reaches a layer - what the image carries is the public
half, `flotestro-repo.asc`, which is what a host imports before it installs
anything.

```
packaging/build-release.sh all 0.59.0 /srv/release
packaging/sign-repo.sh /srv/release <gpg-key-id> /srv/repo

docker build -f deploy/Containerfile --target package-repository \
  --build-context repository=/srv/repo \
  --build-arg VERSION=0.59.0 \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t ghcr.io/ultherego/flotestro-package-repository:0.59.0 .
```

The build refuses a context without `flotestro-repo.asc`: a tree that carries
no public key is not one a host could verify, and an image that served it
would fail on every managed host instead of on the machine that built it.

These are the commands by hand, for a laboratory. A release runs the three
service images from `.github/workflows/images.yml`, which also attaches the
bills of materials and the provenance, signs the result and prints the
digests; see "The supply chain" below. The repository image is built after the
packages are signed, because that is the artefact it is made of.

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

The package repository image is the same base again: it is a static server
and a directory of already-signed files, and an image the whole fleet
downloads from is the last place to put a shell.

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
| A tag `v*` | The build context is checked, every Compose combination is parsed, the three service images are built for `linux/amd64` and `linux/arm64` and **pushed** to GHCR, each with a bill of materials and a provenance statement attached, signed with cosign when the run has an identity, and the digests are printed. |
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

### What proves a package's origin

The three package families do not answer "who built this file" the same way,
and the product does not pretend they do.

| Family | What is signed | What the host checks |
|---|---|---|
| pacman | The package file itself, with a detached `.sig` beside it. | `gpg` against pacman's own keyring names the key, and an agent upgrade may demand a particular one. |
| dnf | The package file itself, in its header. | `rpm --checksig` names the key, and an agent upgrade may demand a particular one. |
| apt | The repository index. `InRelease` carries the checksums of `Packages`, and `Packages` the checksum of every `.deb`. | `gpgv` against the keys apt trusts names the key that signed the index, and the index has to publish the very file the host holds. |

The `.deb` is the odd one out on purpose. Debian's trust model does not sign
individual packages: `dpkg-sig` and `debsig-verify` exist, no distribution
enables them, and `apt` never consults them - a package signed that way is
verified by one tool nobody runs. Signing the `.deb` would therefore produce a
signature that proves nothing to the host that installs it.

So an agent upgrade plan for a host of the apt family **names no signing key**.
A plan that names one is refused before it is sent, with
`agent_package_signer_not_applicable`, because the host could never satisfy it;
a host that is asked anyway refuses with `agent_package_signer_unknown` and
installs nothing. What the apt host reports instead is the fact it can
establish: the address the file comes from, the release file of that
repository, and the key `gpgv` accepted the signature of that index on. The
result of the job then reads "the proof is the repository index signed by
&lt;key&gt;" rather than leaving an empty field. Where it cannot be established the
reason is typed - `apt_repository_unsigned`, `apt_index_key_untrusted`,
`apt_index_unreadable`, `apt_artefact_origin_unknown`,
`apt_index_digest_mismatch` - and never a silent pass. None of them fails the
upgrade by itself: the checksum from the release still binds the bytes, and the
panel judges the rest.

`packaging/sign-repo.sh` is what produces that proof: it writes `InRelease` and
`Release.gpg` over the index, signs the `.rpm` files themselves and the
`repomd.xml`, and signs the pacman database. A repository served without it
leaves the apt family with no proof of origin at all.

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
FLOTESTRO_VERSION=0.59.0
FLOTESTRO_GATEWAY_ID=cp-prod-01
FLOTESTRO_ADVERTISE=panel.example.org
FLOTESTRO_PUBLIC_URL=https://panel.example.org
SETTINGS

# 2. The database DSN, as a file and with no trailing surprises.
mkdir -p secrets && chmod 700 secrets
printf '%s' 'postgresql://flotestro:PASSWORD@db.example.org:5432/flotestro?sslmode=verify-full&application_name=flotestro-control-plane' > secrets/database-url
# The container runs as 65532 and a Compose secret keeps the file's ownership,
# so the file has to be readable by that account and by nobody else. Rootless
# Podman maps the other way round - see the Podman section.
sudo chown 65532:65532 secrets/database-url
chmod 400 secrets/database-url
# On a host with SELinux, without the container label the read fails with a
# plain "permission denied" that says nothing about SELinux.
command -v chcon >/dev/null && sudo chcon -Rt container_file_t secrets

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

## Into an isolated site

An air-gapped site receives the release on media and nothing else. Four images
cross the gap:

| Image | Why it has to be there |
|---|---|
| `flotestro-control-plane` | The panel and the two agent listeners. |
| `flotestro-package-repository` | The signed packages of the same release; the fleet installs its agents from it and from nowhere else. |
| `flotestro-admin-tools` | The backup pair. A site that cannot pull an image cannot improvise one on the day it has to restore. |
| `flotestro-relay` | Only where the site has a relay; a single-network site does not need it. |

PostgreSQL is the site's own, from whatever channel the site already trusts
for its databases: it is not ours to carry.

### On the connected side

Verify the identity of each image first, then take it. A signature checked
after the crossing would be a signature checked against a transparency log the
site cannot reach - the verification belongs where the network is.

```
version=0.56.0
owner=ultherego
images="control-plane package-repository admin-tools relay"

for name in $images; do
  reference="ghcr.io/$owner/flotestro-$name:$version"
  cosign verify \
    --certificate-identity-regexp '^https://github\.com/ultherego/Flotestro/\.github/workflows/images\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$reference"
  docker pull "$reference"
  docker save -o "flotestro-$name-$version.tar" "$reference"
done
```

Then write down what the isolated side is to check, and sign it with the same
GPG key the packages are signed with - that key is the one trust anchor the
site already has, and it is the only one that survives a gap:

```
for name in $images; do
  printf '%s %s\n' "flotestro-$name-$version.tar" \
    "$(docker image inspect --format '{{.Id}}' "ghcr.io/$owner/flotestro-$name:$version")"
done > IMAGE-IDS

sha256sum flotestro-*-$version.tar IMAGE-IDS > SHA256SUMS
gpg --local-user <gpg-key-id> --armor --detach-sign SHA256SUMS
```

The image id and not the registry digest, deliberately: `docker save` writes an
archive of its own and `docker load` gives the image a new manifest, so the
`sha256:` the release printed does not survive the crossing. The pin at an
isolated site is therefore the image id recorded here plus the signed
checksum of the archive, and `compose.pins.yaml` is not usable there. A site
that runs a local registry of its own has the other option - `skopeo copy
docker://<reference>@sha256:... oci-archive:...` keeps the manifest, and then
the digest pin works as everywhere else.

### On the isolated side

The public key is imported once, from a copy whose fingerprint was compared
out of band; everything after that is checked against it.

```
gpg --import flotestro-repo.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Only then is anything loaded, and the ids are compared against the file that
was signed:

```
for archive in flotestro-*.tar; do docker load -i "$archive"; done

while read -r archive expected; do
  reference="$(printf '%s' "$archive" | sed -E 's/^flotestro-(.*)-([^-]+)\.tar$/ghcr.io\/ultherego\/flotestro-\1:\2/')"
  actual="$(docker image inspect --format '{{.Id}}' "$reference")"
  [ "$actual" = "$expected" ] || echo "$reference is $actual, not the $expected that was signed" >&2
done < IMAGE-IDS
```

The images keep the `ghcr.io/ultherego/...` names although the site cannot
reach that registry. That is on purpose: `docker load` restores an image under
exactly the name it was saved with, the Compose files name it the same way,
and an image renamed at the gap is one nobody can match against what was
signed. Nothing pulls, because every reference already resolves locally.

### Pointing the panel at it

The panel does not serve the repository and does not proxy it: it composes the
"Add host" commands from one address, and the hosts fetch from that address
themselves. So the address is the one the *hosts* reach - a name or address of
this machine and the published port - never a Compose service name.

```
cat >> .env <<'SETTINGS'
FLOTESTRO_PACKAGE_REPOSITORY_URL=http://panel.site.example.org:8090
SETTINGS

docker compose -f compose.yaml -f compose.airgap.yaml up -d
```

What the panel then writes into the commands, and what the repository image
serves, is the layout `packaging/sign-repo.sh` writes: `flotestro-repo.asc`
at the root, `deb/dists/<channel>/main` for apt, `rpm/<channel>` for dnf and
`arch/<channel>` for pacman. Left empty, `FLOTESTRO_PACKAGE_REPOSITORY_URL`
leaves a placeholder in those commands and the "Add host" screen says so in a
warning; it is not a setting the panel guesses.

Plain HTTP is not a weakness here. What a package manager trusts is the
signature over the index and the key it imported once, and the fleet's
verification of a package is the same on an isolated site as anywhere else. A
site that wants TLS anyway puts the same edge in front of port 8090 as in
front of the panel.

From a managed host, the whole chain is one command:

```
curl -fsS http://panel.site.example.org:8090/flotestro-repo.asc | gpg --show-keys
```

## What an isolated site cannot do

The vulnerability feeds reach the Internet by design, and no profile changes
that. This is the honest account of what a site without a route out keeps,
what it loses, and what it can do about each.

**What still works, completely.** Everything the fleet is managed with: the
inventory, the tasks, the campaigns, the monitoring and its alert rules, the
audit trail, the backups, the agent upgrades from the repository above. The
vulnerability assessment itself is local too - the hosts report their package
lists, the panel compares versions with dpkg and rpm rules of its own, and the
feed snapshots live in the database rather than being fetched per request. A
panel that synchronised once goes on assessing its fleet from what it has,
offline, indefinitely.

**What reports itself unavailable, and how.** The status block
`vulnerability_feeds` answers *unknown* while no feed has ever been read and
*failed* once a snapshot is older than `FLOTESTRO_VULN_MAX_SNAPSHOT_AGE` (six
hours by default). Per source the panel shows the moment of the last fetch,
whether it is stale, and the error of the last attempt. Per host the coverage
reason says which of the two cases it is: `feed_stale` still produces findings
- day-old data beat none - while `feed_missing` produces none at all, and the
panel states in as many words that zero findings there means nothing could be
decided, not that the host is clean. Two things are worth knowing before they
are seen: a fetch that simply cannot reach the network is recorded as the raw
error text of the attempt rather than as a typed code, and on an installation
that never fetched anything the per-source table stays empty, so the status
block is the place that says so.

**What an operator does instead.** Every distribution source accepts a
`file://` address, and a copy on the panel's disk is read exactly as the
remote feed is - including the conditional fetch, so an unchanged copy is not
re-parsed. The commented block in `compose.airgap.yaml` is the shape of it;
what has to be on the media is:

| Source | What to copy |
|---|---|
| Debian | The tracker dump, one JSON file, pointed at directly. |
| Ubuntu | A directory holding `com.ubuntu.<release>.cve.oval.xml.bz2` for each release in the fleet. |
| Red Hat and Fedora | A directory holding `archive_latest.txt`, the `.tar.zst` archive it names, `changes.csv` and `deletions.csv`. |

A scheduled import is then a copy job on the media and nothing more; the panel
picks the new file up at its next cycle.

**The gaps, plainly.** Four of them, and none has a workaround inside the
product today.

*The age of a copied feed is not the panel's to know.* A local file is
confirmed unchanged from its own size and modification time, so a copy nobody
replaces keeps reporting itself fresh instead of going stale. The warning an
isolated site needs most is the one the offline path suppresses, and until
that changes the age of the feeds is the operator's calendar, not a panel
screen.

*NVD has no offline form at all.* It is read page by page from a live API
against one address, so no static file can stand in for it; this profile
therefore switches it off rather than letting a timer fail every six hours.
What is lost is enrichment only - the descriptions and the CVSS scores. The
findings, their packages and the vendor's own severity stay; a CVE the vendor
did not rate shows as unrated rather than as harmless.

*A Fedora host reads its own advisories, and that read needs a repository.*
For Fedora the findings are settled by the host's `dnf updateinfo` rather than
by a central feed, and that call is the one place in the product that does not
run against the cache alone. On a host whose metadata has expired and which
has no route to a mirror it fails, the host is then assessed as nothing at
all, and the shell's own error stands where a typed reason should. A site that
mirrors its distribution for its own hosts does not meet this; a site that
mirrors only Flotestro does.

*A copied feed is trusted because it is on the disk.* Nothing verifies a
signature over it and nothing records where it came from, so the trust
boundary moves to whoever put the file there. On an isolated site that is a
deliberate, auditable act by an operator - but it is not the product checking
anything, and it should not be described as if it were.

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

## Upgrading

An upgrade is three decisions in one order: the backup, the schema, the
replicas. The control plane refuses to serve a schema it does not match, in
either direction, so the order is not a matter of taste.

1. **Take the pair.** The backup above, with the new images already pulled
   but nothing started from them. A backup taken after the migration is a
   backup of the version you are trying to leave.
2. **Ask what the new version would do.** With the new image, against the
   running database:

   ```
   docker compose run --rm control-plane schema-check
   ```

   Exit 0 means the new version needs no migration and the upgrade is a
   restart. Exit 1 with `schema_behind` means it carries migrations; the
   message names how many. Any other answer stops the upgrade.
3. **Migrate once, as its own job**, with the credentials of the migrator:

   ```
   FLOTESTRO_MIGRATION_DATABASE_URL_FILE=/run/secrets/migration-database-url \
   docker compose run --rm control-plane migrate
   ```

   Two migrators at once do not race: the second waits on the advisory lock
   and says so. Run `schema-check` again afterwards; it must now exit 0.
4. **Roll the replicas** onto the new image, one at a time, watching the
   fleet reconnect between them. An agent of the previous release keeps
   working: every change of the protocol carries either compatibility with
   the release before it or a refusal that names what to upgrade.

The agents are upgraded afterwards and separately - the panel does that
itself, through the agent upgrade operation, against a package it has
verified. A fleet running the previous agent against the new panel is an
ordinary state, not a broken one.

## Going back

A version can be gone back to; a schema cannot. That asymmetry is the whole
of the rollback procedure.

* **The new version applied no migration** (`schema-check` said so before the
  upgrade): put the previous image back and start it. Nothing else is needed.
* **The new version migrated the database**: the old control plane will
  refuse to start with `schema_ahead`, and it is right to - it would read
  tables whose shape it does not know. Going back then means restoring the
  pair taken in step 1, which loses everything recorded since: stop every
  control plane, restore the database *and* the state directory together,
  start the previous image. Never delete rows from `schema_migrations` to
  make the two agree; the tables are still the new ones and the panel would
  write into a shape it misreads.

This is why step 1 is not optional and why the two halves of the pair are
never restored apart: the database holds the encrypted secrets, and the
state directory holds the key that opens them and the CA the fleet trusts.

## Removing an installation

```
docker compose down
docker compose -f compose.yaml -f compose.local-db.yaml down    # quick start
```

The volumes survive on purpose: `docker compose down` stops the containers
and leaves the state and the database where they are, because an operator
stopping a panel for an hour must not lose the fleet's certificate authority
by typing the usual command.

Removing the installation for good is deliberate and in this order:

1. Decommission the hosts from the panel while it still runs, so each one
   stops trusting the centre and revokes its own certificate. A host nobody
   decommissioned keeps an agent asking for a panel that no longer exists.
2. Take a last backup pair if the audit trail has to outlive the panel.
3. `docker compose down --volumes`, which takes the state volume with it.
4. Remove the database, if it is one this installation owns - the external
   database of a production deployment is not this command's to drop.

What remains on a managed host after a decommission is the agent package
itself; `apt purge`, `dnf remove` or `pacman -Rns` on the host removes it
together with its identity files, which is what the packaging's purge step
is for.
