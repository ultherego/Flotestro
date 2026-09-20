# Security policy

Flotestro manages Linux fleets. One installation holds the fleet's certificate
authority, an encrypted secret store and an open session to an agent on every
managed host, with a root helper standing behind that agent. A fault here is
not a fault in a web application: it is root on every machine the panel can
reach. It is treated that way.

## Reporting a vulnerability

Report it through this repository's private security advisories:

**<https://github.com/ultherego/Flotestro/security/advisories/new>**

That is the channel. There is no address to write to and no PGP key to fetch:
the advisory is private between you and the maintainer from the first word, it
carries attachments and patches, and it becomes the published advisory when the
fix ships — so nothing has to be copied from one place to another, and nothing
is lost on the way.

Do not open an issue, a discussion or a pull request for something you believe
is exploitable. A pull request explains the fault in its diff, to everybody,
before anyone has the fix installed.

### What makes a report usable

- The release you are running — the package version or the image tag — and
  which part it is in: control plane, agent, root helper, relay, packaging.
- What the attacker starts with: nothing at all, a host on the network, an
  enrolled agent, an API token, an operator account with a named role, a
  compromised relay.
- What they end with, said plainly: read a secret, get a certificate signed,
  run something as root on a host that approved nothing, forge or lose an
  audit event, make the panel report a fact nobody established.
- The steps, and the smallest installation that shows it. `tests/e2e/smoke.sh`
  brings up a control plane, a database and an agent on one machine, which is
  usually enough to reproduce against.
- Anything you already know about the fix. It is welcome and it is never
  assumed.

### What you can expect

This project is maintained by one person. What follows is what that can
honestly carry, rather than the paragraph such a file usually contains.

- The report is acknowledged in the advisory thread when it is first seen.
  There is no on-call rota and no response time this project could keep, so
  none is promised here.
- If a week passes with no word at all, assume the notification was missed.
  Open a public issue saying that a security advisory is waiting — the fact
  only, no detail and no reproducer — and it will be picked up.
- After that, the thread is where the state lives: what was confirmed, what was
  not, what the fix is and which release carries it. A report that turns out
  not to be a vulnerability gets the reasoning, not silence.
- The fix ships as a new release. A published artefact is never replaced in
  place, so there is no quiet correction under an old version number: a fixed
  build is a new tag with its own signature, its own provenance and its own
  entry in [CHANGELOG.md](CHANGELOG.md).
- The advisory is published together with that release and credits you by
  whatever name you ask for, or by none.
- There is no bug bounty and no payment of any kind. Nobody is going to be
  told otherwise here.

We ask that you keep the detail to yourself until the advisory is published or
ninety days have passed, whichever comes first. That is a request to you, not a
deadline this project is claiming it will meet.

## Versions that get fixes

| Version | Fixes |
|---|---|
| the newest 0.60.x release | yes |
| anything older | no |

Flotestro is before 1.0 and has no maintenance branches. A fix goes into the
next patch release cut from `main`, and nothing is backported. Packages, images
and the signed repository are published from the same tag at the same moment,
so "move to the current release" is `apt upgrade`, `dnf upgrade` or
`pacman -Syu` on a host and a new image tag for the panel.

## What is in scope

The product as it ships:

- **Control plane** (`flotestro-control-plane`) — the REST API under
  `/api/v1`, the panel, the agent gateway on 8443, the enrollment endpoint on
  8444, the fleet CA, the scheduler and the campaign engine, the secret store,
  the monitoring ingest, the notification outbox and the audit trail.
- **Agent** (`flotestro-agent`) — the unprivileged daemon, its single mTLS
  session, its identity generations and its spools.
- **Root helper** (`flotestro-agent-helper`) — the only part that runs as
  root: its socket, the peer check on the calling uid, the capability the panel
  signs and it verifies per request, its frame limits, and the fixed repertoire
  of actions it will carry out at all.
- **Relay** (`flotestro-relay`) — the sessions of a site it terminates, the
  host's own identity envelope that the centre verifies end to end, and the
  spool of what the centre has not acknowledged.
- **The packages and the images** — `.deb`, `.rpm`, `.pkg.tar.zst`, the GHCR
  images, and what they install: units, scriptlets, directories, ownership and
  modes.
- **The signed package repository** at
  <https://ultherego.github.io/Flotestro/packages/> — the indexes, their
  signatures, and the key published beside them.

And, named separately because they are the claims the product is sold on rather
than incidental properties:

- a way to have an operation carried out without the permission, the approval,
  the fresh authentication or the plan digest that operation declares;
- a way to make the panel report a fact nobody established — an unread module
  shown as zero, a missing verification read as a success, a check that could
  not run shown as passed;
- a way to put a secret into a task envelope, a log line, a support bundle or
  an export;
- a way to add an event to the audit trail, remove one or alter one and still
  have `flotestro-auditverify` call the chain intact.

## What is not in scope

- **A deployment the documentation tells you not to run.** The admin port is
  plain HTTP and belongs behind a TLS proxy; 8443 and 8444 are end to end and
  must not be terminated by one. Doing the opposite and reporting the result is
  a configuration, not a vulnerability.
- **A principal doing what their role permits.** Permissions are the boundary,
  and an installation that grants a broad role has made that decision. A way
  *around* a permission is very much in scope.
- **Root on a managed host, already held.** The agent is unprivileged and the
  helper answers only the agent's uid, but neither defends a host against its
  own root, and nothing could.
- **A dependency finding with no call path into this code.** `govulncheck`
  runs on every change and reports what the binaries actually call into; the
  rest belongs upstream. A finding that *is* reachable here is in scope, and
  naming the path makes it actionable the same day.
- **Volumetric denial of service** and load testing against anything this
  project publishes.
- **The laboratory.** The Vagrant fleet the maintainer tests on is not in this
  repository and is not shipped.
- **GitHub itself** — the advisory platform, GHCR, GitHub Pages — rather than
  what this project puts there.
- **Scanner output with no consequence shown.** A missing header, a cipher
  rating, a version banner: say what an attacker does with it, or it is a note
  rather than a report.
- **Social engineering, physical access**, and anything that needs the
  maintainer's own machine or account.

## What you can verify without trusting this page

**The release is signed.** Every release publishes `SHA256SUMS` over each asset
and a detached signature beside it. The job that signs is not the job that
built: the build jobs hold no key at all, and signing runs in a protected
environment where the key is imported and deleted inside the run, after every
file has been re-checked against the manifest it is about to be signed under.

    gpg --verify SHA256SUMS.asc SHA256SUMS
    sha256sum --check --strict SHA256SUMS

The public key stands beside the repository at
`https://ultherego.github.io/Flotestro/packages/flotestro-repo.asc`, and every
release keeps its own manifests under
`https://ultherego.github.io/Flotestro/packages/releases/<version>/` instead of
one file the next release overwrites.

**The repository indexes are signed.** What a host installs from is the index,
and each family verifies its own: `InRelease` and `Release.gpg` over the apt
index, a signature over `repodata/repomd.xml` and over the `.rpm` files
themselves for dnf, a signed package database for pacman. The `.deb` carries no
individual signature and is not meant to — `InRelease` covers `Packages`, and
`Packages` carries the checksum of every package file. Import the key once and
`apt update` verifies from then on.

**Every artefact says which run built it.** Each `.deb`, `.rpm`, `.pkg.tar.*`
and `SHA256SUMS` carries a keyless build attestation made against the identity
of the release run:

    gh attestation verify flotestro-agent_0.60.5_amd64.deb --repo ultherego/Flotestro

It answers with the commit, the workflow and the run. The signature says who
signed; the attestation says what built. A run that receives no OIDC identity
publishes without an attestation and says so in its checks rather than
inventing one. The images carry the same provenance, and each release also
carries a CycloneDX bill of materials for every binary it ships and for the
panel.

**The audit trail checks out without the panel.** Every order, approval, result
and refusal is an event in a hash chain. `flotestro-auditverify` recomputes that
chain from an export of `GET /api/v1/audit/export`, with no database and no
control plane:

    flotestro-auditverify export.jsonl

Exit 0 intact, 1 broken, 2 a wrong invocation. An installation cannot both have
had its history edited and pass this.

## How the project tries not to make them

Every change to `main` passes gitleaks over the commits it adds, `govulncheck`
against what the binaries call into, the race detector over the whole unit
suite, a fuzz budget on each decoder that reads what a host or an operator
sends, a migration proven forward from the last released tag, and a bill of
materials for every shipped binary. `main` requires a review, and
[`.github/CODEOWNERS`](.github/CODEOWNERS) names the paths that never pass on a
glance: authorization, the helper's capabilities, the crypto state, the PKI,
the gateway, the migrations and the workflows themselves.
[CONTRIBUTING.md](CONTRIBUTING.md) has the whole list.
