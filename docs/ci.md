# The checks a change passes

Every push to `main` and every pull request runs `.github/workflows/ci.yml`.
Eight jobs run side by side; the pull request waits for the slowest of them, not
for their sum. Nothing in them sends the sources, the logs or the test output
anywhere: the runner downloads its tools and the module cache, and publishes
nothing.

Two things cannot run on a runner. The integration suite carries the build tag
`integration` and drives the fleet - the panel, the database, the relay and the
hosts with the agent - and the Playwright suite of the panel drives that fleet
through a browser. Their verdict reaches a commit through a separate workflow
the owner triggers by hand, described under
[The laboratory gate](#the-laboratory-gate). The one browser test that needs no
fleet - the smoke test, against a control plane and a fake agent the runner
starts itself - runs here.

## What runs

| Check | What it proves | Roughly | Required |
|---|---|---|---|
| `Go` | `gofmt`, `go vet ./...`, `go vet -tags=integration ./tests/...`, `go build ./...` and `go test -race -shuffle=on -count=1 ./...` | 8-14 min | yes |
| `Database` | Every migration applies in order to an empty `postgres:17`, the recorded versions match the files, a second pass applies nothing and changes no schema, and an upgrade from the last released tag ends in the schema of a first installation | 3-6 min | yes |
| `Panel` | `npm ci`, the Polish catalogue, `tsc -b && vite build`, `vitest run` | 3-5 min | yes |
| `E2E smoke` | A real control plane against `postgres:17`, a fake agent against the real gateway, and a browser that signs in, sees the host, orders one operation and reads the host's answer | 6-10 min | yes |
| `Bill of materials` | A CycloneDX bill for every shipped binary and for the panel, each naming its artefact, every component with a name, a version and a purl, every Go module with a recorded checksum | 3-5 min | yes |
| `Secrets` | gitleaks over the commits the change adds, and a check of our own for a key block or a token under `db/`, `internal/`, `cmd/`, `packaging/` | 1-2 min | yes |
| `Known vulnerabilities` | `govulncheck ./...` against the modules the binaries call into | 3-5 min | yes |
| `Fuzz the decoders` | Twenty seconds per fuzz target on the parsers that read what a host or an operator sends | 5-7 min | advisory |
| `lab-suite` | The integration suite and the Playwright screenshots, as the laboratory ran them | by hand | yes for a release, advisory for a merge |

The first run of a branch is the slow one. Afterwards the module cache, the
build cache and the npm cache are keyed by `go.sum` and `web/package-lock.json`,
and only a dependency change makes them cold again.

`Fuzz the decoders` is advisory because a fuzz run is a lottery with a budget:
twenty seconds finds what twenty seconds finds, and a target that fails once in
ten runs is a fault to open as an issue rather than a reason to hold a merge.
When it does fail it is a real fault - Go writes the input that broke the target
into `testdata/fuzz/`, and that file belongs in the repository with the fix.

## When a check fails

**`Go`, gofmt.** `gofmt -w` on the named files. Nothing else in the job runs
until the tree is formatted.

**`Go`, vet or build.** Read the message: vet reports what the compiler accepts
and a reader would not. A failure of `go vet -tags=integration ./tests/...` is
the integration suite no longer compiling against the code - usually a renamed
field or a changed signature. The suite is part of the product; fix it in the
same change.

**`Go`, unit tests.** `-shuffle=on` means the order differs between runs; the
log prints the seed, and `go test -shuffle=<seed>` repeats exactly that order. A
test that fails only under a seed depends on another test's state, which is the
fault. A report from the race detector is never a flake: it is two goroutines
touching the same memory, and it is reproduced with
`go test -race -run=<test> -count=10 ./<package>`.

**`Database`.** The job applies `db/migrations/*.sql` in order to an empty
database, one transaction per file, recording the file name in
`schema_migrations` - the contract of `internal/database.Migrate` written out.
Three ways it fails:

- a migration errors: the SQL is wrong, or it assumes a state an empty database
  does not have. The database of the laboratory has history; this one has none,
  and a customer's first installation has none either.
- the count of recorded versions does not match the count of files, or two files
  share a number: two branches added the same number, and whichever is applied
  second on one installation is applied first on another. Renumber the newer one.
- the second pass applies something or the schema dump differs: a file name was
  changed after the migration had been applied somewhere, so the same SQL runs
  again under a new version. Restore the name, or add the old name to
  `renamedMigrations` in `internal/database/database.go`, which is what that map
  is for.

The job runs the migrator the product ships - `flotestro-control-plane migrate`
- rather than a second implementation of the same loop in shell, and every
`psql` and `pg_dump` runs from the server's own image, so the client never
refuses a newer server.

**`Database`, the upgrade from the last release.** A migration that works on an
empty database and not on one with history breaks every installation there is,
and a from-zero run says nothing about it. The step takes the last stable tag
this commit descends from, lets *that* release's migrator build its own
database, brings it forward with this tree's migrations, and compares the result
- the schema dump and the recorded versions - with a from-zero migration of the
same tree. A difference is one of two things: a migration that assumes what only
an empty database has, or a migration file edited after it had already been
applied on a released version, so that the two databases were built by different
SQL under the same version number. Neither is fixed by changing the check.
Until the first `v*` tag exists the step says so and passes: there is no
previous version to upgrade from.

**`Panel`, the Polish catalogue.** A string reached `t()` with no line in
`web/src/i18n/pl.ts`; the message names the key and the file and line it is used
in. Add the Polish line. The catalogue is keyed by the English source string, so
a missing line is not an error at runtime - the panel simply shows English, and
that is exactly what the check exists to prevent.

**`Panel`, types or bundle.** `tsc -b` under the project references; the error
names the file. A stale `web/tsconfig.tsbuildinfo` never causes it on a runner,
which starts clean.

**`Secrets`.** gitleaks names the commit, the file and the rule, and never the
secret itself - the run is scanned with `--redact`. If the finding is real, the
secret is compromised the moment it is pushed: rotate it first, then remove it
from the branch. A rewritten branch hides it from the scan but not from anyone
who fetched it. If the finding is a test fixture shaped like a key, add its
literal to the allowlist in `.github/gitleaks.toml` with the file it stands in;
never allowlist a path, because a whole file taken out of the scan is a file
where a real key can then be committed unnoticed. Our own check is narrower and
has no allowlist: a PEM header at the beginning of a line under `db/`,
`internal/`, `cmd/` or `packaging/` is a key file, and a token of a recognisable
shape is a token.

The scan covers the commits the change adds - the range of the pull request, or
the range of the push. A sweep of the whole history is a separate, slower thing
to run by hand from the laboratory:

    gitleaks detect --source . --redact --config .github/gitleaks.toml

**`Known vulnerabilities`.** govulncheck reports only what the binaries actually
call into, so a report is a call path, not an advisory to file away. Raise the
module in `go.mod` and run `go mod tidy`. When there is no fixed version yet,
the finding holds the merge until the owner decides otherwise; that decision
belongs in the pull request, in writing.

**`E2E smoke`.** The job runs `tests/e2e/smoke.sh`, which brings up the whole
stack on the runner: the control plane migrates the service database and serves
the API, the gateway, the enrollment endpoint and the built panel; an
enrollment is ordered through the API with the bootstrap token; the agent
simulator enrolls one fake host against the real gateway and keeps its session;
and one Playwright test signs in with the bootstrap token, finds the host,
opens it and orders a read of its unit list.

The fake agent carries no task executor, so it answers a task with the typed
refusal `unsupported`. That refusal is the point: it proves the order left the
panel, passed the gateway, reached the agent and came back to the screen. A
different code - `payload_hash_mismatch`, `expired`, a timeout - means something
on the way changed the task or lost it, and that is a fault of the product, not
of the test. A green run guards that the parts start and talk; what every screen
shows is Vitest's and the laboratory's to check.

Three ways it fails:

- the control plane did not start: the job prints the last fifty lines of its
  log. The usual cause is a migration that did not apply or a listener whose
  address is taken.
- the host never appeared online: the last lines of the agent's log say why -
  a refused enrollment token, a certificate the agent would not accept, a
  gateway it could not reach.
- the browser failed an assertion: the message names the step. It is the panel,
  the API or the round trip - never the fleet, because there is none.

The same script runs on a workstation against an empty database:

    FLOTESTRO_DATABASE_URL=postgres://... tests/e2e/smoke.sh

It needs the panel built (`npm ci && npm run build` in `web/`) and Chromium
installed (`npx playwright install chromium`), and it leaves nothing behind but
its work directory.

The test itself is `web/e2e/ci/smoke.spec.ts` under `web/playwright.smoke.config.ts`;
it lives beside the laboratory suite because Playwright and its browser are
installed in `web/`, and the laboratory's configuration ignores `e2e/ci` so
that the smoke test never runs against a real fleet.

**`Bill of materials`.** The job builds the seven binaries the release ships,
writes a CycloneDX bill of each with `cmd/sbom` - read out of the built binary,
so the bill describes the artefact and not the `go.mod` of the working tree -
and takes the panel's bill from the lock file with `npm sbom`. It refuses:

- a bill that could not be produced at all, which is the minimum: a dependency
  nobody can describe is a dependency nobody will find in an advisory;
- a document that is not CycloneDX, or that does not name the artefact it is
  the bill of;
- a component without a name, a version or a purl - the three fields an
  advisory is matched on;
- a Go module that entered a binary without a recorded checksum. The toolchain
  records the `h1:` sum of every module it takes from the cache, so a component
  without one came in some other way, and nobody can verify afterwards what it
  was.

One npm detail: `npm sbom` refuses a package that declares no version, because
it cannot write a purl for it, and `web/package.json` declares none - the panel
takes its version from the release that packs it. The step therefore stamps
`0.0.0` into the runner's copy when the field is missing, the way the Go
toolchain records `(devel)` for a build from a working tree. Nothing is written
back to the repository; the day `web/package.json` carries a version of its
own, the step leaves it alone.

The bills are not kept: the release writes them again from the same tool, and a
bill of a commit that was never released describes nothing anybody will install.
A failure here is a dependency that arrived in a shape the release could not
describe, and it is fixed in the dependency, not in the gate.

## The release

`.github/workflows/release.yml` fires on a `v*` tag and publishes the packages,
their bills, the provenance and one signature over `SHA256SUMS`. Two rules
decide whether it publishes at all.

**Every architecture, or none.** `rpmbuild` refuses a foreign architecture, so a
run on an amd64 machine cannot produce the arm64 `.rpm` and writes the names
into `dist/missing-rpm.txt`. For a stable tag that stops the release: either tag
a pre-release, or build the missing packages on a native machine and tag again.
A tag with a suffix - `v1.2.3-rc1` - is a pre-release and may ship incomplete.
The same comparison runs without the note: `.deb`, `.rpm` and `.pkg.tar` each
have to carry both architectures or neither.

**One runner, three families.** The laboratory builds each package on a machine
of its own family; the release builds all three on one `ubuntu-latest` runner,
so anything a Fedora or an Arch machine provides by being that machine is
absent here and no laboratory run can find it. What that has already cost:
`%{_unitdir}` and the `%systemd_*` scriptlet macros come from Fedora's
`systemd-rpm-macros` and are undefined on Ubuntu, `%{_sharedstatedir}` reads
`/usr/com` there instead of `/var/lib`, and `makepkg` and `bsdtar` are separate
apt packages that nothing else pulls in. The specs now define what they need
and the workflow names every tool it calls. The rule for anything added later:
a packaging file may use only what it defines itself or what the workflow
installs by name.

**The tag belongs to the default branch.** A tag can be pushed from anywhere,
and an artefact built from a commit nobody reviewed is worth nothing whatever
signs it. The first step of the release refuses a tag whose commit the default
branch does not contain: merge first, then tag the merge. An unsigned tag is
reported in the job summary rather than refused - tag signing is a repository
setting the workflow cannot turn on, and refusing would block a release the
owner never configured for it.

**Where the file came from.** Every `.deb`, `.rpm`, `.pkg.tar.*` and
`SHA256SUMS` carries a keyless build attestation made against the identity of
the release run, so anyone can ask where a file was built:

    gh attestation verify flotestro-agent_1.2.3_amd64.deb --repo ultherego/Flotestro

It answers with the commit, the workflow and the run. The GPG signature over
`SHA256SUMS` stays beside it: one says who signed the release, the other says
what built it. A run that receives no OIDC identity publishes without an
attestation and says so in the checks list rather than inventing one.

**Each package is built on a machine of its own architecture.** `rpmbuild`
refuses a foreign architecture, so the release is four jobs, not one: `Panel`
builds the web bundle once, `Packages` runs twice in parallel - amd64 on
`ubuntu-latest`, arm64 on `ubuntu-24.04-arm` - each packing natively with the
same panel bundle, `The release as a whole` joins both, writes the manifest and
the checksums and makes the attestation, and `Sign and publish` signs and
publishes. The completeness check in the third job is what says both
architectures really arrived.

**The key is not on the machine that built.** The signing runs in its own job.
`Panel`, `Packages` and `The release as a whole` compile, pack, write the
checksums and make the attestation; none of them holds a signing secret. `Sign and publish` runs in the protected environment
`release-signing`, downloads what the first job produced, re-checks every file
against `SHA256SUMS` before it signs anything, signs, and uploads. A compromise
of the build job is then not a compromise of the release signature, and the
environment's reviewers - which the owner configures in the repository - stand
between a tag and a signature.

**Nothing is replaced.** The upload refuses an asset the release already holds
and names it; there is no `--clobber`. A release is corrected by a new version,
not by a new file under the old name.

**What proves a package, per family.** `packaging/sign-repo.sh` composes the
repositories out of a finished release and signs what each family verifies: the
`.rpm` files themselves and `repodata/repomd.xml`, the pacman database, and -
for apt - `InRelease` and `Release.gpg` over the index. The `.deb` is not signed
individually and is not meant to be: Debian's trust model puts the signature on
the repository index, `InRelease` covers `Packages` and `Packages` covers the
checksum of every package file. `dpkg-sig` and `debsig-verify` are read by no
distribution and by no `apt`. An agent upgrade therefore names a signing key for
the rpm and pacman families only; on an apt host the panel names none and the
host reports which key signed the index it installed from. `deploy/README.md`,
under "What proves a package's origin", has the whole table.

**Where the fleet installs from.** Loose files on a release page are not a
repository: there is no `apt update` against them, no upgrade path, and a URL
that carries a version number stops resolving the day the next version exists.
So the same signing job composes the repository and pushes it to the
`gh-pages` branch, which GitHub Pages serves at
`https://ultherego.github.io/Flotestro/packages/` - a plain HTTPS directory tree, which
is all apt, dnf and pacman ever ask for. `FLOTESTRO_PACKAGE_REPOSITORY_URL` set
to that address makes the commands the panel writes under "Add host" work
against the project's own packages.

The publication runs **before** the assets are attached to the release. A
missing tool, a key that cannot sign, an index that does not verify - all of it
stops while the tag can still be built again; once an asset is on the release
page the no-replacement rule has closed that door.

**The repository is added to, never rewritten.** `packaging/sign-repo.sh`
drops the new packages beside the ones already published and composes every
index again over all of them: `--multiversion` for the apt `Packages`,
`createrepo_c` over the whole channel directory for dnf. A host that still runs
1.2.3 therefore still finds 1.2.3 after 1.2.4 is published, and `apt update`
followed by `apt upgrade` is how it learns of the newer one and takes it - apt
and dnf install the highest version they can see, and pacman's database names
the newest by construction. A file already published with different bytes stops
the publication by name; identical bytes are a re-run and change nothing, so the
step is safe to repeat. The branch keeps the history of the tree itself: a bad
publication is backed out like any other commit.

**A pre-release does not reach a stable host.** `v1.2.3-rc1` publishes to the
`testing` channel - its own pool, its own `dists` suite, its own `rpm` and
`arch` directories. Nothing a stable host reads is touched, and `stable` is what
the panel writes unless somebody typed another channel.

**What the owner sets once.** GitHub Pages for this repository has to be served
from the branch `gh-pages`, at the root - the workflow pushes the branch, the
setting is what publishes it. And `RELEASE_SIGNING_KEY` has to be a key the
runner can use without a person: rpm's package signature and pacman's database
signature are made by `gpg` called from inside those tools, so a passphrase
belongs in `RELEASE_SIGNING_KEY_PASSPHRASE` beside it. Without the key there is
no repository publication at all and the run says so - an unsigned index would
be taken by apt with a warning nobody reads.

**When the publication fails after the release is out.** The repository is
composed from a finished release, so it is reproducible by hand on the machine
that holds the key:

    gh release download v1.2.3 --repo ultherego/Flotestro --dir release
    git clone --branch gh-pages https://github.com/ultherego/Flotestro repo
    packaging/sign-repo.sh release <gpg-key-id> repo 1.2.3
    git -C repo add -A && git -C repo commit -m "Publish v1.2.3" && git -C repo push

The script refuses to replace anything it finds already published, so running
it against a release that is partly there finishes the job rather than
repeating it.

**The `.rpm` in the repository is not the `.rpm` on the release page.**
`rpmsign --addsign` writes the signature into the package header, so the
repository's copy differs from the loose asset by exactly that. The loose asset
is what `SHA256SUMS` and the build attestation describe; the repository's copy
is what `rpm --checksig` and `repo_gpgcheck` describe. Both manifests travel
with the tree: `releases/<version>/` holds that release's `SHA256SUMS`, its
signature and its `provenance.json`, one directory per release and never a file
the next release overwrites.

## The laboratory gate

`.github/workflows/lab-gate.yml` records what the laboratory reports, and runs
nothing itself. After `Vagrant/test.sh` and `Vagrant/test-integration.sh` have
finished against a pushed commit:

    gh workflow run lab-gate.yml \
        -f sha=$(git rev-parse HEAD) \
        -f result=pass \
        -f report="$(cat /tmp/flotestro-lab-verdict.txt)"

The commit has to be pushed first: a status belongs to a commit the repository
knows. The workflow writes the commit status `lab-suite` - `pass` becomes
success, `fail` becomes failure - with the first line of the report as its
description and the run as its link; the whole report is kept in the run's
summary, where it is still readable a month later. The counts of the suite and
the version the laboratory runs belong in that report.

The status says as much as the owner typed. It is a signature under a run that
happened elsewhere, and it is worth exactly the care taken before typing `pass`.

## What the owner sets by hand

A workflow cannot protect a branch; these are set once in the repository
settings, under Branches, for `main`:

- require a pull request before merging, with one approving review and a review
  from a code owner (`.github/CODEOWNERS` is a list of reviewers until that box
  is ticked, not a gate);
- require the status checks `Go`, `Database`, `Panel`, `E2E smoke`, `Secrets`,
  `Known vulnerabilities` and `Bill of materials` to pass, and require branches
  to be up to date before merging;
- require the status check `lab-suite` as well before a release tag is cut. Held
  as a required check for every merge it stops every merge until the laboratory
  has run, which is honest but slow; the owner decides which of the two the pace
  of the work can carry.
- forbid force pushes and deletion of the branch, and apply the rules to
  administrators - a gate that the person holding the key walks around is a gate
  for everybody else;
- for tags: a ruleset on `v*` that forbids deletion and overwriting, because the
  release workflow refuses to replace a published artefact and a deleted tag is
  the way around that refusal.

The actions are pinned to exact versions rather than commit digests. Pinning
them to digests is stronger and is done with `gh api` against each version, one
line per action; a digest also has to be raised by hand when an action is
upgraded, which is the point of it.
