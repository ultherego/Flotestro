# The checks a change passes

Every push to `main` and every pull request runs `.github/workflows/ci.yml`.
Six jobs run side by side; the pull request waits for the slowest of them, not
for their sum. Nothing in them sends the sources, the logs or the test output
anywhere: the runner downloads its tools and the module cache, and publishes
nothing.

Two things cannot run on a runner. The integration suite carries the build tag
`integration` and drives the fleet - the panel, the database, the relay and the
hosts with the agent - and the Playwright screenshots drive the panel of the
laboratory. Their verdict reaches a commit through a separate workflow the owner
triggers by hand, described under [The laboratory gate](#the-laboratory-gate).

## What runs

| Check | What it proves | Roughly | Required |
|---|---|---|---|
| `Go` | `gofmt`, `go vet ./...`, `go vet -tags=integration ./tests/...`, `go build ./...` and `go test -race -shuffle=on -count=1 ./...` | 8-14 min | yes |
| `Database` | Every migration applies in order to an empty `postgres:17`, the recorded versions match the files, and a second pass applies nothing and changes no schema | 2-4 min | yes |
| `Panel` | `npm ci`, the Polish catalogue, `tsc -b && vite build`, `vitest run` | 3-5 min | yes |
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

The control plane applies the migrations itself at start and has no flag that
applies them and exits, so the job cannot simply run the binary without also
giving it a state directory, a secret key and a certificate authority. If such a
flag is ever added to `cmd/control-plane`, the step becomes one call to the
binary and stops being a second implementation of the same loop.

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

**The tag belongs to the default branch.** A tag can be pushed from anywhere,
and an artefact built from a commit nobody reviewed is worth nothing whatever
signs it. The first step of the release refuses a tag whose commit the default
branch does not contain: merge first, then tag the merge. An unsigned tag is
reported in the job summary rather than refused - tag signing is a repository
setting the workflow cannot turn on, and refusing would block a release the
owner never configured for it.

**Nothing is replaced.** The upload refuses an asset the release already holds
and names it; there is no `--clobber`. A release is corrected by a new version,
not by a new file under the old name.

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
- require the status checks `Go`, `Database`, `Panel`, `Secrets` and
  `Known vulnerabilities` to pass, and require branches to be up to date before
  merging;
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
