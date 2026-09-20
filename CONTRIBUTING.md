# Contributing

## What this is built from

Go for the control plane, the agent, the root helper and the relay; React and
TypeScript for the panel; PostgreSQL for everything the panel remembers. The
versions are the ones the build uses: `go.mod` for Go and `web/.nvmrc` for
Node. Nothing else is needed to build it.

```
make build          the control plane, the agent and the audit verifier
make test           the Go unit tests
make generate       the protobuf code, after api/proto has changed
make lint tidy      go vet, and go mod tidy
```

## The tests, and which of them you can run

**Unit tests** run anywhere: `go test ./...`. They need no database and no
host, and they are the ones CI runs on every push.

**`tests/integration`** carries the `integration` build tag and needs a live
fleet: a control plane, a database and agents on real machines of each family.
It is not runnable from a clean checkout, and that is deliberate — it tests
apt, dnf and pacman against the actual package managers, which cannot be
faked usefully. CI compiles it (`go vet -tags=integration ./tests/...`) so it
cannot rot, and runs it nowhere.

**`tests/e2e/smoke.sh`** starts a control plane against a throwaway database,
orders an enrollment and checks the panel answers. It runs in CI on every
push and needs only Docker.

## What CI checks

`.github/workflows/ci.yml` is the gate. It builds, vets, runs the unit tests,
compiles the integration suite, runs the panel's own tests and the end-to-end
smoke, checks formatting with `gofmt -l`, and refuses a change that leaves the
tree unformatted. `images.yml` builds the container images and parses every
compose file under every profile. `release.yml` runs on a tag: it builds the
packages for both architectures, attests what produced them, signs the
checksums in a separate job that never sees the build runner, and publishes
the apt, dnf and pacman repositories.

A change that does not pass locally will not pass there. Run `gofmt -l` and
`go test ./...` before you push; everything else CI will tell you.

## The conventions this code actually holds to

These are not style preferences. They are the product's contract with the
operator, and a change that breaks one of them is a bug however well it reads.

**Unknown is never zero.** A fact the agent could not read is reported as
unknown, with a typed reason, and never rounded into a clean number. A fleet
view that could not reach every host says so and carries its denominator. A
host that cannot answer is a host that cannot answer — not a host with nothing
wrong.

**Every refusal carries a stable code.** A new way to refuse means a new code,
an entry in `internal/opspec/errors.go` giving its meaning and what to do
about it, and an entry in `docs/site/docs/errors.html`. A test fails if the
two disagree, because an operator who meets a code in the panel has to be able
to look it up.

**A change is not done until the host says so.** Every mutating operation
declares a verifier, the agent re-reads the host after the change, and a
result that does not match what was ordered becomes `applied_unverified`
rather than a success. Where the host cannot be read, that is unknown — not a
pass.

**Fail closed.** When the answer is not established, refuse with a reason.

**Comments say why, in one or two lines.** The code says what it does. A
comment that restates it is noise; a comment that explains the decision behind
it is worth keeping. Anything longer than two lines belongs in the commit
message, which is where this project keeps its reasoning.

**English throughout** — identifiers, comments, messages, test names. The
panel's strings go through `web/src/i18n`, English as the base and Polish
beside it; a test fails on a key with no translation.

**N-1 compatibility.** An agent one release behind keeps working, or the
change announces itself through a capability the panel checks before it relies
on it.

## Commits

Write what changed and why it was wrong before. The subject is a sentence in
the imperative; the body is prose, not a list of files. If you found the
problem by measuring something, say what you measured — the next person to
touch that code will want to know whether you guessed.

## Reporting a security problem

Not here. See [SECURITY.md](SECURITY.md).
