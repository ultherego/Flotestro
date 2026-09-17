package packages

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/plan"
)

func samplePlan() Plan {
	return Plan{
		Manager: "apt", Mode: ModeUpgrade,
		SchemaVersion: plan.SchemaVersion, PlannerVersion: PlannerVersion,
		HostID: "host-1", InventoryRevision: "abc", ResourceRevision: "apt:0123",
		ExpiresAt: time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Changes: []Change{
			{Name: "openssl", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
				Origin: "Debian-Security:12/stable-security", Architecture: "amd64", Action: ActionUpgrade},
			{Name: "libssl3", CurrentVersion: "3.0.15-1", CandidateVersion: "3.0.16-1",
				Origin: "Debian-Security:12/stable-security", Architecture: "amd64", Action: ActionUpgrade},
		},
		Rollback: Rollback{Mechanism: RollbackNone, Reason: "apt keeps no transaction to undo"},
	}
}

// The digest is the digest of the envelope: the architecture, the origin
// and the direction of every element enter it, the order of the elements
// does not.
func TestPlanHashCoversArchitectureOriginAndDirection(t *testing.T) {
	reference := hex.EncodeToString(samplePlan().Hash())
	if reference == "" {
		t.Fatal("the plan cannot be hashed")
	}
	other := samplePlan()
	other.Changes[0].Architecture = "i386"
	if hex.EncodeToString(other.Hash()) == reference {
		t.Error("another architecture did not change the digest")
	}
	other = samplePlan()
	other.Changes[1].Origin = "Debian:12/stable"
	if hex.EncodeToString(other.Hash()) == reference {
		t.Error("another origin did not change the digest")
	}
	other = samplePlan()
	other.Changes[1].Action = ActionDowngrade
	if hex.EncodeToString(other.Hash()) == reference {
		t.Error("another direction did not change the digest")
	}
	other = samplePlan()
	other.Changes[0], other.Changes[1] = other.Changes[1], other.Changes[0]
	if hex.EncodeToString(other.Hash()) != reference {
		t.Error("the order of the elements changed the digest")
	}
}

// The envelope names an artifact and an effect for every element, and the
// steps carry the exact spec of the tool.
func TestEnvelopeAndExactSpecs(t *testing.T) {
	p := samplePlan()
	p.Changes = append(p.Changes, Change{Name: "old-tool", CurrentVersion: "1.0", Action: ActionRemove})
	envelope := p.Envelope()
	if envelope.ActionType != "packages.upgrade" || envelope.PlannerVersion != PlannerVersion {
		t.Errorf("header = %+v", envelope)
	}
	if len(envelope.Artifacts) != 2 || len(envelope.Effects.Expected) != 3 || len(envelope.Steps) != 3 {
		t.Errorf("artifacts %d, effects %d, steps %d", len(envelope.Artifacts), len(envelope.Effects.Expected), len(envelope.Steps))
	}
	specs := p.ExactSpecs()
	if len(specs) != 2 || specs[0] != "libssl3:amd64=3.0.16-1" || specs[1] != "openssl:amd64=3.0.16-1" {
		t.Errorf("apt specs = %v", specs)
	}
	if p.HasDowngrade() {
		t.Error("an upgrade plan reports a downgrade")
	}
	if got := exactSpec("dnf", Change{Name: "tree", CandidateVersion: "2.2.1-1.fc42", Architecture: "x86_64"}); got != "tree-2.2.1-1.fc42.x86_64" {
		t.Errorf("dnf spec = %s", got)
	}
	if got := exactSpec("apt", Change{Name: "libc6:i386", CandidateVersion: "2.36-9", Architecture: "i386"}); got != "libc6:i386=2.36-9" {
		t.Errorf("apt multiarch spec = %s", got)
	}
	if ids := p.RepositoryIDs(); len(ids) != 1 || ids[0] != "Debian-Security:12/stable-security" {
		t.Errorf("repositories = %v", ids)
	}
}

func TestAptInstLineCarriesTheArchitectureApartFromTheOrigin(t *testing.T) {
	change, ok := parseAptInstLine("Inst openssl [3.0.15-1~deb12u1] (3.0.16-1~deb12u1 Debian-Security:12/stable-security [amd64])")
	if !ok {
		t.Fatal("the line was not read")
	}
	if change.Origin != "Debian-Security:12/stable-security" || change.Architecture != "amd64" {
		t.Errorf("origin = %q, architecture = %q", change.Origin, change.Architecture)
	}
	if !change.Security || change.CurrentVersion != "3.0.15-1~deb12u1" || change.CandidateVersion != "3.0.16-1~deb12u1" {
		t.Errorf("change = %+v", change)
	}
	// Two origins are printed with a comma; both stay in the origin.
	change, _ = parseAptInstLine("Inst libfoo (1.0-2 Debian:12/stable, Debian-Security:12/stable-security [amd64])")
	if change.Origin != "Debian:12/stable, Debian-Security:12/stable-security" || change.Architecture != "amd64" || change.CurrentVersion != "" {
		t.Errorf("change = %+v", change)
	}
}

func TestAptPrintURIsGiveTheSizesAndTheDigests(t *testing.T) {
	output := "'http://deb.debian.org/debian-security/pool/updates/main/o/openssl/openssl_3.0.16-1~deb12u1_amd64.deb' openssl_3.0.16-1~deb12u1_amd64.deb 1456 SHA256:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08\n" +
		"'http://deb.debian.org/debian-security/pool/updates/main/o/openssl/libssl3_3.0.16-1~deb12u1_amd64.deb' libssl3_3.0.16-1~deb12u1_amd64.deb 2000 SHA256:abcd\n"
	total, digests := ParseAPTPrintURIs(output)
	if total != 3456 {
		t.Errorf("total = %d", total)
	}
	if digests["openssl"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" || digests["libssl3"] != "sha256:abcd" {
		t.Errorf("digests = %v", digests)
	}
}

func TestDNFInstallPlanCarriesArchitectureVersionRepositoryAndDirection(t *testing.T) {
	output := `Package        Arch   Version         Repository  Size
Installing:
 nginx         x86_64 1.26.2-1.fc42   updates    1.6 MiB
Installing dependencies:
 nginx-core    x86_64 1.26.2-1.fc42   updates    1.4 MiB
Upgrading:
 openssl       x86_64 1:3.2.4-1.fc42  updates    2.0 MiB
Downgrading:
 curl          x86_64 8.11.0-1.fc42   fedora     300 KiB

Transaction Summary:
 Installing:         2 packages
`
	changes := ParseDNFInstallPlan(output)
	if len(changes) != 4 {
		t.Fatalf("read %d changes: %+v", len(changes), changes)
	}
	byName := map[string]Change{}
	for _, change := range changes {
		byName[change.Name] = change
	}
	nginx := byName["nginx"]
	if nginx.Architecture != "x86_64" || nginx.CandidateVersion != "1.26.2-1.fc42" || nginx.Origin != "updates" ||
		nginx.Action != ActionInstall || nginx.Reason != ReasonRequested {
		t.Errorf("nginx = %+v", nginx)
	}
	if byName["nginx-core"].Reason != ReasonDependency {
		t.Errorf("nginx-core = %+v", byName["nginx-core"])
	}
	if byName["openssl"].Action != ActionUpgrade || byName["openssl"].CandidateVersion != "1:3.2.4-1.fc42" {
		t.Errorf("openssl = %+v", byName["openssl"])
	}
	if byName["curl"].Action != ActionDowngrade || byName["curl"].Origin != "fedora" {
		t.Errorf("curl = %+v", byName["curl"])
	}
}

func TestDNFUpdateLineCarriesTheArchitecture(t *testing.T) {
	change, ok := parseDNFUpdateLine("NetworkManager.x86_64   1:1.52.2-1.fc42   updates")
	if !ok || change.Name != "NetworkManager" || change.Architecture != "x86_64" ||
		change.CandidateVersion != "1:1.52.2-1.fc42" || change.Origin != "updates" {
		t.Errorf("change = %+v, ok = %v", change, ok)
	}
}

func TestPacmanTargetsCarryTheLocationAndTheArchitecture(t *testing.T) {
	output := "linux\t6.16.6.arch1-1\tcore\t150000000\thttps://mirror/core/os/x86_64/linux-6.16.6.arch1-1-x86_64.pkg.tar.zst\n" +
		"which\t2.23-2\tcore\t17000\n"
	targets := ParsePacmanTargets(output)
	if targets["linux"].File() != "linux-6.16.6.arch1-1-x86_64.pkg.tar.zst" || targets["linux"].Architecture() != "x86_64" {
		t.Errorf("linux = %+v", targets["linux"])
	}
	if targets["which"].File() != "" || targets["which"].Architecture() != "" {
		t.Errorf("a target without a location = %+v", targets["which"])
	}
}

func TestPacmanInfoCarriesArchitectureAndChecksum(t *testing.T) {
	output := `Repository      : core
Name            : linux
Version         : 6.16.6.arch1-1
Architecture    : x86_64
Installed Size  : 143.39 MiB
SHA-256 Sum     : 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
Signatures      : Yes

Repository      : core
Name            : which
Architecture    : x86_64
Installed Size  : 30.00 KiB
SHA-256 Sum     : None
`
	info := ParsePacmanInfo(output)
	if info["linux"].Architecture != "x86_64" || info["linux"].SHA256 != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" ||
		info["linux"].InstalledSize == 0 {
		t.Errorf("linux = %+v", info["linux"])
	}
	if info["which"].SHA256 != "" || info["which"].InstalledSize == 0 {
		t.Errorf("which = %+v", info["which"])
	}
	if sizes := ParsePacmanInfoSizes(output); sizes["which"] != info["which"].InstalledSize {
		t.Errorf("sizes = %v", sizes)
	}
}
