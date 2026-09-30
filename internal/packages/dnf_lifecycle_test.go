package packages

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/plan"
)

// dnf5RemovalOutput is the real output of "dnf remove --assumeno" from Fedora
// 42: the table of a transaction interrupted before execution.
const dnf5RemovalOutput = `Package      Arch   Version       Repository      Size
Removing:
 restic      x86_64 0.18.1-1.fc42 updates     45.3 MiB
Removing unused dependencies:
 fuse        x86_64 2.9.9-23.fc42 fedora     222.5 KiB
 fuse-common x86_64 3.16.2-6.fc42 updates     38.0   B

Transaction Summary:
 Removing:           3 packages

After this operation, 46 MiB will be freed (install 0 B, remove 46 MiB).
Operation aborted by the user.
`

// dnf4RemovalOutput has different headings and a different summary.
const dnf4RemovalOutput = `Dependencies resolved.
================================================================================
 Package              Arch        Version            Repository           Size
================================================================================
Removing:
 httpd                x86_64      2.4.62-1.el9       @appstream          4.9 M
Removing dependent packages:
 mod_ssl              x86_64      1:2.4.62-1.el9     @appstream          256 k
Removing unused dependencies:
 apr                  x86_64      1.7.0-12.el9       @appstream          290 k

Transaction Summary
================================================================================
Remove  3 Packages

Freed space: 5.4 M
Operation aborted.
`

func TestParseDNFRemovalPlanReadsEverySection(t *testing.T) {
	removals, announced, err := ParseDNFRemovalPlan(dnf5RemovalOutput)
	if err != nil {
		t.Fatalf("ParseDNFRemovalPlan: %v", err)
	}
	if len(removals) != 3 {
		t.Fatalf("read %d packages: %v", len(removals), removals)
	}
	// A named package and a package left without a user mean different things
	// to a person - but both disappear, so both have to be on the list.
	expected := map[string]bool{"restic": true, "fuse": true, "fuse-common": true}
	for _, name := range removals {
		if !expected[name] {
			t.Errorf("an unexpected package %q", name)
		}
	}
	if announced != 3 {
		t.Errorf("dnf announced %d packages", announced)
	}
}

func TestParseDNFRemovalPlanAlsoReadsTheOlderFormat(t *testing.T) {
	removals, announced, err := ParseDNFRemovalPlan(dnf4RemovalOutput)
	if err != nil {
		t.Fatalf("ParseDNFRemovalPlan: %v", err)
	}
	if len(removals) != 3 {
		t.Fatalf("read %d packages: %v", len(removals), removals)
	}
	// The dependent package matters most here: it is what turns the removal of
	// one thing into the removal of something nobody thought about.
	found := false
	for _, name := range removals {
		if name == "mod_ssl" {
			found = true
		}
	}
	if !found {
		t.Errorf("the dependent package did not land on the list: %v", removals)
	}
	// The number from the summary is the only guard against an incomplete read,
	// so it has to be read in the older format as well - the line there says
	// "Remove 3 Packages", without a colon.
	if announced != 3 {
		t.Fatalf("dnf4 announced %d packages", announced)
	}
}

func TestAMissingDNFPackageIsNotAnError(t *testing.T) {
	// "There is nothing to remove" is an answer rather than a failure of the
	// plan.
	if !DNFPackageMissing("No match for argument: no-such-package\nNothing to do.") {
		t.Fatal("a missing package was treated as an error")
	}
	if DNFPackageMissing(dnf5RemovalOutput) {
		t.Fatal("a correct plan was treated as a missing package")
	}
}

func TestParseDNFInstallPlan(t *testing.T) {
	output := `Package        Arch   Version         Repository  Size
Installing:
 nginx         x86_64 1.26.2-1.fc42   updates    1.6 MiB
Installing dependencies:
 nginx-core    x86_64 1.26.2-1.fc42   updates    1.4 MiB
 nginx-filesystem noarch 1.26.2-1.fc42 updates   1.0 KiB

Transaction Summary:
 Installing:         3 packages
`
	changes := ParseDNFInstallPlan(output)
	if len(changes) != 3 {
		t.Fatalf("read %d changes: %+v", len(changes), changes)
	}
	if changes[0].Name != "nginx" {
		t.Errorf("the first change = %+v", changes[0])
	}
}

func TestParseVersionlockReadsBothFormats(t *testing.T) {
	dnf5 := "# Added by 'versionlock add' command on 2026-09-05 16:14:05\n" +
		"Package name: restic\nevr = 0.18.1-1.fc42\n"
	if names := ParseVersionlock(dnf5); len(names) != 1 || names[0] != "restic" {
		t.Fatalf("dnf5: read %v", names)
	}

	// A line about metadata is not a lock. Shown as the name of a package it
	// would tell the operator that something that does not exist was held.
	dnf4 := "Last metadata expiration check: 0:00:12 ago on Sat 05 Sep 2026.\n" +
		"restic-0:0.18.1-1.fc42.*\nkernel-0:6.11.4-201.fc41.*\n"
	names := ParseVersionlock(dnf4)
	if len(names) != 2 {
		t.Fatalf("dnf4: read %v, expected exactly two locks", names)
	}
	if names[0] != "restic" || names[1] != "kernel" {
		t.Fatalf("dnf4: read %v", names)
	}

	// A name with a dash and a package without an epoch are valid entries as
	// well.
	compound := ParseVersionlock("python3-dnf-plugin-versionlock-0:4.5.0-1.fc42.*\n" +
		"tree-2.2.1-1.fc42.*\n")
	if len(compound) != 2 || compound[0] != "python3-dnf-plugin-versionlock" || compound[1] != "tree" {
		t.Fatalf("read %v", compound)
	}
}

func TestAnInstallationPlanDoesNotStaySilentAboutARefusal(t *testing.T) {
	// A package that is in no source must not end with an empty plan: an empty
	// plan reads as "nothing needs to be added".
	if !DNFPackageMissing("Unable to find a match: no-such-package") {
		t.Fatal("a missing package was not recognised")
	}
	// "nothing to do" during an installation, on the other hand, means
	// everything is already there.
	if !WholeTransactionReady("Package tree-2.2.1-1.fc42.x86_64 is already installed.\nNothing to do.") {
		t.Fatal("a ready transaction was not recognised")
	}
	if WholeTransactionReady(dnf5RemovalOutput) {
		t.Fatal("an ordinary transaction table was treated as ready")
	}
}

func TestAnUnresolvableTransactionIsNotAnEmptyPlan(t *testing.T) {
	// The real answer of dnf5 to an attempt to remove systemd from Fedora 42.
	output := `Failed to resolve the transaction:
Problem: installed package kernel-core-6.17.4-200.fc42.x86_64 requires systemd >= 200, but none of the providers can be installed
  - conflicting requests
  - problem with installed package
`
	reason := DNFUnresolvable(output)
	if reason == "" {
		t.Fatal("a refusal of dnf was read as an empty plan")
	}
	if !strings.Contains(reason, "kernel-core") {
		t.Errorf("the reason does not say what cannot be reconciled: %q", reason)
	}
	// A correct transaction table must not be treated as a refusal.
	if DNFUnresolvable(dnf5RemovalOutput) != "" {
		t.Fatal("a correct plan was treated as a refusal")
	}
}

// dnf5UpgradeOutput is the table of "dnf upgrade --assumeno" on Fedora 42: an
// upgrade that also installs a dependency, replaces an obsolete package, lowers
// one version and drops the kernel the new one leaves behind. The replaced
// package stands where dnf5 really puts it - indented under the package that
// takes its place, in the columns of the table.
const dnf5UpgradeOutput = `Updating and loading repositories:
Repositories loaded.
Package                               Arch   Version         Repository            Size
Upgrading:
 NetworkManager                       x86_64 1:1.52.2-1.fc42 updates            2.3 MiB
 openssl                              x86_64 1:3.2.4-1.fc42  updates-security   1.1 MiB
Installing:
 kernel-core                          x86_64 6.17.4-200.fc42 updates           16.0 MiB
 python3-setuptools                   noarch 69.0.3-8.fc42   updates            1.6 MiB
   replacing python3-setuptools-wheel noarch 53.0.0-13.fc42  anaconda         480.0 KiB
Installing dependencies:
 libnvme                              x86_64 1.11.1-1.fc42   fedora           112.0 KiB
Downgrading:
 curl                                 x86_64 8.11.0-1.fc42   fedora           300.0 KiB
Removing:
 kernel-core                          x86_64 6.15.9-200.fc42 updates           16.0 MiB

Transaction Summary:
 Installing:          3 packages
 Upgrading:           2 packages
 Replacing:           1 package
 Downgrading:         1 package
 Removing:            1 package

Total size of inbound packages is 21 MiB. Need to download 21 MiB.
After this operation, 3 MiB extra will be used (install 40 MiB, remove 37 MiB).
Operation aborted by the user.
`

// dnf4UpgradeOutput is the same kind of transaction in the older spelling: the
// obsoleting package heads a section of its own, and the package it replaces
// stands under it as one token of name and architecture, then a version.
const dnf4UpgradeOutput = `Last metadata expiration check: 0:05:00 ago on Sat 27 Sep 2026.
Dependencies resolved.
================================================================================
 Package               Arch     Version              Repository           Size
================================================================================
Upgrading:
 NetworkManager        x86_64   1:1.52.2-1.el9       updates            2.3 M
Installing dependencies:
 libnvme               x86_64   1.11.1-1.el9         baseos             112 k
Downgrading:
 curl                  x86_64   8.11.0-1.el9         baseos             300 k
Removing:
 kernel-core           x86_64   5.14.0-503.el9       @baseos             16 M
Obsoleting:
 python3-setuptools    noarch   69.0.3-8.el9         appstream          1.6 M
     replacing  python3-setuptools-wheel.noarch 53.0.0-13.el9

Transaction Summary
================================================================================
Install     2 Packages
Upgrade     1 Package
Remove      1 Package
Downgrade   1 Package

Total download size: 21 M
Installed size: 40 M
Operation aborted.
`

// A list of direct updates does not describe the transaction being approved:
// the dependency, the replacement, the downgrade and the removal are exactly
// what the operator would never see, so all of them are read with their
// repositories.
func TestDNFUpgradePlanCarriesTheWholeTransaction(t *testing.T) {
	changes, err := ParseDNFUpgradePlan(dnf5UpgradeOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	if len(changes) != 8 {
		t.Fatalf("read %d changes: %+v", len(changes), changes)
	}
	type element struct{ action, version, origin, reason string }
	expected := map[string]element{
		"NetworkManager": {ActionUpgrade, "1:1.52.2-1.fc42", "updates", ReasonRequested},
		"openssl":        {ActionUpgrade, "1:3.2.4-1.fc42", "updates-security", ReasonRequested},
		"libnvme":        {ActionInstall, "1.11.1-1.fc42", "fedora", ReasonDependency},
		// The obsoleting package arrives; the one it replaces is the removal, with
		// the name, the architecture and the version of its own line.
		"python3-setuptools":       {ActionInstall, "69.0.3-8.fc42", "updates", ReasonRequested},
		"python3-setuptools-wheel": {ActionRemove, "53.0.0-13.fc42", "anaconda", ReasonOrphan},
		"curl":                     {ActionDowngrade, "8.11.0-1.fc42", "fedora", ReasonRequested},
	}
	for _, change := range changes {
		// The replaced package is written on a line of its own shape; read as a row
		// of the table it would be a package called "replacing".
		if change.Name == "replacing" {
			t.Fatalf("the replaced package read as a package of its own: %+v", change)
		}
		want, named := expected[change.Name]
		if !named {
			continue
		}
		delete(expected, change.Name)
		version := change.CandidateVersion
		if change.Action == ActionRemove {
			version = change.CurrentVersion
		}
		if change.Action != want.action || version != want.version ||
			change.Origin != want.origin || change.Reason != want.reason {
			t.Errorf("%s = %+v, expected %+v", change.Name, change, want)
		}
		if change.Architecture == "" {
			t.Errorf("%s carries no architecture: %+v", change.Name, change)
		}
	}
	if len(expected) > 0 {
		t.Errorf("the plan does not name %v", expected)
	}
	// The kernel arrives and the old one goes in the same transaction, under one
	// name: a plan that read it once would promise the disk of one and free the
	// space of neither.
	var kernels []Change
	for _, change := range changes {
		if change.Name == "kernel-core" {
			kernels = append(kernels, change)
		}
	}
	if len(kernels) != 2 {
		t.Fatalf("the two kernels of the transaction read as %+v", kernels)
	}
	// The table publishes no checksum, so every arriving package says so rather
	// than leaving the field empty.
	for _, change := range changes {
		if change.Action == ActionRemove {
			if change.Digest != "" {
				t.Errorf("%s goes away and carries an artefact: %q", change.Name, change.Digest)
			}
			continue
		}
		if change.Digest != DNFDigestUnknown {
			t.Errorf("%s carries the digest %q", change.Name, change.Digest)
		}
	}
}

// The older spelling says the same things differently: the replaced package has
// no section of its own, and reading its line as a row of the table would put a
// package called "replacing" into the plan.
func TestDNFUpgradePlanReadsTheOlderFormat(t *testing.T) {
	changes, err := ParseDNFUpgradePlan(dnf4UpgradeOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	byName := map[string]Change{}
	for _, change := range changes {
		if change.Name == "replacing" {
			t.Fatalf("the replaced package read as a package of its own: %+v", change)
		}
		byName[change.Name] = change
	}
	if len(changes) != 6 {
		t.Fatalf("read %d changes: %+v", len(changes), changes)
	}
	// The obsoleting package arrives from a repository; the one it replaces goes
	// away, and neither is in the list of direct updates.
	if obsoleting := byName["python3-setuptools"]; obsoleting.Action != ActionInstall ||
		obsoleting.Origin != "appstream" || obsoleting.Reason != ReasonDependency {
		t.Errorf("the obsoleting package = %+v", obsoleting)
	}
	replaced := byName["python3-setuptools-wheel"]
	if replaced.Action != ActionRemove || replaced.Architecture != "noarch" ||
		replaced.CurrentVersion != "53.0.0-13.el9" || replaced.Reason != ReasonOrphan {
		t.Errorf("the replaced package = %+v", replaced)
	}
	if removed := byName["kernel-core"]; removed.Action != ActionRemove || removed.Origin != "@baseos" {
		t.Errorf("the removed kernel = %+v", removed)
	}
	if dependency := byName["libnvme"]; dependency.Reason != ReasonDependency ||
		dependency.CandidateVersion != "1.11.1-1.el9" {
		t.Errorf("the dependency = %+v", dependency)
	}
}

// Output the agent does not recognise is a refusal with the code of a plan that
// could not be read. A partial plan would be approved for a transaction nobody
// saw.
func TestAnUnreadableDNFTransactionTableIsRefused(t *testing.T) {
	for name, output := range map[string]string{
		"another format entirely": "Updating and loading repositories:\nRepositories loaded.\n" +
			"willi 1 2 3 4\n",
		"a table read short": strings.Replace(dnf5UpgradeOutput,
			" Installing:          3 packages", " Installing:          9 packages", 1),
		"a row without a repository": strings.Replace(dnf5UpgradeOutput,
			" libnvme                              x86_64 1.11.1-1.fc42   fedora           112.0 KiB",
			" libnvme                              x86_64 1.11.1-1.fc42   <unknown>        112.0 KiB", 1),
		// A replaced package the agent cannot name is not a line to skip: skipping
		// it would hide a removal from the operator who approves the plan.
		"a replaced package in neither shape": strings.Replace(dnf5UpgradeOutput,
			"   replacing python3-setuptools-wheel noarch 53.0.0-13.fc42  anaconda         480.0 KiB",
			"   replacing python3-setuptools-wheel", 1),
	} {
		changes, err := ParseDNFUpgradePlan(output)
		if err == nil {
			t.Errorf("%s was accepted as a plan: %+v", name, changes)
			continue
		}
		if len(changes) != 0 {
			t.Errorf("%s was refused and still gave %d changes", name, len(changes))
		}
		if !errors.Is(err, ErrPlanMetadataMissing) {
			t.Errorf("%s = %v, expected the refusal of a plan that cannot be read", name, err)
		}
		if code, ok := ErrorCodeOf(err); !ok || code != ErrorPlanMetadataMissing {
			t.Errorf("%s: the code of the refusal is %q, %v", name, code, ok)
		}
		if !Refused(err) {
			t.Errorf("%s was counted as a failed transaction", name)
		}
	}
	// A host whose pending updates are all held or excluded has nothing to
	// change: that is an empty plan rather than an unread table.
	changes, err := ParseDNFUpgradePlan("Package flotestro-agent-0.62.0-1.fc42.x86_64 is already installed.\n" +
		"Nothing to do.\n")
	if err != nil || len(changes) != 0 {
		t.Errorf("a transaction with nothing to do = %+v, %v", changes, err)
	}
}

// The table says nothing about the state of the host or about advisories, so
// the plan takes the version installed now and the security flag from there;
// the protected package an upgrade drops is marked on the element rather than
// refusing an upgrade whose whole point is to replace an old kernel.
func TestDNFUpgradePlanCompletesTheChangesFromTheHost(t *testing.T) {
	changes, err := ParseDNFUpgradePlan(dnf5UpgradeOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	installed := parseInstalledRPM(strings.Join([]string{
		"NetworkManager x86_64 1:1.52.1-1.fc42",
		"openssl x86_64 1:3.2.3-1.fc42",
		"curl x86_64 8.12.1-1.fc42",
		"kernel-core x86_64 6.15.9-200.fc42",
	}, "\n"))
	completeDNFChanges(changes, installed,
		[]Change{{Name: "openssl", Architecture: "x86_64", Security: true}})

	byName := map[string]Change{}
	for _, change := range changes {
		if change.Action != ActionRemove {
			byName[change.Name] = change
		}
	}
	if byName["NetworkManager"].CurrentVersion != "1:1.52.1-1.fc42" {
		t.Errorf("NetworkManager = %+v", byName["NetworkManager"])
	}
	// A downgrade is only recognisable next to what is installed now.
	if byName["curl"].CurrentVersion != "8.12.1-1.fc42" {
		t.Errorf("curl = %+v", byName["curl"])
	}
	// A package that arrives has no version on the host, and that is not an
	// unread one.
	if byName["libnvme"].CurrentVersion != "" {
		t.Errorf("a new dependency was given a current version: %+v", byName["libnvme"])
	}
	if !byName["openssl"].Security || byName["NetworkManager"].Security {
		t.Errorf("the advisories were carried as %+v / %+v", byName["openssl"], byName["NetworkManager"])
	}

	finished := finishPlan(context.Background(), &DNF{},
		Plan{Manager: "dnf", Mode: ModeUpgrade, Changes: changes}, Options{Mode: ModeUpgrade})
	var dropped Change
	for _, change := range finished.Changes {
		if change.Name == "kernel-core" && change.Action == ActionRemove {
			dropped = change
		}
	}
	if dropped.CurrentVersion != "6.15.9-200.fc42" || !dropped.Protected {
		t.Errorf("the kernel the transaction drops = %+v", dropped)
	}
	// The list that refuses the whole transaction stays empty: the kernel does
	// not disappear from this host, it is replaced.
	if len(finished.Protected) != 0 {
		t.Errorf("an ordinary kernel upgrade would be refused over %v", finished.Protected)
	}
	// What the operator reads before consenting names every direction.
	description := finished.Description()
	for _, word := range []string{"install", "upgrade", "downgrade", "remove"} {
		if !strings.Contains(description, word) {
			t.Errorf("the plan reads %q and does not name %s", description, word)
		}
	}
}

// dnf5ObsoletingOutput is the answer of dnf5 5.2.18 on Fedora 42, byte for
// byte: a package that obsoletes three installed ones, next to an ordinary
// installation. dnf5 writes each replaced package in the columns of the table,
// under the package that takes its place, and counts them in the summary.
const dnf5ObsoletingOutput = `Updating and loading repositories:
Repositories loaded.
Package                      Arch   Version          Repository        Size
Installing:
 flotestro-probe             noarch 2.0-1.fc42       @commandline   0.0   B
   replacing tree            x86_64 2.2.1-1.fc42     fedora       112.2 KiB
   replacing vim-minimal     x86_64 2:9.2.390-1.fc42 <unknown>      1.7 MiB
   replacing words           noarch 3.0-61.fc42      anaconda       4.7 MiB
 nginx                       x86_64 2:1.30.1-1.fc42  updates      123.6 KiB
Installing dependencies:
 fedora-logos-httpd          noarch 42.0.1-1.fc42    fedora        12.1 KiB
 gperftools-libs             x86_64 2.15-5.fc42      fedora         1.4 MiB
 libunwind                   x86_64 1.8.1-2.fc42     fedora       194.1 KiB
 nginx-core                  x86_64 2:1.30.1-1.fc42  updates        1.9 MiB
 nginx-filesystem            noarch 2:1.30.1-1.fc42  updates      141.0   B
 nginx-mimetypes             noarch 2.1.54-8.fc42    fedora        46.6 KiB
Installing weak dependencies:
 julietaula-montserrat-fonts noarch 1:9.000-2.fc42   updates        5.6 MiB

Transaction Summary:
 Installing:         9 packages
 Replacing:          3 packages

Total size of inbound packages is 3 MiB. Need to download 3 MiB.
After this operation, 3 MiB extra will be used (install 9 MiB, remove 7 MiB).
Operation aborted by the user.
`

// dnf4ObsoletingOutput is the same transaction through dnf4 on the same host:
// the replaced package is one token of name and architecture, then a version,
// and no summary counts it.
const dnf4ObsoletingOutput = `Last metadata expiration check: 0:00:09 ago on Mon 28 Sep 2026 02:36:15 PM UTC.
Dependencies resolved.
================================================================================
 Package               Architecture Version            Repository          Size
================================================================================
Installing:
 flotestro-probe       noarch       2.0-1.fc42         @commandline       6.2 k
     replacing  tree.x86_64 2.2.1-1.fc42
     replacing  vim-minimal.x86_64 2:9.2.390-1.fc42
     replacing  words.noarch 3.0-61.fc42

Transaction Summary
================================================================================
Install  1 Package

Total size: 6.2 k
Operation aborted.
`

// A replaced package becomes a removal, so reading its line wrongly removes the
// wrong thing. Both generations write that line their own way, and the plan has
// to carry the same three packages out of either.
func TestDNFReadsTheReplacedPackageOfBothGenerations(t *testing.T) {
	for generation, output := range map[string]string{
		"dnf5": dnf5ObsoletingOutput,
		"dnf4": dnf4ObsoletingOutput,
	} {
		changes, err := ParseDNFUpgradePlan(output)
		if err != nil {
			t.Fatalf("%s: ParseDNFUpgradePlan: %v", generation, err)
		}
		byName := map[string]Change{}
		for _, change := range changes {
			if change.Name == "replacing" {
				t.Fatalf("%s: the replaced package read as a package of its own: %+v", generation, change)
			}
			byName[change.Name] = change
		}
		replaced := map[string][2]string{
			"tree":        {"x86_64", "2.2.1-1.fc42"},
			"vim-minimal": {"x86_64", "2:9.2.390-1.fc42"},
			"words":       {"noarch", "3.0-61.fc42"},
		}
		for name, want := range replaced {
			change, named := byName[name]
			if !named {
				t.Errorf("%s: the plan does not name the replaced %s", generation, name)
				continue
			}
			// The version is what an operator compares against the host, and the
			// architecture is what tells two builds of one name apart.
			if change.Action != ActionRemove || change.Architecture != want[0] ||
				change.CurrentVersion != want[1] || change.Reason != ReasonOrphan {
				t.Errorf("%s: the replaced %s = %+v, expected a removal of %v", generation, name, change, want)
			}
			if change.CandidateVersion != "" {
				t.Errorf("%s: %s goes away and carries a candidate %q", generation,
					name, change.CandidateVersion)
			}
		}
		if obsoleting := byName["flotestro-probe"]; obsoleting.Action != ActionInstall ||
			obsoleting.CandidateVersion != "2.0-1.fc42" {
			t.Errorf("%s: the obsoleting package = %+v", generation, obsoleting)
		}
	}
	// dnf5 names the repository the replaced package came from; dnf4 writes none,
	// and an unnamed repository does not refuse a removal.
	changes, err := ParseDNFUpgradePlan(dnf5ObsoletingOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	for _, change := range changes {
		if change.Name == "words" && change.Origin != "anaconda" {
			t.Errorf("the replaced words comes from %q", change.Origin)
		}
	}
}

// A line that says "replacing" in neither shape is a removal the agent cannot
// name, and a plan that quietly left it out would be approved for more than it
// says.
func TestAnUnreadableReplacedPackageIsRefused(t *testing.T) {
	for _, line := range []string{
		"   replacing words",
		"   replacing words noarch",
		"     replacing  words 3.0-61.fc42",
	} {
		output := "Package Arch Version Repository Size\nInstalling:\n" +
			" flotestro-probe noarch 2.0-1.fc42 @commandline 6.2 k\n" + line + "\n"
		changes, err := ParseDNFUpgradePlan(output)
		if err == nil {
			t.Errorf("%q was accepted as a plan: %+v", line, changes)
			continue
		}
		if !errors.Is(err, ErrPlanMetadataMissing) {
			t.Errorf("%q = %v, expected the refusal of a plan that cannot be read", line, err)
		}
		if len(changes) != 0 {
			t.Errorf("%q was refused and still gave %d changes", line, len(changes))
		}
	}
}

// dnf5SelfUpgradeOutput is what "dnf --assumeno upgrade" really printed on the
// laboratory's Fedora 42 host (dnf5 5.2.18.0) with one ordinary update
// pending. The package obsoletes nothing: the "replacing" row is the version
// the upgrade raises away from, and dnf5 writes one under every upgraded
// package and counts it in the summary. Every hand-written table in this file
// was missing it, which is why only a live host found it.
const dnf5SelfUpgradeOutput = `Updating and loading repositories:
Repositories loaded.
Package                             Arch   Version Repository                  Size
Upgrading:
 flotestro-lab-security             noarch 1.0.1-1 flotestro-lab-security 290.0   B
   replacing flotestro-lab-security noarch 1.0.0-1 flotestro-lab-security 290.0   B

Transaction Summary:
 Upgrading:          1 package
 Replacing:          1 package

Total size of inbound packages is 7 KiB. Need to download 7 KiB.
After this operation, 0 B extra will be used (install 290 B, remove 290 B).
Operation aborted by the user.
`

// An upgrade of one package is one change. Read as a row of its own the
// superseded version becomes a removal of a name the host keeps, the screen
// offers the operator a removal that will not happen, and the transaction is
// handed a "dnf remove" of the version it has just replaced.
func TestDNFUpgradeDoesNotPromiseToRemoveWhatItRaises(t *testing.T) {
	changes, err := ParseDNFUpgradePlan(dnf5SelfUpgradeOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("read %d changes from an upgrade of one package: %+v", len(changes), changes)
	}
	change := changes[0]
	if change.Name != "flotestro-lab-security" || change.Action != ActionUpgrade ||
		change.CandidateVersion != "1.0.1-1" || change.Architecture != "noarch" ||
		change.Origin != "flotestro-lab-security" {
		t.Errorf("the change = %+v", change)
	}

	upgrade := Plan{Manager: "dnf", Mode: ModeUpgrade, Changes: changes}
	envelope := upgrade.Envelope()
	for _, step := range envelope.Steps {
		if step.Kind == ActionRemove {
			t.Errorf("the plan carries a removal step: %+v", step)
		}
	}
	for _, effect := range envelope.Effects.Expected {
		if effect.Kind == plan.EffectPackageAbsent {
			t.Errorf("the plan expects %s to be absent after an upgrade", effect.Subject)
		}
	}
	if description := upgrade.Description(); description != "1 upgrade (dnf)" {
		t.Errorf("the plan reads %q", description)
	}
}

// The same row under "Removing:" is a real removal: an installonly package
// drops its old build that way, and folding it would leave the old kernel on
// the host with nothing in the plan saying it should go.
func TestDNFUpgradeKeepsTheRemovalOfAnInstallonlyBuild(t *testing.T) {
	changes, err := ParseDNFUpgradePlan(dnf5UpgradeOutput)
	if err != nil {
		t.Fatalf("ParseDNFUpgradePlan: %v", err)
	}
	removed := ""
	for _, change := range changes {
		if change.Name == "kernel-core" && change.Action == ActionRemove {
			removed = change.CurrentVersion
		}
	}
	if removed != "6.15.9-200.fc42" {
		t.Errorf("the old kernel reads as %q, the plan must still take it away", removed)
	}
}
