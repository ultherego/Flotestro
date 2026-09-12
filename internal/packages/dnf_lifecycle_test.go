package packages

import (
	"strings"
	"testing"
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
	// The number from the summary is the only guard against an incomplete
	// read, so it has to be read in the older format as well - the line there
	// says "Remove  3 Packages", without a colon.
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
