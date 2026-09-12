package vuln

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

var now = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func debianSnapshot(releases ...string) Snapshot {
	return Snapshot{
		Provider: "debian", Digest: "abc123", Releases: releases,
		FetchedAt: now.Add(-time.Hour), Active: true,
	}
}

func debianInput(pkgs ...packages.InstalledPackage) Input {
	return Input{
		HostID: "host-1", Hostname: "web-01", Distribution: "debian", Release: "trixie",
		Packages: pkgs, InventoryDigest: "list-1",
	}
}

func debPackage(name, version, source string) packages.InstalledPackage {
	if source == "" {
		source = name
	}
	// APT does not record a vendor with the package, so the origin is
	// collected by the agent from the repository metadata. A package without
	// one is undetermined - and that is how it should be, but here we
	// describe a package of the distribution.
	return packages.InstalledPackage{
		Name: name, Version: version, Architecture: "amd64", SourceName: source,
		SourceVersion: version, Origin: "deb.debian.org",
		OriginClass: packages.OriginDistribution,
	}
}

// TestMissingDataIsNotAMissingVulnerability guards the property this module
// exists for at all: the panel must not say "safe" when it really means "I do
// not know".
func TestMissingDataIsNotAMissingVulnerability(t *testing.T) {
	pkgs := []packages.InstalledPackage{debPackage("openssl", "3.0.11-1", "openssl")}

	cases := map[string]struct {
		input    Input
		snapshot Snapshot
		reason   string
	}{
		"a missing package list": {
			input: func() Input {
				i := debianInput(pkgs...)
				i.ListMissing = true
				return i
			}(),
			snapshot: debianSnapshot("trixie"),
			reason:   ReasonPackageListMissing,
		},
		"a missing feed": {
			input: debianInput(pkgs...), snapshot: Snapshot{Provider: "debian"},
			reason: ReasonFeedMissing,
		},
		"a release outside the feed": {
			input: debianInput(pkgs...), snapshot: debianSnapshot("bookworm"),
			reason: ReasonReleaseUnsupported,
		},
	}
	for name, c := range cases {
		evaluation := Evaluate(c.input, c.snapshot, nil, 6*time.Hour, now)
		if evaluation.State.CoverageReason != c.reason {
			t.Errorf("%s: coverage reason = %q, expected %q",
				name, evaluation.State.CoverageReason, c.reason)
		}
		if len(evaluation.Findings) != 0 {
			t.Errorf("%s: an assessment without data returned %d findings", name, len(evaluation.Findings))
		}
		if evaluation.State.PackagesCovered != 0 {
			t.Errorf("%s: coverage of %d packages without data", name, evaluation.State.PackagesCovered)
		}
	}
}

func TestAStaleFeedDoesNotStopTheAssessmentButIsVisible(t *testing.T) {
	snapshot := debianSnapshot("trixie")
	snapshot.FetchedAt = now.Add(-48 * time.Hour)
	advisories := map[string][]Advisory{
		"openssl": {{
			Provider: "debian", AdvisoryID: "CVE-2026-1000", CVEIDs: []string{"CVE-2026-1000"},
			Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
			FixedVersion: "3.0.15-1", Status: StatusFixed, VendorSeverity: "high",
		}},
	}
	evaluation := Evaluate(debianInput(debPackage("openssl", "3.0.11-1", "openssl")),
		snapshot, advisories, 6*time.Hour, now)

	// Data from two days ago are better than none, but the operator is to
	// know they are looking at yesterday's picture.
	if evaluation.State.CoverageReason != ReasonFeedStale {
		t.Fatalf("coverage reason = %q", evaluation.State.CoverageReason)
	}
	if evaluation.State.Affected != 1 {
		t.Fatalf("an assessment with a stale feed found no vulnerability: %+v", evaluation.State)
	}
}

func TestTheVendorVersionSettlesTheAssessment(t *testing.T) {
	advisories := map[string][]Advisory{
		"openssl": {{
			Provider: "debian", AdvisoryID: "CVE-2026-1000", CVEIDs: []string{"CVE-2026-1000"},
			Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
			FixedVersion: "3.0.11-1~deb13u2", Status: StatusFixed, VendorSeverity: "high",
		}},
	}

	// A version with a backported fix looks by the upstream numbering exactly
	// like a vulnerable one - and only the rule of the distribution tells
	// them apart.
	vulnerable := Evaluate(debianInput(debPackage("openssl", "3.0.11-1~deb13u1", "openssl")),
		debianSnapshot("trixie"), advisories, 6*time.Hour, now)
	if vulnerable.State.Affected != 1 || len(vulnerable.Findings) != 1 {
		t.Fatalf("a host with a vulnerable version: %+v", vulnerable.State)
	}
	if vulnerable.Findings[0].State != StateAffected {
		t.Fatalf("state = %q", vulnerable.Findings[0].State)
	}
	if vulnerable.Findings[0].ComparatorVersion != ComparatorRule {
		t.Error("the finding does not say which comparison rule settled it")
	}

	fixed := Evaluate(debianInput(debPackage("openssl", "3.0.11-1~deb13u2", "openssl")),
		debianSnapshot("trixie"), advisories, 6*time.Hour, now)
	if fixed.State.Affected != 0 || len(fixed.Findings) != 0 {
		t.Fatalf("a host with the fixed version: %+v", fixed)
	}
	// The package does not concern the assessment - but it is still covered
	// by the feed.
	if fixed.State.PackagesCovered != 1 {
		t.Fatalf("coverage = %d", fixed.State.PackagesCovered)
	}
}

func TestTheVendorStatusesHaveSeparateMeanings(t *testing.T) {
	cases := map[string]struct {
		status    string
		state     AssessmentState
		reason    string
		fix       VendorFixState
		candidate RepositoryCandidateState
	}{
		"not affected": {StatusNotAffected, StateNotAffected, "",
			VendorFixUnknown, CandidateUnknown},
		"under investigation": {StatusUnderInvestigation, StateUnknown, ReasonVendorInvestigating,
			VendorFixUnknown, CandidateUnknown},
		"open without a fix": {StatusOpen, StateAffected, "",
			VendorFixUnavailable, CandidateAbsent},
		"deferred": {StatusDeferred, StateAffected, "",
			VendorFixUnavailable, CandidateAbsent},
	}
	for name, c := range cases {
		advisories := map[string][]Advisory{
			"openssl": {{
				Provider: "debian", AdvisoryID: "CVE-2026-2000", Distribution: "debian",
				Release: "trixie", SourcePackage: "openssl", Status: c.status,
			}},
		}
		evaluation := Evaluate(debianInput(debPackage("openssl", "3.0.11-1", "openssl")),
			debianSnapshot("trixie"), advisories, 6*time.Hour, now)
		if c.state == StateNotAffected {
			if len(evaluation.Findings) != 0 {
				t.Errorf("%s: a 'not affected' finding landed on the list", name)
			}
			continue
		}
		if len(evaluation.Findings) != 1 {
			t.Fatalf("%s: %d findings", name, len(evaluation.Findings))
		}
		finding := evaluation.Findings[0]
		if finding.State != c.state {
			t.Errorf("%s: state = %q", name, finding.State)
		}
		if finding.ReasonCode != c.reason {
			t.Errorf("%s: reason = %q, expected %q", name, finding.ReasonCode, c.reason)
		}
		if finding.State == StateUnknown && finding.ReasonCode == "" {
			t.Errorf("%s: an undetermined state without a reason code", name)
		}
		if finding.VendorFix != c.fix {
			t.Errorf("%s: vendor fix = %q", name, finding.VendorFix)
		}
		if finding.RepositoryCandidate != c.candidate {
			t.Errorf("%s: candidate in the repositories = %q", name, finding.RepositoryCandidate)
		}
		// Only the package plan of the host knows whether the transaction can
		// be carried out. The panel has no right to promise that from an
		// advisory alone.
		if finding.Transaction != TransactionUnknown {
			t.Errorf("%s: transaction = %q, and nobody computed a plan",
				name, finding.Transaction)
		}
	}
}

func TestAPackageFromOutsideTheDistributionIsUnknown(t *testing.T) {
	// An RPM rebuilt locally or taken from a foreign repository has a version
	// the vendor does not know. Pretending its findings apply to it would
	// give a false "safe".
	own := packages.InstalledPackage{
		Name: "docker-ce", Version: "27.1.1", Release: "1.fc42", Architecture: "x86_64",
		SourceName: "docker-ce", Vendor: "Docker Inc.",
	}
	fromFedora := packages.InstalledPackage{
		Name: "openssl", Epoch: "1", Version: "3.2.6", Release: "4.fc42",
		Architecture: "x86_64", SourceName: "openssl", Vendor: "Fedora Project",
	}
	input := Input{
		HostID: "host-2", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{own, fromFedora}, InventoryDigest: "list-2",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: now.Add(-time.Hour)}

	evaluation := Evaluate(input, snapshot, nil, 6*time.Hour, now)
	if evaluation.State.PackagesCovered != 1 {
		t.Fatalf("coverage = %d of %d", evaluation.State.PackagesCovered, evaluation.State.PackagesTotal)
	}
	if len(evaluation.Findings) != 1 || evaluation.Findings[0].BinaryPackage != "docker-ce" {
		t.Fatalf("findings = %+v", evaluation.Findings)
	}
	if evaluation.Findings[0].ReasonCode != ReasonPackageOriginUnknown {
		t.Errorf("reason = %q", evaluation.Findings[0].ReasonCode)
	}
	if evaluation.State.Unknown != 1 {
		t.Errorf("counter of undetermined findings = %d", evaluation.State.Unknown)
	}
}

func TestAnRPMAssessmentTakesTheEpochIntoAccount(t *testing.T) {
	// Without the epoch "3.2.6" and "1:3.2.6" look the same and mean
	// different things.
	pkg := packages.InstalledPackage{
		Name: "openssl", Epoch: "1", Version: "3.2.6", Release: "4.fc42",
		Architecture: "x86_64", SourceName: "openssl", Vendor: "Fedora Project",
	}
	advisories := map[string][]Advisory{
		"openssl": {{
			Provider: "fedora", AdvisoryID: "FEDORA-2026-abc", Distribution: "fedora",
			Release: "42", SourcePackage: "openssl", FixedVersion: "1:3.2.7-1.fc42",
			Status: StatusFixed, VendorSeverity: "important",
		}},
	}
	input := Input{
		HostID: "host-3", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{pkg}, InventoryDigest: "list-3",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: now.Add(-time.Hour)}

	evaluation := Evaluate(input, snapshot, advisories, 6*time.Hour, now)
	if evaluation.State.Affected != 1 {
		t.Fatalf("state = %+v", evaluation.State)
	}
	if evaluation.Findings[0].InstalledVersion != "1:3.2.6-4.fc42" {
		t.Fatalf("installed version = %q", evaluation.Findings[0].InstalledVersion)
	}
}

func TestAFindingForAnotherArchitectureDoesNotConcernThePackage(t *testing.T) {
	// The vendor releases separate packages for every architecture; a finding
	// for i686 does not fix the x86_64 package - and attached to it would give
	// two findings about the same package.
	pkg := packages.InstalledPackage{
		Name: "openssh", Version: "9.9p1", Release: "13.fc42", Architecture: "x86_64",
		SourceName: "openssh", Vendor: "Fedora Project",
	}
	advisories := map[string][]Advisory{
		"openssh": {
			{Provider: "fedora", AdvisoryID: "FEDORA-2026-a", SourcePackage: "openssh",
				BinaryPackage: "openssh", Architecture: "i686", FixedVersion: "9.9p1-14.fc42",
				Status: StatusFixed, FromHostRepositories: true},
			{Provider: "fedora", AdvisoryID: "FEDORA-2026-a", SourcePackage: "openssh",
				BinaryPackage: "openssh", Architecture: "x86_64", FixedVersion: "9.9p1-14.fc42",
				Status: StatusFixed, FromHostRepositories: true},
		},
	}
	input := Input{
		HostID: "host-4", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{pkg}, InventoryDigest: "list-4",
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "f1", Releases: []string{"42"},
		FetchedAt: now.Add(-time.Hour)}

	evaluation := Evaluate(input, snapshot, advisories, 6*time.Hour, now)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("read %d findings: %+v", len(evaluation.Findings), evaluation.Findings)
	}
	// A finding from the metadata of the host means the vendor released a fix
	// and that it lies in a repository the host takes packages from. Whether
	// the transaction goes through is a third question - and the package plan
	// answers it.
	finding := evaluation.Findings[0]
	if finding.VendorFix != VendorFixKnown {
		t.Errorf("vendor fix = %q", finding.VendorFix)
	}
	if finding.RepositoryCandidate != CandidateVisible {
		t.Errorf("candidate in the repositories = %q", finding.RepositoryCandidate)
	}
	if finding.Transaction != TransactionUnknown {
		t.Errorf("transaction = %q, and nobody computed a plan", finding.Transaction)
	}
}

// TestDebianComparesTheSourceVersion guards the rule that settles the
// correctness of the whole assessment for Debian.
//
// The tracker speaks about the source package and gives its version. The
// binary version is sometimes from an entirely different numbering: the
// metapackage "gcc" from the source "gcc-defaults" carries the version of the
// compiler it points at rather than the version of its own source. Comparing
// the binary one against a source finding then calls the package fixed
// although it does not carry the fix - and that is a miss, not a false alarm.
func TestDebianComparesTheSourceVersion(t *testing.T) {
	metapackage := packages.InstalledPackage{
		Name: "gcc", Epoch: "4", Version: "12.2.0", Release: "3", Architecture: "amd64",
		SourceName: "gcc-defaults", SourceVersion: "1.220",
		Origin: "deb.debian.org", OriginClass: packages.OriginDistribution,
	}
	advisories := map[string][]Advisory{
		"gcc-defaults": {{
			Provider: "debian", AdvisoryID: "CVE-2026-3000", CVEIDs: []string{"CVE-2026-3000"},
			Distribution: "debian", Release: "trixie", SourcePackage: "gcc-defaults",
			FixedVersion: "1.221", Status: StatusFixed, VendorSeverity: "high",
		}},
	}
	input := debianInput(metapackage)

	evaluation := Evaluate(input, debianSnapshot("trixie"), advisories, 6*time.Hour, now)
	if evaluation.State.Affected != 1 {
		t.Fatalf("the binary version hid the source finding: %+v", evaluation.State)
	}
	finding := evaluation.Findings[0]
	if finding.ComparisonVersion != "1.220" || finding.ComparisonBasis != BasisSource {
		t.Errorf("compared %q on the basis of %q",
			finding.ComparisonVersion, finding.ComparisonBasis)
	}
	// The operator sees the binary version on the host and it has to be
	// written down as well.
	if finding.InstalledVersion != "4:12.2.0-3" {
		t.Errorf("installed version = %q", finding.InstalledVersion)
	}

	// Without the source version we compare the binary one and say so
	// outright: this is an approximation rather than the same answer.
	withoutSource := metapackage
	withoutSource.SourceVersion = ""
	approximate := Evaluate(debianInput(withoutSource), debianSnapshot("trixie"),
		advisories, 6*time.Hour, now)
	if len(approximate.Findings) != 0 {
		t.Fatalf("the binary comparison was to give a different answer: %+v", approximate.Findings)
	}
}

// TestAnAPTPackageFromAForeignRepositoryIsUnknown guards that the coverage
// counts only the packages the distribution vendor has any right to speak
// about.
func TestAnAPTPackageFromAForeignRepositoryIsUnknown(t *testing.T) {
	cases := map[string]struct {
		class  string
		reason string
	}{
		"a foreign repository": {packages.OriginThirdParty, ReasonPackageOriginUnknown},
		"a local package":      {packages.OriginLocal, ReasonPackageOriginUnknown},
		"an unknown origin":    {packages.OriginUnknown, ReasonPackageOriginUnknown},
	}
	for name, c := range cases {
		pkg := debPackage("nginx", "1.27.0-1", "nginx")
		pkg.OriginClass = c.class
		pkg.Origin = "nginx.org"
		evaluation := Evaluate(debianInput(pkg), debianSnapshot("trixie"), nil, 6*time.Hour, now)
		if evaluation.State.PackagesCovered != 0 {
			t.Errorf("%s: coverage = %d", name, evaluation.State.PackagesCovered)
		}
		if len(evaluation.Findings) != 1 || evaluation.Findings[0].ReasonCode != c.reason {
			t.Fatalf("%s: findings = %+v", name, evaluation.Findings)
		}
		if evaluation.Findings[0].PackageOrigin != c.class {
			t.Errorf("%s: origin = %q", name, evaluation.Findings[0].PackageOrigin)
		}
		// A host with an undetermined package has no full assessment even
		// though nothing blocked it.
		if evaluation.State.FullAssessment() {
			t.Errorf("%s: an assessment with an undetermined package was called full", name)
		}
	}
}

// TestAFullAssessmentRequiresFullCoverage guards that "everything checked"
// means everything rather than "nothing got in the way".
func TestAFullAssessmentRequiresFullCoverage(t *testing.T) {
	full := Evaluate(debianInput(debPackage("openssl", "3.0.11-1", "openssl")),
		debianSnapshot("trixie"), nil, 6*time.Hour, now)
	if !full.State.FullAssessment() {
		t.Fatalf("an assessment without obstacles was not called full: %+v", full.State)
	}

	// A host that has not been assessed yet has no full assessment.
	if (HostState{}).FullAssessment() {
		t.Error("a host without an assessment was called fully assessed")
	}
	// Neither does a host without a single package: that is not a clean host.
	empty := HostState{EvaluatedAt: &now}
	if empty.FullAssessment() {
		t.Error("a host without packages was called fully assessed")
	}
}

// TestTheFindingsOfAHostHaveTheirOwnReasonForBeingMissing guards that unread
// repository metadata do not look like a host without vendor findings.
func TestTheFindingsOfAHostHaveTheirOwnReasonForBeingMissing(t *testing.T) {
	pkg := packages.InstalledPackage{
		Name: "openssl", Epoch: "1", Version: "3.2.6", Release: "4.fc42",
		Architecture: "x86_64", SourceName: "openssl", Vendor: "Fedora Project",
	}
	for _, reason := range []string{ReasonHostAdvisoriesMissing, ReasonHostAdvisoriesUnreadable} {
		input := Input{
			HostID: "host-5", Distribution: "fedora", Release: "42",
			Packages: []packages.InstalledPackage{pkg}, InventoryDigest: "list-5",
			AdvisoriesReason: reason,
		}
		snapshot := Snapshot{Provider: "fedora", Digest: "", Releases: []string{"42"}}
		evaluation := Evaluate(input, snapshot, nil, 6*time.Hour, now)
		if evaluation.State.CoverageReason != reason {
			t.Errorf("coverage reason = %q, expected %q", evaluation.State.CoverageReason, reason)
		}
		if evaluation.State.AdvisoriesReason != reason {
			t.Errorf("reason for the findings = %q", evaluation.State.AdvisoriesReason)
		}
	}

	// Old findings do not stop the assessment - just like a stale feed.
	input := Input{
		HostID: "host-5", Distribution: "fedora", Release: "42",
		Packages: []packages.InstalledPackage{pkg}, InventoryDigest: "list-5",
		AdvisoriesReason: ReasonHostAdvisoriesStale, AdvisoryDigest: "a1",
	}
	advisories := map[string][]Advisory{
		"openssl": {{
			Provider: "fedora", AdvisoryID: "FEDORA-2026-abc", Distribution: "fedora",
			Release: "42", SourcePackage: "openssl", FixedVersion: "1:3.2.7-1.fc42",
			Status: StatusFixed, FromHostRepositories: true,
		}},
	}
	snapshot := Snapshot{Provider: "fedora", Digest: "a1", Releases: []string{"42"},
		FetchedAt: now.Add(-time.Hour)}
	evaluation := Evaluate(input, snapshot, advisories, 6*time.Hour, now)
	if evaluation.State.Affected != 1 {
		t.Fatalf("old findings stopped the assessment: %+v", evaluation.State)
	}
	if evaluation.State.CoverageReason != ReasonHostAdvisoriesStale {
		t.Errorf("coverage reason = %q", evaluation.State.CoverageReason)
	}
	if evaluation.Findings[0].AdvisoryDigest != "a1" {
		t.Error("the finding does not say which set of findings settled it")
	}
}

// TestTheUniqueCountersAreSeparate guards that one number does not pretend to
// answer four different questions.
func TestTheUniqueCountersAreSeparate(t *testing.T) {
	openssl := debPackage("openssl", "3.0.11-1", "openssl")
	libssl := debPackage("libssl3", "3.0.11-1", "openssl")
	advisories := map[string][]Advisory{
		"openssl": {
			{Provider: "debian", AdvisoryID: "DSA-5000", CVEIDs: []string{"CVE-2026-1", "CVE-2026-2"},
				Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
				FixedVersion: "3.0.12-1", Status: StatusFixed},
			{Provider: "debian", AdvisoryID: "DSA-5001", CVEIDs: []string{"CVE-2026-2"},
				Distribution: "debian", Release: "trixie", SourcePackage: "openssl",
				FixedVersion: "3.0.13-1", Status: StatusFixed},
		},
	}
	evaluation := Evaluate(debianInput(openssl, libssl), debianSnapshot("trixie"),
		advisories, 6*time.Hour, now)

	// Two binary packages times two findings give four findings - but these
	// are two matters of the vendor, two CVEs and two package instances.
	if evaluation.State.Affected != 4 {
		t.Fatalf("findings = %d", evaluation.State.Affected)
	}
	if evaluation.State.AffectedPackages != 2 {
		t.Errorf("package instances = %d", evaluation.State.AffectedPackages)
	}
	if evaluation.State.UniqueAdvisories != 2 {
		t.Errorf("matters of the vendor = %d", evaluation.State.UniqueAdvisories)
	}
	if evaluation.State.UniqueCVEs != 2 {
		t.Errorf("distinct CVEs = %d", evaluation.State.UniqueCVEs)
	}
}
