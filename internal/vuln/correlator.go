package vuln

import (
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// ComparatorRule describes the version comparison rule used in an
// assessment.
//
// It is written down with every finding, because a change of the rule
// changes the answer: without it there is no telling whether an old finding
// was computed the same way.
const ComparatorRule = "deb/dpkg-1,rpm/rpmvercmp-1"

// Input is everything the assessment of one host is computed from.
type Input struct {
	HostID   string
	Hostname string
	// Distribution and Release describe the host the way its vendor names
	// it: "debian"/"trixie", "fedora"/"42". The feed speaks the same
	// language.
	Distribution string
	Release      string
	Packages     []packages.InstalledPackage
	// InventoryDigest binds the assessment to a specific image of the
	// package list, and AdvisoryDigest - to a specific set of vendor
	// findings.
	InventoryDigest string
	AdvisoryDigest  string
	// AdvisoriesReason says why there are no vendor findings or why they are
	// old. It applies to the distributions where the repository metadata of
	// the host itself settle the matter.
	AdvisoriesReason string
	// ListStale means the host reports a package list digest other than the
	// one the panel holds.
	ListStale bool
	// ListMissing means a host whose list the panel has not fetched yet.
	ListMissing bool
}

// Evaluation is the result of the correlation for one host.
type Evaluation struct {
	Findings []Assessment
	State    HostState
}

// Evaluate correlates the packages of a host with the findings of the
// distribution vendor.
//
// There are three rules and all of them serve one purpose: the panel must
// not say "safe" when it really means "I do not know".
//
// First, missing data is not a missing vulnerability - a host without a
// feed, with a stale feed or with a release outside the feed gets an
// undetermined state with a reason code rather than zero findings.
//
// Second, the vendor settles the matter: its "not affected" is an answer,
// its "under investigation" is a missing answer, and the fixed version is a
// version from its own numbering, not from upstream.
//
// Third, the assessment only says whether a package is vulnerable. Whether
// the fix can be installed right now is settled by the package plan of the
// host - not by an advisory.
func Evaluate(input Input, snapshot Snapshot, advisories map[string][]Advisory,
	maxFeedAge time.Duration, now time.Time) Evaluation {
	state := HostState{
		HostID: input.HostID, Hostname: input.Hostname,
		Distribution: input.Distribution, Release: input.Release,
		Provider: snapshot.Provider, SnapshotDigest: snapshot.Digest,
		InventoryDigest:  input.InventoryDigest,
		AdvisoryDigest:   input.AdvisoryDigest,
		AdvisoriesReason: input.AdvisoriesReason,
		PackagesTotal:    len(input.Packages),
		EvaluatedAt:      &now,
	}

	reason, blocking := CoverageReasonFor(input, snapshot, maxFeedAge, now)
	state.CoverageReason = reason
	if blocking {
		return Evaluation{State: state}
	}

	var findings []Assessment
	for _, pkg := range input.Packages {
		if reason := SkipReason(pkg, input.Distribution); reason != "" {
			// A package from outside the distribution: rebuilt locally or
			// taken from a foreign repository. The vendor says nothing about
			// it and has no right to - this is an undetermined state rather
			// than a safe package.
			findings = append(findings, unknownFinding(input, snapshot, pkg, reason, now))
			continue
		}
		state.PackagesCovered++

		for _, advisory := range advisories[CorrelationKey(pkg, input.Distribution)] {
			if advisory.BinaryPackage != "" && advisory.BinaryPackage != pkg.Name {
				continue
			}
			// A fix for another architecture does not fix this package: the
			// vendor releases them separately and numbers them separately.
			if advisory.Architecture != "" && pkg.Architecture != "" &&
				advisory.Architecture != pkg.Architecture {
				continue
			}
			assessment := evaluatePackage(input, snapshot, pkg, advisory, now)
			if assessment.State == StateNotAffected {
				// "Not affected" findings are not written down: there would
				// be millions of them and they carry as much as their
				// absence does under full coverage.
				continue
			}
			findings = append(findings, assessment)
		}
	}

	// Counters of unique items: one advisory carries several CVEs and
	// several packages, so "1354 findings" does not say how many genuinely
	// different matters that is.
	affectedPackages := map[string]bool{}
	matters := map[string]bool{}
	cves := map[string]bool{}
	for _, finding := range findings {
		switch finding.State {
		case StateAffected:
			state.Affected++
			affectedPackages[finding.BinaryPackage+"\x1f"+finding.Architecture+"\x1f"+
				finding.InstalledVersion] = true
			if finding.AdvisoryID != "" {
				matters[finding.AdvisoryID] = true
			}
			for _, number := range finding.CVEIDs {
				cves[number] = true
			}
			// A vulnerability with a fix can be installed today; one without
			// a fix is a matter of risk assessment. Glued into one number
			// they give a wall nobody reads - and the ones that really can
			// be closed are lost in it.
			if finding.VendorFix == VendorFixKnown {
				state.AffectedWithVendorFix++
			} else {
				state.AffectedNoFix++
			}
		case StateUnknown:
			state.Unknown++
		}
	}
	state.AffectedPackages = len(affectedPackages)
	state.UniqueAdvisories = len(matters)
	state.UniqueCVEs = len(cves)
	return Evaluation{Findings: findings, State: state}
}

// CoverageReasonFor says what stands in the way of a full assessment of a
// host and whether that obstacle stops the assessment.
//
// One function, because the same reckoning is done in two places: the
// assessment itself and the decision whether the host has to be recomputed
// at all. A divergence between them would freeze an assessment in a state
// that had stopped being true.
//
// The order of the reasons matters: we name the most serious obstacle rather
// than the first one encountered.
func CoverageReasonFor(input Input, snapshot Snapshot,
	maxFeedAge time.Duration, now time.Time) (string, bool) {
	switch {
	case input.ListMissing:
		return ReasonPackageListMissing, true
	case input.AdvisoriesReason != "" && input.AdvisoriesReason != ReasonHostAdvisoriesStale:
		// A host whose repository metadata the panel has not read is not a
		// host without vendor findings: it is a host nobody has checked for
		// any.
		return input.AdvisoriesReason, true
	case snapshot.Digest == "":
		return ReasonFeedMissing, true
	case !CoversRelease(snapshot, input.Release):
		return ReasonReleaseUnsupported, true
	}
	// A stale feed does not stop the assessment: data from a day ago are
	// better than none. But the operator is to know they are looking at
	// yesterday's picture.
	if snapshot.Stale(maxFeedAge, now) {
		return ReasonFeedStale, false
	}
	if input.ListStale {
		return ReasonPackageListStale, false
	}
	if input.AdvisoriesReason != "" {
		return input.AdvisoriesReason, false
	}
	return "", false
}

// evaluatePackage settles one package against one vendor finding.
func evaluatePackage(input Input, snapshot Snapshot, pkg packages.InstalledPackage,
	advisory Advisory, now time.Time) Assessment {
	comparisonVersion, basis := ComparisonVersionFor(pkg, input.Distribution)
	assessment := Assessment{
		HostID: input.HostID, InventoryDigest: input.InventoryDigest,
		AdvisoryDigest: input.AdvisoryDigest,
		Provider:       advisory.Provider, SnapshotDigest: snapshot.Digest,
		AdvisoryID: advisory.AdvisoryID, CVEIDs: advisory.CVEIDs,
		Distribution: input.Distribution, Release: input.Release,
		SourcePackage: advisory.SourcePackage, BinaryPackage: pkg.Name,
		Architecture:      pkg.Architecture,
		InstalledVersion:  PackageVersion(pkg, input.Distribution),
		ComparisonVersion: comparisonVersion, ComparisonBasis: basis,
		FixedVersion: advisory.FixedVersion, VendorSeverity: advisory.VendorSeverity,
		ComparatorVersion: ComparatorRule, EvaluatedAt: now,
		PackageOrigin:       OriginClassOf(pkg, input.Distribution),
		VendorFix:           VendorFixUnknown,
		RepositoryCandidate: CandidateUnknown,
		// Only the package plan of the host knows whether the transaction
		// can be carried out: it is the one that sees holds, exclusions and
		// conflicts. Until there is one, the panel has no right to promise
		// anything.
		Transaction: TransactionUnknown,
	}

	switch advisory.Status {
	case StatusNotAffected:
		// The vendor settled this - and that is an answer, not a gap in
		// knowledge.
		assessment.State = StateNotAffected
		return assessment
	case StatusUnderInvestigation:
		assessment.State = StateUnknown
		assessment.ReasonCode = ReasonVendorInvestigating
		return assessment
	case StatusOpen, StatusDeferred:
		// A vulnerability without a fix: the package is vulnerable and there
		// is nothing to fix it with. That is a more important message than a
		// vulnerability with a fix.
		assessment.State = StateAffected
		assessment.VendorFix = VendorFixUnavailable
		assessment.RepositoryCandidate = CandidateAbsent
		return assessment
	}

	if advisory.FixedVersion == "" {
		assessment.State = StateAffected
		assessment.VendorFix = VendorFixUnavailable
		assessment.RepositoryCandidate = CandidateAbsent
		return assessment
	}
	result, ok := Compare(input.Distribution, comparisonVersion, advisory.FixedVersion)
	if !ok {
		assessment.State = StateUnknown
		assessment.ReasonCode = ReasonVersionUnparseable
		return assessment
	}
	assessment.VendorFix = VendorFixKnown
	if result < 0 {
		assessment.State = StateAffected
		// A finding read from the metadata of the host itself means the fix
		// is visible in a repository the host takes packages from. That
		// still does not mean the transaction will go through - the plan
		// says that.
		if advisory.FromHostRepositories {
			assessment.RepositoryCandidate = CandidateVisible
		}
		return assessment
	}
	assessment.State = StateNotAffected
	return assessment
}

// unknownFinding describes a package the vendor has no right to say anything
// about.
func unknownFinding(input Input, snapshot Snapshot, pkg packages.InstalledPackage,
	reason string, now time.Time) Assessment {
	return Assessment{
		HostID: input.HostID, InventoryDigest: input.InventoryDigest,
		Provider: snapshot.Provider, SnapshotDigest: snapshot.Digest,
		Distribution: input.Distribution, Release: input.Release,
		SourcePackage: sourcePackageName(pkg), BinaryPackage: pkg.Name,
		Architecture:     pkg.Architecture,
		InstalledVersion: PackageVersion(pkg, input.Distribution),
		State:            StateUnknown, ReasonCode: reason,
		VendorFix: VendorFixUnknown, RepositoryCandidate: CandidateUnknown,
		Transaction: TransactionUnknown, ComparatorVersion: ComparatorRule,
		PackageOrigin:  OriginClassOf(pkg, input.Distribution),
		AdvisoryDigest: input.AdvisoryDigest, EvaluatedAt: now,
	}
}

// OriginClassOf says whose package this is.
//
// A distribution vendor has the right to speak only about its own packages.
// A package from a foreign repository or built locally has a version its
// findings do not describe - counting such a package as covered would give
// "a hundred per cent" coverage where the panel knows nothing.
func OriginClassOf(pkg packages.InstalledPackage, distribution string) string {
	if isRPMFamily(distribution) {
		// RPM carries the vendor in the package metadata.
		switch {
		case pkg.Vendor == "":
			return OriginUnknown
		case isDistributionVendor(pkg.Vendor, distribution):
			return OriginDistribution
		default:
			return OriginThirdParty
		}
	}
	// APT does not record a vendor with the package: the origin comes from
	// the repository the version arrived from, and the agent collects it.
	switch pkg.OriginClass {
	case OriginDistribution, OriginThirdParty, OriginLocal:
		return pkg.OriginClass
	}
	return OriginUnknown
}

// SkipReason says why a package is not subject to the vendor assessment.
func SkipReason(pkg packages.InstalledPackage, distribution string) string {
	if sourcePackageName(pkg) == "" {
		return ReasonSourcePackageUnknown
	}
	if OriginClassOf(pkg, distribution) != OriginDistribution {
		return ReasonPackageOriginUnknown
	}
	return ""
}

// isDistributionVendor recognises the vendor of a package.
func isDistributionVendor(vendor, distribution string) bool {
	lower := strings.ToLower(vendor)
	switch distribution {
	case "fedora":
		return strings.Contains(lower, "fedora")
	case "rhel", "centos":
		return strings.Contains(lower, "red hat") || strings.Contains(lower, "centos")
	case "almalinux":
		return strings.Contains(lower, "alma")
	case "rocky":
		return strings.Contains(lower, "rocky")
	}
	return false
}

// CorrelationKey returns the key the findings for a package are looked up
// by.
//
// Debian and Ubuntu track security by the source package: one finding covers
// every binary package from the same source. Fedora speaks about binary
// packages in updateinfo, because a finding there is a list of specific
// versions to install.
func CorrelationKey(pkg packages.InstalledPackage, distribution string) string {
	if isRPMFamily(distribution) {
		return pkg.Name
	}
	return sourcePackageName(pkg)
}

// sourcePackageName returns the name of the source package.
func sourcePackageName(pkg packages.InstalledPackage) string {
	if pkg.SourceName != "" {
		return pkg.SourceName
	}
	return pkg.Name
}

// PackageVersion assembles the version of the binary package - the one the
// operator sees.
func PackageVersion(pkg packages.InstalledPackage, distribution string) string {
	if isRPMFamily(distribution) {
		return pkg.EVR()
	}
	return pkg.DebVersion()
}

// ComparisonVersionFor returns the version that has to be compared against
// the finding, along with where it came from.
//
// Debian and Ubuntu track security by the source package and give the source
// version - and the binary version is sometimes different: a binary rebuild
// appends a suffix ("+b9"), so the binary one is higher than the source one
// for the same code. Comparing a binary version against a source finding can
// therefore call a package fixed although it does not carry the fix.
//
// When the source version is unknown, we compare the binary one and say so
// outright: this is an approximation rather than the same answer.
func ComparisonVersionFor(pkg packages.InstalledPackage, distribution string) (string, string) {
	if isRPMFamily(distribution) {
		return pkg.EVR(), BasisBinary
	}
	if pkg.SourceVersion != "" {
		return pkg.SourceVersion, BasisSource
	}
	return pkg.DebVersion(), BasisBinary
}

// The bases of a version comparison.
const (
	BasisSource = "source"
	BasisBinary = "binary"
)

// Compare compares versions by the rules proper to the distribution.
func Compare(distribution, installed, fixed string) (int, bool) {
	if strings.TrimSpace(installed) == "" || strings.TrimSpace(fixed) == "" {
		return 0, false
	}
	if isRPMFamily(distribution) {
		return version.CompareRPM(installed, fixed), true
	}
	return version.CompareDeb(installed, fixed), true
}

func isRPMFamily(distribution string) bool {
	switch distribution {
	case "fedora", "rhel", "centos", "almalinux", "rocky", "opensuse", "sles":
		return true
	}
	return false
}

// CoversRelease says whether the snapshot covers the release of the host.
func CoversRelease(snapshot Snapshot, release string) bool {
	if release == "" {
		return false
	}
	for _, covered := range snapshot.Releases {
		if covered == release {
			return true
		}
	}
	return false
}
