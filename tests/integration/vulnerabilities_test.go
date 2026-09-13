//go:build integration

package integration

import (
	"net/http"
	"regexp"
	"testing"
	"time"
)

type vulnerabilityView struct {
	Provider            string   `json:"provider"`
	AdvisoryID          string   `json:"advisory_id"`
	CVEIDs              []string `json:"cve_ids"`
	SourcePackage       string   `json:"source_package"`
	BinaryPackage       string   `json:"binary_package"`
	Architecture        string   `json:"architecture"`
	InstalledVersion    string   `json:"installed_version"`
	ComparisonVersion   string   `json:"comparison_version"`
	ComparisonBasis     string   `json:"comparison_basis"`
	FixedVersion        string   `json:"fixed_version"`
	State               string   `json:"state"`
	ReasonCode          string   `json:"reason_code"`
	VendorFix           string   `json:"vendor_fix"`
	RepositoryCandidate string   `json:"repository_candidate"`
	Transaction         string   `json:"transaction"`
	PackageOrigin       string   `json:"package_origin"`
	VendorSeverity      string   `json:"vendor_severity"`
	SnapshotDigest      string   `json:"snapshot_digest"`
	InventoryDigest     string   `json:"inventory_digest"`
	AdvisoryDigest      string   `json:"advisory_digest"`
	Comparator          string   `json:"comparator_version"`
}

type assessmentStateView struct {
	Distribution          string     `json:"distribution"`
	Release               string     `json:"release"`
	Provider              string     `json:"provider"`
	PackagesTotal         int        `json:"packages_total"`
	PackagesCovered       int        `json:"packages_covered"`
	Affected              int        `json:"affected"`
	AffectedWithVendorFix int        `json:"affected_with_vendor_fix"`
	AffectedNoFix         int        `json:"affected_no_fix"`
	Unknown               int        `json:"unknown"`
	AffectedPackages      int        `json:"affected_packages"`
	UniqueAdvisories      int        `json:"unique_advisories"`
	UniqueCVEs            int        `json:"unique_cves"`
	CoverageReason        string     `json:"coverage_reason"`
	AdvisoriesReason      string     `json:"advisories_reason"`
	EvaluatedAt           *time.Time `json:"evaluated_at"`
}

type vulnerabilityReportView struct {
	State        assessmentStateView `json:"state"`
	Findings     []vulnerabilityView `json:"findings"`
	PackageState struct {
		Digest       string     `json:"digest"`
		PackageCount int        `json:"package_count"`
		CollectedAt  *time.Time `json:"collected_at"`
		Reason       string     `json:"unavailable_reason"`
	} `json:"package_state"`
	AdvisoryState struct {
		Digest        string     `json:"digest"`
		AdvisoryCount int        `json:"advisory_count"`
		CollectedAt   *time.Time `json:"collected_at"`
		Reason        string     `json:"unavailable_reason"`
	} `json:"advisory_state"`
	Snapshot *struct {
		Provider      string   `json:"provider"`
		Digest        string   `json:"digest"`
		AdvisoryCount int      `json:"advisory_count"`
		Releases      []string `json:"releases"`
	} `json:"snapshot"`
	// CVEDetails is the enrichment: the CVSS score and a description from
	// the upstream database.
	CVEDetails      map[string]cveDetailsView `json:"cve_details"`
	CoveragePercent float64                   `json:"coverage_percent"`
	FullyAssessed   bool                      `json:"fully_assessed"`
}

type fleetVulnerabilitiesView struct {
	Affected              int `json:"affected"`
	AffectedWithVendorFix int `json:"affected_with_vendor_fix"`
	AffectedNoFix         int `json:"affected_no_fix"`
	Unknown               int `json:"unknown"`
	UniqueCVEs            int `json:"unique_cves"`
	UniqueAdvisories      int `json:"unique_advisories"`
	PackageInstances      int `json:"affected_package_instances"`
	HostsAffected         int `json:"hosts_affected"`
	HostsTotal            int `json:"hosts_total"`
	HostsAssessed         int `json:"hosts_assessed"`
	Items                 []struct {
		HostID          string  `json:"host_id"`
		CoveragePercent float64 `json:"coverage_percent"`
		FullyAssessed   bool    `json:"fully_assessed"`
		PackagesTotal   int     `json:"packages_total"`
		PackagesCovered int     `json:"packages_covered"`
	} `json:"items"`
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// cveDetailsView mirrors the enrichment of one CVE number.
type cveDetailsView struct {
	CVE          string   `json:"cve"`
	Source       string   `json:"source"`
	CVSSScore    *float64 `json:"cvss_score"`
	CVSSSeverity string   `json:"cvss_severity"`
	CVSSVector   string   `json:"cvss_vector"`
	CVSSVersion  string   `json:"cvss_version"`
	Summary      string   `json:"summary"`
}

// hostVulnerabilities reads the assessment of a host.
func hostVulnerabilities(h *harness, hostID string) vulnerabilityReportView {
	h.t.Helper()
	var report vulnerabilityReportView
	h.get("/api/v1/hosts/"+hostID+"/vulnerabilities", &report)
	return report
}

// hostOfDistribution looks for a host by distribution, not by family.
//
// Ubuntu is in the Debian family, but has its own tracker, its own pockets
// and its own versions: a test that takes "the first host of the debian
// family" would ask Debian one time and Ubuntu another - and stay quiet
// about which one it really checked.
func hostOfDistribution(h *harness, distribution string) (hostView, vulnerabilityReportView) {
	h.t.Helper()
	for _, host := range h.hosts() {
		if host.ConnectionState != "online" {
			continue
		}
		report := hostVulnerabilities(h, host.ID)
		if report.State.Distribution == distribution {
			return host, withFreshList(h, host.ID, report)
		}
	}
	h.t.Fatalf("the test fleet has no host of the distribution %s", distribution)
	return hostView{}, vulnerabilityReportView{}
}

// withFreshList settles an assessment that describes the state before the
// last change.
//
// The assessment is computed from the package list recorded in the panel,
// not from the host. Every package transaction - also one ordered by
// another test - leaves that list older than the digest reported by the
// host, and the panel says so outright (package_list_stale). The panel
// orders the read itself, but does so in its own cycle, half an hour longer
// than the whole test run: here it is ordered at once and the recomputation
// awaited, instead of asking for an assessment from before the change.
func withFreshList(h *harness, hostID string, report vulnerabilityReportView) vulnerabilityReportView {
	h.t.Helper()
	if report.State.CoverageReason != "package_list_stale" {
		return report
	}
	job, attempts := h.runOperation(hostID, map[string]any{
		"action": "packages.list", "reason": "integration test of the vulnerability assessment",
	}, 5*time.Minute)
	if job.State != "succeeded" {
		h.t.Fatalf("reading the package list: state = %s, %s",
			job.State, lastMessage(attempts))
	}
	// The correlator gathers recomputation requests for a dozen seconds, so
	// as not to compute the same host twice. The result is awaited, not
	// only the end of the job: the recorded assessment is one cycle later
	// than the host's answer.
	deadline := time.Now().Add(90 * time.Second)
	for {
		fresh := hostVulnerabilities(h, hostID)
		if fresh.State.CoverageReason != "package_list_stale" {
			return fresh
		}
		if time.Now().After(deadline) {
			return fresh
		}
		time.Sleep(3 * time.Second)
	}
}

// TestVulnerabilityAssessmentDescribesCoverage guards the property this
// module makes sense for at all: zero findings must not mean "clean host"
// when it really means "there was nothing to assess with".
//
// The test does not let an incomplete assessment through. The test fleet
// has the Debian feed and the Fedora metadata, so the assessment must
// succeed; "incomplete, but with a reason" was convenient for the test and
// useless as a check.
func TestVulnerabilityAssessmentDescribesCoverage(t *testing.T) {
	h := newHarness(t)
	for _, distribution := range []string{"debian", "ubuntu", "fedora"} {
		_, report := hostOfDistribution(h, distribution)
		state := report.State

		if state.CoverageReason != "" {
			t.Fatalf("%s: incomplete assessment (%s) - the test fleet has something to assess with",
				distribution, state.CoverageReason)
		}
		if state.EvaluatedAt == nil {
			t.Fatalf("%s: no assessment timestamp despite full coverage", distribution)
		}
		if state.PackagesTotal == 0 {
			t.Fatalf("%s: assessment without packages", distribution)
		}
		if report.PackageState.PackageCount != state.PackagesTotal {
			t.Errorf("%s: the assessment counts %d packages, the list has %d",
				distribution, state.PackagesTotal, report.PackageState.PackageCount)
		}
		// The assessment must point at the data that decided it.
		if report.Snapshot == nil || report.Snapshot.Digest == "" {
			t.Errorf("%s: assessment without a reference to the source data", distribution)
		}
		if report.CoveragePercent <= 0 {
			t.Errorf("%s: coverage = %.1f%%", distribution, report.CoveragePercent)
		}
		// "Everything checked" is to mean everything. A host where the feed
		// did not cover even one package is not fully assessed - even when
		// nothing blocked that assessment.
		full := state.PackagesCovered == state.PackagesTotal && state.Unknown == 0
		if report.FullyAssessed != full {
			t.Errorf("%s: full assessment = %v with %d/%d packages and %d undetermined",
				distribution, report.FullyAssessed, state.PackagesCovered,
				state.PackagesTotal, state.Unknown)
		}
		if !full && report.CoveragePercent >= 100 {
			t.Errorf("%s: coverage %d/%d shown as %.1f%%", distribution,
				state.PackagesCovered, state.PackagesTotal, report.CoveragePercent)
		}
	}
}

// TestFindingIsBoundToDataAndVersions guards that every finding can be
// reproduced: it says what was installed, what was really compared, what
// fixes it, which data and which comparison rule decided it.
func TestFindingIsBoundToDataAndVersions(t *testing.T) {
	h := newHarness(t)
	// Every family has its own comparison basis: Debian tracks security by
	// source package, Fedora by binary.
	bases := map[string]string{"debian": "source", "ubuntu": "source", "fedora": "binary"}

	for _, distribution := range []string{"debian", "ubuntu", "fedora"} {
		_, report := hostOfDistribution(h, distribution)
		if len(report.Findings) == 0 {
			t.Fatalf("%s: no package could be assessed - that is not a result", distribution)
		}
		affected := 0
		for _, finding := range report.Findings {
			if finding.State == "unknown" && finding.ReasonCode == "" {
				t.Errorf("%s: undetermined state without a reason code: %+v", distribution, finding)
			}
			// Every finding says whose package it is: without that a
			// package from a foreign repository would count as covered by
			// the distribution vendor's advisories.
			if finding.PackageOrigin == "" {
				t.Errorf("%s: finding without a package origin: %+v", distribution, finding)
			}
			// The third axis belongs to the package plan, and nobody
			// computed a plan here - the panel has no right to promise that
			// the transaction will pass.
			if finding.Transaction != "unknown" {
				t.Errorf("%s: transaction = %q without a plan: %+v",
					distribution, finding.Transaction, finding)
			}
			if finding.State != "affected" {
				continue
			}
			affected++
			if finding.InstalledVersion == "" {
				t.Errorf("%s: finding without the installed version: %+v", distribution, finding)
			}
			if finding.ComparisonVersion == "" || finding.ComparisonBasis != bases[distribution] {
				t.Errorf("%s: compared %q on the basis of %q, expected basis %q",
					distribution, finding.ComparisonVersion, finding.ComparisonBasis,
					bases[distribution])
			}
			if finding.Comparator == "" {
				t.Errorf("%s: finding without a comparison rule: %+v", distribution, finding)
			}
			if finding.SnapshotDigest == "" {
				t.Errorf("%s: finding without a reference to the source data: %+v", distribution, finding)
			}
			if finding.InventoryDigest == "" {
				t.Errorf("%s: finding without a reference to the package list: %+v", distribution, finding)
			}
			// A fix without a fixed version must be described as not
			// released by the vendor, not as waiting for a plan.
			if finding.FixedVersion == "" && finding.VendorFix != "unavailable" {
				t.Errorf("%s: vulnerability without a fix described as %q: %+v",
					distribution, finding.VendorFix, finding)
			}
			if finding.FixedVersion != "" && finding.VendorFix != "known" {
				t.Errorf("%s: fix %q described as %q: %+v", distribution,
					finding.FixedVersion, finding.VendorFix, finding)
			}
			if affected > 200 {
				break
			}
		}
		if affected == 0 {
			t.Errorf("%s: not one vendor advisory concerns this host - "+
				"that is an implausible result, not a clean host", distribution)
		}
	}
}

// TestDebianAssessmentHasConcreteCVEs guards that the Debian assessment
// really carries the tracker's findings, not only the structure.
//
// Trixie has open vulnerabilities without a fix in the base packages - a
// dozen of them concern every installation. Zero findings would mean the
// feed arrived empty or the correlation did not catch the source package.
func TestDebianAssessmentHasConcreteCVEs(t *testing.T) {
	h := newHarness(t)
	_, report := hostOfDistribution(h, "debian")

	withCVE, withoutFix := 0, 0
	packages := map[string]bool{}
	for _, finding := range report.Findings {
		if finding.State != "affected" {
			continue
		}
		packages[finding.SourcePackage] = true
		for _, number := range finding.CVEIDs {
			if cvePattern.MatchString(number) {
				withCVE++
			}
		}
		if finding.FixedVersion == "" {
			withoutFix++
		}
	}
	if withCVE == 0 {
		t.Fatalf("the Debian assessment without a single CVE number (%d findings)",
			len(report.Findings))
	}
	if withoutFix == 0 {
		t.Error("the Debian assessment without a single vulnerability without a fix - " +
			"trixie has such, so something is not seen")
	}
	// The tracker's findings concern source packages, and one source gives
	// several binaries: correlating by the binary name alone would lose
	// most of them.
	if len(packages) < 2 {
		t.Errorf("the assessment concerns %d source packages", len(packages))
	}
	if report.State.UniqueCVEs == 0 || report.State.UniqueAdvisories == 0 {
		t.Errorf("the unique counters are empty with %d findings: %+v",
			report.State.Affected, report.State)
	}
	if report.State.AffectedPackages > report.State.Affected {
		t.Errorf("more package instances (%d) than findings (%d)",
			report.State.AffectedPackages, report.State.Affected)
	}
}

// TestFedoraReadsAdvisoriesFromTheHostMetadata guards that for the RPM
// family the panel has its own, separate read cycle of the vendor
// advisories - and says when it read them.
func TestFedoraReadsAdvisoriesFromTheHostMetadata(t *testing.T) {
	h := newHarness(t)
	_, report := hostOfDistribution(h, "fedora")

	if report.AdvisoryState.CollectedAt == nil {
		t.Fatalf("the panel did not record when it read the vendor advisories: %+v",
			report.AdvisoryState)
	}
	if report.AdvisoryState.Reason != "" {
		t.Fatalf("vendor advisories unavailable: %s", report.AdvisoryState.Reason)
	}
	if report.AdvisoryState.AdvisoryCount == 0 || report.AdvisoryState.Digest == "" {
		t.Errorf("host advisories without content or without a digest: %+v", report.AdvisoryState)
	}
	// The assessment must refer to that set: without the digest there is no
	// telling which advisories decided it.
	if report.State.EvaluatedAt != nil && report.State.Affected > 0 {
		for _, finding := range report.Findings {
			if finding.State == "affected" && finding.AdvisoryDigest == "" {
				t.Errorf("finding without a reference to the advisory set: %+v", finding)
				break
			}
		}
	}
}

// TestUbuntuAssessmentCarriesVendorFixes guards that the Canonical OVAL data
// reaches the assessment as findings, not only as structure.
//
// What the test does not check: the number of vulnerabilities with a fix.
// The lab host installs security updates itself, so that number drops to
// zero with every full patching - and then a zero counter is the correct
// answer, not a symptom of losing data. That the states with a fixed
// version are read is guarded by the parser's unit test.
func TestUbuntuAssessmentCarriesVendorFixes(t *testing.T) {
	h := newHarness(t)
	_, report := hostOfDistribution(h, "ubuntu")

	if report.Snapshot == nil || report.Snapshot.Provider != "ubuntu" ||
		report.Snapshot.AdvisoryCount == 0 {
		t.Fatalf("the Ubuntu assessment without a reference to the vendor data: %+v", report.Snapshot)
	}

	withFix, withoutFix := 0, 0
	packages := map[string]bool{}
	withCVE := 0
	for _, finding := range report.Findings {
		if finding.State != "affected" {
			continue
		}
		packages[finding.SourcePackage] = true
		for _, number := range finding.CVEIDs {
			if cvePattern.MatchString(number) {
				withCVE++
			}
		}
		if finding.FixedVersion != "" {
			withFix++
			if finding.VendorFix != "known" {
				t.Fatalf("fix %q described as %q: %+v",
					finding.FixedVersion, finding.VendorFix, finding)
			}
		} else {
			withoutFix++
			if finding.VendorFix != "unavailable" {
				t.Fatalf("vulnerability without a fix described as %q: %+v",
					finding.VendorFix, finding)
			}
		}
		// Ubuntu tracks security by source package, just like Debian:
		// comparing a binary version with a source advisory can classify a
		// vulnerability the opposite way to what is needed.
		if finding.ComparisonBasis != "source" {
			t.Fatalf("Ubuntu compares on the basis of %q: %+v",
				finding.ComparisonBasis, finding)
		}
		if finding.Provider != "ubuntu" {
			t.Fatalf("Ubuntu finding from the provider %q", finding.Provider)
		}
	}
	if withCVE == 0 {
		t.Fatalf("the Ubuntu assessment without a single CVE number (%d findings)",
			len(report.Findings))
	}
	if withoutFix == 0 {
		t.Error("the Ubuntu assessment without a single vulnerability without a fix - " +
			"the tests without a state did not arrive")
	}
	// A vulnerability with a fix and without one are two different answers
	// and must not swap places. How many of each there are depends on
	// whether the host is patched - but the consistency of both axes must
	// hold always.
	if withFix+withoutFix == 0 {
		t.Fatal("the Ubuntu assessment without a single finding")
	}
	// One source package gives several binaries: correlating by the binary
	// name alone would lose most of Canonical's advisories.
	if len(packages) < 2 {
		t.Errorf("the assessment concerns %d source packages", len(packages))
	}
}

// TestFleetCountsUniquesSeparately guards that one number does not pose as
// the answer to four different questions.
func TestFleetCountsUniquesSeparately(t *testing.T) {
	h := newHarness(t)
	var view fleetVulnerabilitiesView
	h.get("/api/v1/vulnerabilities", &view)

	if view.HostsTotal == 0 || len(view.Items) == 0 {
		t.Fatal("the fleet screen without hosts")
	}
	if view.Affected == 0 {
		t.Fatal("the whole fleet without a single vulnerability - that is not a result")
	}
	// One advisory carries several CVEs and touches several packages, so
	// these numbers never agree - but none may be empty or greater than the
	// number of findings.
	for name, count := range map[string]int{
		"unique CVEs":                view.UniqueCVEs,
		"vendor advisories":          view.UniqueAdvisories,
		"package instances":          view.PackageInstances,
		"hosts with a vulnerability": view.HostsAffected,
	} {
		if count == 0 {
			t.Errorf("the %s counter is empty with %d findings", name, view.Affected)
		}
	}
	if view.HostsAffected > view.HostsTotal {
		t.Errorf("hosts with a vulnerability %d out of %d", view.HostsAffected, view.HostsTotal)
	}
	if view.Affected != view.AffectedWithVendorFix+view.AffectedNoFix {
		t.Errorf("%d findings is not %d with a fix and %d without",
			view.Affected, view.AffectedWithVendorFix, view.AffectedNoFix)
	}
	// Coverage on the fleet screen must be as honest as on the host:
	// incomplete coverage must not round up to a hundred percent.
	for _, item := range view.Items {
		if item.PackagesTotal == 0 {
			continue
		}
		full := item.PackagesCovered == item.PackagesTotal
		if full != item.FullyAssessed && item.CoveragePercent > 0 {
			t.Errorf("host %s: full assessment = %v with %d/%d packages",
				item.HostID[:8], item.FullyAssessed,
				item.PackagesCovered, item.PackagesTotal)
		}
	}
}

// TestEnrichmentAddsAScoreButDoesNotDecide guards that the upstream data
// reaches the host tab and that it changes nothing in the assessment.
//
// The vendor severity and the CVSS score are two different answers: the
// vendor knows its distribution, and CVSS speaks of the vulnerability
// itself. The panel is to show both and not let the second replace the
// first.
func TestEnrichmentAddsAScoreButDoesNotDecide(t *testing.T) {
	h := newHarness(t)
	_, report := hostOfDistribution(h, "debian")
	if len(report.CVEDetails) == 0 {
		t.Fatal("the host tab without a single vulnerability description - the enrichment did not arrive")
	}

	withScore := 0
	for number, entry := range report.CVEDetails {
		if !cvePattern.MatchString(number) {
			t.Errorf("description under the key %q, which is not a CVE number", number)
		}
		if entry.Source == "" {
			t.Errorf("%s: description without a source reference", number)
		}
		if entry.CVSSScore == nil {
			continue
		}
		withScore++
		if *entry.CVSSScore < 0 || *entry.CVSSScore > 10 {
			t.Errorf("%s: CVSS score = %v", number, *entry.CVSSScore)
		}
		if entry.CVSSVector == "" || entry.CVSSVersion == "" {
			t.Errorf("%s: score without a vector or a version: %+v", number, entry)
		}
	}
	if withScore == 0 {
		t.Fatal("not a single description carries a CVSS score")
	}

	// The findings stay as the vendor issued them: the enrichment stands
	// next to them, not inside them.
	for _, finding := range report.Findings {
		if finding.State != "affected" {
			continue
		}
		if finding.Provider == "nvd" {
			t.Fatalf("finding decided by the enrichment source: %+v", finding)
		}
	}
}

// TestVulnerabilityAssessmentRequiresAPermission guards that the fleet
// vulnerability list is not public: it is reconnaissance material about
// this installation.
func TestVulnerabilityAssessmentRequiresAPermission(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	operatorToken := h.createPrincipal(uniqueSubject("no-vulnerabilities"),
		[]map[string]string{{"role": "approver", "site": host.Site, "environment": host.Environment}})
	withoutRight := h.withToken(operatorToken)

	withoutRight.do(http.MethodGet, "/api/v1/vulnerabilities", nil, nil, http.StatusForbidden)
	withoutRight.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/vulnerabilities",
		nil, nil, http.StatusForbidden)
}
