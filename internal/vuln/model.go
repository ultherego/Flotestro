package vuln

import "time"

// The state of the assessment of a single package against one tracker
// finding.
//
// Three states, not two. "Unknown" is an answer rather than a missing
// answer: a host whose distribution the feed does not cover is not a safe
// host - it is a host the panel has no right to say anything about.
type AssessmentState string

const (
	StateAffected    AssessmentState = "affected"
	StateNotAffected AssessmentState = "not_affected"
	StateUnknown     AssessmentState = "unknown"
)

// A fix has three axes, because these are three different questions with
// three different sources of answers. Glued into one word they promised more
// than the panel had checked: "available" only meant that the vendor had
// released a newer version somewhere.
//
// VendorFix says whether the vendor released a fix at all. The advisory
// answers that. RepositoryCandidate says whether that version is visible in
// the repositories of the host. The repository metadata answer that - and
// only for the hosts we have them for. Transaction says whether it can be
// installed right now. Only the package plan of the host answers that: it is
// the first to see holds, exclusions, module conflicts and the dependency
// resolution.
type VendorFixState string

const (
	VendorFixKnown       VendorFixState = "known"
	VendorFixUnavailable VendorFixState = "unavailable"
	VendorFixUnknown     VendorFixState = "unknown"
)

type RepositoryCandidateState string

const (
	CandidateVisible RepositoryCandidateState = "visible"
	CandidateAbsent  RepositoryCandidateState = "absent"
	CandidateUnknown RepositoryCandidateState = "unknown"
)

type TransactionState string

const (
	TransactionInstallable TransactionState = "installable"
	TransactionBlocked     TransactionState = "blocked"
	TransactionUnknown     TransactionState = "unknown"
)

// Classes of package origin. A distribution vendor has the right to speak
// only about its own packages: one rebuilt locally or taken from a foreign
// repository has a version its findings do not describe.
const (
	OriginDistribution = "vendor_distribution"
	OriginThirdParty   = "third_party_repository"
	OriginLocal        = "local_package"
	OriginUnknown      = "origin_unknown"
)

// Reason codes for an undetermined state. Every "unknown" has to carry a
// reason: without one there is no telling a hole in the data from a hole in
// the host.
const (
	// ReasonFeedMissing means there is no snapshot for this distribution.
	ReasonFeedMissing = "feed_missing"
	// ReasonFeedStale means a snapshot older than the policy allows.
	ReasonFeedStale = "feed_stale"
	// ReasonReleaseUnsupported means a release outside the feed.
	ReasonReleaseUnsupported = "release_unsupported"
	// ReasonPackageOriginUnknown means a package whose vendor cannot be
	// established - for instance one rebuilt locally or taken from a foreign
	// repository.
	ReasonPackageOriginUnknown = "package_origin_unknown"
	// ReasonSourcePackageUnknown means a package with no known source
	// package.
	ReasonSourcePackageUnknown = "source_package_unknown"
	// ReasonVendorInvestigating means a finding the vendor has not settled
	// yet.
	ReasonVendorInvestigating = "vendor_investigating"
	// ReasonVersionUnparseable means a version that cannot be compared.
	ReasonVersionUnparseable = "version_unparseable"
	// ReasonDistributionEOL means a release past the end of support: the
	// vendor no longer issues fixes, so a missing finding does not mean
	// "safe".
	ReasonDistributionEOL = "distribution_eol"
	// ReasonPackageListMissing means a host whose package list the panel has
	// not fetched yet. It is the most common reason for an empty assessment
	// and the most dangerous one to pass over in silence.
	ReasonPackageListMissing = "package_list_missing"
	// ReasonPackageListStale means a list older than the state the host
	// reported in the inventory.
	ReasonPackageListStale = "package_list_stale"
	// ReasonHostAdvisoriesMissing means a host whose repository metadata the
	// panel has not read yet. For the RPM family it is those metadata that
	// settle the matter, so their absence is a missing assessment rather
	// than a clean host.
	ReasonHostAdvisoriesMissing = "host_advisories_missing"
	// ReasonHostAdvisoriesUnreadable means metadata that could not be
	// recognised. A read error must not look like a host without findings.
	ReasonHostAdvisoriesUnreadable = "host_advisories_unreadable"
	// ReasonHostAdvisoriesStale means findings older than the refresh policy
	// allows.
	ReasonHostAdvisoriesStale = "host_advisories_stale"
)

// Assessment is one finding: what the panel knows about one package on one
// host against one finding of a tracker.
type Assessment struct {
	HostID string `json:"host_id"`
	// InventoryDigest binds the finding to a specific image of the package
	// list, and AdvisoryDigest - to a specific set of vendor findings. Two
	// digests, because these are two independent sources: the set of
	// findings changes also when not a single package on the host has
	// changed.
	InventoryDigest string `json:"inventory_digest,omitempty"`
	AdvisoryDigest  string `json:"advisory_digest,omitempty"`

	// Provider and SnapshotDigest say which data settled the matter. Without
	// them there is no reconstructing why the panel said what it said.
	Provider       string   `json:"provider"`
	SnapshotDigest string   `json:"snapshot_digest,omitempty"`
	AdvisoryID     string   `json:"advisory_id,omitempty"`
	CVEIDs         []string `json:"cve_ids,omitempty"`

	Distribution  string `json:"distribution"`
	Release       string `json:"release,omitempty"`
	SourcePackage string `json:"source_package,omitempty"`
	BinaryPackage string `json:"binary_package,omitempty"`
	Architecture  string `json:"architecture,omitempty"`

	// InstalledVersion is the version of the binary package - the one the
	// operator sees on the host.
	InstalledVersion string `json:"installed_version,omitempty"`
	// ComparisonVersion is the version that was really compared against the
	// finding, and ComparisonBasis says where it came from. Debian tracks
	// security by the source package, and the binary version is sometimes
	// different from the source one (a binary rebuild appends a suffix) -
	// comparing a binary version against a source one can classify a
	// vulnerability the wrong way round.
	ComparisonVersion string `json:"comparison_version,omitempty"`
	ComparisonBasis   string `json:"comparison_basis,omitempty"`
	FixedVersion      string `json:"fixed_version,omitempty"`

	State      AssessmentState `json:"state"`
	ReasonCode string          `json:"reason_code,omitempty"`
	// The three axes of a fix: what the vendor released, what is visible in
	// the repositories of the host and what can really be installed. Only
	// the package plan settles the last one, so until there is one it stays
	// undetermined.
	VendorFix           VendorFixState           `json:"vendor_fix"`
	RepositoryCandidate RepositoryCandidateState `json:"repository_candidate"`
	Transaction         TransactionState         `json:"transaction"`
	VendorSeverity      string                   `json:"vendor_severity,omitempty"`
	// PackageOrigin says whose package this is. Without it a package from a
	// foreign repository would count as covered by the vendor findings.
	PackageOrigin string `json:"package_origin,omitempty"`

	// ComparatorVersion describes the version comparison rule that was used.
	ComparatorVersion string    `json:"comparator_version,omitempty"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// Resolved says whether the finding is settled.
func (a Assessment) Resolved() bool { return a.State != StateUnknown }

// NeedsAction says whether the finding calls for action.
func (a Assessment) NeedsAction() bool { return a.State == StateAffected }

// Advisory is one finding of a distribution tracker.
//
// It is the distribution vendor that says which version is fixed - and only
// it. An upstream feed may later add a CVSS and a description, but it cannot
// change that answer: backported fixes have version numbers no range from
// NVD covers.
type Advisory struct {
	Provider   string   `json:"provider"`
	AdvisoryID string   `json:"advisory_id"`
	CVEIDs     []string `json:"cve_ids,omitempty"`

	Distribution string `json:"distribution"`
	Release      string `json:"release"`
	// SourcePackage is the correlation key: a tracker speaks about the
	// source package, and a host has binary packages.
	SourcePackage string `json:"source_package"`
	// BinaryPackage narrows the finding to one binary package; empty means
	// the whole source.
	BinaryPackage string `json:"binary_package,omitempty"`
	// Architecture narrows the finding to one architecture. The vendor
	// releases separate packages for each, and a fix for i686 does not fix
	// the x86_64 package - and must not be attached to it.
	Architecture string `json:"architecture,omitempty"`
	// An empty FixedVersion means a finding without a fix: the package is
	// vulnerable and there is nothing to fix it with.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Status is the state of the finding at the vendor.
	Status         string     `json:"status"`
	VendorSeverity string     `json:"vendor_severity,omitempty"`
	Title          string     `json:"title,omitempty"`
	URL            string     `json:"url,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	// FromHostRepositories marks a finding read from the repository metadata
	// of the host itself. The fix is then reachable by definition: the host
	// sees it in a repository it takes packages from.
	FromHostRepositories bool `json:"from_host_repositories,omitempty"`
}

// The statuses of findings at the vendor.
const (
	// StatusFixed means the version from which the package is not
	// vulnerable.
	StatusFixed = "fixed"
	// StatusOpen means a vulnerability without a fix.
	StatusOpen = "open"
	// StatusNotAffected means a package the finding does not apply to in
	// this release - the vendor settled that, so it is not an "unknown".
	StatusNotAffected = "not_affected"
	// StatusUnderInvestigation means a finding the vendor has not closed
	// yet.
	StatusUnderInvestigation = "under_investigation"
	// StatusDeferred means a vulnerability the vendor does not intend to fix
	// in this release.
	StatusDeferred = "deferred"
)

// Snapshot is one fetch of a feed.
//
// A snapshot has a digest and an age: an assessment that does not name the
// data which settled it can be neither repeated nor defended.
type Snapshot struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider"`
	// Digest is the digest of the canonical form of the data. A repeated
	// fetch of the same data gives the same digest and creates no new
	// snapshot.
	Digest string `json:"digest"`
	// Releases lists the releases covered by this snapshot. That is where
	// the answer "the feed does not cover this release" comes from.
	Releases      []string  `json:"releases,omitempty"`
	AdvisoryCount int       `json:"advisory_count"`
	FetchedAt     time.Time `json:"fetched_at"`
	// CheckedAt says when the panel last confirmed that these data are still
	// current. A feed that changes once a day is not stale because it has
	// not changed - it is stale only once the panel cannot confirm that.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// SourceModifiedAt is the date the feed server gave.
	SourceModifiedAt *time.Time `json:"source_modified_at,omitempty"`
	// ETag makes it possible not to fetch data that have not changed.
	ETag   string `json:"etag,omitempty"`
	Active bool   `json:"active"`
	// Error describes a failed fetch. A snapshot with an error does not
	// replace the previous one: better to assess with older data and say
	// they are older than not to assess at all.
	Error string `json:"error,omitempty"`
}

// Stale says whether the snapshot is older than the policy allows.
//
// What counts is the last confirmation rather than the last change: data
// from a day ago that the panel asked about a quarter of an hour ago
// describe the current state. Stale is only a feed the panel has lost
// contact with.
func (s Snapshot) Stale(maxAge time.Duration, now time.Time) bool {
	reference := s.FetchedAt
	if s.CheckedAt != nil && s.CheckedAt.After(reference) {
		reference = *s.CheckedAt
	}
	if reference.IsZero() {
		return true
	}
	return now.Sub(reference) > maxAge
}
