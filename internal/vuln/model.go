package vuln

import "time"

// The state of the assessment of a single package against one tracker finding.
// Three states, not two.
type AssessmentState string

const (
	StateAffected    AssessmentState = "affected"
	StateNotAffected AssessmentState = "not_affected"
	StateUnknown     AssessmentState = "unknown"
)

// A fix has three axes, because these are three different questions with three
// different sources of answers.
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

// Classes of package origin.
const (
	OriginDistribution = "vendor_distribution"
	OriginThirdParty   = "third_party_repository"
	OriginLocal        = "local_package"
	OriginUnknown      = "origin_unknown"
)

// EvaluationStatus says how much of a host's verdict may be trusted. It is
// derived from the facts of the assessment, never stored.
type EvaluationStatus string

const (
	// StatusComplete means every package was matched against a fresh feed.
	StatusComplete EvaluationStatus = "complete"
	// StatusPartial means the verdict holds for part of the host only.
	StatusPartial EvaluationStatus = "partial"
	// StatusUnknown means nothing can be said: there is no verdict, or an
	// obstacle stopped the assessment before it began.
	StatusUnknown EvaluationStatus = "unknown"
	// StatusStale means the numbers are real but were computed against
	// something that has since aged, or the last pass could not run at all.
	StatusStale EvaluationStatus = "stale"
)

// EvaluationFailed is the typed code of a pass the panel could not compute.
// The numbers of such a host are the ones from before it.
const EvaluationFailed = "evaluation_failed"

// The reads that stop a pass, named on the host so an operator knows which
// source to repair.
const (
	SourcePackageListState  = "package_list_state"
	SourcePackageList       = "package_list"
	SourceHostAdvisoryState = "host_advisory_state"
	SourceHostAdvisories    = "host_advisories"
	SourceFeedAdvisories    = "feed_advisories"
	SourceSave              = "save"
)

// BlockingReason says whether the code is one that stops an assessment rather
// than merely narrowing it.
func BlockingReason(reason string) bool {
	switch reason {
	case ReasonPackageListMissing, ReasonFamilyUnsupported, ReasonFeedMissing,
		ReasonReleaseUnsupported, ReasonHostAdvisoriesMissing,
		ReasonHostAdvisoriesUnreadable:
		return true
	}
	return false
}

// StaleReason says whether the code means the sources aged rather than failed.
func StaleReason(reason string) bool {
	switch reason {
	case ReasonFeedStale, ReasonPackageListStale, ReasonHostAdvisoriesStale:
		return true
	}
	return false
}

// Reason codes for an undetermined state.
const (
	// ReasonFeedMissing means there is no snapshot for this distribution yet;
	// the family itself has a tracker.
	ReasonFeedMissing = "feed_missing"
	// ReasonFamilyUnsupported means a system family no tracker of the panel
	// speaks about at all: nothing about such a host arrives later.
	ReasonFamilyUnsupported = "family_unsupported"
	// ReasonFeedStale means a snapshot older than the policy allows.
	ReasonFeedStale = "feed_stale"
	// ReasonFeedEmpty means a fetch that carried no findings where the previous
	// one did.
	ReasonFeedEmpty = "feed_empty"
	// ReasonFeedShrank means a fetch whose finding count fell against the active
	// snapshot by more than the installation allows.
	ReasonFeedShrank = "feed_shrank"
	// ReasonFeedReleaseMissing means a fetch that lost a whole release - or a
	// whole distribution family - the active snapshot covered.
	ReasonFeedReleaseMissing = "feed_release_missing"
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
	// ReasonDistributionEOL means a release past the end of support: the vendor
	// no longer issues fixes, so a missing finding does not mean "safe".
	ReasonDistributionEOL = "distribution_eol"
	// ReasonPackageListMissing means a host whose package list the panel has not
	// fetched yet.
	ReasonPackageListMissing = "package_list_missing"
	// ReasonPackageListStale means a list older than the state the host
	// reported in the inventory.
	ReasonPackageListStale = "package_list_stale"
	// ReasonHostAdvisoriesMissing means a host whose repository metadata the
	// panel has not read yet.
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
	// InventoryDigest binds the finding to a specific image of the package list,
	// and AdvisoryDigest - to a specific set of vendor findings.
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
	// finding, and ComparisonBasis says where it came from.
	ComparisonVersion string `json:"comparison_version,omitempty"`
	ComparisonBasis   string `json:"comparison_basis,omitempty"`
	FixedVersion      string `json:"fixed_version,omitempty"`

	State      AssessmentState `json:"state"`
	ReasonCode string          `json:"reason_code,omitempty"`
	// The three axes of a fix: what the vendor released, what is visible in the
	// repositories of the host and what can really be installed.
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

// Advisory is one finding of a distribution tracker. It is the distribution
// vendor that says which version is fixed - and only it.
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
	// Architecture narrows the finding to one architecture.
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
	// FromHostRepositories marks a finding read from the repository metadata of
	// the host itself.
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
type Snapshot struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider"`
	// Digest is the digest of the canonical form of the data. A repeated fetch of
	// the same data gives the same digest and creates no new snapshot.
	Digest string `json:"digest"`
	// GenerationID names this fetch of the feed and GenerationAt says when it was
	// taken.
	GenerationID string    `json:"generation_id,omitempty"`
	GenerationAt time.Time `json:"generation_at"`
	// CandidateReason is the typed reason the gate refused to activate this
	// fetch: ReasonFeedShrank or ReasonFeedReleaseMissing.
	CandidateReason string     `json:"candidate_reason,omitempty"`
	CandidateAt     *time.Time `json:"candidate_at,omitempty"`
	// Releases lists the releases covered by this snapshot. That is where
	// the answer "the feed does not cover this release" comes from.
	Releases      []string  `json:"releases,omitempty"`
	AdvisoryCount int       `json:"advisory_count"`
	FetchedAt     time.Time `json:"fetched_at"`
	// CheckedAt says when the panel last confirmed that these data are still
	// current.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// SourceModifiedAt is the date the feed server gave.
	SourceModifiedAt *time.Time `json:"source_modified_at,omitempty"`
	// ETag makes it possible not to fetch data that have not changed.
	ETag   string `json:"etag,omitempty"`
	Active bool   `json:"active"`
	// Error describes a failed fetch.
	Error string `json:"error,omitempty"`
}

// Candidate says whether the gate held this fetch back. A candidate
// carries its findings and is not in force.
func (s Snapshot) Candidate() bool { return s.CandidateReason != "" }

// Stale says whether the snapshot is older than the policy allows.
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
