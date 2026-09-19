package vuln

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoSnapshot means a provider without an active snapshot.
var ErrNoSnapshot = errors.New("this provider has no active snapshot")

// ErrFeedEmpty means a fetch with no findings offered in place of a snapshot
// that had them.
var ErrFeedEmpty = errors.New("the feed came back empty")

// ErrFeedShrank means a fetch the sanity gate refused to activate: it lost
// more findings than the installation allows, or it lost a whole release.
var ErrFeedShrank = errors.New("the feed shrank against the snapshot in force")

// ErrNotCandidate means an acceptance aimed at a snapshot the gate never
// held back.
var ErrNotCandidate = errors.New("this snapshot is not a candidate")

// DefaultShrinkShare is how much of the active snapshot a fetch may lose and
// still be activated without anybody looking.
const DefaultShrinkShare = 0.4

// Store holds feed snapshots, vendor findings and the results of the
// assessment.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the connection pool to the operations that run a transaction
// of their own.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// SaveSnapshot writes a snapshot together with its findings and activates it.
func (s *Store) SaveSnapshot(ctx context.Context, snapshot Snapshot,
	advisories []Advisory, shrinkShare float64) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A snapshot that lost its findings does not replace one that had them.
	var active Snapshot
	err = tx.QueryRow(ctx,
		`select advisory_count, releases from vuln_snapshots where provider = $1 and active`,
		snapshot.Provider).Scan(&active.AdvisoryCount, &active.Releases)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	// The same digest means the same data: a repeated fetch does not create
	// a second snapshot, it only refreshes the timestamp.
	var id string
	var existingCount int
	var existingReleases []string
	const existing = `
		select id::text, advisory_count, releases
		from vuln_snapshots where provider = $1 and digest = $2`
	err = tx.QueryRow(ctx, existing, snapshot.Provider, snapshot.Digest).
		Scan(&id, &existingCount, &existingReleases)
	if err == nil {
		refusal := feedRefusal(active, existingCount, existingReleases, shrinkShare)
		if refusal == ReasonFeedEmpty {
			return "", fmt.Errorf("%w: the previous snapshot of %s carries %d findings",
				ErrFeedEmpty, snapshot.Provider, active.AdvisoryCount)
		}
		const refresh = `
			update vuln_snapshots set fetched_at = now(), checked_at = now(),
			                          etag = $2, error = ''
			where id = $1::uuid`
		if _, err := tx.Exec(ctx, refresh, id, snapshot.ETag); err != nil {
			return "", err
		}
		if refusal != "" {
			// The same refused data came again.
			if err := markCandidate(ctx, tx, id, refusal); err != nil {
				return "", err
			}
			if err := tx.Commit(ctx); err != nil {
				return "", err
			}
			return id, shrinkError(refusal, snapshot.Provider, active, existingCount, existingReleases)
		}
		// A fetch that was held back before may pass the gate now - the snapshot in
		// force has itself shrunk in the meantime, so the comparison has moved.
		if _, err := tx.Exec(ctx,
			`update vuln_snapshots set candidate_reason = '', candidate_at = null
			 where id = $1::uuid and candidate_reason <> ''`, id); err != nil {
			return "", err
		}
		if err := activate(ctx, tx, snapshot.Provider, id); err != nil {
			return "", err
		}
		if err := pruneSnapshots(ctx, tx, snapshot.Provider); err != nil {
			return "", err
		}
		return id, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	refusal := feedRefusal(active, len(advisories), snapshot.Releases, shrinkShare)
	// The empty row is not written at all: an inactive empty snapshot
	// would only be pruned, and there is nothing in it to accept later.
	if refusal == ReasonFeedEmpty {
		return "", fmt.Errorf("%w: the previous snapshot of %s carries %d findings",
			ErrFeedEmpty, snapshot.Provider, active.AdvisoryCount)
	}

	const insert = `
		insert into vuln_snapshots (provider, digest, releases, advisory_count,
		                            source_modified_at, etag, active, checked_at,
		                            candidate_reason, candidate_at)
		values ($1, $2, $3, $4, $5, $6, false, now(), $7::text,
		        case when $7::text = '' then null else now() end)
		returning id::text`
	if err := tx.QueryRow(ctx, insert, snapshot.Provider, snapshot.Digest, snapshot.Releases,
		len(advisories), snapshot.SourceModifiedAt, snapshot.ETag, refusal).Scan(&id); err != nil {
		return "", err
	}

	if len(advisories) > 0 {
		// The rows are handed over one at a time rather than from a ready array: the
		// Red Hat feed carries close to a million findings per release and copying
		// them into memory first would cost the panel more than the write itself.
		source := pgx.CopyFromSlice(len(advisories), func(i int) ([]any, error) {
			advisory := advisories[i]
			return []any{
				id, advisory.Provider, advisory.AdvisoryID, advisory.CVEIDs,
				advisory.Distribution, advisory.Release, advisory.SourcePackage,
				advisory.BinaryPackage, advisory.FixedVersion, advisory.Status,
				advisory.VendorSeverity, advisory.Title, advisory.URL, advisory.PublishedAt,
			}, nil
		})
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_advisories"}, []string{
			"snapshot_id", "provider", "advisory_id", "cve_ids", "distribution", "release",
			"source_package", "binary_package", "fixed_version", "status", "vendor_severity",
			"title", "url", "published_at",
		}, source); err != nil {
			return "", fmt.Errorf("writing the findings: %w", err)
		}
	}

	if refusal != "" {
		// The candidate keeps its findings and is not activated: the snapshot in
		// force stays in force and ages into stale, which the panel shows, instead
		// of being replaced by a fetch nobody has looked at.
		if err := pruneSnapshots(ctx, tx, snapshot.Provider); err != nil {
			return "", err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return id, shrinkError(refusal, snapshot.Provider, active, len(advisories), snapshot.Releases)
	}
	if err := activate(ctx, tx, snapshot.Provider, id); err != nil {
		return "", err
	}
	if err := pruneSnapshots(ctx, tx, snapshot.Provider); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// feedReplacementRefused says whether a fetch of the given size may take the
// place of the active snapshot with the given count.
func feedReplacementRefused(previousCount, fetched int) bool {
	return fetched == 0 && previousCount > 0
}

// feedRefusal says whether a fetch may take the place of the snapshot in
// force, and names the reason when it may not.
func feedRefusal(active Snapshot, fetchedCount int, fetchedReleases []string,
	shrinkShare float64) string {
	if feedReplacementRefused(active.AdvisoryCount, fetchedCount) {
		return ReasonFeedEmpty
	}
	if len(missingReleases(active.Releases, fetchedReleases)) > 0 {
		return ReasonFeedReleaseMissing
	}
	if feedShrankTooFar(active.AdvisoryCount, fetchedCount, shrinkShare) {
		return ReasonFeedShrank
	}
	return ""
}

// feedShrankTooFar says whether a fetch lost more of the active snapshot than
// the installation allows.
func feedShrankTooFar(previousCount, fetched int, shrinkShare float64) bool {
	if previousCount <= 0 || fetched >= previousCount {
		return false
	}
	if shrinkShare <= 0 || shrinkShare >= 1 {
		shrinkShare = DefaultShrinkShare
	}
	return float64(fetched) < float64(previousCount)*(1-shrinkShare)
}

// missingReleases lists the releases the snapshot in force covered and the
// fetch does not.
func missingReleases(active, fetched []string) []string {
	if len(active) == 0 || len(fetched) == 0 {
		return nil
	}
	covered := make(map[string]bool, len(fetched))
	for _, release := range fetched {
		covered[release] = true
	}
	var missing []string
	for _, release := range active {
		if !covered[release] {
			missing = append(missing, release)
		}
	}
	return missing
}

// FeedRefusal is what the sanity gate answers when it holds a fetch back.
type FeedRefusal struct {
	// Reason is ReasonFeedShrank or ReasonFeedReleaseMissing.
	Reason      string
	Provider    string
	ActiveCount int
	// FetchedCount is what the refused fetch carried.
	FetchedCount int
	// MissingReleases names the releases the fetch stopped covering; empty
	// for a refusal by count alone.
	MissingReleases []string
}

func (r *FeedRefusal) Error() string {
	if r.Reason == ReasonFeedReleaseMissing {
		return fmt.Sprintf("%s (%s): the fetch of %s no longer covers %s",
			ErrFeedShrank, r.Reason, r.Provider, strings.Join(r.MissingReleases, ", "))
	}
	return fmt.Sprintf("%s (%s): the fetch of %s carries %d findings against %d in force",
		ErrFeedShrank, r.Reason, r.Provider, r.FetchedCount, r.ActiveCount)
}

func (r *FeedRefusal) Unwrap() error { return ErrFeedShrank }

// shrinkError describes a refusal of the gate.
func shrinkError(reason, provider string, active Snapshot, fetchedCount int,
	fetchedReleases []string) error {
	return &FeedRefusal{
		Reason: reason, Provider: provider, ActiveCount: active.AdvisoryCount,
		FetchedCount:    fetchedCount,
		MissingReleases: missingReleases(active.Releases, fetchedReleases),
	}
}

// markCandidate records that the gate held a fetch back.
func markCandidate(ctx context.Context, tx pgx.Tx, id, reason string) error {
	_, err := tx.Exec(ctx,
		`update vuln_snapshots set candidate_reason = $2, candidate_at = now(), active = false
		 where id = $1::uuid`, id, reason)
	return err
}

// AcceptCandidate activates a fetch the gate held back.
func (s *Store) AcceptCandidate(ctx context.Context, id string) (Snapshot, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var provider, reason string
	err = tx.QueryRow(ctx,
		`select provider, candidate_reason from vuln_snapshots where id = $1::uuid for update`, id).
		Scan(&provider, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrNoSnapshot
	}
	if err != nil {
		return Snapshot{}, err
	}
	if reason == "" {
		return Snapshot{}, ErrNotCandidate
	}
	if _, err := tx.Exec(ctx,
		`update vuln_snapshots set candidate_reason = '', candidate_at = null, error = ''
		 where id = $1::uuid`, id); err != nil {
		return Snapshot{}, err
	}
	if err := activate(ctx, tx, provider, id); err != nil {
		return Snapshot{}, err
	}
	// The fetch that was held back now carries the source, so the error
	// the scheduler wrote on the snapshot in force has been answered.
	if _, err := tx.Exec(ctx,
		`update vuln_snapshots set error = '' where provider = $1 and error = any($2)`,
		provider, []string{ReasonFeedShrank, ReasonFeedReleaseMissing}); err != nil {
		return Snapshot{}, err
	}
	if err := pruneSnapshots(ctx, tx, provider); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Snapshot{}, err
	}
	return s.ActiveSnapshot(ctx, provider)
}

// Candidates returns the fetches the gate is holding back, newest first.
func (s *Store) Candidates(ctx context.Context) ([]Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       checked_at, source_modified_at, etag, active, error,
		       generation_id::text, generation_at, candidate_reason, candidate_at
		from vuln_snapshots where candidate_reason <> ''
		order by candidate_at desc`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := []Snapshot{}
	for rows.Next() {
		snapshot, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, snapshot)
	}
	return candidates, rows.Err()
}

// scanSnapshot reads one snapshot row in the order every snapshot query
// selects its columns.
func scanSnapshot(rows pgx.Rows) (Snapshot, error) {
	var snapshot Snapshot
	err := rows.Scan(&snapshot.ID, &snapshot.Provider, &snapshot.Digest,
		&snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
		&snapshot.CheckedAt, &snapshot.SourceModifiedAt, &snapshot.ETag,
		&snapshot.Active, &snapshot.Error, &snapshot.GenerationID,
		&snapshot.GenerationAt, &snapshot.CandidateReason, &snapshot.CandidateAt)
	return snapshot, err
}

// InactiveSnapshotsKept says how many previous fetches stay next to the active
// one.
const InactiveSnapshotsKept = 2

// pruneSnapshots deletes the fetches older than the last few. A candidate is
// never pruned by age.
func pruneSnapshots(ctx context.Context, tx pgx.Tx, provider string) error {
	const remove = `
		delete from vuln_snapshots
		where provider = $1 and not active and candidate_reason = '' and id not in (
		    select id from vuln_snapshots
		    where provider = $1 and not active and candidate_reason = ''
		    order by fetched_at desc limit $2)`
	_, err := tx.Exec(ctx, remove, provider, InactiveSnapshotsKept)
	return err
}

// activate switches the active snapshot of a provider in one move.
func activate(ctx context.Context, tx pgx.Tx, provider, id string) error {
	if _, err := tx.Exec(ctx,
		`update vuln_snapshots set active = false where provider = $1 and active`, provider); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`update vuln_snapshots set active = true where id = $1::uuid`, id)
	return err
}

// ConfirmSnapshot records that the data are still current.
func (s *Store) ConfirmSnapshot(ctx context.Context, provider string) error {
	const query = `
		update vuln_snapshots set checked_at = now(), error = ''
		where provider = $1 and active`
	_, err := s.pool.Exec(ctx, query, provider)
	return err
}

// SaveFetchError records a failed fetch without touching the active
// snapshot.
func (s *Store) SaveFetchError(ctx context.Context, provider, reason string) error {
	const query = `
		update vuln_snapshots set error = $2 where provider = $1 and active`
	_, err := s.pool.Exec(ctx, query, provider, reason)
	return err
}

// ActiveSnapshot returns the snapshot the panel assesses with right now.
func (s *Store) ActiveSnapshot(ctx context.Context, provider string) (Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       checked_at, source_modified_at, etag, active, error,
		       generation_id::text, generation_at, candidate_reason, candidate_at
		from vuln_snapshots where provider = $1 and active`
	var snapshot Snapshot
	err := s.pool.QueryRow(ctx, query, provider).Scan(&snapshot.ID, &snapshot.Provider,
		&snapshot.Digest, &snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
		&snapshot.CheckedAt, &snapshot.SourceModifiedAt, &snapshot.ETag,
		&snapshot.Active, &snapshot.Error, &snapshot.GenerationID,
		&snapshot.GenerationAt, &snapshot.CandidateReason, &snapshot.CandidateAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{Provider: provider}, ErrNoSnapshot
	}
	return snapshot, err
}

// Snapshots returns the active snapshots of every provider.
func (s *Store) HostRepositorySource(ctx context.Context, hostIDs []string) (*RepositorySource, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	var source RepositorySource
	var collected *time.Time
	err := s.pool.QueryRow(ctx, `
		select count(distinct advisory_id), count(distinct host_id), max(collected_at)
		from host_advisories where host_id = any($1::uuid[])`, hostIDs).
		Scan(&source.Advisories, &source.Hosts, &collected)
	if err != nil {
		return nil, err
	}
	if source.Hosts == 0 || collected == nil {
		return nil, nil
	}
	source.CollectedAt = *collected
	return &source, nil
}

// RepositorySource is the tally of the advisories hosts carry from their
// own repositories, as one source next to the feeds.
type RepositorySource struct {
	Advisories  int
	Hosts       int
	CollectedAt time.Time
}

func (s *Store) Snapshots(ctx context.Context) ([]Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       checked_at, source_modified_at, etag, active, error,
		       generation_id::text, generation_at, candidate_reason, candidate_at
		from vuln_snapshots where active order by provider`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []Snapshot
	for rows.Next() {
		snapshot, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

// AdvisoriesForRelease returns the findings of a snapshot for one release.
func (s *Store) AdvisoriesForRelease(ctx context.Context, snapshotID, distribution,
	release string) (map[string][]Advisory, error) {
	const query = `
		select provider, advisory_id, cve_ids, distribution, release, source_package,
		       binary_package, fixed_version, status, vendor_severity, title, url, published_at
		from vuln_advisories
		where snapshot_id = $1::uuid and distribution = $2 and release = $3`
	rows, err := s.pool.Query(ctx, query, snapshotID, distribution, release)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string][]Advisory{}
	for rows.Next() {
		var advisory Advisory
		if err := rows.Scan(&advisory.Provider, &advisory.AdvisoryID, &advisory.CVEIDs,
			&advisory.Distribution, &advisory.Release, &advisory.SourcePackage,
			&advisory.BinaryPackage, &advisory.FixedVersion, &advisory.Status,
			&advisory.VendorSeverity, &advisory.Title, &advisory.URL,
			&advisory.PublishedAt); err != nil {
			return nil, err
		}
		result[advisory.SourcePackage] = append(result[advisory.SourcePackage], advisory)
	}
	return result, rows.Err()
}

// SaveAdvisories swaps the findings of a host together with the state of
// its assessment.
func (s *Store) SaveAdvisories(ctx context.Context, hostID string,
	advisories []Assessment, state HostState) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from vuln_findings where host_id = $1`, hostID); err != nil {
		return err
	}
	if len(advisories) > 0 {
		rows := make([][]any, 0, len(advisories))
		for _, advisory := range advisories {
			// A finding without a CVE is normal: the vendor does not always assign one
			// and the column does not take a null.
			cve := advisory.CVEIDs
			if cve == nil {
				cve = []string{}
			}
			rows = append(rows, []any{
				hostID, advisory.Provider, advisory.AdvisoryID, cve,
				advisory.Distribution, advisory.Release, advisory.SourcePackage,
				advisory.BinaryPackage, advisory.Architecture, advisory.InstalledVersion,
				advisory.FixedVersion, string(advisory.State), advisory.ReasonCode,
				string(advisory.VendorFix), string(advisory.RepositoryCandidate),
				string(advisory.Transaction), advisory.ComparisonVersion,
				advisory.ComparisonBasis, advisory.PackageOrigin,
				advisory.VendorSeverity, advisory.SnapshotDigest,
				advisory.InventoryDigest, advisory.AdvisoryDigest,
				advisory.ComparatorVersion, advisory.EvaluatedAt,
			})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_findings"}, []string{
			"host_id", "provider", "advisory_id", "cve_ids", "distribution", "release",
			"source_package", "binary_package", "architecture", "installed_version",
			"fixed_version", "state", "reason_code", "vendor_fix", "repository_candidate",
			"transaction_state", "comparison_version", "comparison_basis", "package_origin",
			"vendor_severity", "snapshot_digest", "inventory_digest", "advisory_digest",
			"comparator_version", "evaluated_at",
		}, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("writing the findings of the host: %w", err)
		}
	}

	const saveState = `
		insert into vuln_host_state (host_id, distribution, release, provider,
		                             snapshot_digest, inventory_digest, advisory_digest,
		                             packages_total, packages_covered, affected,
		                             affected_with_vendor_fix, affected_no_fix, unknown,
		                             affected_packages, unique_advisories, unique_cves,
		                             coverage_reason, advisories_reason, evaluated_at,
		                             generation_id, generation_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		        $17, $18, $19, nullif($20, '')::uuid, $21)
		on conflict (host_id) do update set
			generation_id = excluded.generation_id,
			generation_at = excluded.generation_at,
			distribution = excluded.distribution, release = excluded.release,
			provider = excluded.provider, snapshot_digest = excluded.snapshot_digest,
			inventory_digest = excluded.inventory_digest,
			advisory_digest = excluded.advisory_digest,
			packages_total = excluded.packages_total,
			packages_covered = excluded.packages_covered,
			affected = excluded.affected,
			affected_with_vendor_fix = excluded.affected_with_vendor_fix,
			affected_no_fix = excluded.affected_no_fix, unknown = excluded.unknown,
			affected_packages = excluded.affected_packages,
			unique_advisories = excluded.unique_advisories,
			unique_cves = excluded.unique_cves,
			coverage_reason = excluded.coverage_reason,
			advisories_reason = excluded.advisories_reason,
			evaluated_at = excluded.evaluated_at`
	if _, err := tx.Exec(ctx, saveState, hostID, state.Distribution, state.Release,
		state.Provider, state.SnapshotDigest, state.InventoryDigest, state.AdvisoryDigest,
		state.PackagesTotal, state.PackagesCovered, state.Affected, state.AffectedWithVendorFix,
		state.AffectedNoFix, state.Unknown, state.AffectedPackages, state.UniqueAdvisories,
		state.UniqueCVEs, state.CoverageReason, state.AdvisoriesReason,
		state.EvaluatedAt, state.GenerationID, state.GenerationAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Advisories returns the findings of a host.
func (s *Store) Advisories(ctx context.Context, hostID string, onlyAffected bool) ([]Assessment, error) {
	const query = `
		select provider, advisory_id, cve_ids, distribution, release, source_package,
		       binary_package, architecture, installed_version, fixed_version, state,
		       reason_code, vendor_fix, repository_candidate, transaction_state,
		       comparison_version, comparison_basis, package_origin, vendor_severity,
		       snapshot_digest, inventory_digest, advisory_digest, comparator_version,
		       evaluated_at
		from vuln_findings
		where host_id = $1 and ($2 = false or state = 'affected')
		order by case vendor_severity
		           when 'critical' then 0 when 'high' then 1 when 'medium' then 2
		           when 'low' then 3 else 4 end,
		         source_package, advisory_id`
	rows, err := s.pool.Query(ctx, query, hostID, onlyAffected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Assessment
	for rows.Next() {
		var advisory Assessment
		var state, fix, candidate, transaction string
		if err := rows.Scan(&advisory.Provider, &advisory.AdvisoryID, &advisory.CVEIDs,
			&advisory.Distribution, &advisory.Release, &advisory.SourcePackage,
			&advisory.BinaryPackage, &advisory.Architecture, &advisory.InstalledVersion,
			&advisory.FixedVersion, &state, &advisory.ReasonCode, &fix, &candidate,
			&transaction, &advisory.ComparisonVersion, &advisory.ComparisonBasis,
			&advisory.PackageOrigin, &advisory.VendorSeverity, &advisory.SnapshotDigest,
			&advisory.InventoryDigest, &advisory.AdvisoryDigest,
			&advisory.ComparatorVersion, &advisory.EvaluatedAt); err != nil {
			return nil, err
		}
		advisory.HostID = hostID
		advisory.State = AssessmentState(state)
		advisory.VendorFix = VendorFixState(fix)
		advisory.RepositoryCandidate = RepositoryCandidateState(candidate)
		advisory.Transaction = TransactionState(transaction)
		result = append(result, advisory)
	}
	return result, rows.Err()
}

// HostState describes the assessment of one host together with its
// coverage.
type HostState struct {
	HostID          string `json:"host_id"`
	Hostname        string `json:"hostname,omitempty"`
	Distribution    string `json:"distribution,omitempty"`
	Release         string `json:"release,omitempty"`
	Provider        string `json:"provider,omitempty"`
	SnapshotDigest  string `json:"snapshot_digest,omitempty"`
	InventoryDigest string `json:"inventory_digest,omitempty"`
	// AdvisoryDigest binds the assessment to the set of vendor findings. That is
	// a source separate from the package list and it changes independently of it.
	AdvisoryDigest string `json:"advisory_digest,omitempty"`
	// GenerationID names the feed snapshot that produced this verdict and
	// GenerationAt says when that snapshot was taken.
	GenerationID    string     `json:"generation_id,omitempty"`
	GenerationAt    *time.Time `json:"generation_at,omitempty"`
	PackagesTotal   int        `json:"packages_total"`
	PackagesCovered int        `json:"packages_covered"`
	Affected        int        `json:"affected"`
	// AffectedWithVendorFix and AffectedNoFix separate what the vendor released a
	// fix for from what it has not fixed.
	AffectedWithVendorFix int `json:"affected_with_vendor_fix"`
	AffectedNoFix         int `json:"affected_no_fix"`
	Unknown               int `json:"unknown"`
	// Three counters of the same set, because these are three different
	// questions: how many packages have to be touched, how many vendor matters
	// closed and how many CVEs it concerns.
	AffectedPackages int `json:"affected_packages"`
	UniqueAdvisories int `json:"unique_advisories"`
	UniqueCVEs       int `json:"unique_cves"`
	// CoverageReason says why the assessment is incomplete.
	CoverageReason string `json:"coverage_reason,omitempty"`
	// AdvisoriesReason says why there are no vendor findings. An error
	// reading the metadata must not look like a host without findings.
	AdvisoriesReason string     `json:"advisories_reason,omitempty"`
	EvaluatedAt      *time.Time `json:"evaluated_at,omitempty"`
}

// FullAssessment says whether the assessment of this host is complete.
func (s HostState) FullAssessment() bool {
	return s.EvaluatedAt != nil && s.CoverageReason == "" &&
		s.PackagesTotal > 0 && s.PackagesCovered == s.PackagesTotal && s.Unknown == 0
}

// Coverage computes the share of packages covered by the feed.
func (s HostState) Coverage() float64 {
	if s.PackagesTotal == 0 {
		return 0
	}
	return float64(s.PackagesCovered) / float64(s.PackagesTotal)
}

// UniqueCounts counts the distinct matters in a set of hosts.
type UniqueCounts struct {
	CVE        int `json:"unique_cves"`
	Advisories int `json:"unique_advisories"`
}

// Uniques returns the number of distinct CVEs and distinct advisories among
// the findings.
func (s *Store) Uniques(ctx context.Context, hostIDs []string) (UniqueCounts, error) {
	var result UniqueCounts
	if len(hostIDs) == 0 {
		return result, nil
	}
	const query = `
		select coalesce(count(distinct cve), 0), count(distinct advisory_id)
		from vuln_findings
		left join lateral unnest(cve_ids) as cve on true
		where host_id = any($1) and state = 'affected'`
	err := s.pool.QueryRow(ctx, query, hostIDs).Scan(&result.CVE, &result.Advisories)
	return result, err
}

// HostStates returns the assessment state of many hosts.
func (s *Store) HostStates(ctx context.Context, hostIDs []string) (map[string]HostState, error) {
	result := map[string]HostState{}
	if len(hostIDs) == 0 {
		return result, nil
	}
	const query = `
		select host_id::text, distribution, release, provider, snapshot_digest,
		       inventory_digest, advisory_digest, packages_total, packages_covered,
		       affected, affected_with_vendor_fix, affected_no_fix, unknown,
		       affected_packages, unique_advisories, unique_cves, coverage_reason,
		       advisories_reason, evaluated_at, coalesce(generation_id::text, ''),
		       generation_at
		from vuln_host_state where host_id = any($1)`
	rows, err := s.pool.Query(ctx, query, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var state HostState
		if err := rows.Scan(&state.HostID, &state.Distribution, &state.Release, &state.Provider,
			&state.SnapshotDigest, &state.InventoryDigest, &state.AdvisoryDigest,
			&state.PackagesTotal, &state.PackagesCovered, &state.Affected,
			&state.AffectedWithVendorFix, &state.AffectedNoFix, &state.Unknown,
			&state.AffectedPackages, &state.UniqueAdvisories, &state.UniqueCVEs,
			&state.CoverageReason, &state.AdvisoriesReason, &state.EvaluatedAt,
			&state.GenerationID, &state.GenerationAt); err != nil {
			return nil, err
		}
		result[state.HostID] = state
	}
	return result, rows.Err()
}
