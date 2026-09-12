package vuln

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoSnapshot means a provider without an active snapshot.
var ErrNoSnapshot = errors.New("this provider has no active snapshot")

// Store holds feed snapshots, vendor findings and the results of the
// assessment.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool exposes the connection pool to the operations that run a transaction
// of their own.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// SaveSnapshot writes a snapshot together with its findings and activates
// it.
//
// Everything in one transaction and only at the very end: an import that
// fails must not leave half the findings behind or take the previous
// snapshot away from the panel. Better to assess with older data and say
// they are older than not to assess at all.
func (s *Store) SaveSnapshot(ctx context.Context, snapshot Snapshot,
	advisories []Advisory) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The same digest means the same data: a repeated fetch does not create
	// a second snapshot, it only refreshes the timestamp.
	var id string
	const existing = `
		select id::text from vuln_snapshots where provider = $1 and digest = $2`
	err = tx.QueryRow(ctx, existing, snapshot.Provider, snapshot.Digest).Scan(&id)
	if err == nil {
		const refresh = `
			update vuln_snapshots set fetched_at = now(), checked_at = now(),
			                          etag = $2, error = ''
			where id = $1::uuid`
		if _, err := tx.Exec(ctx, refresh, id, snapshot.ETag); err != nil {
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

	const insert = `
		insert into vuln_snapshots (provider, digest, releases, advisory_count,
		                            source_modified_at, etag, active, checked_at)
		values ($1, $2, $3, $4, $5, $6, false, now())
		returning id::text`
	if err := tx.QueryRow(ctx, insert, snapshot.Provider, snapshot.Digest, snapshot.Releases,
		len(advisories), snapshot.SourceModifiedAt, snapshot.ETag).Scan(&id); err != nil {
		return "", err
	}

	if len(advisories) > 0 {
		// The rows are handed over one at a time rather than from a ready
		// array: the Red Hat feed carries close to a million findings per
		// release and copying them into memory first would cost the panel
		// more than the write itself.
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

	if err := activate(ctx, tx, snapshot.Provider, id); err != nil {
		return "", err
	}
	if err := pruneSnapshots(ctx, tx, snapshot.Provider); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// InactiveSnapshotsKept says how many previous fetches stay next to the
// active one.
//
// They stay, because an assessment names the digest of the data that settled
// it, and without them there is no saying why the panel said what it said.
// Not all of them stay, because one fetch of a vendor feed is anything from
// tens of thousands to a million findings a day.
const InactiveSnapshotsKept = 2

// pruneSnapshots deletes the fetches older than the last few.
func pruneSnapshots(ctx context.Context, tx pgx.Tx, provider string) error {
	const remove = `
		delete from vuln_snapshots
		where provider = $1 and not active and id not in (
		    select id from vuln_snapshots
		    where provider = $1 and not active
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
//
// A feed that has not changed is not a stale feed: the panel has just asked
// about it and got the answer "no changes". Without this record a source
// that changes once a day would look abandoned after a few hours.
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
		       checked_at, source_modified_at, etag, active, error
		from vuln_snapshots where provider = $1 and active`
	var snapshot Snapshot
	err := s.pool.QueryRow(ctx, query, provider).Scan(&snapshot.ID, &snapshot.Provider,
		&snapshot.Digest, &snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
		&snapshot.CheckedAt, &snapshot.SourceModifiedAt, &snapshot.ETag,
		&snapshot.Active, &snapshot.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{Provider: provider}, ErrNoSnapshot
	}
	return snapshot, err
}

// Snapshots returns the active snapshots of every provider.
func (s *Store) Snapshots(ctx context.Context) ([]Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       checked_at, source_modified_at, etag, active, error
		from vuln_snapshots where active order by provider`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []Snapshot
	for rows.Next() {
		var snapshot Snapshot
		if err := rows.Scan(&snapshot.ID, &snapshot.Provider, &snapshot.Digest,
			&snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
			&snapshot.CheckedAt, &snapshot.SourceModifiedAt, &snapshot.ETag,
			&snapshot.Active, &snapshot.Error); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

// AdvisoriesForRelease returns the findings of a snapshot for one release.
//
// They come back gathered by the source package, because that is how the
// correlation runs: a host has binary packages and a tracker speaks about
// source ones.
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
			// A finding without a CVE is normal: the vendor does not always
			// assign one and the column does not take a null. A missing list
			// and an empty list mean the same thing here.
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
		                             coverage_reason, advisories_reason, evaluated_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
		        $17, $18, $19)
		on conflict (host_id) do update set
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
		state.EvaluatedAt); err != nil {
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
	// AdvisoryDigest binds the assessment to the set of vendor findings.
	// That is a source separate from the package list and it changes
	// independently of it.
	AdvisoryDigest  string `json:"advisory_digest,omitempty"`
	PackagesTotal   int    `json:"packages_total"`
	PackagesCovered int    `json:"packages_covered"`
	Affected        int    `json:"affected"`
	// AffectedWithVendorFix and AffectedNoFix separate what the vendor
	// released a fix for from what it has not fixed. These are two different
	// decisions for the operator, and glued into one number they give a wall
	// nobody reads. Note: "the vendor released a fix" does not yet mean the
	// host sees it - a separate axis next to every finding says that.
	AffectedWithVendorFix int `json:"affected_with_vendor_fix"`
	AffectedNoFix         int `json:"affected_no_fix"`
	Unknown               int `json:"unknown"`
	// Three counters of the same set, because these are three different
	// questions: how many packages have to be touched, how many vendor
	// matters closed and how many CVEs it concerns. One advisory carries
	// several CVEs and several packages, so these numbers never agree - and
	// that is the point.
	AffectedPackages int `json:"affected_packages"`
	UniqueAdvisories int `json:"unique_advisories"`
	UniqueCVEs       int `json:"unique_cves"`
	// CoverageReason says why the assessment is incomplete. Empty means full
	// coverage; every other state has to be visible next to the number of
	// findings.
	CoverageReason string `json:"coverage_reason,omitempty"`
	// AdvisoriesReason says why there are no vendor findings. An error
	// reading the metadata must not look like a host without findings.
	AdvisoriesReason string     `json:"advisories_reason,omitempty"`
	EvaluatedAt      *time.Time `json:"evaluated_at,omitempty"`
}

// FullAssessment says whether the assessment of this host is complete.
//
// Complete means three things at once: nothing stood in the way of coverage,
// the feed covered every package of the host and none of them was left
// undetermined. An empty reason alone is not enough - a host with a single
// package from outside the distribution has an incomplete assessment even
// though nothing blocked it.
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
//
// Distinct rather than summed: the same CVE on twenty hosts is one matter of
// the vendor and twenty hosts to touch. A sum of per-host counters mixes one
// with the other and gives a number that answers no question at all.
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
		       advisories_reason, evaluated_at
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
			&state.CoverageReason, &state.AdvisoriesReason, &state.EvaluatedAt); err != nil {
			return nil, err
		}
		result[state.HostID] = state
	}
	return result, rows.Err()
}
