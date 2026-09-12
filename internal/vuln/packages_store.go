// Package vuln correlates installed packages with the findings of the
// security trackers of distributions.
//
// It is the distribution vendor that settles the matter, not an upstream
// feed: Debian, Ubuntu and Fedora backport fixes into versions that still
// look vulnerable by the upstream numbering. Comparing a range from NVD with
// the version of a Debian package gives false alarms one way and misses the
// other way.
//
// The panel does not guess: a package the feed says nothing about is an
// undetermined state with a reason code - not a safe package.
package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/packages"
)

// PackageListState describes what the panel knows about the package list of
// a host.
type PackageListState struct {
	HostID string `json:"host_id"`
	// Digest is the digest of the list the panel holds.
	Digest       string     `json:"digest,omitempty"`
	PackageCount int        `json:"package_count"`
	CollectedAt  *time.Time `json:"collected_at,omitempty"`
	JobID        string     `json:"job_id,omitempty"`
	// UnavailableReason says why the list is missing or why it is
	// incomplete.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// AdvisoryState describes what the panel knows about the vendor findings the
// host knows from the metadata of its repositories.
//
// Separate from the state of the package list, because it is a separate
// source and a separate cycle: the vendor releases fixes also when not a
// single package on the host has changed. Without it the panel would refresh
// the findings only when the list changed - that is, sometimes never.
type AdvisoryState struct {
	HostID string `json:"host_id"`
	// Digest is the digest of the set of findings the panel holds.
	Digest        string     `json:"digest,omitempty"`
	AdvisoryCount int        `json:"advisory_count"`
	CollectedAt   *time.Time `json:"collected_at,omitempty"`
	JobID         string     `json:"job_id,omitempty"`
	// UnavailableReason says why the findings are missing. An error reading
	// the metadata must not look like a host without findings.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// PackageStore holds the package lists of hosts.
type PackageStore struct {
	pool *pgxpool.Pool
}

func NewPackageStore(pool *pgxpool.Pool) *PackageStore {
	return &PackageStore{pool: pool}
}

// ReplaceImage swaps the whole image of a host in one transaction.
//
// One, because the package list and the vendor findings come from the same
// read and describe the same moment. Written separately they could drift
// apart: a new list with the previous findings gives an assessment that
// never held on any host.
//
// A swap rather than a merge: a partial list is worse than a missing one,
// because it looks like the full thing. Either the panel has an image from
// one moment or it has none at all.
func (m *PackageStore) ReplaceImage(ctx context.Context, hostID string,
	pkgs []packages.InstalledPackage, state PackageListState,
	advisories []HostAdvisory, advisoryState AdvisoryState) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from host_packages where host_id = $1`, hostID); err != nil {
		return err
	}
	if len(pkgs) > 0 {
		rows := make([][]any, 0, len(pkgs))
		for _, pkg := range pkgs {
			rows = append(rows, []any{
				hostID, pkg.Name, pkg.Architecture, pkg.Epoch, pkg.Version,
				pkg.Release, pkg.SourceName, pkg.SourceVersion, pkg.SourceRPM,
				pkg.Vendor, pkg.RepositoryID, pkg.ModuleStream,
				pkg.Origin, pkg.OriginClass,
			})
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"host_packages"}, []string{
			"host_id", "name", "architecture", "epoch", "version", "release",
			"source_name", "source_version", "source_rpm", "vendor",
			"repository_id", "module_stream", "origin", "origin_class",
		}, pgx.CopyFromRows(rows))
		if err != nil {
			return err
		}
	}

	const saveListState = `
		insert into host_package_state (host_id, digest, package_count, collected_at,
		                                job_id, unavailable_reason)
		values ($1, $2, $3, $4, nullif($5, '')::uuid, $6)
		on conflict (host_id) do update set
			digest = excluded.digest, package_count = excluded.package_count,
			collected_at = excluded.collected_at, job_id = excluded.job_id,
			unavailable_reason = excluded.unavailable_reason`
	if _, err := tx.Exec(ctx, saveListState, hostID, state.Digest, state.PackageCount,
		state.CollectedAt, state.JobID, state.UnavailableReason); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `delete from host_advisories where host_id = $1`, hostID); err != nil {
		return err
	}
	if len(advisories) > 0 {
		rows := make([][]any, 0, len(advisories))
		for _, advisory := range advisories {
			rows = append(rows, []any{
				hostID, advisory.AdvisoryID, advisory.PackageName, advisory.Architecture,
				advisory.FixedEVR, advisory.CVEIDs, advisory.Severity, advisory.Title,
				advisory.IssuedAt, advisory.CollectedAt,
			})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"host_advisories"}, []string{
			"host_id", "advisory_id", "package_name", "architecture", "fixed_evr",
			"cve_ids", "severity", "title", "issued_at", "collected_at",
		}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}

	const saveAdvisoryState = `
		insert into host_advisory_state (host_id, digest, advisory_count, collected_at,
		                                 job_id, unavailable_reason)
		values ($1, $2, $3, $4, nullif($5, '')::uuid, $6)
		on conflict (host_id) do update set
			digest = excluded.digest, advisory_count = excluded.advisory_count,
			collected_at = excluded.collected_at, job_id = excluded.job_id,
			unavailable_reason = excluded.unavailable_reason`
	if _, err := tx.Exec(ctx, saveAdvisoryState, hostID, advisoryState.Digest,
		advisoryState.AdvisoryCount, advisoryState.CollectedAt, advisoryState.JobID,
		advisoryState.UnavailableReason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AdvisoriesDigest computes the digest of the set of findings known to a
// host.
//
// A digest rather than a mere count: the set changes also when the count
// stays the same - the vendor raises the fixed version inside the same
// advisory.
func AdvisoriesDigest(advisories []HostAdvisory) string {
	lines := make([]string, 0, len(advisories))
	for _, advisory := range advisories {
		lines = append(lines, strings.Join([]string{
			advisory.AdvisoryID, advisory.PackageName, advisory.Architecture,
			advisory.FixedEVR, advisory.Severity,
		}, "\x1f"))
	}
	sort.Strings(lines)
	sum := sha256.New()
	sum.Write([]byte("flotestro/vuln/host-advisories/v1\n"))
	for _, line := range lines {
		sum.Write([]byte(line))
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// State returns what the panel knows about the package list of a host.
func (m *PackageStore) State(ctx context.Context, hostID string) (PackageListState, error) {
	const query = `
		select host_id::text, digest, package_count, collected_at,
		       coalesce(job_id::text, ''), unavailable_reason
		from host_package_state where host_id = $1`
	var state PackageListState
	err := m.pool.QueryRow(ctx, query, hostID).Scan(&state.HostID, &state.Digest,
		&state.PackageCount, &state.CollectedAt, &state.JobID, &state.UnavailableReason)
	if err == pgx.ErrNoRows {
		// A missing row is not a host without packages: it is a host nobody
		// has asked yet.
		return PackageListState{HostID: hostID, UnavailableReason: ReasonPackageListMissing}, nil
	}
	return state, err
}

// States returns the state of the list for many hosts at once.
func (m *PackageStore) States(ctx context.Context, hostIDs []string) (map[string]PackageListState, error) {
	result := map[string]PackageListState{}
	if len(hostIDs) == 0 {
		return result, nil
	}
	const query = `
		select host_id::text, digest, package_count, collected_at,
		       coalesce(job_id::text, ''), unavailable_reason
		from host_package_state where host_id = any($1)`
	rows, err := m.pool.Query(ctx, query, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var state PackageListState
		if err := rows.Scan(&state.HostID, &state.Digest, &state.PackageCount,
			&state.CollectedAt, &state.JobID, &state.UnavailableReason); err != nil {
			return nil, err
		}
		result[state.HostID] = state
	}
	return result, rows.Err()
}

// HostAdvisoryState returns what the panel knows about the vendor findings
// known to a host.
func (m *PackageStore) HostAdvisoryState(ctx context.Context, hostID string) (AdvisoryState, error) {
	const query = `
		select host_id::text, digest, advisory_count, collected_at,
		       coalesce(job_id::text, ''), unavailable_reason
		from host_advisory_state where host_id = $1`
	var state AdvisoryState
	err := m.pool.QueryRow(ctx, query, hostID).Scan(&state.HostID, &state.Digest,
		&state.AdvisoryCount, &state.CollectedAt, &state.JobID, &state.UnavailableReason)
	if err == pgx.ErrNoRows {
		// A missing row is not a host without findings: it is a host nobody
		// has asked about the metadata of its repositories yet.
		return AdvisoryState{HostID: hostID, UnavailableReason: ReasonHostAdvisoriesMissing}, nil
	}
	return state, err
}

// Packages returns the package list of a host.
func (m *PackageStore) Packages(ctx context.Context, hostID string) ([]packages.InstalledPackage, error) {
	const query = `
		select name, architecture, epoch, version, release, source_name,
		       source_version, source_rpm, vendor, repository_id, module_stream,
		       origin, origin_class
		from host_packages where host_id = $1 order by name, architecture`
	rows, err := m.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pkgs []packages.InstalledPackage
	for rows.Next() {
		var pkg packages.InstalledPackage
		if err := rows.Scan(&pkg.Name, &pkg.Architecture, &pkg.Epoch,
			&pkg.Version, &pkg.Release, &pkg.SourceName, &pkg.SourceVersion,
			&pkg.SourceRPM, &pkg.Vendor, &pkg.RepositoryID,
			&pkg.ModuleStream, &pkg.Origin, &pkg.OriginClass); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, rows.Err()
}

// HostAdvisory is a vendor finding known to a host from its repositories.
type HostAdvisory struct {
	AdvisoryID   string     `json:"advisory_id"`
	PackageName  string     `json:"package_name"`
	Architecture string     `json:"architecture,omitempty"`
	FixedEVR     string     `json:"fixed_evr,omitempty"`
	CVEIDs       []string   `json:"cve_ids,omitempty"`
	Severity     string     `json:"severity,omitempty"`
	Title        string     `json:"title,omitempty"`
	IssuedAt     *time.Time `json:"issued_at,omitempty"`
	CollectedAt  time.Time  `json:"collected_at"`
}

// HostAdvisories returns the vendor findings known to a host, gathered by the
// name of the binary package - because that is how updateinfo speaks about
// them.
func (m *PackageStore) HostAdvisories(ctx context.Context, hostID string) (map[string][]Advisory, time.Time, error) {
	const query = `
		select advisory_id, package_name, architecture, fixed_evr, cve_ids,
		       severity, title, collected_at
		from host_advisories where host_id = $1`
	rows, err := m.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()

	result := map[string][]Advisory{}
	var newest time.Time
	for rows.Next() {
		var advisory HostAdvisory
		if err := rows.Scan(&advisory.AdvisoryID, &advisory.PackageName,
			&advisory.Architecture, &advisory.FixedEVR, &advisory.CVEIDs,
			&advisory.Severity, &advisory.Title, &advisory.CollectedAt); err != nil {
			return nil, time.Time{}, err
		}
		if advisory.CollectedAt.After(newest) {
			newest = advisory.CollectedAt
		}
		result[advisory.PackageName] = append(result[advisory.PackageName], Advisory{
			AdvisoryID: advisory.AdvisoryID, CVEIDs: advisory.CVEIDs,
			SourcePackage: advisory.PackageName, BinaryPackage: advisory.PackageName,
			Architecture: advisory.Architecture,
			FixedVersion: advisory.FixedEVR, Status: StatusFixed,
			VendorSeverity: advisory.Severity, Title: advisory.Title,
			// A finding from the metadata of the host means the fix lies in
			// a repository the host takes packages from.
			FromHostRepositories: true,
		})
	}
	return result, newest, rows.Err()
}
