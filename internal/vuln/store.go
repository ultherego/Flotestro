package vuln

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrBrakSnapshotu oznacza dostawce bez aktywnego snapshotu.
var ErrBrakSnapshotu = errors.New("ten dostawca nie ma aktywnego snapshotu")

// Store trzyma snapshoty feedow, ustalenia producentow i wyniki oceny.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool udostepnia pule polaczen operacjom, ktore prowadza wlasna transakcje.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ZapiszSnapshot zapisuje snapshot razem z ustaleniami i aktywuje go.
//
// Wszystko w jednej transakcji i dopiero na koncu: import, ktory sie nie uda,
// nie moze zostawic polowy ustalen ani odebrac panelowi poprzedniego
// snapshotu. Lepiej ocenic starszymi danymi i powiedziec, ze sa starsze, niz
// nie ocenic wcale.
func (s *Store) ZapiszSnapshot(ctx context.Context, snapshot Snapshot,
	ustalenia []Advisory) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ten sam odcisk oznacza te same dane: powtorzone pobranie nie tworzy
	// drugiego snapshotu, tylko odswieza znacznik czasu.
	var identyfikator string
	const istniejacy = `
		select id::text from vuln_snapshots where provider = $1 and digest = $2`
	err = tx.QueryRow(ctx, istniejacy, snapshot.Provider, snapshot.Digest).Scan(&identyfikator)
	if err == nil {
		const odswiez = `
			update vuln_snapshots set fetched_at = now(), etag = $2, error = ''
			where id = $1::uuid`
		if _, err := tx.Exec(ctx, odswiez, identyfikator, snapshot.ETag); err != nil {
			return "", err
		}
		if err := aktywuj(ctx, tx, snapshot.Provider, identyfikator); err != nil {
			return "", err
		}
		return identyfikator, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	const wstaw = `
		insert into vuln_snapshots (provider, digest, releases, advisory_count,
		                            source_modified_at, etag, active)
		values ($1, $2, $3, $4, $5, $6, false)
		returning id::text`
	if err := tx.QueryRow(ctx, wstaw, snapshot.Provider, snapshot.Digest, snapshot.Releases,
		len(ustalenia), snapshot.SourceModifiedAt, snapshot.ETag).Scan(&identyfikator); err != nil {
		return "", err
	}

	if len(ustalenia) > 0 {
		wiersze := make([][]any, 0, len(ustalenia))
		for _, ustalenie := range ustalenia {
			wiersze = append(wiersze, []any{
				identyfikator, ustalenie.Provider, ustalenie.AdvisoryID, ustalenie.CVEIDs,
				ustalenie.Distribution, ustalenie.Release, ustalenie.SourcePackage,
				ustalenie.BinaryPackage, ustalenie.FixedVersion, ustalenie.Status,
				ustalenie.VendorSeverity, ustalenie.Title, ustalenie.URL, ustalenie.PublishedAt,
			})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_advisories"}, []string{
			"snapshot_id", "provider", "advisory_id", "cve_ids", "distribution", "release",
			"source_package", "binary_package", "fixed_version", "status", "vendor_severity",
			"title", "url", "published_at",
		}, pgx.CopyFromRows(wiersze)); err != nil {
			return "", fmt.Errorf("zapis ustalen: %w", err)
		}
	}

	if err := aktywuj(ctx, tx, snapshot.Provider, identyfikator); err != nil {
		return "", err
	}
	return identyfikator, tx.Commit(ctx)
}

// aktywuj przelacza aktywny snapshot dostawcy jednym ruchem.
func aktywuj(ctx context.Context, tx pgx.Tx, dostawca, identyfikator string) error {
	if _, err := tx.Exec(ctx,
		`update vuln_snapshots set active = false where provider = $1 and active`, dostawca); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`update vuln_snapshots set active = true where id = $1::uuid`, identyfikator)
	return err
}

// ZapiszBladPobrania odnotowuje nieudane pobranie, nie ruszajac aktywnego
// snapshotu.
func (s *Store) ZapiszBladPobrania(ctx context.Context, dostawca, powod string) error {
	const query = `
		update vuln_snapshots set error = $2 where provider = $1 and active`
	_, err := s.pool.Exec(ctx, query, dostawca, powod)
	return err
}

// AktywnySnapshot zwraca snapshot, ktorym panel ocenia teraz.
func (s *Store) AktywnySnapshot(ctx context.Context, dostawca string) (Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       source_modified_at, etag, active, error
		from vuln_snapshots where provider = $1 and active`
	var snapshot Snapshot
	err := s.pool.QueryRow(ctx, query, dostawca).Scan(&snapshot.ID, &snapshot.Provider,
		&snapshot.Digest, &snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
		&snapshot.SourceModifiedAt, &snapshot.ETag, &snapshot.Active, &snapshot.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{Provider: dostawca}, ErrBrakSnapshotu
	}
	return snapshot, err
}

// Snapshoty zwraca aktywne snapshoty wszystkich dostawcow.
func (s *Store) Snapshoty(ctx context.Context) ([]Snapshot, error) {
	const query = `
		select id::text, provider, digest, releases, advisory_count, fetched_at,
		       source_modified_at, etag, active, error
		from vuln_snapshots where active order by provider`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshoty []Snapshot
	for rows.Next() {
		var snapshot Snapshot
		if err := rows.Scan(&snapshot.ID, &snapshot.Provider, &snapshot.Digest,
			&snapshot.Releases, &snapshot.AdvisoryCount, &snapshot.FetchedAt,
			&snapshot.SourceModifiedAt, &snapshot.ETag, &snapshot.Active,
			&snapshot.Error); err != nil {
			return nil, err
		}
		snapshoty = append(snapshoty, snapshot)
	}
	return snapshoty, rows.Err()
}

// UstaleniaDlaWydania zwraca ustalenia snapshotu dla jednego wydania.
//
// Zwracamy je zebrane po pakiecie zrodlowym, bo tak wlasnie przebiega
// korelacja: host ma pakiety binarne, a tracker mowi o zrodlowych.
func (s *Store) UstaleniaDlaWydania(ctx context.Context, snapshotID, dystrybucja,
	wydanie string) (map[string][]Advisory, error) {
	const query = `
		select provider, advisory_id, cve_ids, distribution, release, source_package,
		       binary_package, fixed_version, status, vendor_severity, title, url, published_at
		from vuln_advisories
		where snapshot_id = $1::uuid and distribution = $2 and release = $3`
	rows, err := s.pool.Query(ctx, query, snapshotID, dystrybucja, wydanie)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	wynik := map[string][]Advisory{}
	for rows.Next() {
		var ustalenie Advisory
		if err := rows.Scan(&ustalenie.Provider, &ustalenie.AdvisoryID, &ustalenie.CVEIDs,
			&ustalenie.Distribution, &ustalenie.Release, &ustalenie.SourcePackage,
			&ustalenie.BinaryPackage, &ustalenie.FixedVersion, &ustalenie.Status,
			&ustalenie.VendorSeverity, &ustalenie.Title, &ustalenie.URL,
			&ustalenie.PublishedAt); err != nil {
			return nil, err
		}
		wynik[ustalenie.SourcePackage] = append(wynik[ustalenie.SourcePackage], ustalenie)
	}
	return wynik, rows.Err()
}

// ZapiszUstalenia podmienia ustalenia hosta razem z jego stanem oceny.
func (s *Store) ZapiszUstalenia(ctx context.Context, hostID string,
	ustalenia []Assessment, stan StanHosta) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from vuln_findings where host_id = $1`, hostID); err != nil {
		return err
	}
	if len(ustalenia) > 0 {
		wiersze := make([][]any, 0, len(ustalenia))
		for _, ustalenie := range ustalenia {
			wiersze = append(wiersze, []any{
				hostID, ustalenie.Provider, ustalenie.AdvisoryID, ustalenie.CVEIDs,
				ustalenie.Distribution, ustalenie.Release, ustalenie.SourcePackage,
				ustalenie.BinaryPackage, ustalenie.Architecture, ustalenie.InstalledVersion,
				ustalenie.FixedVersion, string(ustalenie.State), ustalenie.ReasonCode,
				string(ustalenie.Remediation), ustalenie.VendorSeverity,
				ustalenie.SnapshotDigest, ustalenie.InventoryDigest,
				ustalenie.ComparatorVersion, ustalenie.EvaluatedAt,
			})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_findings"}, []string{
			"host_id", "provider", "advisory_id", "cve_ids", "distribution", "release",
			"source_package", "binary_package", "architecture", "installed_version",
			"fixed_version", "state", "reason_code", "remediation", "vendor_severity",
			"snapshot_digest", "inventory_digest", "comparator_version", "evaluated_at",
		}, pgx.CopyFromRows(wiersze)); err != nil {
			return fmt.Errorf("zapis ustalen hosta: %w", err)
		}
	}

	const zapisStanu = `
		insert into vuln_host_state (host_id, distribution, release, provider,
		                             snapshot_digest, inventory_digest, packages_total,
		                             packages_covered, affected, affected_fixable,
		                             affected_no_fix, unknown, coverage_reason, evaluated_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		on conflict (host_id) do update set
			distribution = excluded.distribution, release = excluded.release,
			provider = excluded.provider, snapshot_digest = excluded.snapshot_digest,
			inventory_digest = excluded.inventory_digest,
			packages_total = excluded.packages_total,
			packages_covered = excluded.packages_covered,
			affected = excluded.affected, affected_fixable = excluded.affected_fixable,
			affected_no_fix = excluded.affected_no_fix, unknown = excluded.unknown,
			coverage_reason = excluded.coverage_reason, evaluated_at = excluded.evaluated_at`
	if _, err := tx.Exec(ctx, zapisStanu, hostID, stan.Distribution, stan.Release,
		stan.Provider, stan.SnapshotDigest, stan.InventoryDigest, stan.PackagesTotal,
		stan.PackagesCovered, stan.Affected, stan.AffectedFixable, stan.AffectedNoFix,
		stan.Unknown, stan.CoverageReason, stan.EvaluatedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Ustalenia zwraca ustalenia hosta.
func (s *Store) Ustalenia(ctx context.Context, hostID string, tylkoPodatne bool) ([]Assessment, error) {
	const query = `
		select provider, advisory_id, cve_ids, distribution, release, source_package,
		       binary_package, architecture, installed_version, fixed_version, state,
		       reason_code, remediation, vendor_severity, snapshot_digest, inventory_digest,
		       comparator_version, evaluated_at
		from vuln_findings
		where host_id = $1 and ($2 = false or state = 'affected')
		order by case vendor_severity
		           when 'critical' then 0 when 'high' then 1 when 'medium' then 2
		           when 'low' then 3 else 4 end,
		         source_package, advisory_id`
	rows, err := s.pool.Query(ctx, query, hostID, tylkoPodatne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wynik []Assessment
	for rows.Next() {
		var ustalenie Assessment
		var stan, naprawa string
		if err := rows.Scan(&ustalenie.Provider, &ustalenie.AdvisoryID, &ustalenie.CVEIDs,
			&ustalenie.Distribution, &ustalenie.Release, &ustalenie.SourcePackage,
			&ustalenie.BinaryPackage, &ustalenie.Architecture, &ustalenie.InstalledVersion,
			&ustalenie.FixedVersion, &stan, &ustalenie.ReasonCode, &naprawa,
			&ustalenie.VendorSeverity, &ustalenie.SnapshotDigest, &ustalenie.InventoryDigest,
			&ustalenie.ComparatorVersion, &ustalenie.EvaluatedAt); err != nil {
			return nil, err
		}
		ustalenie.HostID = hostID
		ustalenie.State = AssessmentState(stan)
		ustalenie.Remediation = RemediationState(naprawa)
		wynik = append(wynik, ustalenie)
	}
	return wynik, rows.Err()
}

// StanHosta opisuje ocene jednego hosta razem z jej pokryciem.
type StanHosta struct {
	HostID          string `json:"host_id"`
	Hostname        string `json:"hostname,omitempty"`
	Distribution    string `json:"distribution,omitempty"`
	Release         string `json:"release,omitempty"`
	Provider        string `json:"provider,omitempty"`
	SnapshotDigest  string `json:"snapshot_digest,omitempty"`
	InventoryDigest string `json:"inventory_digest,omitempty"`
	PackagesTotal   int    `json:"packages_total"`
	PackagesCovered int    `json:"packages_covered"`
	Affected        int    `json:"affected"`
	// AffectedFixable i AffectedNoFix rozdzielaja to, co da sie zalatac, od
	// tego, czego producent nie naprawil. To sa dwie rozne decyzje operatora,
	// a sklejone w jedna liczbe daja sciane, ktorej nikt nie przeczyta.
	AffectedFixable int `json:"affected_fixable"`
	AffectedNoFix   int `json:"affected_no_fix"`
	Unknown         int `json:"unknown"`
	// CoverageReason mowi, dlaczego ocena jest niepelna. Pusty oznacza pelne
	// pokrycie; kazdy inny stan musi byc widoczny obok liczby znalezisk.
	CoverageReason string     `json:"coverage_reason,omitempty"`
	EvaluatedAt    *time.Time `json:"evaluated_at,omitempty"`
}

// Pokrycie liczy udzial pakietow objetych feedem.
func (s StanHosta) Pokrycie() float64 {
	if s.PackagesTotal == 0 {
		return 0
	}
	return float64(s.PackagesCovered) / float64(s.PackagesTotal)
}

// StanyHostow zwraca stan oceny wielu hostow.
func (s *Store) StanyHostow(ctx context.Context, hostIDs []string) (map[string]StanHosta, error) {
	wynik := map[string]StanHosta{}
	if len(hostIDs) == 0 {
		return wynik, nil
	}
	const query = `
		select host_id::text, distribution, release, provider, snapshot_digest,
		       inventory_digest, packages_total, packages_covered, affected,
		       affected_fixable, affected_no_fix, unknown, coverage_reason, evaluated_at
		from vuln_host_state where host_id = any($1)`
	rows, err := s.pool.Query(ctx, query, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var stan StanHosta
		if err := rows.Scan(&stan.HostID, &stan.Distribution, &stan.Release, &stan.Provider,
			&stan.SnapshotDigest, &stan.InventoryDigest, &stan.PackagesTotal,
			&stan.PackagesCovered, &stan.Affected, &stan.AffectedFixable, &stan.AffectedNoFix,
			&stan.Unknown, &stan.CoverageReason, &stan.EvaluatedAt); err != nil {
			return nil, err
		}
		wynik[stan.HostID] = stan
	}
	return wynik, rows.Err()
}
