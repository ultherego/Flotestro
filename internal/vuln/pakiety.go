// Package vuln koreluje zainstalowane pakiety z ustaleniami trackerow
// bezpieczenstwa dystrybucji.
//
// Rozstrzyga producent dystrybucji, a nie feed upstreamowy: Debian, Ubuntu
// i Fedora wydaja poprawki wstecz do wersji, ktore wedlug numeracji upstream
// nadal wygladaja na podatne. Porownanie zakresu z NVD z wersja pakietu
// Debiana daje falszywe alarmy w jedna strone i przeoczenia w druga.
//
// Panel nie zgaduje: pakiet, o ktorym feed nie mowi nic, jest stanem
// nieustalonym z kodem powodu - a nie pakietem bezpiecznym.
package vuln

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/packages"
)

// StanListy opisuje to, co panel wie o liscie pakietow hosta.
type StanListy struct {
	HostID string `json:"host_id"`
	// Digest jest odciskiem listy, ktora panel ma u siebie.
	Digest       string     `json:"digest,omitempty"`
	PackageCount int        `json:"package_count"`
	CollectedAt  *time.Time `json:"collected_at,omitempty"`
	JobID        string     `json:"job_id,omitempty"`
	// UnavailableReason mowi, dlaczego listy nie ma albo dlaczego jest
	// niepelna.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// wykonawca pozwala wolac te same zapytania w transakcji i poza nia.
type wykonawca interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// MagazynPakietow trzyma liste pakietow hostow.
type MagazynPakietow struct {
	pool *pgxpool.Pool
}

func NowyMagazynPakietow(pool *pgxpool.Pool) *MagazynPakietow {
	return &MagazynPakietow{pool: pool}
}

// Zastap podmienia cala liste pakietow hosta w jednej transakcji.
//
// Podmiana, a nie scalanie: lista czesciowa jest gorsza niz jej brak, bo
// wyglada jak komplet. Albo panel ma obraz z jednej chwili, albo nie ma go
// wcale.
func (m *MagazynPakietow) Zastap(ctx context.Context, hostID string,
	pakiety []packages.InstalledPackage, stan StanListy) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from host_packages where host_id = $1`, hostID); err != nil {
		return err
	}
	if len(pakiety) > 0 {
		wiersze := make([][]any, 0, len(pakiety))
		for _, pakiet := range pakiety {
			wiersze = append(wiersze, []any{
				hostID, pakiet.Name, pakiet.Architecture, pakiet.Epoch, pakiet.Version,
				pakiet.Release, pakiet.SourceName, pakiet.SourceVersion, pakiet.SourceRPM,
				pakiet.Vendor, pakiet.RepositoryID, pakiet.ModuleStream,
			})
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"host_packages"}, []string{
			"host_id", "name", "architecture", "epoch", "version", "release",
			"source_name", "source_version", "source_rpm", "vendor",
			"repository_id", "module_stream",
		}, pgx.CopyFromRows(wiersze))
		if err != nil {
			return err
		}
	}

	const zapisStanu = `
		insert into host_package_state (host_id, digest, package_count, collected_at,
		                                job_id, unavailable_reason)
		values ($1, $2, $3, $4, nullif($5, '')::uuid, $6)
		on conflict (host_id) do update set
			digest = excluded.digest, package_count = excluded.package_count,
			collected_at = excluded.collected_at, job_id = excluded.job_id,
			unavailable_reason = excluded.unavailable_reason`
	if _, err := tx.Exec(ctx, zapisStanu, hostID, stan.Digest, stan.PackageCount,
		stan.CollectedAt, stan.JobID, stan.UnavailableReason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Stan zwraca to, co panel wie o liscie pakietow hosta.
func (m *MagazynPakietow) Stan(ctx context.Context, hostID string) (StanListy, error) {
	const query = `
		select host_id::text, digest, package_count, collected_at,
		       coalesce(job_id::text, ''), unavailable_reason
		from host_package_state where host_id = $1`
	var stan StanListy
	err := m.pool.QueryRow(ctx, query, hostID).Scan(&stan.HostID, &stan.Digest,
		&stan.PackageCount, &stan.CollectedAt, &stan.JobID, &stan.UnavailableReason)
	if err == pgx.ErrNoRows {
		// Brak wiersza to nie host bez pakietow: to host, ktorego jeszcze
		// nie zapytano.
		return StanListy{HostID: hostID, UnavailableReason: RodzajBrakListy}, nil
	}
	return stan, err
}

// Stany zwraca stan listy dla wielu hostow naraz.
func (m *MagazynPakietow) Stany(ctx context.Context, hostIDs []string) (map[string]StanListy, error) {
	wynik := map[string]StanListy{}
	if len(hostIDs) == 0 {
		return wynik, nil
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
		var stan StanListy
		if err := rows.Scan(&stan.HostID, &stan.Digest, &stan.PackageCount,
			&stan.CollectedAt, &stan.JobID, &stan.UnavailableReason); err != nil {
			return nil, err
		}
		wynik[stan.HostID] = stan
	}
	return wynik, rows.Err()
}

// Pakiety zwraca liste pakietow hosta.
func (m *MagazynPakietow) Pakiety(ctx context.Context, hostID string) ([]packages.InstalledPackage, error) {
	const query = `
		select name, architecture, epoch, version, release, source_name,
		       source_version, source_rpm, vendor, repository_id, module_stream
		from host_packages where host_id = $1 order by name, architecture`
	rows, err := m.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pakiety []packages.InstalledPackage
	for rows.Next() {
		var pakiet packages.InstalledPackage
		if err := rows.Scan(&pakiet.Name, &pakiet.Architecture, &pakiet.Epoch,
			&pakiet.Version, &pakiet.Release, &pakiet.SourceName, &pakiet.SourceVersion,
			&pakiet.SourceRPM, &pakiet.Vendor, &pakiet.RepositoryID,
			&pakiet.ModuleStream); err != nil {
			return nil, err
		}
		pakiety = append(pakiety, pakiet)
	}
	return pakiety, rows.Err()
}
