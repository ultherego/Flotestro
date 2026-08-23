// Package files przechowuje stan docelowy plikow konfiguracyjnych i historie
// ich zmian.
//
// Panel trzyma stan docelowy u siebie, bo bez niego nie da sie odpowiedziec
// na dwa pytania, ktore operator zadaje najczesciej: czy ktos zmienil plik
// poza panelem i jak wrocic do tresci sprzed zmiany.
package files

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	modul "github.com/ultherego/flotestro/internal/modules/files"
)

// ErrNieZnaleziono oznacza brak pliku albo wersji.
var ErrNieZnaleziono = errors.New("plik nie jest zarzadzany przez panel")

// StanDocelowy opisuje plik, ktorym zarzadza panel.
type StanDocelowy struct {
	HostID    string    `json:"host_id"`
	Path      string    `json:"path"`
	SHA256    string    `json:"desired_sha256"`
	Mode      string    `json:"mode,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Group     string    `json:"group,omitempty"`
	Validator string    `json:"validator,omitempty"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Wersja to jedna tresc pliku w historii.
type Wersja struct {
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
	JobID     *string   `json:"job_id,omitempty"`
	AppliedBy string    `json:"applied_by"`
	AppliedAt time.Time `json:"applied_at"`
}

// wykonawca pozwala wolac te same zapytania w transakcji i poza nia.
// Wpis historii musi widziec zadanie, ktore powstalo w tej samej transakcji,
// wiec zapis nie moze isc obok niej wlasnym polaczeniem.
type wykonawca interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store realizuje dostep do tabel plikow.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ZapiszWersje zapisuje tresc adresowana odciskiem.
//
// Ta sama tresc na stu hostach zajmuje miejsce raz: klucz glowny jest
// odciskiem, wiec powtorzony zapis nie tworzy drugiego wiersza.
func (s *Store) ZapiszWersje(ctx context.Context, q wykonawca, tresc []byte) (string, error) {
	odcisk := modul.Odcisk(tresc)
	const query = `
		insert into file_versions (sha256, content, size_bytes)
		values ($1, $2, $3)
		on conflict (sha256) do nothing`
	if _, err := q.Exec(ctx, query, odcisk, tresc, len(tresc)); err != nil {
		return "", err
	}
	return odcisk, nil
}

// Tresc zwraca zawartosc wersji o podanym odcisku.
func (s *Store) Tresc(ctx context.Context, odcisk string) ([]byte, error) {
	const query = `select content from file_versions where sha256 = $1`
	var tresc []byte
	err := s.pool.QueryRow(ctx, query, odcisk).Scan(&tresc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNieZnaleziono
	}
	return tresc, err
}

// Ustaw zapisuje stan docelowy pliku i dopisuje wpis do historii.
func (s *Store) Ustaw(ctx context.Context, q wykonawca, stan StanDocelowy, jobID string) error {
	const zapisStanu = `
		insert into managed_files (host_id, path, desired_sha256, mode, owner_name,
		                           group_name, validator, updated_by, updated_at)
		values ($1, $2, $3, nullif($4, ''), nullif($5, ''), nullif($6, ''), nullif($7, ''), $8, now())
		on conflict (host_id, path) do update set
			desired_sha256 = excluded.desired_sha256,
			mode = excluded.mode, owner_name = excluded.owner_name,
			group_name = excluded.group_name, validator = excluded.validator,
			updated_by = excluded.updated_by, updated_at = now()`
	if _, err := q.Exec(ctx, zapisStanu, stan.HostID, stan.Path, stan.SHA256,
		stan.Mode, stan.Owner, stan.Group, stan.Validator, stan.UpdatedBy); err != nil {
		return err
	}

	const zapisHistorii = `
		insert into managed_file_history (host_id, path, sha256, job_id, applied_by)
		values ($1, $2, $3, nullif($4, '')::uuid, $5)`
	if _, err := q.Exec(ctx, zapisHistorii, stan.HostID, stan.Path, stan.SHA256,
		jobID, stan.UpdatedBy); err != nil {
		return err
	}
	return nil
}

// Usun kasuje stan docelowy. Historia zostaje: to, ze plik byl zarzadzany
// i przestal, jest faktem, ktory trzeba umiec odtworzyc.
func (s *Store) Usun(ctx context.Context, q wykonawca, hostID, sciezka string) error {
	const query = `delete from managed_files where host_id = $1 and path = $2`
	_, err := q.Exec(ctx, query, hostID, sciezka)
	return err
}

// Lista zwraca pliki zarzadzane na hoscie.
func (s *Store) Lista(ctx context.Context, hostID string) ([]StanDocelowy, error) {
	const query = `
		select host_id, path, desired_sha256, coalesce(mode, ''), coalesce(owner_name, ''),
		       coalesce(group_name, ''), coalesce(validator, ''), updated_by, updated_at
		from managed_files where host_id = $1 order by path`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []StanDocelowy
	for rows.Next() {
		var stan StanDocelowy
		if err := rows.Scan(&stan.HostID, &stan.Path, &stan.SHA256, &stan.Mode,
			&stan.Owner, &stan.Group, &stan.Validator, &stan.UpdatedBy, &stan.UpdatedAt); err != nil {
			return nil, err
		}
		wynik = append(wynik, stan)
	}
	return wynik, rows.Err()
}

// Historia zwraca kolejne wersje pliku, od najnowszej.
func (s *Store) Historia(ctx context.Context, hostID, sciezka string, limit int) ([]Wersja, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	const query = `
		select h.sha256, v.size_bytes, h.job_id::text, h.applied_by, h.applied_at
		from managed_file_history h
		join file_versions v on v.sha256 = h.sha256
		where h.host_id = $1 and h.path = $2
		order by h.applied_at desc
		limit $3`
	rows, err := s.pool.Query(ctx, query, hostID, sciezka, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Wersja
	for rows.Next() {
		var wersja Wersja
		if err := rows.Scan(&wersja.SHA256, &wersja.SizeBytes, &wersja.JobID,
			&wersja.AppliedBy, &wersja.AppliedAt); err != nil {
			return nil, err
		}
		wynik = append(wynik, wersja)
	}
	return wynik, rows.Err()
}
