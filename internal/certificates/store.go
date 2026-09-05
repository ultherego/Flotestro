// Package certificates przechowuje zakres obserwacji certyfikatow i historie
// ich wdrozen.
//
// Panel trzyma u siebie to, czego host sam nie powie: ktory plik jest
// certyfikatem uslugi, ktora usluga go czyta i pod jakim adresem widac skutek
// wdrozenia. Bez tego modul musialby zgadywac - albo przeszukiwac caly dysk,
// co konczy sie lista urzedow z magazynu zaufania zamiast odpowiedzia.
//
// Klucza prywatnego nie ma tu w zadnej postaci: zostaje sama nazwa sekretu.
package certificates

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNieZnaleziono oznacza brak celu albo wdrozenia.
var ErrNieZnaleziono = errors.New("panel nie obserwuje tego certyfikatu")

// Cel opisuje plik, ktorego panel pilnuje na hoscie.
type Cel struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	Path   string `json:"path"`
	// KeyPath i KeySecret opisuja klucz prywatny: gdzie ma lezec i skad
	// pochodzi. Wartosci klucza panel nie zna i znac nie moze.
	KeyPath   string `json:"key_path,omitempty"`
	KeySecret string `json:"key_secret,omitempty"`
	// ReloadUnit jest usluga, ktora ten plik czyta; ProbeTarget adresem,
	// pod ktorym widac, ze go przeczytala.
	ReloadUnit  string    `json:"reload_unit,omitempty"`
	ProbeTarget string    `json:"probe_target,omitempty"`
	Service     string    `json:"service,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Wdrozenie opisuje jedno wdrozenie certyfikatu przez panel.
type Wdrozenie struct {
	HostID            string     `json:"host_id"`
	Path              string     `json:"path"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	// Certificate jest trescia jawna: certyfikat wraz z lancuchem. Panel
	// trzyma go, zeby dalo sie pokazac, co dokladnie wyslano - i zeby dalo
	// sie do tego wrocic.
	Certificate string    `json:"certificate,omitempty"`
	KeySecret   string    `json:"key_secret,omitempty"`
	KeyVersion  int       `json:"key_secret_version,omitempty"`
	JobID       string    `json:"job_id,omitempty"`
	DeployedBy  string    `json:"deployed_by"`
	DeployedAt  time.Time `json:"deployed_at"`
}

// wykonawca pozwala wolac te same zapytania w transakcji i poza nia.
type wykonawca interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store realizuje dostep do tabel certyfikatow.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Cele zwraca pliki, ktorych panel pilnuje na hoscie.
func (s *Store) Cele(ctx context.Context, hostID string) ([]Cel, error) {
	const query = `
		select id::text, host_id::text, path, key_path, key_secret, reload_unit,
		       probe_target, service, note, created_by, created_at, updated_by, updated_at
		from certificate_targets where host_id = $1 order by path`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Cel
	for rows.Next() {
		var cel Cel
		if err := rows.Scan(&cel.ID, &cel.HostID, &cel.Path, &cel.KeyPath, &cel.KeySecret,
			&cel.ReloadUnit, &cel.ProbeTarget, &cel.Service, &cel.Note,
			&cel.CreatedBy, &cel.CreatedAt, &cel.UpdatedBy, &cel.UpdatedAt); err != nil {
			return nil, err
		}
		wynik = append(wynik, cel)
	}
	return wynik, rows.Err()
}

// Cel zwraca jeden obserwowany plik.
func (s *Store) Cel(ctx context.Context, hostID, sciezka string) (Cel, error) {
	const query = `
		select id::text, host_id::text, path, key_path, key_secret, reload_unit,
		       probe_target, service, note, created_by, created_at, updated_by, updated_at
		from certificate_targets where host_id = $1 and path = $2`
	var cel Cel
	err := s.pool.QueryRow(ctx, query, hostID, sciezka).Scan(&cel.ID, &cel.HostID, &cel.Path,
		&cel.KeyPath, &cel.KeySecret, &cel.ReloadUnit, &cel.ProbeTarget, &cel.Service,
		&cel.Note, &cel.CreatedBy, &cel.CreatedAt, &cel.UpdatedBy, &cel.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cel{}, ErrNieZnaleziono
	}
	return cel, err
}

// Ustaw zaklada albo aktualizuje obserwowany plik.
func (s *Store) Ustaw(ctx context.Context, cel Cel) (Cel, error) {
	const query = `
		insert into certificate_targets (host_id, path, key_path, key_secret, reload_unit,
		                                 probe_target, service, note, created_by, updated_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
		on conflict (host_id, path) do update set
			key_path = excluded.key_path, key_secret = excluded.key_secret,
			reload_unit = excluded.reload_unit, probe_target = excluded.probe_target,
			service = excluded.service, note = excluded.note,
			updated_by = excluded.updated_by, updated_at = now()
		returning id::text, created_at, updated_at`
	err := s.pool.QueryRow(ctx, query, cel.HostID, cel.Path, cel.KeyPath, cel.KeySecret,
		cel.ReloadUnit, cel.ProbeTarget, cel.Service, cel.Note, cel.UpdatedBy).
		Scan(&cel.ID, &cel.CreatedAt, &cel.UpdatedAt)
	cel.CreatedBy = cel.UpdatedBy
	return cel, err
}

// Usun konczy obserwacje pliku. Historia wdrozen zostaje: to, ze panel
// kiedys tam cos polozyl, jest faktem, ktorego skasowanie celu nie odwraca.
func (s *Store) Usun(ctx context.Context, hostID, sciezka string) error {
	const query = `delete from certificate_targets where host_id = $1 and path = $2`
	znacznik, err := s.pool.Exec(ctx, query, hostID, sciezka)
	if err != nil {
		return err
	}
	if znacznik.RowsAffected() == 0 {
		return ErrNieZnaleziono
	}
	return nil
}

// ZapiszWdrozenie dopisuje wpis do historii wdrozen.
func (s *Store) ZapiszWdrozenie(ctx context.Context, q wykonawca, wdrozenie Wdrozenie) error {
	const query = `
		insert into certificate_deployments (host_id, path, fingerprint_sha256, subject,
		                                     issuer, not_after, certificate, key_secret,
		                                     key_secret_version, job_id, deployed_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, nullif($10, '')::uuid, $11)`
	_, err := q.Exec(ctx, query, wdrozenie.HostID, wdrozenie.Path, wdrozenie.FingerprintSHA256,
		wdrozenie.Subject, wdrozenie.Issuer, wdrozenie.NotAfter, wdrozenie.Certificate,
		wdrozenie.KeySecret, wdrozenie.KeyVersion, wdrozenie.JobID, wdrozenie.DeployedBy)
	return err
}

// Wdrozenia zwraca historie wdrozen pliku, od najnowszego.
func (s *Store) Wdrozenia(ctx context.Context, hostID, sciezka string, limit int) ([]Wdrozenie, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	const query = `
		select host_id::text, path, fingerprint_sha256, subject, issuer, not_after,
		       certificate, key_secret, key_secret_version,
		       coalesce(job_id::text, ''), deployed_by, deployed_at
		from certificate_deployments
		where host_id = $1 and ($2 = '' or path = $2)
		order by deployed_at desc
		limit $3`
	rows, err := s.pool.Query(ctx, query, hostID, sciezka, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Wdrozenie
	for rows.Next() {
		var wdrozenie Wdrozenie
		if err := rows.Scan(&wdrozenie.HostID, &wdrozenie.Path, &wdrozenie.FingerprintSHA256,
			&wdrozenie.Subject, &wdrozenie.Issuer, &wdrozenie.NotAfter, &wdrozenie.Certificate,
			&wdrozenie.KeySecret, &wdrozenie.KeyVersion, &wdrozenie.JobID,
			&wdrozenie.DeployedBy, &wdrozenie.DeployedAt); err != nil {
			return nil, err
		}
		wynik = append(wynik, wdrozenie)
	}
	return wynik, rows.Err()
}

// Ostatnie zwraca najnowsze wdrozenie dla kazdego pliku na hoscie.
//
// To ono odpowiada na pytanie "czy to, co lezy na hoscie, polozyl tam panel":
// odcisk z wdrozenia porownany z odciskiem z inwentarza rozroznia certyfikat
// wdrozony od podmienionego poza panelem.
func (s *Store) Ostatnie(ctx context.Context, hostID string) (map[string]Wdrozenie, error) {
	const query = `
		select distinct on (path) path, fingerprint_sha256, subject, issuer, not_after,
		       key_secret, key_secret_version, coalesce(job_id::text, ''),
		       deployed_by, deployed_at
		from certificate_deployments
		where host_id = $1
		order by path, deployed_at desc`
	rows, err := s.pool.Query(ctx, query, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wynik := map[string]Wdrozenie{}
	for rows.Next() {
		wdrozenie := Wdrozenie{HostID: hostID}
		if err := rows.Scan(&wdrozenie.Path, &wdrozenie.FingerprintSHA256, &wdrozenie.Subject,
			&wdrozenie.Issuer, &wdrozenie.NotAfter, &wdrozenie.KeySecret,
			&wdrozenie.KeyVersion, &wdrozenie.JobID,
			&wdrozenie.DeployedBy, &wdrozenie.DeployedAt); err != nil {
			return nil, err
		}
		wynik[wdrozenie.Path] = wdrozenie
	}
	return wynik, rows.Err()
}
