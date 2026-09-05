// Package backup przechowuje definicje kopii i historie ich przebiegow.
//
// Danych backupowych tu nie ma i nie bedzie: host rozmawia z repozytorium
// wprost. Panel trzyma to, czego host sam nie powie - co ma byc backupowane,
// dokad i jak dlugo zostaje - oraz to, czego host nie pamieta miedzy
// operacjami: kiedy ostatnia kopia sie udala.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNieZnaleziono oznacza brak definicji.
var ErrNieZnaleziono = errors.New("panel nie zna takiej definicji kopii")

// Definicja opisuje, co i dokad backupowac.
type Definicja struct {
	ID     string `json:"id"`
	HostID string `json:"host_id"`
	Name   string `json:"name"`
	Tool   string `json:"tool"`
	// Repository jest odnosnikiem do celu backupu. Panel go pokazuje, ale
	// przez niego nie posredniczy.
	Repository  string   `json:"repository,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Excludes    []string `json:"excludes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	KeepLast    int      `json:"keep_last,omitempty"`
	KeepDaily   int      `json:"keep_daily,omitempty"`
	KeepWeekly  int      `json:"keep_weekly,omitempty"`
	KeepMonthly int      `json:"keep_monthly,omitempty"`
	Prune       bool     `json:"prune,omitempty"`
	Runbook     string   `json:"runbook,omitempty"`
	// Initialize jest zgoda na zalozenie repozytorium przy pierwszej kopii.
	Initialize bool `json:"initialize,omitempty"`
	// PasswordSecret i EnvSecrets sa nazwami sekretow. Wartosci nie zna ani
	// ta tabela, ani nikt poza magazynem.
	PasswordSecret string            `json:"password_secret,omitempty"`
	EnvSecrets     map[string]string `json:"env_secrets,omitempty"`
	Note           string            `json:"note,omitempty"`
	CreatedBy      string            `json:"created_by"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedBy      string            `json:"updated_by"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// Przebieg jest jednym wykonaniem operacji backupu.
type Przebieg struct {
	HostID     string `json:"host_id"`
	Definition string `json:"definition"`
	Kind       string `json:"kind"`
	JobID      string `json:"job_id,omitempty"`
	Outcome    string `json:"outcome"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	// Liczniki sa wskaznikami: narzedzie, ktore ich nie poda, zostawia brak
	// wiedzy, a nie zero.
	BytesAdded      *int64     `json:"bytes_added,omitempty"`
	TotalBytes      *int64     `json:"total_bytes,omitempty"`
	FilesNew        *int64     `json:"files_new,omitempty"`
	DurationSeconds *float64   `json:"duration_seconds,omitempty"`
	Snapshots       *int       `json:"snapshots,omitempty"`
	RepositorySize  *int64     `json:"repository_size,omitempty"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	Message         string     `json:"message,omitempty"`
	StartedBy       string     `json:"started_by,omitempty"`
	RecordedAt      time.Time  `json:"recorded_at"`
}

// wykonawca pozwala wolac te same zapytania w transakcji i poza nia.
type wykonawca interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store realizuje dostep do tabel backupu.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const koluminyDefinicji = `id::text, host_id::text, name, tool, repository, paths, excludes,
	tags, keep_last, keep_daily, keep_weekly, keep_monthly, prune, runbook, initialize,
	password_secret, env_secrets, note, created_by, created_at, updated_by, updated_at`

// Definicje zwraca definicje kopii hosta.
func (s *Store) Definicje(ctx context.Context, hostID string) ([]Definicja, error) {
	rows, err := s.pool.Query(ctx,
		`select `+koluminyDefinicji+` from backup_definitions where host_id = $1 order by name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Definicja
	for rows.Next() {
		definicja, err := czytajDefinicje(rows)
		if err != nil {
			return nil, err
		}
		wynik = append(wynik, definicja)
	}
	return wynik, rows.Err()
}

// Definicja zwraca jedna definicje.
func (s *Store) Definicja(ctx context.Context, hostID, nazwa string) (Definicja, error) {
	rows, err := s.pool.Query(ctx,
		`select `+koluminyDefinicji+` from backup_definitions where host_id = $1 and name = $2`,
		hostID, nazwa)
	if err != nil {
		return Definicja{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Definicja{}, ErrNieZnaleziono
	}
	return czytajDefinicje(rows)
}

func czytajDefinicje(rows pgx.Rows) (Definicja, error) {
	var definicja Definicja
	var zmienne []byte
	if err := rows.Scan(&definicja.ID, &definicja.HostID, &definicja.Name, &definicja.Tool,
		&definicja.Repository, &definicja.Paths, &definicja.Excludes, &definicja.Tags,
		&definicja.KeepLast, &definicja.KeepDaily, &definicja.KeepWeekly, &definicja.KeepMonthly,
		&definicja.Prune, &definicja.Runbook, &definicja.Initialize,
		&definicja.PasswordSecret, &zmienne,
		&definicja.Note, &definicja.CreatedBy, &definicja.CreatedAt,
		&definicja.UpdatedBy, &definicja.UpdatedAt); err != nil {
		return Definicja{}, err
	}
	if len(zmienne) > 0 {
		_ = json.Unmarshal(zmienne, &definicja.EnvSecrets)
	}
	return definicja, nil
}

// Ustaw zaklada albo aktualizuje definicje.
func (s *Store) Ustaw(ctx context.Context, definicja Definicja) (Definicja, error) {
	// Pusta lista i brak listy znacza w bazie to samo - kolumna nie przyjmuje
	// wartosci pustej, a definicja bez wykluczen jest zwyczajna definicja.
	definicja.Paths = niepustaLista(definicja.Paths)
	definicja.Excludes = niepustaLista(definicja.Excludes)
	definicja.Tags = niepustaLista(definicja.Tags)
	zmienne, err := json.Marshal(definicja.EnvSecrets)
	if err != nil {
		return Definicja{}, err
	}
	if definicja.EnvSecrets == nil {
		zmienne = []byte("{}")
	}
	const query = `
		insert into backup_definitions (host_id, name, tool, repository, paths, excludes, tags,
		                                keep_last, keep_daily, keep_weekly, keep_monthly, prune,
		                                runbook, initialize, password_secret, env_secrets, note,
		                                created_by, updated_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $18)
		on conflict (host_id, name) do update set
			tool = excluded.tool, repository = excluded.repository, paths = excluded.paths,
			excludes = excluded.excludes, tags = excluded.tags, keep_last = excluded.keep_last,
			keep_daily = excluded.keep_daily, keep_weekly = excluded.keep_weekly,
			keep_monthly = excluded.keep_monthly, prune = excluded.prune,
			runbook = excluded.runbook, initialize = excluded.initialize,
			password_secret = excluded.password_secret,
			env_secrets = excluded.env_secrets, note = excluded.note,
			updated_by = excluded.updated_by, updated_at = now()
		returning id::text, created_at, updated_at`
	err = s.pool.QueryRow(ctx, query, definicja.HostID, definicja.Name, definicja.Tool,
		definicja.Repository, definicja.Paths, definicja.Excludes, definicja.Tags,
		definicja.KeepLast, definicja.KeepDaily, definicja.KeepWeekly, definicja.KeepMonthly,
		definicja.Prune, definicja.Runbook, definicja.Initialize,
		definicja.PasswordSecret, zmienne, definicja.Note, definicja.UpdatedBy).
		Scan(&definicja.ID, &definicja.CreatedAt, &definicja.UpdatedAt)
	definicja.CreatedBy = definicja.UpdatedBy
	return definicja, err
}

// Usun kasuje definicje. Historia przebiegow zostaje.
func (s *Store) Usun(ctx context.Context, hostID, nazwa string) error {
	znacznik, err := s.pool.Exec(ctx,
		`delete from backup_definitions where host_id = $1 and name = $2`, hostID, nazwa)
	if err != nil {
		return err
	}
	if znacznik.RowsAffected() == 0 {
		return ErrNieZnaleziono
	}
	return nil
}

// ZapiszPrzebieg dopisuje wynik operacji do historii.
func (s *Store) ZapiszPrzebieg(ctx context.Context, q wykonawca, przebieg Przebieg) error {
	const query = `
		insert into backup_runs (host_id, definition, kind, job_id, outcome, snapshot_id,
		                         bytes_added, total_bytes, files_new, duration_seconds,
		                         snapshots, repository_size, last_success_at, message, started_by)
		values ($1, $2, $3, nullif($4, '')::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := q.Exec(ctx, query, przebieg.HostID, przebieg.Definition, przebieg.Kind,
		przebieg.JobID, przebieg.Outcome, przebieg.SnapshotID, przebieg.BytesAdded,
		przebieg.TotalBytes, przebieg.FilesNew, przebieg.DurationSeconds, przebieg.Snapshots,
		przebieg.RepositorySize, przebieg.LastSuccessAt, przebieg.Message, przebieg.StartedBy)
	return err
}

const kolumnyPrzebiegu = `host_id::text, definition, kind, coalesce(job_id::text, ''), outcome,
	snapshot_id, bytes_added, total_bytes, files_new, duration_seconds, snapshots,
	repository_size, last_success_at, message, started_by, recorded_at`

// Przebiegi zwraca historie operacji hosta, od najnowszej.
func (s *Store) Przebiegi(ctx context.Context, hostID, definicja string, limit int) ([]Przebieg, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `select `+kolumnyPrzebiegu+`
		from backup_runs where host_id = $1 and ($2 = '' or definition = $2)
		order by recorded_at desc limit $3`, hostID, definicja, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Przebieg
	for rows.Next() {
		przebieg, err := czytajPrzebieg(rows)
		if err != nil {
			return nil, err
		}
		wynik = append(wynik, przebieg)
	}
	return wynik, rows.Err()
}

// Ostatnie zwraca najnowszy przebieg kazdego rodzaju dla kazdej definicji.
//
// To z niego bierze sie odpowiedz na dwa pytania, ktore operator zadaje
// najczesciej: kiedy ostatnia kopia sie udala i czy ktos ja kiedykolwiek
// sprawdzil.
func (s *Store) Ostatnie(ctx context.Context, hostID string) (map[string]map[string]Przebieg, error) {
	rows, err := s.pool.Query(ctx, `select distinct on (definition, kind) `+kolumnyPrzebiegu+`
		from backup_runs where host_id = $1 and outcome = 'succeeded'
		order by definition, kind, recorded_at desc`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wynik := map[string]map[string]Przebieg{}
	for rows.Next() {
		przebieg, err := czytajPrzebieg(rows)
		if err != nil {
			return nil, err
		}
		if wynik[przebieg.Definition] == nil {
			wynik[przebieg.Definition] = map[string]Przebieg{}
		}
		wynik[przebieg.Definition][przebieg.Kind] = przebieg
	}
	return wynik, rows.Err()
}

// OstatnieWeFlocie zwraca najnowszy udany przebieg danego rodzaju dla kazdego
// hosta i kazdej definicji.
func (s *Store) OstatnieWeFlocie(ctx context.Context, hostIDs []string, rodzaj string) ([]Przebieg, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `select distinct on (host_id, definition) `+kolumnyPrzebiegu+`
		from backup_runs where host_id = any($1) and kind = $2 and outcome = 'succeeded'
		order by host_id, definition, recorded_at desc`, hostIDs, rodzaj)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Przebieg
	for rows.Next() {
		przebieg, err := czytajPrzebieg(rows)
		if err != nil {
			return nil, err
		}
		wynik = append(wynik, przebieg)
	}
	return wynik, rows.Err()
}

// DefinicjeFloty zwraca definicje wielu hostow naraz.
func (s *Store) DefinicjeFloty(ctx context.Context, hostIDs []string) ([]Definicja, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `select `+koluminyDefinicji+`
		from backup_definitions where host_id = any($1) order by host_id, name`, hostIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var wynik []Definicja
	for rows.Next() {
		definicja, err := czytajDefinicje(rows)
		if err != nil {
			return nil, err
		}
		wynik = append(wynik, definicja)
	}
	return wynik, rows.Err()
}

func czytajPrzebieg(rows pgx.Rows) (Przebieg, error) {
	var przebieg Przebieg
	if err := rows.Scan(&przebieg.HostID, &przebieg.Definition, &przebieg.Kind,
		&przebieg.JobID, &przebieg.Outcome, &przebieg.SnapshotID, &przebieg.BytesAdded,
		&przebieg.TotalBytes, &przebieg.FilesNew, &przebieg.DurationSeconds,
		&przebieg.Snapshots, &przebieg.RepositorySize, &przebieg.LastSuccessAt,
		&przebieg.Message, &przebieg.StartedBy, &przebieg.RecordedAt); err != nil {
		return Przebieg{}, err
	}
	return przebieg, nil
}

// niepustaLista zamienia brak listy na liste pusta.
func niepustaLista(wartosci []string) []string {
	if wartosci == nil {
		return []string{}
	}
	return wartosci
}
