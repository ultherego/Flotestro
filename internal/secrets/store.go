package secrets

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store trzyma sekrety i dzierzawy.
type Store struct {
	pool  *pgxpool.Pool
	szyfr *Szyfr
}

func NewStore(pool *pgxpool.Pool, szyfr *Szyfr) *Store {
	return &Store{pool: pool, szyfr: szyfr}
}

// Pool udostepnia pule do transakcji laczonych z innymi zapisami.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Utworz zaklada sekret wraz z pierwsza wersja.
func (s *Store) Utworz(ctx context.Context, nazwa, opis string, wartosc []byte, autor string) (*Secret, error) {
	if err := WalidujNazwe(nazwa); err != nil {
		return nil, err
	}
	if err := WalidujWartosc(wartosc); err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	if err := tx.QueryRow(ctx, `
		insert into secrets (name, description, created_by) values ($1, $2, $3)
		returning id`, nazwa, nullable(opis), autor).Scan(&id); err != nil {
		return nil, err
	}
	if err := s.zapiszWersje(ctx, tx, id, 1, wartosc, autor); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Sekret(ctx, nazwa)
}

// Obroc dokłada nowa wersje i czyni ja biezaca.
//
// Poprzednie wersje zostaja: host, ktory dostal dzierzawe na wersje 3, ma ja
// dostac takze wtedy, gdy w miedzyczasie powstala wersja 4.
func (s *Store) Obroc(ctx context.Context, nazwa string, wartosc []byte, autor string) (*Secret, error) {
	if err := WalidujWartosc(wartosc); err != nil {
		return nil, err
	}
	sekret, err := s.Sekret(ctx, nazwa)
	if err != nil {
		return nil, err
	}
	if sekret.RetiredAt != nil {
		return nil, ErrRetired
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.zapiszWersje(ctx, tx, sekret.ID, sekret.CurrentVersion+1, wartosc, autor); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Sekret(ctx, nazwa)
}

// zapiszWersje zapisuje zaszyfrowana wartosc i przesuwa wersje biezaca.
func (s *Store) zapiszWersje(ctx context.Context, tx pgx.Tx, secretID string,
	wersja int, wartosc []byte, autor string) error {
	nonce, szyfrogram, err := s.szyfr.Zaszyfruj(wartosc)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		insert into secret_versions (secret_id, version, nonce, ciphertext, size_bytes, created_by)
		values ($1, $2, $3, $4, $5, $6)`,
		secretID, wersja, nonce, szyfrogram, len(wartosc), autor); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		update secrets set current_version = $2, updated_at = now() where id = $1`, secretID, wersja)
	return err
}

// Sekret zwraca metadane sekretu wraz z historia wersji - bez tresci.
func (s *Store) Sekret(ctx context.Context, nazwa string) (*Secret, error) {
	sekrety, err := s.zapytaj(ctx, "where name = $1", nazwa)
	if err != nil {
		return nil, err
	}
	if len(sekrety) == 0 {
		return nil, ErrNotFound
	}
	wersje, err := s.wersje(ctx, sekrety[0].ID)
	if err != nil {
		return nil, err
	}
	sekrety[0].Versions = wersje
	return &sekrety[0], nil
}

// Lista zwraca wszystkie sekrety.
func (s *Store) Lista(ctx context.Context) ([]Secret, error) {
	return s.zapytaj(ctx, "order by name")
}

func (s *Store) zapytaj(ctx context.Context, klauzula string, argumenty ...any) ([]Secret, error) {
	rows, err := s.pool.Query(ctx, `
		select id, name, coalesce(description, ''), current_version,
		       created_by, created_at, updated_at, retired_at
		  from secrets `+klauzula, argumenty...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sekrety []Secret
	for rows.Next() {
		var sekret Secret
		if err := rows.Scan(&sekret.ID, &sekret.Name, &sekret.Description, &sekret.CurrentVersion,
			&sekret.CreatedBy, &sekret.CreatedAt, &sekret.UpdatedAt, &sekret.RetiredAt); err != nil {
			return nil, err
		}
		sekrety = append(sekrety, sekret)
	}
	return sekrety, rows.Err()
}

func (s *Store) wersje(ctx context.Context, secretID string) ([]Wersja, error) {
	rows, err := s.pool.Query(ctx, `
		select version, size_bytes, created_by, created_at, destroyed_at
		  from secret_versions where secret_id = $1 order by version desc`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wersje []Wersja
	for rows.Next() {
		var wersja Wersja
		if err := rows.Scan(&wersja.Version, &wersja.SizeBytes, &wersja.CreatedBy,
			&wersja.CreatedAt, &wersja.Destroyed); err != nil {
			return nil, err
		}
		wersje = append(wersje, wersja)
	}
	return wersje, rows.Err()
}

// Wycofaj zamyka sekret: metadane zostaja, wydawanie sie konczy.
func (s *Store) Wycofaj(ctx context.Context, nazwa string) error {
	tag, err := s.pool.Exec(ctx, `
		update secrets set retired_at = now(), updated_at = now()
		 where name = $1 and retired_at is null`, nazwa)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Dzierzawy wystawione wczesniej traca waznosc razem z sekretem.
	_, err = s.pool.Exec(ctx, `
		update secret_leases set revoked_at = now()
		 where secret_id = (select id from secrets where name = $1)
		   and redeemed_at is null and revoked_at is null`, nazwa)
	return err
}

// Zniszcz kasuje tresc jednej wersji, zostawiajac slad, ze istniala.
func (s *Store) Zniszcz(ctx context.Context, nazwa string, wersja int) error {
	tag, err := s.pool.Exec(ctx, `
		update secret_versions
		   set ciphertext = '\x'::bytea, nonce = '\x'::bytea, destroyed_at = now()
		 where secret_id = (select id from secrets where name = $1)
		   and version = $2 and destroyed_at is null`, nazwa, wersja)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Wystaw zaklada dzierzawe na czas wykonania jednego zadania.
//
// Wersje ustalamy w chwili wystawienia: zadanie zlecone wobec wersji biezacej
// ma dostac te wersje, ktora byla biezaca, gdy je dostarczano - a nie te,
// ktora powstanie w trakcie.
func (s *Store) Wystaw(ctx context.Context, nazwa string, wersja int,
	jobID, hostID string, okno time.Duration) (*Dzierzawa, error) {
	if err := WalidujNazwe(nazwa); err != nil {
		return nil, err
	}
	sekret, err := s.Sekret(ctx, nazwa)
	if err != nil {
		return nil, err
	}
	if sekret.RetiredAt != nil {
		return nil, ErrRetired
	}
	if wersja == 0 {
		wersja = sekret.CurrentVersion
	}
	if wersja <= 0 {
		return nil, ErrNotFound
	}
	if okno <= 0 {
		okno = OknoDzierzawy
	}

	dzierzawa := &Dzierzawa{
		SecretID: sekret.ID, SecretName: sekret.Name, Version: wersja,
		JobID: jobID, HostID: hostID,
	}
	err = s.pool.QueryRow(ctx, `
		insert into secret_leases (secret_id, version, job_id, host_id, expires_at)
		values ($1, $2, $3, $4, now() + $5::interval)
		returning id, issued_at, expires_at`,
		sekret.ID, wersja, jobID, hostID, okno.String()).
		Scan(&dzierzawa.ID, &dzierzawa.IssuedAt, &dzierzawa.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return dzierzawa, nil
}

// Wydaj zwraca wartosc sekretu i zuzywa dzierzawe.
//
// Dzierzawa jest jednorazowa: to samo zadanie moze pobrac sekret raz. Ponowna
// proba jest odmowa, a nie druga kopia - powtorzone pobranie oznacza albo
// ponowienie operacji, ktore dostanie wlasna dzierzawe, albo kogos, kto uzywa
// cudzej.
func (s *Store) Wydaj(ctx context.Context, jobID, hostID, nazwa string, wersja int) ([]byte, int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var leaseID, secretID string
	var wydanaWersja int
	warunekWersji := ""
	argumenty := []any{jobID, hostID, nazwa}
	if wersja > 0 {
		warunekWersji = " and l.version = $4"
		argumenty = append(argumenty, wersja)
	}
	err = tx.QueryRow(ctx, `
		select l.id, l.secret_id, l.version
		  from secret_leases l
		  join secrets s on s.id = l.secret_id
		 where l.job_id = $1 and l.host_id = $2 and s.name = $3
		   and l.redeemed_at is null and l.revoked_at is null
		   and l.expires_at > now() and s.retired_at is null`+warunekWersji+`
		 order by l.issued_at desc
		 limit 1
		   for update`, argumenty...).Scan(&leaseID, &secretID, &wydanaWersja)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, ErrNoLease
	}
	if err != nil {
		return nil, 0, err
	}

	var nonce, szyfrogram []byte
	var zniszczona *time.Time
	if err := tx.QueryRow(ctx, `
		select nonce, ciphertext, destroyed_at from secret_versions
		 where secret_id = $1 and version = $2`, secretID, wydanaWersja).
		Scan(&nonce, &szyfrogram, &zniszczona); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	if zniszczona != nil || len(szyfrogram) == 0 {
		return nil, 0, ErrDestroyed
	}

	wartosc, err := s.szyfr.Odszyfruj(nonce, szyfrogram)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `
		update secret_leases set redeemed_at = now() where id = $1`, leaseID); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return wartosc, wydanaWersja, nil
}

// Uniewaznij zamyka niezuzyte dzierzawy zadania.
//
// Zadanie, ktore sie skonczylo albo zostalo anulowane, nie ma po co trzymac
// otwartego prawa do sekretu.
func (s *Store) Uniewaznij(ctx context.Context, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		update secret_leases set revoked_at = now()
		 where job_id = $1 and redeemed_at is null and revoked_at is null`, jobID)
	return err
}

// Dzierzawy zwraca dzierzawy zadania - do pokazania w audycie operacji.
func (s *Store) Dzierzawy(ctx context.Context, jobID string) ([]Dzierzawa, error) {
	rows, err := s.pool.Query(ctx, `
		select l.id, l.secret_id, s.name, l.version, l.job_id, l.host_id,
		       l.issued_at, l.expires_at, l.redeemed_at, l.revoked_at
		  from secret_leases l join secrets s on s.id = l.secret_id
		 where l.job_id = $1 order by l.issued_at`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dzierzawy []Dzierzawa
	for rows.Next() {
		var dzierzawa Dzierzawa
		if err := rows.Scan(&dzierzawa.ID, &dzierzawa.SecretID, &dzierzawa.SecretName,
			&dzierzawa.Version, &dzierzawa.JobID, &dzierzawa.HostID,
			&dzierzawa.IssuedAt, &dzierzawa.ExpiresAt,
			&dzierzawa.RedeemedAt, &dzierzawa.RevokedAt); err != nil {
			return nil, err
		}
		dzierzawy = append(dzierzawy, dzierzawa)
	}
	return dzierzawy, rows.Err()
}

func nullable(wartosc string) any {
	if wartosc == "" {
		return nil
	}
	return wartosc
}
