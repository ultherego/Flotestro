package budgets

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// domyslnaDzierzawa jest terminem tokenow. Krotszy niz najdluzsza
	// operacja, bo dzierzawa jest odnawiana dopoki zadanie zyje. Awaria
	// orkiestratora ma zwolnic pojemnosc po chwili, a nie po godzinie.
	domyslnaDzierzawa = 2 * time.Minute
	// wiekOczekiwania mowi, jak dlugo nieodswiezone oczekiwanie liczy sie do
	// udzialu. Kampania, ktora przestala pytac, nie moze w nieskonczonosc
	// zmniejszac udzialu pozostalym.
	wiekOczekiwania = 30 * time.Second
	// okresSprzatania wyznacza czestotliwosc usuwania wygaslych wierszy.
	okresSprzatania = time.Minute
)

// Store jest autorytatywnym stanem przyznan.
//
// Trzymamy go w bazie, a nie w pamieci procesu, bo orkiestratorow moze byc
// wiecej niz jeden. Limit egzekwowany w pamieci kazdego z nich nie jest
// limitem floty, tylko limitem instancji - i przy dwoch instancjach znaczy
// dwa razy tyle, co obiecywal.
type Store struct {
	pool      *pgxpool.Pool
	log       *slog.Logger
	dzierzawa time.Duration
}

func NewStore(pool *pgxpool.Pool, log *slog.Logger) *Store {
	return &Store{pool: pool, log: log, dzierzawa: domyslnaDzierzawa}
}

// Zajmij przyznaje wszystkie potrzeby albo zadna.
//
// Czesciowe zajecie byloby gorsze niz odmowa: token globalny trzymany podczas
// czekania na token lokalizacji zmniejsza pojemnosc floty dla wszystkich
// innych, nie zblizajac tego zadania do startu. Dlatego caly zestaw idzie
// w jednej transakcji, a wiersze pojemnosci sa blokowane w ustalonej
// kolejnosci - bez tego dwa orkiestratory potrafilyby sie zakleszczyc.
//
// Pusta odmowa oznacza sukces. Wlasciciel jest identyfikatorem zadania
// (u nas: celu kampanii), roszczacy - jednostka sprawiedliwosci, czyli calej
// kampanii.
func (s *Store) Zajmij(ctx context.Context, wlasciciel, roszczacy string, klasa Klasa,
	potrzeby []Potrzeba) (Odmowa, error) {
	if len(potrzeby) == 0 {
		return Odmowa{}, nil
	}
	uporzadkowane := make([]Potrzeba, len(potrzeby))
	copy(uporzadkowane, potrzeby)
	sort.Slice(uporzadkowane, func(i, j int) bool {
		return uporzadkowane[i].Klucz < uporzadkowane[j].Klucz
	})

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Odmowa{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pojemnosci, err := s.pojemnosci(ctx, tx, uporzadkowane)
	if err != nil {
		return Odmowa{}, err
	}

	przyznane := make([]Potrzeba, 0, len(uporzadkowane))
	for _, potrzeba := range uporzadkowane {
		pojemnosc, opisany := pojemnosci[potrzeba.Klucz]
		if !opisany {
			// Budzet nieskonfigurowany nie jest budzetem zerowym. Nie
			// zatrzymuje zadania, ale tez nie udaje, ze czegos pilnuje.
			continue
		}
		odmowa, err := s.sprawdz(ctx, tx, wlasciciel, roszczacy, klasa, potrzeba, pojemnosc)
		if err != nil {
			return Odmowa{}, err
		}
		if !odmowa.Pusta() {
			if err := s.zapiszOczekiwanie(ctx, tx, potrzeba.Klucz, roszczacy, klasa); err != nil {
				return Odmowa{}, err
			}
			// Oczekiwanie musi przetrwac odmowe: bez niego nikt nie policzy
			// udzialu ani nie awansuje czekajacego po czasie.
			if err := tx.Commit(ctx); err != nil {
				return Odmowa{}, err
			}
			return odmowa, nil
		}
		przyznane = append(przyznane, potrzeba)
	}

	for _, potrzeba := range przyznane {
		if err := s.zapiszDzierzawe(ctx, tx, potrzeba, wlasciciel, roszczacy); err != nil {
			return Odmowa{}, err
		}
	}
	if _, err := tx.Exec(ctx,
		`delete from budget_waiters where claimant = $1 and key = any($2)`,
		roszczacy, klucze(przyznane)); err != nil {
		return Odmowa{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Odmowa{}, err
	}
	return Odmowa{}, nil
}

// pojemnosci czyta i blokuje wiersze pojemnosci dla calego zestawu potrzeb.
//
// Klucz scisly wygrywa z wzorcem: instalacja moze opisac jedna lokalizacje
// inaczej niz wszystkie pozostale.
func (s *Store) pojemnosci(ctx context.Context, tx pgx.Tx,
	potrzeby []Potrzeba) (map[string]int, error) {
	szukane := make([]string, 0, 2*len(potrzeby))
	for _, potrzeba := range potrzeby {
		szukane = append(szukane, potrzeba.Klucz)
		if wzorzec := Wzorzec(potrzeba.Klucz); wzorzec != "" {
			szukane = append(szukane, wzorzec)
		}
	}
	// Kolejnosc blokowania jest ustalona kluczem, wiec dwa orkiestratory
	// biora te same wiersze w tej samej kolejnosci.
	rows, err := tx.Query(ctx,
		`select key, capacity from budget_limits where key = any($1) order by key for update`,
		szukane)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zrodlo := map[string]int{}
	for rows.Next() {
		var klucz string
		var pojemnosc int
		if err := rows.Scan(&klucz, &pojemnosc); err != nil {
			return nil, err
		}
		zrodlo[klucz] = pojemnosc
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	wynik := map[string]int{}
	for _, potrzeba := range potrzeby {
		if pojemnosc, ok := zrodlo[potrzeba.Klucz]; ok {
			wynik[potrzeba.Klucz] = pojemnosc
			continue
		}
		if pojemnosc, ok := zrodlo[Wzorzec(potrzeba.Klucz)]; ok {
			wynik[potrzeba.Klucz] = pojemnosc
		}
	}
	return wynik, nil
}

// sprawdz rozstrzyga jeden budzet: najpierw pojemnosc, potem udzial.
func (s *Store) sprawdz(ctx context.Context, tx pgx.Tx, wlasciciel, roszczacy string,
	klasa Klasa, potrzeba Potrzeba, pojemnosc int) (Odmowa, error) {
	// Wlasne, wczesniejsze zajecie tego samego klucza nie moze liczyc sie
	// dwa razy: ponowienie zadania nie jest nowym obciazeniem.
	const zajetosc = `
		select coalesce(sum(weight), 0),
		       coalesce(sum(weight) filter (where claimant = $2), 0)
		  from budget_leases
		 where key = $1 and lease_until > now() and owner <> $3`
	var zajete, moje int
	if err := tx.QueryRow(ctx, zajetosc, potrzeba.Klucz, roszczacy, wlasciciel).
		Scan(&zajete, &moje); err != nil {
		return Odmowa{}, err
	}

	czeka, err := s.czasOczekiwania(ctx, tx, potrzeba.Klucz, roszczacy)
	if err != nil {
		return Odmowa{}, err
	}
	if zajete+potrzeba.Waga > pojemnosc {
		return Odmowa{Klucz: potrzeba.Klucz, Powod: PowodPojemnosc,
			Zajete: zajete, Pojemnosc: pojemnosc, Czeka: czeka}, nil
	}

	// Udzial liczymy dopiero, gdy pojemnosc jest. Wolne tokeny dzielimy
	// miedzy tych, ktorzy o nie prosza: kampania obejmujaca tysiac hostow
	// dostaje porcje, a nie wszystko, co akurat zostalo wolne.
	chetnych, err := s.chetnych(ctx, tx, potrzeba.Klucz)
	if err != nil {
		return Odmowa{}, err
	}
	udzial := pojemnosc / max(chetnych, 1)
	if udzial < 1 {
		udzial = 1
	}
	if moje+potrzeba.Waga > udzial && czeka < klasa.WiekAwansu() {
		return Odmowa{Klucz: potrzeba.Klucz, Powod: PowodUdzial, Zajete: zajete,
			Pojemnosc: pojemnosc, Udzial: udzial, Trzymane: moje, Czeka: czeka}, nil
	}
	return Odmowa{}, nil
}

// chetnych liczy roszczacych, ktorzy trzymaja tokeny albo o nie prosza.
func (s *Store) chetnych(ctx context.Context, tx pgx.Tx, klucz string) (int, error) {
	const query = `
		select count(*) from (
		    select claimant from budget_leases where key = $1 and lease_until > now()
		    union
		    select claimant from budget_waiters
		     where key = $1 and seen_at > now() - make_interval(secs => $2)
		) as chetni`
	var ile int
	err := tx.QueryRow(ctx, query, klucz, wiekOczekiwania.Seconds()).Scan(&ile)
	return ile, err
}

// czasOczekiwania mowi, jak dlugo roszczacy czeka na ten budzet.
func (s *Store) czasOczekiwania(ctx context.Context, tx pgx.Tx,
	klucz, roszczacy string) (time.Duration, error) {
	var sekundy *float64
	const query = `
		select extract(epoch from (now() - since))::float8 from budget_waiters
		 where key = $1 and claimant = $2`
	if err := tx.QueryRow(ctx, query, klucz, roszczacy).Scan(&sekundy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	if sekundy == nil {
		return 0, nil
	}
	return time.Duration(*sekundy * float64(time.Second)), nil
}

func (s *Store) zapiszOczekiwanie(ctx context.Context, tx pgx.Tx,
	klucz, roszczacy string, klasa Klasa) error {
	// since zostaje z pierwszego zgloszenia: to ono jest podstawa awansu.
	// seen_at mowi, czy ktos jeszcze o ten budzet prosi.
	const query = `
		insert into budget_waiters (key, claimant, class)
		values ($1, $2, $3)
		on conflict (key, claimant) do update set seen_at = now(), class = excluded.class`
	_, err := tx.Exec(ctx, query, klucz, roszczacy, string(klasa))
	return err
}

func (s *Store) zapiszDzierzawe(ctx context.Context, tx pgx.Tx, potrzeba Potrzeba,
	wlasciciel, roszczacy string) error {
	const query = `
		insert into budget_leases (key, owner, claimant, weight, lease_until)
		values ($1, $2, $3, $4, now() + make_interval(secs => $5))
		on conflict (key, owner) do update
		   set claimant = excluded.claimant, weight = excluded.weight,
		       lease_until = excluded.lease_until`
	_, err := tx.Exec(ctx, query, potrzeba.Klucz, wlasciciel, roszczacy,
		potrzeba.Waga, s.dzierzawa.Seconds())
	return err
}

// Odnow przedluza dzierzawy zadan, ktore nadal pracuja.
//
// Bez odnowienia dlugie operacje - transakcja pakietowa potrafi trwac
// kwadrans - zwalnialyby pojemnosc w polowie pracy, a system uruchamialby
// wiecej, niz naprawde uniesie.
func (s *Store) Odnow(ctx context.Context, wlasciciele []string) error {
	if len(wlasciciele) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`update budget_leases set lease_until = now() + make_interval(secs => $2)
		  where owner = any($1)`, wlasciciele, s.dzierzawa.Seconds())
	return err
}

// Zwolnij oddaje tokeny zadania.
func (s *Store) Zwolnij(ctx context.Context, wlasciciel string) error {
	_, err := s.pool.Exec(ctx, `delete from budget_leases where owner = $1`, wlasciciel)
	return err
}

// ZwolnijRoszczacego oddaje wszystko, co trzyma jedna kampania.
//
// Anulowanie nie przechodzi przez zamkniecie kazdego hosta z osobna: kampania
// jest zatrzymywana jednym zapisem, a jej hosty nie dostaja juz zadnego
// obiegu, w ktorym mialyby cokolwiek oddac. Bez tego tokeny zostawaly do
// wygasniecia dzierzawy i nastepna kampania czekala na pojemnosc, ktorej
// nikt juz nie uzywal.
func (s *Store) ZwolnijRoszczacego(ctx context.Context, roszczacy string) error {
	if _, err := s.pool.Exec(ctx,
		`delete from budget_leases where claimant = $1`, roszczacy); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `delete from budget_waiters where claimant = $1`, roszczacy)
	return err
}

// Run sprzata wygasle dzierzawy i porzucone oczekiwania.
//
// Wygasla dzierzawa i tak nie liczy sie do zajetosci, wiec sprzatanie nie
// zmienia decyzji - porzadkuje tabele i pilnuje, zeby oczekiwanie po awarii
// nie zmniejszalo udzialu w nieskonczonosc.
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(okresSprzatania)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.sprzataj(ctx); err != nil {
				s.log.Error("nie posprzatano budzetow", "err", err)
			}
		}
	}
}

func (s *Store) sprzataj(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`delete from budget_leases where lease_until < now() - make_interval(secs => $1)`,
		(10 * time.Minute).Seconds()); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx,
		`delete from budget_waiters where seen_at < now() - make_interval(secs => $1)`,
		(10 * time.Minute).Seconds())
	return err
}

// UstawPojemnosc zapisuje polityke pojemnosci jednego budzetu.
//
// Klucz moze byc scisly ('site:warsaw:packages') albo wzorcem
// ('site:*:packages'). Wzorzec zmienia polityke domyslna dla lokalizacji,
// ktorych nikt nie opisal osobno; klucz scisly wyjmuje jedna z nich spod
// tej polityki.
func (s *Store) UstawPojemnosc(ctx context.Context, klucz string, pojemnosc int,
	nota string) error {
	const query = `
		insert into budget_limits (key, capacity, note)
		values ($1, $2, $3)
		on conflict (key) do update
		   set capacity = excluded.capacity, note = excluded.note, updated_at = now()`
	_, err := s.pool.Exec(ctx, query, klucz, pojemnosc, nota)
	return err
}

// Stan opisuje jeden budzet na potrzeby ekranu operatora.
type Stan struct {
	Klucz     string `json:"key"`
	Pojemnosc int    `json:"capacity"`
	Zajete    int    `json:"used"`
	Chetnych  int    `json:"claimants"`
}

// Stany zwracaja obraz budzetow, ktore cokolwiek trzymaja albo maja chetnych.
//
// Budzet, ktory nikogo nie zatrzymuje, nie musi byc na ekranie. Budzet, ktory
// zatrzymuje, musi - inaczej kampania stoi bez podanego powodu.
func (s *Store) Stany(ctx context.Context) ([]Stan, error) {
	const query = `
		select l.key, l.capacity,
		       coalesce((select sum(weight) from budget_leases d
		                  where d.key = l.key and d.lease_until > now()), 0),
		       (select count(*) from (
		            select claimant from budget_leases d
		             where d.key = l.key and d.lease_until > now()
		            union
		            select claimant from budget_waiters w
		             where w.key = l.key and w.seen_at > now() - make_interval(secs => $1)
		       ) as chetni)
		  from budget_limits l
		 order by l.key`
	rows, err := s.pool.Query(ctx, query, wiekOczekiwania.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stany := []Stan{}
	for rows.Next() {
		var stan Stan
		if err := rows.Scan(&stan.Klucz, &stan.Pojemnosc, &stan.Zajete, &stan.Chetnych); err != nil {
			return nil, err
		}
		stany = append(stany, stan)
	}
	return stany, rows.Err()
}

func klucze(potrzeby []Potrzeba) []string {
	wynik := make([]string, 0, len(potrzeby))
	for _, potrzeba := range potrzeby {
		wynik = append(wynik, potrzeba.Klucz)
	}
	return wynik
}
