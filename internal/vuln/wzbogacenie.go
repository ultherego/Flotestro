package vuln

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// SzczegolyCVE sa tym, co o samej podatnosci mowi zrodlo upstreamowe.
//
// To jest wzbogacenie, a nie rozstrzygniecie. Czy pakiet jest podatny i ktora
// wersja to zamyka, mowi wylacznie producent dystrybucji: jego poprawki sa
// backportowane, wiec zaden zakres wersji z NVD ich nie obejmuje. Stad bierze
// sie tylko to, czego producent nie mowi - jak grozna jest sama podatnosc
// i czego dotyczy.
type SzczegolyCVE struct {
	CVE          string     `json:"cve"`
	Source       string     `json:"source"`
	CVSSScore    *float64   `json:"cvss_score,omitempty"`
	CVSSSeverity string     `json:"cvss_severity,omitempty"`
	CVSSVector   string     `json:"cvss_vector,omitempty"`
	CVSSVersion  string     `json:"cvss_version,omitempty"`
	Summary      string     `json:"summary,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	ModifiedAt   *time.Time `json:"modified_at,omitempty"`
}

// ZrodloSzczegolow jest adapterem zrodla wzbogacajacego.
//
// Pobierz oddaje wyniki stronami, a nie w calosci: zbior ma blisko czterysta
// tysiecy wpisow i nie ma powodu, zeby lezal w pamieci panelu naraz.
type ZrodloSzczegolow interface {
	Nazwa() string
	Pobierz(ctx context.Context, od time.Time,
		przyjmij func([]SzczegolyCVE) error) (time.Time, error)
}

// ZapiszSzczegoly dopisuje albo odswieza opisy podatnosci.
func (s *Store) ZapiszSzczegoly(ctx context.Context, szczegoly []SzczegolyCVE) error {
	if len(szczegoly) == 0 {
		return nil
	}
	const zapis = `
		insert into vuln_cve_details (cve, source, cvss_score, cvss_severity, cvss_vector,
		                              cvss_version, summary, published_at, modified_at, fetched_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		on conflict (cve) do update set
			source = excluded.source, cvss_score = excluded.cvss_score,
			cvss_severity = excluded.cvss_severity, cvss_vector = excluded.cvss_vector,
			cvss_version = excluded.cvss_version, summary = excluded.summary,
			published_at = excluded.published_at, modified_at = excluded.modified_at,
			fetched_at = now()`
	partia := &pgx.Batch{}
	for _, wpis := range szczegoly {
		if wpis.CVE == "" {
			continue
		}
		partia.Queue(zapis, wpis.CVE, wpis.Source, wpis.CVSSScore, wpis.CVSSSeverity,
			wpis.CVSSVector, wpis.CVSSVersion, wpis.Summary, wpis.PublishedAt, wpis.ModifiedAt)
	}
	if partia.Len() == 0 {
		return nil
	}
	wyniki := s.pool.SendBatch(ctx, partia)
	defer wyniki.Close()
	for i := 0; i < partia.Len(); i++ {
		if _, err := wyniki.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// Szczegoly czyta opisy wskazanych podatnosci.
//
// Brak opisu nie jest bledem: wzbogacenie moze byc niepelne albo moze go nie
// byc wcale, a ocena hosta ma z niego nie korzystac.
func (s *Store) Szczegoly(ctx context.Context, numery []string) (map[string]SzczegolyCVE, error) {
	wynik := map[string]SzczegolyCVE{}
	if len(numery) == 0 {
		return wynik, nil
	}
	const query = `
		select cve, source, cvss_score, cvss_severity, cvss_vector, cvss_version,
		       summary, published_at, modified_at
		from vuln_cve_details where cve = any($1)`
	rows, err := s.pool.Query(ctx, query, numery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var wpis SzczegolyCVE
		if err := rows.Scan(&wpis.CVE, &wpis.Source, &wpis.CVSSScore, &wpis.CVSSSeverity,
			&wpis.CVSSVector, &wpis.CVSSVersion, &wpis.Summary, &wpis.PublishedAt,
			&wpis.ModifiedAt); err != nil {
			return nil, err
		}
		wynik[wpis.CVE] = wpis
	}
	return wynik, rows.Err()
}

// StanWzbogacenia mowi, do kiedy zrodlo zostalo odczytane.
func (s *Store) StanWzbogacenia(ctx context.Context, zrodlo string) (time.Time, error) {
	var znacznik *time.Time
	err := s.pool.QueryRow(ctx,
		`select last_modified from vuln_enrichment_state where source = $1`, zrodlo).Scan(&znacznik)
	if err != nil {
		if err == pgx.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if znacznik == nil {
		return time.Time{}, nil
	}
	return znacznik.UTC(), nil
}

// ZapiszStanWzbogacenia odnotowuje, do kiedy zrodlo zostalo odczytane.
func (s *Store) ZapiszStanWzbogacenia(ctx context.Context, zrodlo string, znacznik time.Time,
	wpisow int, powod string) error {
	const zapis = `
		insert into vuln_enrichment_state (source, last_modified, entries, updated_at, error)
		values ($1, $2, $3, now(), $4)
		on conflict (source) do update set
			last_modified = coalesce(excluded.last_modified, vuln_enrichment_state.last_modified),
			entries = vuln_enrichment_state.entries + excluded.entries,
			updated_at = now(), error = excluded.error`
	var wskaznik *time.Time
	if !znacznik.IsZero() {
		chwila := znacznik.UTC()
		wskaznik = &chwila
	}
	_, err := s.pool.Exec(ctx, zapis, zrodlo, wskaznik, wpisow, powod)
	return err
}

// Wzbogacacz utrzymuje opisy podatnosci w bazie panelu.
//
// Osobny cykl od korelatora i celowo rzadszy: te dane nie zmieniaja ani
// jednej odpowiedzi o hostach. Gdy ich nie ma, ocena jest ta sama - brakuje
// tylko wagi upstreamowej obok wagi producenta.
type Wzbogacacz struct {
	store  *Store
	zrodlo ZrodloSzczegolow
	odstep time.Duration
	log    *slog.Logger
}

// NowyWzbogacacz tworzy cykl wzbogacania.
func NowyWzbogacacz(store *Store, zrodlo ZrodloSzczegolow, odstep time.Duration,
	log *slog.Logger) *Wzbogacacz {
	if odstep <= 0 {
		odstep = 6 * time.Hour
	}
	return &Wzbogacacz{store: store, zrodlo: zrodlo, odstep: odstep, log: log}
}

// Run prowadzi wzbogacanie do zamkniecia kontekstu.
func (w *Wzbogacacz) Run(ctx context.Context) {
	w.Cykl(ctx)
	ticker := time.NewTicker(w.odstep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Cykl(ctx)
		}
	}
}

// Cykl dociaga opisy zmienione od ostatniego odczytu.
func (w *Wzbogacacz) Cykl(ctx context.Context) {
	od, err := w.store.StanWzbogacenia(ctx, w.zrodlo.Nazwa())
	if err != nil {
		w.log.Error("nie odczytano stanu wzbogacania", "zrodlo", w.zrodlo.Nazwa(), "err", err)
		return
	}
	zapisanych := 0
	znacznik, err := w.zrodlo.Pobierz(ctx, od, func(strona []SzczegolyCVE) error {
		if err := w.store.ZapiszSzczegoly(ctx, strona); err != nil {
			return err
		}
		zapisanych += len(strona)
		return nil
	})
	if err != nil {
		// Nieudane pobranie nie kasuje tego, co juz jest: opisy sprzed doby
		// sa lepsze niz ich brak, a ocena i tak z nich nie korzysta.
		w.log.Error("nie pobrano opisow podatnosci", "zrodlo", w.zrodlo.Nazwa(), "err", err)
		_ = w.store.ZapiszStanWzbogacenia(ctx, w.zrodlo.Nazwa(), time.Time{}, zapisanych, err.Error())
		return
	}
	if err := w.store.ZapiszStanWzbogacenia(ctx, w.zrodlo.Nazwa(), znacznik, zapisanych, ""); err != nil {
		w.log.Error("nie zapisano stanu wzbogacania", "zrodlo", w.zrodlo.Nazwa(), "err", err)
		return
	}
	if zapisanych > 0 {
		w.log.Info("opisy podatnosci odswiezone", "zrodlo", w.zrodlo.Nazwa(),
			"wpisow", zapisanych, "do", znacznik)
	}
}
