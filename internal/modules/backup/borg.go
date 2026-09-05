package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var sciezkiBorg = []string{"/usr/bin/borg", "/usr/local/bin/borg"}

// ZmiennaHaslaBorg jest nazwa zmiennej, ktora borg czyta zamiast pytac.
const ZmiennaHaslaBorg = "BORG_PASSPHRASE"

// Borg jest adapterem narzedzia borgbackup.
type Borg struct{}

func (b *Borg) Nazwa() string { return NarzedzieBorg }

func (b *Borg) Dostepny() bool { return b.sciezka() != "" }

func (b *Borg) sciezka() string {
	for _, sciezka := range sciezkiBorg {
		if istnieje(sciezka) {
			return sciezka
		}
	}
	return ""
}

// srodowisko doklada zmienne, bez ktorych borg zatrzymuje sie na pytaniu.
//
// Borg pyta czlowieka o zgode, gdy repozytorium jest nieznane albo zmienilo
// tozsamosc. Proces bez terminala czekalby na odpowiedz do konca limitu czasu,
// wiec odpowiadamy z gory: relokacji nie akceptujemy, bo zmiana tozsamosci
// repozytorium jest zdarzeniem, o ktorym operator ma sie dowiedziec.
func (b *Borg) srodowisko(zlecenie Zlecenie) []string {
	return append(srodowiskoNarzedzia(zlecenie, ZmiennaHaslaBorg),
		"BORG_RELOCATED_REPO_ACCESS_IS_OK=no",
		"BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no",
		"BORG_EXIT_CODES=modern")
}

func (b *Borg) Wersja(ctx context.Context) string {
	if b.sciezka() == "" {
		return ""
	}
	wynik := uruchom(ctx, b.sciezka(), []string{"--version"},
		srodowiskoNarzedzia(Zlecenie{}, ""), nil, nil)
	return strings.TrimSpace(wynik.Stdout)
}

// Plan czyta archiwa repozytorium.
func (b *Borg) Plan(ctx context.Context, zlecenie Zlecenie) (Stan, error) {
	stan := Stan{Tool: NarzedzieBorg, Repository: zlecenie.Repository, ObservedAt: time.Now().UTC()}
	if b.sciezka() == "" {
		stan.UnavailableReason = "this host does not have borg"
		return stan, fmt.Errorf("ten host nie ma borga")
	}
	stan.ToolVersion = b.Wersja(ctx)

	wynik := uruchom(ctx, b.sciezka(), []string{"list", "--json", zlecenie.Repository},
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if !wynik.Ran || wynik.ExitCode != 0 || wynik.Err != nil {
		stan.UnavailableReason = wynik.Powod()
		return stan, fmt.Errorf("borg list: %s", wynik.Powod())
	}
	var lista struct {
		Archives []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Start string `json:"start"`
		} `json:"archives"`
	}
	if err := json.Unmarshal([]byte(wynik.Stdout), &lista); err != nil {
		stan.UnavailableReason = "nie rozpoznano listy archiwow: " + err.Error()
		return stan, err
	}
	for _, archiwum := range lista.Archives {
		snapshot := Snapshot{ID: archiwum.Name}
		// Borg podaje czas lokalny hosta bez strefy; czytamy go tak, jak
		// zostal zapisany, i nie udajemy, ze wiemy wiecej.
		if chwila, err := time.Parse("2006-01-02T15:04:05.000000", archiwum.Start); err == nil {
			snapshot.Time = chwila.UTC()
		} else if chwila, err := time.Parse(time.RFC3339, archiwum.Start); err == nil {
			snapshot.Time = chwila.UTC()
		}
		stan.Snapshots = append(stan.Snapshots, snapshot)
	}
	PosortujSnapshoty(stan.Snapshots)
	stan.LastSuccessAt = OstatniUdany(stan.Snapshots)

	info := uruchom(ctx, b.sciezka(), []string{"info", "--json", zlecenie.Repository},
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if info.Ran && info.ExitCode == 0 {
		var opis struct {
			Cache struct {
				Stats struct {
					UniqueCSize uint64 `json:"unique_csize"`
					TotalSize   uint64 `json:"total_size"`
				} `json:"stats"`
			} `json:"cache"`
		}
		if err := json.Unmarshal([]byte(info.Stdout), &opis); err == nil {
			rozmiar := opis.Cache.Stats.UniqueCSize
			if rozmiar == 0 {
				rozmiar = opis.Cache.Stats.TotalSize
			}
			if rozmiar > 0 {
				stan.TotalSizeBytes = &rozmiar
			}
		}
	}
	return stan, nil
}

// Wykonaj tworzy archiwum i sprzata stare.
func (b *Borg) Wykonaj(ctx context.Context, zlecenie Zlecenie, postep PostepFunc) (Wynik, error) {
	wynik := Wynik{}
	if b.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma borga")
	}
	if len(zlecenie.Paths) == 0 {
		return wynik, fmt.Errorf("definicja nie wskazuje, co backupowac")
	}

	if err := b.upewnijSieZeIstnieje(ctx, zlecenie); err != nil {
		return wynik, err
	}

	// Nazwa archiwum musi byc unikalna w repozytorium; znacznik czasu jest
	// tu jedynym sensownym wyroznikiem i jednoczesnie informacja dla czlowieka.
	nazwa := zlecenie.ID + "-" + time.Now().UTC().Format("20060102T150405Z")
	argumenty := []string{"create", "--json", "--stats",
		zlecenie.Repository + "::" + nazwa}
	argumenty = append(argumenty, zlecenie.Paths...)
	for _, wzorzec := range zlecenie.Excludes {
		argumenty = append(argumenty, "--exclude", wzorzec)
	}
	if postep != nil {
		postep(Postep{Message: "archiwum " + nazwa})
	}

	uruchomienie := uruchom(ctx, b.sciezka(), argumenty,
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	wynik.Output = uruchomienie.Stderr
	if !uruchomienie.Ran || uruchomienie.Err != nil {
		return wynik, fmt.Errorf("borg create: %s", uruchomienie.Powod())
	}
	// Kod 1 borga oznacza ostrzezenia - najczesciej pliki, ktorych nie dalo
	// sie odczytac. Archiwum powstalo, ale jest niepelne.
	if uruchomienie.ExitCode != 0 && uruchomienie.ExitCode != 1 {
		return wynik, fmt.Errorf("borg create: %s", uruchomienie.Powod())
	}

	wynik.SnapshotID = nazwa
	var statystyki struct {
		Archive struct {
			Stats struct {
				DeduplicatedSize uint64  `json:"deduplicated_size"`
				OriginalSize     uint64  `json:"original_size"`
				NFiles           uint64  `json:"nfiles"`
				Duration         float64 `json:"duration"`
			} `json:"stats"`
		} `json:"archive"`
	}
	if err := json.Unmarshal([]byte(uruchomienie.Stdout), &statystyki); err == nil {
		dodane := statystyki.Archive.Stats.DeduplicatedSize
		przetworzone := statystyki.Archive.Stats.OriginalSize
		pliki := statystyki.Archive.Stats.NFiles
		czas := statystyki.Archive.Stats.Duration
		wynik.BytesAdded = &dodane
		wynik.TotalBytesProcessed = &przetworzone
		wynik.FilesNew = &pliki
		wynik.DurationSeconds = &czas
	}
	wynik.Message = "archiwum " + nazwa + " utworzone"
	if uruchomienie.ExitCode == 1 {
		wynik.Message += "; czesci plikow nie udalo sie odczytac"
	}

	if err := b.retencja(ctx, zlecenie); err != nil {
		wynik.Message += "; retencja nie powiodla sie: " + err.Error()
	}
	return wynik, nil
}

// retencja kasuje archiwa spoza polityki.
func (b *Borg) retencja(ctx context.Context, zlecenie Zlecenie) error {
	argumenty := []string{"prune", "--glob-archives", zlecenie.ID + "-*"}
	ustawione := false
	for _, prog := range []struct {
		flaga   string
		wartosc int
	}{
		{"--keep-last", zlecenie.KeepLast},
		{"--keep-daily", zlecenie.KeepDaily},
		{"--keep-weekly", zlecenie.KeepWeekly},
		{"--keep-monthly", zlecenie.KeepMonthly},
	} {
		if prog.wartosc > 0 {
			argumenty = append(argumenty, prog.flaga, strconv.Itoa(prog.wartosc))
			ustawione = true
		}
	}
	if !ustawione {
		return nil
	}
	argumenty = append(argumenty, zlecenie.Repository)

	wynik := uruchom(ctx, b.sciezka(), argumenty,
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if !wynik.Ran || (wynik.ExitCode != 0 && wynik.ExitCode != 1) {
		return fmt.Errorf("%s", wynik.Powod())
	}
	if !zlecenie.Prune {
		return nil
	}
	// Sprzatanie w borgu jest osobnym krokiem: prune odpina archiwa,
	// a miejsce zwalnia dopiero compact.
	kompakt := uruchom(ctx, b.sciezka(), []string{"compact", zlecenie.Repository},
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if !kompakt.Ran || (kompakt.ExitCode != 0 && kompakt.ExitCode != 1) {
		return fmt.Errorf("%s", kompakt.Powod())
	}
	return nil
}

// Sprawdz weryfikuje repozytorium.
func (b *Borg) Sprawdz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	wynik := Wynik{}
	if b.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma borga")
	}
	argumenty := []string{"check"}
	if zlecenie.ReadData {
		argumenty = append(argumenty, "--verify-data")
	}
	argumenty = append(argumenty, zlecenie.Repository)

	uruchomienie := uruchom(ctx, b.sciezka(), argumenty,
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	wynik.Output = uruchomienie.Stdout + uruchomienie.Stderr
	if !uruchomienie.Ran || uruchomienie.ExitCode != 0 || uruchomienie.Err != nil {
		return wynik, fmt.Errorf("borg check: %s", uruchomienie.Powod())
	}
	wynik.Message = "repozytorium sprawdzone"
	if zlecenie.ReadData {
		wynik.Message += " razem z odczytem danych"
	}
	return wynik, nil
}

// Odtworz rozpakowuje archiwum do wskazanego katalogu.
func (b *Borg) Odtworz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	wynik := Wynik{}
	if b.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma borga")
	}
	argumenty := []string{"extract",
		zlecenie.Repository + "::" + zlecenie.Odtworzenie.SnapshotID}
	for _, wzorzec := range zlecenie.Odtworzenie.Include {
		// Borg dopasowuje sciezki wewnatrz archiwum, czyli bez wiodacego
		// ukosnika. Zamiana jest tu, a nie w panelu: to szczegol narzedzia.
		argumenty = append(argumenty, strings.TrimPrefix(wzorzec, "/"))
	}
	uruchomienie := uruchomWKatalogu(ctx, zlecenie.Odtworzenie.Target, b.sciezka(), argumenty,
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	wynik.Output = uruchomienie.Stdout + uruchomienie.Stderr
	if !uruchomienie.Ran || uruchomienie.ExitCode != 0 || uruchomienie.Err != nil {
		return wynik, fmt.Errorf("borg extract: %s", uruchomienie.Powod())
	}
	wynik.Message = "archiwum " + zlecenie.Odtworzenie.SnapshotID +
		" odtworzone do " + zlecenie.Odtworzenie.Target
	return wynik, nil
}

// upewnijSieZeIstnieje zaklada repozytorium, jesli definicja na to pozwala.
func (b *Borg) upewnijSieZeIstnieje(ctx context.Context, zlecenie Zlecenie) error {
	sprawdzenie := uruchom(ctx, b.sciezka(), []string{"info", "--json", zlecenie.Repository},
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if sprawdzenie.Ran && sprawdzenie.ExitCode == 0 {
		return nil
	}
	if !zlecenie.Initialize {
		return nil
	}
	// Szyfrowanie kluczem w repozytorium: haslo mamy z magazynu, a klucz
	// przy repozytorium przezyje przebudowe hosta.
	utworzenie := uruchom(ctx, b.sciezka(),
		[]string{"init", "--encryption", "repokey", zlecenie.Repository},
		b.srodowisko(zlecenie), tajneZlecenia(zlecenie), nil)
	if !utworzenie.Ran || utworzenie.ExitCode != 0 {
		return fmt.Errorf("borg init: %s", utworzenie.Powod())
	}
	return nil
}
