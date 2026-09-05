package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sciezki narzedzia. Restic bywa w /usr/bin albo w /usr/local/bin - to drugie
// jest miejscem, w ktorym laduje binarka pobrana ze strony projektu.
var sciezkiRestic = []string{"/usr/bin/restic", "/usr/local/bin/restic"}

// ZmiennaHaslaRestic jest nazwa zmiennej, ktora restic czyta zamiast pytac.
const ZmiennaHaslaRestic = "RESTIC_PASSWORD"

// Restic jest adapterem narzedzia restic.
type Restic struct{}

func (r *Restic) Nazwa() string { return NarzedzieRestic }

func (r *Restic) Dostepny() bool { return r.sciezka() != "" }

func (r *Restic) sciezka() string {
	for _, sciezka := range sciezkiRestic {
		if istnieje(sciezka) {
			return sciezka
		}
	}
	return ""
}

func (r *Restic) Wersja(ctx context.Context) string {
	if r.sciezka() == "" {
		return ""
	}
	wynik := uruchom(ctx, r.sciezka(), []string{"version"},
		srodowiskoNarzedzia(Zlecenie{}, ""), nil, nil)
	return strings.TrimSpace(wynik.Stdout)
}

// argumentyPodstawowe sklada argumenty wspolne dla kazdego wywolania.
//
// Adres repozytorium idzie argumentem, bo nim nie jest: to nazwa celu, ktora
// panel i tak pokazuje. Haslo idzie srodowiskiem.
func (r *Restic) argumentyPodstawowe(zlecenie Zlecenie) []string {
	return []string{"--repo", zlecenie.Repository, "--json"}
}

// snapshotResticu jest wpisem z "restic snapshots --json".
type snapshotResticu struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
	Tags     []string  `json:"tags"`
}

// Plan czyta stan repozytorium: kopie i ich rozmiar.
func (r *Restic) Plan(ctx context.Context, zlecenie Zlecenie) (Stan, error) {
	stan := Stan{
		Tool: NarzedzieRestic, Repository: zlecenie.Repository,
		ObservedAt: time.Now().UTC(),
	}
	if r.sciezka() == "" {
		stan.UnavailableReason = "this host does not have restic"
		return stan, fmt.Errorf("ten host nie ma resticu")
	}
	stan.ToolVersion = r.Wersja(ctx)

	argumenty := append(r.argumentyPodstawowe(zlecenie), "snapshots")
	wynik := uruchom(ctx, r.sciezka(), argumenty,
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	if !wynik.Ran || wynik.ExitCode != 0 || wynik.Err != nil {
		stan.UnavailableReason = wynik.Powod()
		return stan, fmt.Errorf("restic snapshots: %s", wynik.Powod())
	}

	var wpisy []snapshotResticu
	if err := json.Unmarshal([]byte(wynik.Stdout), &wpisy); err != nil {
		stan.UnavailableReason = "nie rozpoznano listy kopii: " + err.Error()
		return stan, err
	}
	for _, wpis := range wpisy {
		identyfikator := wpis.ShortID
		if identyfikator == "" {
			identyfikator = wpis.ID
		}
		stan.Snapshots = append(stan.Snapshots, Snapshot{
			ID: identyfikator, Time: wpis.Time.UTC(), Hostname: wpis.Hostname,
			Paths: wpis.Paths, Tags: wpis.Tags,
		})
	}
	PosortujSnapshoty(stan.Snapshots)
	stan.LastSuccessAt = OstatniUdany(stan.Snapshots)

	// Rozmiar repozytorium jest osobnym pytaniem i osobnym kosztem: restic
	// liczy go, przechodzac po indeksie. Nieudany odczyt zostawia brak
	// wiedzy, a nie zero - repozytorium bez rozmiaru nadal ma kopie.
	rozmiar := uruchom(ctx, r.sciezka(),
		append(r.argumentyPodstawowe(zlecenie), "stats", "--mode", "raw-data"),
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	if rozmiar.Ran && rozmiar.ExitCode == 0 {
		var statystyki struct {
			TotalSize uint64 `json:"total_size"`
		}
		if err := json.Unmarshal([]byte(rozmiar.Stdout), &statystyki); err == nil {
			stan.TotalSizeBytes = &statystyki.TotalSize
		}
	}
	return stan, nil
}

// komunikatResticu jest linia strumienia "--json" przy backupie.
type komunikatResticu struct {
	MessageType    string  `json:"message_type"`
	PercentDone    float64 `json:"percent_done"`
	TotalFiles     uint64  `json:"total_files"`
	FilesDone      uint64  `json:"files_done"`
	TotalBytes     uint64  `json:"total_bytes"`
	BytesDone      uint64  `json:"bytes_done"`
	SnapshotID     string  `json:"snapshot_id"`
	FilesNew       uint64  `json:"files_new"`
	FilesChanged   uint64  `json:"files_changed"`
	DataAdded      uint64  `json:"data_added"`
	TotalBytesProc uint64  `json:"total_bytes_processed"`
	TotalDuration  float64 `json:"total_duration"`
	Error          struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Wykonaj robi kopie, a po niej - jesli tak mowi definicja - sprzata stare.
func (r *Restic) Wykonaj(ctx context.Context, zlecenie Zlecenie, postep PostepFunc) (Wynik, error) {
	wynik := Wynik{}
	if r.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma resticu")
	}
	if len(zlecenie.Paths) == 0 {
		return wynik, fmt.Errorf("definicja nie wskazuje, co backupowac")
	}

	if err := r.upewnijSieZeIstnieje(ctx, zlecenie); err != nil {
		return wynik, err
	}

	argumenty := append(r.argumentyPodstawowe(zlecenie), "backup")
	argumenty = append(argumenty, zlecenie.Paths...)
	for _, wzorzec := range zlecenie.Excludes {
		argumenty = append(argumenty, "--exclude", wzorzec)
	}
	for _, znacznik := range zlecenie.Tags {
		argumenty = append(argumenty, "--tag", znacznik)
	}

	var podsumowanie komunikatResticu
	var bledy []string
	uruchomienie := uruchom(ctx, r.sciezka(), argumenty,
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie),
		func(linia string) {
			var komunikat komunikatResticu
			if err := json.Unmarshal([]byte(linia), &komunikat); err != nil {
				return
			}
			switch komunikat.MessageType {
			case "status":
				if postep != nil {
					procent := uint32(komunikat.PercentDone * 100)
					postep(Postep{
						Percent: &procent,
						Message: fmt.Sprintf("%s z %s",
							rozmiar(komunikat.BytesDone), rozmiar(komunikat.TotalBytes)),
					})
				}
			case "summary":
				podsumowanie = komunikat
			case "error":
				if komunikat.Error.Message != "" {
					bledy = append(bledy, komunikat.Error.Message)
				}
			}
		})
	wynik.Output = uruchomienie.Stderr

	if uruchomienie.Err != nil || !uruchomienie.Ran {
		return wynik, fmt.Errorf("restic backup: %s", uruchomienie.Powod())
	}
	// Kod 3 oznacza kopie zrobiona mimo plikow, ktorych nie dalo sie
	// odczytac. To nie jest sukces i nie jest awaria: kopia istnieje, ale
	// jest niepelna - i tak trzeba to nazwac.
	if uruchomienie.ExitCode != 0 && uruchomienie.ExitCode != 3 {
		return wynik, fmt.Errorf("restic backup: %s", uruchomienie.Powod())
	}

	wynik.SnapshotID = podsumowanie.SnapshotID
	if podsumowanie.SnapshotID != "" {
		dodane, przetworzone := podsumowanie.DataAdded, podsumowanie.TotalBytesProc
		nowe, zmienione := podsumowanie.FilesNew, podsumowanie.FilesChanged
		czas := podsumowanie.TotalDuration
		wynik.BytesAdded = &dodane
		wynik.TotalBytesProcessed = &przetworzone
		wynik.FilesNew = &nowe
		wynik.FilesChanged = &zmienione
		wynik.DurationSeconds = &czas
		wynik.Message = fmt.Sprintf("kopia %s: %s nowych danych, %d nowych plikow",
			podsumowanie.SnapshotID, rozmiar(podsumowanie.DataAdded), podsumowanie.FilesNew)
	}
	if uruchomienie.ExitCode == 3 || len(bledy) > 0 {
		wynik.Message += "; czesci plikow nie udalo sie odczytac"
		if len(bledy) > 0 {
			wynik.Message += ": " + strings.Join(pierwsze(bledy, 3), "; ")
		}
	}

	if usuniete, err := r.retencja(ctx, zlecenie); err != nil {
		// Kopia jest zrobiona; nieudane sprzatanie nie moze jej uniewaznic,
		// ale nie moze tez zniknac z wyniku.
		wynik.Message += "; retencja nie powiodla sie: " + err.Error()
	} else if usuniete != nil {
		wynik.Removed = usuniete
	}
	return wynik, nil
}

// retencja kasuje kopie spoza polityki. Zero we wszystkich progach oznacza
// "nie sprzataj": skasowanie starych kopii jest osobna decyzja.
func (r *Restic) retencja(ctx context.Context, zlecenie Zlecenie) (*int, error) {
	progi := []struct {
		flaga   string
		wartosc int
	}{
		{"--keep-last", zlecenie.KeepLast},
		{"--keep-daily", zlecenie.KeepDaily},
		{"--keep-weekly", zlecenie.KeepWeekly},
		{"--keep-monthly", zlecenie.KeepMonthly},
	}
	argumenty := append(r.argumentyPodstawowe(zlecenie), "forget")
	ustawione := false
	for _, prog := range progi {
		if prog.wartosc > 0 {
			argumenty = append(argumenty, prog.flaga, strconv.Itoa(prog.wartosc))
			ustawione = true
		}
	}
	if !ustawione {
		return nil, nil
	}
	if zlecenie.Prune {
		argumenty = append(argumenty, "--prune")
	}

	wynik := uruchom(ctx, r.sciezka(), argumenty,
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	if !wynik.Ran || wynik.ExitCode != 0 {
		return nil, fmt.Errorf("%s", wynik.Powod())
	}
	var grupy []struct {
		Remove []snapshotResticu `json:"remove"`
	}
	if err := json.Unmarshal([]byte(wynik.Stdout), &grupy); err != nil {
		return nil, nil
	}
	usuniete := 0
	for _, grupa := range grupy {
		usuniete += len(grupa.Remove)
	}
	return &usuniete, nil
}

// Sprawdz weryfikuje repozytorium.
func (r *Restic) Sprawdz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	wynik := Wynik{}
	if r.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma resticu")
	}
	argumenty := append(r.argumentyPodstawowe(zlecenie), "check")
	if zlecenie.ReadData {
		// Sprawdzenie struktury mowi, ze indeks sie zgadza; dopiero odczyt
		// danych mowi, ze kopia da sie odtworzyc. Drugie kosztuje ruch
		// i czas, wiec jest jawnym wyborem operatora.
		argumenty = append(argumenty, "--read-data-subset", "5%")
	}
	uruchomienie := uruchom(ctx, r.sciezka(), argumenty,
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	wynik.Output = uruchomienie.Stdout + uruchomienie.Stderr
	if !uruchomienie.Ran || uruchomienie.ExitCode != 0 || uruchomienie.Err != nil {
		return wynik, fmt.Errorf("restic check: %s", uruchomienie.Powod())
	}
	wynik.Message = "repozytorium sprawdzone"
	if zlecenie.ReadData {
		wynik.Message += " razem z odczytem czesci danych"
	}
	return wynik, nil
}

// Odtworz rozpakowuje kopie do wskazanego katalogu.
func (r *Restic) Odtworz(ctx context.Context, zlecenie Zlecenie) (Wynik, error) {
	wynik := Wynik{}
	if r.sciezka() == "" {
		return wynik, fmt.Errorf("ten host nie ma resticu")
	}
	argumenty := append(r.argumentyPodstawowe(zlecenie), "restore",
		zlecenie.Odtworzenie.SnapshotID, "--target", zlecenie.Odtworzenie.Target)
	for _, wzorzec := range zlecenie.Odtworzenie.Include {
		argumenty = append(argumenty, "--include", wzorzec)
	}
	uruchomienie := uruchom(ctx, r.sciezka(), argumenty,
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	wynik.Output = uruchomienie.Stdout + uruchomienie.Stderr
	if !uruchomienie.Ran || uruchomienie.ExitCode != 0 || uruchomienie.Err != nil {
		return wynik, fmt.Errorf("restic restore: %s", uruchomienie.Powod())
	}

	var podsumowanie struct {
		MessageType   string `json:"message_type"`
		FilesRestored uint64 `json:"files_restored"`
		TotalBytes    uint64 `json:"total_bytes"`
	}
	for _, linia := range strings.Split(uruchomienie.Stdout, "\n") {
		if err := json.Unmarshal([]byte(linia), &podsumowanie); err == nil &&
			podsumowanie.MessageType == "summary" {
			pliki, bajty := podsumowanie.FilesRestored, podsumowanie.TotalBytes
			wynik.FilesRestored = &pliki
			wynik.TotalBytesProcessed = &bajty
		}
	}
	wynik.Message = "kopia " + zlecenie.Odtworzenie.SnapshotID +
		" odtworzona do " + zlecenie.Odtworzenie.Target
	return wynik, nil
}

// rozmiar opisuje liczbe bajtow tak, jak czyta ja czlowiek.
func rozmiar(bajty uint64) string {
	jednostki := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	wartosc := float64(bajty)
	for _, jednostka := range jednostki {
		if wartosc < 1024 || jednostka == "TiB" {
			cyfry := 1
			if jednostka == "B" {
				cyfry = 0
			}
			return strconv.FormatFloat(wartosc, 'f', cyfry, 64) + " " + jednostka
		}
		wartosc /= 1024
	}
	return strconv.FormatUint(bajty, 10) + " B"
}

// pierwsze przycina liste komunikatow do kilku pierwszych.
func pierwsze(wartosci []string, ile int) []string {
	if len(wartosci) <= ile {
		return wartosci
	}
	return wartosci[:ile]
}

// upewnijSieZeIstnieje zaklada repozytorium, jesli definicja na to pozwala.
//
// Zakladamy je tylko wtedy, gdy operator o to poprosil. Repozytorium
// utworzone po cichu przy literowce w adresie wyglada jak backup, ktory
// dziala - a jest pustym katalogiem obok tego wlasciwego.
func (r *Restic) upewnijSieZeIstnieje(ctx context.Context, zlecenie Zlecenie) error {
	sprawdzenie := uruchom(ctx, r.sciezka(),
		append(r.argumentyPodstawowe(zlecenie), "cat", "config"),
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	if sprawdzenie.Ran && sprawdzenie.ExitCode == 0 {
		return nil
	}
	if !zlecenie.Initialize {
		return nil
	}
	utworzenie := uruchom(ctx, r.sciezka(),
		append(r.argumentyPodstawowe(zlecenie), "init"),
		srodowiskoNarzedzia(zlecenie, ZmiennaHaslaRestic), tajneZlecenia(zlecenie), nil)
	if !utworzenie.Ran || utworzenie.ExitCode != 0 {
		return fmt.Errorf("restic init: %s", utworzenie.Powod())
	}
	return nil
}
