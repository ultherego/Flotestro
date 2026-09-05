// Package backup steruje narzedziami backupu, ktore juz sa na hoscie.
//
// Dane backupowe nie plyna przez Flotestro i plynac nie beda: host rozmawia
// z repozytorium wprost, a panel widzi wylacznie metadane - kiedy backup sie
// udal, ile zajmuje i co obejmuje. Panel, przez ktory plynelyby kopie stu
// hostow, bylby waskim gardlem i najciekawszym celem w calej instalacji.
//
// Poswiadczenia repozytorium nie ida w argumentach polecenia. Wiersz polecen
// procesu jest czytelny dla kazdego uzytkownika hosta przez /proc, wiec haslo
// podane jako argument byloby haslem podanym publicznie. Ida srodowiskiem,
// ktore czyta wylacznie wlasciciel procesu.
package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Narzedzia obslugiwane przez modul.
const (
	NarzedzieRestic  = "restic"
	NarzedzieBorg    = "borg"
	NarzedzieRunbook = "runbook"
)

// Rodzaje operacji. Runbook dostaje je jako pierwszy argument, wiec sa
// czescia kontraktu widocznego poza tym pakietem.
const (
	OperacjaPlan      = "plan"
	OperacjaBackup    = "run"
	OperacjaSprawdz   = "verify"
	OperacjaOdtworzen = "restore"
)

// Plan nadpisania przy odtwarzaniu.
//
// Odtworzenie bez planu nadpisania jest operacja, ktorej skutku nikt nie zna:
// pliki moga trafic obok istniejacych, na nie albo wcale. Dlatego panel wymaga
// decyzji, a host ja sprawdza przed rozpakowaniem czegokolwiek.
const (
	// NadpisaniePuste wymaga, zeby katalog docelowy byl pusty.
	NadpisaniePuste = "empty-target"
	// NadpisanieDozwolone pozwala nadpisac to, co w katalogu juz jest.
	NadpisanieDozwolone = "overwrite"
)

// KatalogRunbookow trzyma skrypty, ktore panel moze uruchomic.
//
// Panel nie przesyla tresci skryptu i nie moze go zalozyc: wskazuje wylacznie
// nazwe pliku, ktory administrator hosta wczesniej tam polozyl. Inaczej
// "runbook" bylby zdalnym wykonaniem dowolnego kodu z inna nazwa.
const KatalogRunbookow = "/etc/flotestro/backup-runbooks"

// Ograniczenia wielkosci. Wyjscie narzedzia backupu bywa dlugie, a panel
// przechowuje je w wyniku zadania.
const (
	MaksymalneWyjscie   = 256 << 10
	MaksymalnaLiczbaSci = 64
)

var (
	nazwaDefinicji = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	nazwaRunbooka  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	nazwaZmiennej  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
)

// Definicja opisuje, co i dokad backupowac.
//
// Poswiadczen tu nie ma: sa osobno, bo maja inne zycie - przychodza z magazynu
// tuz przed operacja i nie zostaja nigdzie poza pamiecia procesu.
type Definicja struct {
	ID   string `json:"id"`
	Tool string `json:"tool"`
	// Repository jest odnosnikiem do celu backupu. Panel go pokazuje, ale
	// nie przechowuje jego zawartosci ani przez niego nie posredniczy.
	Repository string   `json:"repository"`
	Paths      []string `json:"paths,omitempty"`
	Excludes   []string `json:"excludes,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// Retencja opisuje, ile kopii zostaje. Zero oznacza "nie sprzataj":
	// skasowanie starych kopii jest osobna decyzja od zrobienia nowej.
	KeepLast    int  `json:"keep_last,omitempty"`
	KeepDaily   int  `json:"keep_daily,omitempty"`
	KeepWeekly  int  `json:"keep_weekly,omitempty"`
	KeepMonthly int  `json:"keep_monthly,omitempty"`
	Prune       bool `json:"prune,omitempty"`
	// Runbook wskazuje nazwe skryptu w katalogu runbookow.
	Runbook string `json:"runbook,omitempty"`
	// Initialize pozwala zalozyc repozytorium przy pierwszej kopii. Bez tej
	// zgody host nie tworzy niczego: repozytorium powstale przez pomylke
	// w adresie wyglada jak backup, ktory dziala, a jest pustym katalogiem
	// obok tego wlasciwego.
	Initialize bool `json:"initialize,omitempty"`
}

// Odtworzenie opisuje zlecone odtworzenie danych.
type Odtworzenie struct {
	SnapshotID string   `json:"snapshot_id"`
	Target     string   `json:"target"`
	Include    []string `json:"include,omitempty"`
	Overwrite  string   `json:"overwrite"`
}

// Zlecenie jest tym, co adapter dostaje do wykonania.
type Zlecenie struct {
	Definicja
	Odtworzenie Odtworzenie
	// Haslo i Srodowisko niosa wartosci z magazynu. Zyja w pamieci procesu
	// przez czas operacji i nie trafiaja do argumentow, wyniku ani dziennika.
	Haslo      []byte
	Srodowisko map[string][]byte
	// Verify moze czytac dane, a nie tylko strukture repozytorium. To inny
	// koszt i inny czas, wiec jest jawnym wyborem.
	ReadData bool
}

// Snapshot to jedna kopia w repozytorium.
type Snapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname,omitempty"`
	Paths    []string  `json:"paths,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	// SizeBytes bywa nieznany: nie kazde narzedzie liczy rozmiar kopii przy
	// samym wyliczeniu snapshotow. Pusty wskaznik oznacza brak wiedzy.
	SizeBytes *uint64 `json:"size_bytes,omitempty"`
}

// Stan opisuje repozytorium widziane z hosta.
type Stan struct {
	Tool        string `json:"tool"`
	ToolVersion string `json:"tool_version,omitempty"`
	Repository  string `json:"repository,omitempty"`
	// Snapshots jest lista kopii, od najstarszej.
	Snapshots []Snapshot `json:"snapshots,omitempty"`
	// LastSuccessAt jest czasem ostatniej udanej kopii. Pusty oznacza
	// repozytorium bez kopii albo stan nieustalony - rozroznia je powod.
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	TotalSizeBytes *uint64    `json:"total_size_bytes,omitempty"`
	ObservedAt     time.Time  `json:"observed_at"`
	// UnavailableReason mowi, dlaczego stanu nie ustalono. Puste repozytorium
	// i repozytorium nieodczytane to dwie rozne odpowiedzi.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// Wynik opisuje skutek operacji.
type Wynik struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	// Liczniki sa wskaznikami: narzedzie, ktore ich nie poda, zostawia brak
	// wiedzy, a nie zero.
	BytesAdded          *uint64  `json:"bytes_added,omitempty"`
	TotalBytesProcessed *uint64  `json:"total_bytes_processed,omitempty"`
	FilesNew            *uint64  `json:"files_new,omitempty"`
	FilesChanged        *uint64  `json:"files_changed,omitempty"`
	FilesRestored       *uint64  `json:"files_restored,omitempty"`
	DurationSeconds     *float64 `json:"duration_seconds,omitempty"`
	// Removed liczy kopie skasowane przez retencje.
	Removed *int   `json:"snapshots_removed,omitempty"`
	Message string `json:"message,omitempty"`
	// Output jest wyjsciem narzedzia po zaslonieciu poswiadczen.
	Output string `json:"output,omitempty"`
}

// Postep opisuje postep dlugiej operacji.
type Postep struct {
	Percent *uint32
	Message string
}

// PostepFunc odbiera postep operacji.
type PostepFunc func(Postep)

// Adapter jest sterownikiem jednego narzedzia backupu.
//
// Modul nie robi backupu sam i nie bedzie: robia go narzedzia, ktore host juz
// ma i ktorym administrator juz ufa. Zadaniem panelu jest je uruchomic,
// odczytac wynik i pokazac go obok stu innych hostow.
type Adapter interface {
	Nazwa() string
	Dostepny() bool
	Wersja(ctx context.Context) string
	Plan(ctx context.Context, zlecenie Zlecenie) (Stan, error)
	Wykonaj(ctx context.Context, zlecenie Zlecenie, postep PostepFunc) (Wynik, error)
	Sprawdz(ctx context.Context, zlecenie Zlecenie) (Wynik, error)
	Odtworz(ctx context.Context, zlecenie Zlecenie) (Wynik, error)
}

// Wybierz zwraca adapter narzedzia wskazanego w definicji.
func Wybierz(narzedzie string) (Adapter, error) {
	switch narzedzie {
	case NarzedzieRestic:
		return &Restic{}, nil
	case NarzedzieBorg:
		return &Borg{}, nil
	case NarzedzieRunbook:
		return &Runbook{}, nil
	}
	return nil, fmt.Errorf("nieznane narzedzie backupu %q", narzedzie)
}

// Waliduj sprawdza definicje przed wykonaniem czegokolwiek.
func (d Definicja) Waliduj() error {
	if !nazwaDefinicji.MatchString(d.ID) {
		return fmt.Errorf("nieprawidlowy identyfikator definicji %q", d.ID)
	}
	switch d.Tool {
	case NarzedzieRestic, NarzedzieBorg:
		if strings.TrimSpace(d.Repository) == "" {
			return fmt.Errorf("definicja wymaga adresu repozytorium")
		}
	case NarzedzieRunbook:
		if !nazwaRunbooka.MatchString(d.Runbook) {
			return fmt.Errorf("nieprawidlowa nazwa runbooka %q", d.Runbook)
		}
	default:
		return fmt.Errorf("nieznane narzedzie backupu %q", d.Tool)
	}
	if strings.ContainsAny(d.Repository, "\n\r") || len(d.Repository) > 512 {
		return fmt.Errorf("adres repozytorium zawiera znak nowej linii albo jest za dlugi")
	}
	if len(d.Paths) > MaksymalnaLiczbaSci {
		return fmt.Errorf("definicja obejmuje najwyzej %d sciezek", MaksymalnaLiczbaSci)
	}
	for _, sciezka := range d.Paths {
		if !strings.HasPrefix(sciezka, "/") || strings.ContainsAny(sciezka, "\n\r") {
			return fmt.Errorf("sciezka %q nie jest bezwzgledna", sciezka)
		}
	}
	for _, wzorzec := range d.Excludes {
		if strings.ContainsAny(wzorzec, "\n\r") {
			return fmt.Errorf("wzorzec wykluczenia zawiera znak nowej linii")
		}
	}
	for _, znacznik := range d.Tags {
		if znacznik == "" || strings.ContainsAny(znacznik, " \t\n\r,") {
			return fmt.Errorf("nieprawidlowy znacznik %q", znacznik)
		}
	}
	for _, wartosc := range []int{d.KeepLast, d.KeepDaily, d.KeepWeekly, d.KeepMonthly} {
		if wartosc < 0 || wartosc > 10000 {
			return fmt.Errorf("liczba zachowywanych kopii jest poza zakresem")
		}
	}
	return nil
}

// Drzewa, do ktorych panel nie odtwarza danych.
//
// Odtworzenie wprost do systemu plikow hosta zamienia backup w rozpakowanie
// starego stanu na dzialajacy system: konfiguracja, konta i biblioteki
// wracaja skokiem, a nikt tego nie przeglada. Odtwarzamy do katalogu roboczego,
// a to, co z niego wroci na miejsce, jest osobna decyzja i osobna operacja.
var zakazaneDrzewa = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
	"/dev", "/proc", "/sys", "/run",
	// Stan panelu i jego pomocnika nie jest miejscem na odtworzone dane.
	"/var/lib/flotestro", "/var/lib/flotestro-helper",
	// Helper dziala z PrivateTmp, wiec ma wlasny, prywatny /tmp i /var/tmp.
	// Dane odtworzone tam znikaja razem z procesem, a operator widzi sukces
	// i pusty katalog - najgorsza z mozliwych odpowiedzi.
	"/tmp", "/var/tmp",
}

// zakazaneKorzenie wylicza katalogi, ktorych samych nie ruszamy, choc ich
// wnetrze jest zwyczajnym miejscem na dane. Odtworzenie do /home/anna/kopia
// jest normalna praca; odtworzenie do /home juz nie.
var zakazaneKorzenie = []string{"/", "/home", "/root", "/var", "/srv", "/opt", "/mnt", "/media"}

// WalidujOdtworzenie sprawdza cel i plan nadpisania.
func WalidujOdtworzenie(odtworzenie Odtworzenie) error {
	if strings.TrimSpace(odtworzenie.SnapshotID) == "" {
		return fmt.Errorf("odtworzenie wymaga wskazania kopii")
	}
	if strings.ContainsAny(odtworzenie.SnapshotID, " \t\n\r/") || len(odtworzenie.SnapshotID) > 128 {
		return fmt.Errorf("nieprawidlowy identyfikator kopii")
	}
	cel := odtworzenie.Target
	if !strings.HasPrefix(cel, "/") {
		return fmt.Errorf("odtworzenie wymaga bezwzglednej sciezki celu")
	}
	if cel != filepath.Clean(cel) || strings.Contains(cel, "..") {
		return fmt.Errorf("sciezka celu %q nie jest w postaci znormalizowanej", cel)
	}
	if strings.ContainsAny(cel, "\n\r") {
		return fmt.Errorf("sciezka celu zawiera znak nowej linii")
	}
	for _, zakazany := range zakazaneKorzenie {
		if cel == zakazany {
			return fmt.Errorf("panel nie odtwarza danych wprost do %s; wskaz katalog roboczy", zakazany)
		}
	}
	for _, drzewo := range zakazaneDrzewa {
		if cel == drzewo || strings.HasPrefix(cel, drzewo+"/") {
			if drzewo == "/tmp" || drzewo == "/var/tmp" {
				return fmt.Errorf("pomocnik ma wlasny, prywatny %s: odtworzone tam dane znikaja razem z operacja", drzewo)
			}
			return fmt.Errorf("panel nie odtwarza danych wprost do %s; wskaz katalog roboczy", drzewo)
		}
	}
	switch odtworzenie.Overwrite {
	case NadpisaniePuste, NadpisanieDozwolone:
	default:
		return fmt.Errorf("odtworzenie wymaga planu nadpisania (%s albo %s)",
			NadpisaniePuste, NadpisanieDozwolone)
	}
	for _, wzorzec := range odtworzenie.Include {
		if !strings.HasPrefix(wzorzec, "/") || strings.ContainsAny(wzorzec, "\n\r") {
			return fmt.Errorf("zakres %q nie jest bezwzgledna sciezka", wzorzec)
		}
	}
	return nil
}

// SprawdzCel sprawdza katalog docelowy tuz przed rozpakowaniem.
//
// Sprawdzenie jest na hoscie, a nie w panelu, bo tylko host wie, co w tym
// katalogu naprawde lezy - i wie to dopiero w chwili operacji.
func SprawdzCel(odtworzenie Odtworzenie) error {
	info, err := os.Stat(odtworzenie.Target)
	if os.IsNotExist(err) {
		// Katalogu, ktorego nie ma, nie tworzymy w polowie drzewa: rodzic
		// musi istniec, zeby literowka nie zalozyla katalogu w losowym miejscu.
		rodzic := filepath.Dir(odtworzenie.Target)
		if info, err := os.Stat(rodzic); err != nil || !info.IsDir() {
			return fmt.Errorf("katalog %s nie istnieje", rodzic)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("cel %s nie jest katalogiem", odtworzenie.Target)
	}
	if odtworzenie.Overwrite == NadpisanieDozwolone {
		return nil
	}
	wpisy, err := os.ReadDir(odtworzenie.Target)
	if err != nil {
		return err
	}
	if len(wpisy) > 0 {
		return fmt.Errorf("katalog %s nie jest pusty, a plan nadpisania na to nie pozwala",
			odtworzenie.Target)
	}
	return nil
}

// WalidujSrodowisko sprawdza nazwy zmiennych, ktore panel ustawia narzedziu.
func WalidujSrodowisko(zmienne []string) error {
	for _, nazwa := range zmienne {
		if !nazwaZmiennej.MatchString(nazwa) {
			return fmt.Errorf("nieprawidlowa nazwa zmiennej srodowiska %q", nazwa)
		}
	}
	return nil
}

// Zaslon usuwa z wyjscia wartosci, ktore nie moga z niego wyjsc.
//
// Narzedzia backupu wypisuja adres repozytorium, a ten bywa adresem
// z wpisanym haslem. Zaslaniamy takze same wartosci poswiadczen: jedno
// echo w skrypcie wystarczy, zeby haslo trafilo do wyniku zadania, a stamtad
// do bazy panelu.
func Zaslon(wyjscie string, tajne [][]byte) string {
	wynik := wyjscie
	for _, wartosc := range tajne {
		if len(wartosc) < 4 {
			// Krotka wartosc zaslonieta w tekscie zamienilaby wyjscie
			// w rzeszoto; takich hasel magazyn i tak nie powinien wydawac.
			continue
		}
		wynik = strings.ReplaceAll(wynik, string(wartosc), "[zasloniete]")
	}
	return zaslonAdresy(wynik)
}

// wzorzecAdresu wylapuje poswiadczenia wpisane w adres.
var wzorzecAdresu = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@`)

func zaslonAdresy(wyjscie string) string {
	return wzorzecAdresu.ReplaceAllString(wyjscie, "${1}${2}:[zasloniete]@")
}

// Ogranicz przycina wyjscie do rozmiaru, ktory panel przechowa.
func Ogranicz(wyjscie string) string {
	if len(wyjscie) <= MaksymalneWyjscie {
		return wyjscie
	}
	// Koniec wyjscia jest wazniejszy niz poczatek: tam sa bledy i podsumowanie.
	return "[wyjscie przyciete na granicy modulu]\n" + wyjscie[len(wyjscie)-MaksymalneWyjscie:]
}

// PosortujSnapshoty ustawia kopie od najstarszej.
func PosortujSnapshoty(snapshoty []Snapshot) {
	sort.SliceStable(snapshoty, func(i, j int) bool {
		return snapshoty[i].Time.Before(snapshoty[j].Time)
	})
}

// OstatniUdany zwraca czas najnowszej kopii albo nil.
func OstatniUdany(snapshoty []Snapshot) *time.Time {
	if len(snapshoty) == 0 {
		return nil
	}
	najnowszy := snapshoty[0].Time
	for _, snapshot := range snapshoty[1:] {
		if snapshot.Time.After(najnowszy) {
			najnowszy = snapshot.Time
		}
	}
	return &najnowszy
}
