// Package packages jest adapterem menedzerow pakietow. Planowanie dziala bez
// roota; odswiezenie metadanych i transakcja wymagaja helpera.
package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Stabilne kody bledow adaptera. Sa czescia kontraktu wyniku zadania.
const (
	ErrorLocked         = "package_manager_locked"
	ErrorPlanMismatch   = "plan_changed"
	ErrorTransaction    = "transaction_failed"
	ErrorUnsupported    = "unsupported_manager"
	ErrorDatabaseBroken = "package_database_broken"
	ErrorModulesHidden  = "kernel_modules_hidden"
)

// ErrLocked oznacza zajeta blokade menedzera pakietow. Blokady nie obchodzimy:
// druga transakcja na tej samej bazie pakietow moze ja uszkodzic.
var ErrLocked = errors.New("menedzer pakietow jest zajety")

// ErrModulesHidden oznacza, ze proces transakcji nie widzi drzewa modulow
// biezacego jadra. Transakcja w takim srodowisku jest grozna: skrypty pakietow
// przebuduja initramfs bez sterownikow i host nie wstanie po restarcie.
var ErrModulesHidden = errors.New("drzewo modulow jadra jest niewidoczne")

// ErrProtectedPackage oznacza probe usuniecia pakietu, bez ktorego host
// przestaje byc zarzadzalny albo uruchamialny.
var ErrProtectedPackage = errors.New("pakiet chroniony")

// ErrPlanChanged oznacza, ze zbior usuwanych pakietow zmienil sie od
// zatwierdzenia planu.
var ErrPlanChanged = errors.New("plan usuniecia zmienil sie od zatwierdzenia")

// porownajZbiory zwraca opis roznicy albo pustke, gdy zbiory sa rowne.
// Pusty zbior oczekiwany oznacza brak zatwierdzonego planu i tez jest
// roznica: operacja nieodwracalna nie moze isc bez podstawy.
func porownajZbiory(oczekiwane, obecne []string) string {
	if len(oczekiwane) == 0 {
		return "brak zatwierdzonego planu usuniecia"
	}
	zbior := map[string]bool{}
	for _, nazwa := range oczekiwane {
		zbior[nazwa] = true
	}
	var dodatkowe []string
	for _, nazwa := range obecne {
		if !zbior[nazwa] {
			dodatkowe = append(dodatkowe, nazwa)
		}
		delete(zbior, nazwa)
	}
	var brakujace []string
	for nazwa := range zbior {
		brakujace = append(brakujace, nazwa)
	}
	sort.Strings(dodatkowe)
	sort.Strings(brakujace)

	switch {
	case len(dodatkowe) > 0 && len(brakujace) > 0:
		return "doszly: " + strings.Join(dodatkowe, ", ") +
			"; odpadly: " + strings.Join(brakujace, ", ")
	case len(dodatkowe) > 0:
		return "usunieciu podlegloby takze: " + strings.Join(dodatkowe, ", ")
	case len(brakujace) > 0:
		return "nie podlegaja juz usunieciu: " + strings.Join(brakujace, ", ")
	}
	return ""
}

// Change opisuje jedna zmiane wersji pakietu.
type Change struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	Origin           string `json:"origin,omitempty"`
	Security         bool   `json:"security"`
}

// Plan opisuje, co zostaloby zmienione.
type Plan struct {
	Manager            string   `json:"manager"`
	Changes            []Change `json:"changes"`
	DownloadBytes      uint64   `json:"download_bytes"`
	DiskAvailableBytes uint64   `json:"disk_available_bytes"`
	MetadataRefreshed  bool     `json:"metadata_refreshed"`
	RebootPredicted    bool     `json:"reboot_predicted"`
	// Blocked opisuje pakiety, ktore uniemozliwia wykonanie planu. Plan sam
	// w sobie przechodzi, bo niczego nie zmienia, ale transakcja na takim
	// hoscie padnie - operator ma to wiedziec przed jej zleceniem.
	Blocked []Blocked `json:"blocked,omitempty"`
	// Mode mowi, jakiego rodzaju jest to plan.
	Mode string `json:"mode,omitempty"`
	// Removals wylicza pakiety, ktore zniknelyby wraz z wskazanymi. Usuniecie
	// jednego pakietu potrafi pociagnac kilkadziesiat zaleznych - operator ma
	// to zobaczyc przed zatwierdzeniem, a nie po.
	Removals []string `json:"removals,omitempty"`
	// Protected wylicza pakiety chronione, ktore znalazly sie w planie.
	// Ich obecnosc oznacza, ze operacja nie zostanie wykonana.
	Protected []string `json:"protected,omitempty"`
}

// Apply opisuje wynik wykonanej transakcji.
type Apply struct {
	Manager                string   `json:"manager"`
	Applied                []Change `json:"applied"`
	RebootRequired         bool     `json:"reboot_required"`
	ServicesNeedingRestart []string `json:"services_needing_restart,omitempty"`
	DatabaseBroken         bool     `json:"package_database_broken"`
	// PackagesNeedingAttention wskazuje pakiety, ktore blokuja transakcje.
	// Bez nich komunikat o naprawie bazy nie mowi, co naprawic.
	PackagesNeedingAttention []string `json:"packages_needing_attention,omitempty"`
	// SelfRepair opisuje, co adapter naprawil sam przed ponowieniem. Cicha
	// naprawa bylaby gorsza od jej braku: operator musi wiedziec, ze host
	// zostal dotkniety inaczej, niz zlecil.
	SelfRepair []string `json:"self_repair,omitempty"`
	// Output to koncowka wyjscia narzedzia przy niepowodzeniu. Jedno zdanie
	// z opisem bledu wystarcza, zeby wiedziec, ze cos padlo; zeby wiedziec,
	// dlaczego, trzeba czasem zobaczyc kontekst - a logowanie sie na host po
	// kazdej nieudanej transakcji jest dokladnie tym, czego panel ma oszczedzic.
	Output []string `json:"output,omitempty"`
}

// linieKoncowe zwraca ostatnie uzyteczne linie wyjscia narzedzia. Przyczyna
// jest zwykle przy koncu, wiec to poczatek mozna poswiecic.
func linieKoncowe(stderr, stdout string, ile int) []string {
	linie := uzyteczneLinie(stderr)
	if len(linie) == 0 {
		linie = uzyteczneLinie(stdout)
	}
	if len(linie) > ile {
		linie = linie[len(linie)-ile:]
	}
	return linie
}

// maksymalnieLiniiWyniku ogranicza kontekst bledu w wyniku operacji.
const maksymalnieLiniiWyniku = 40

// Tryby planowania. Plan aktualizacji i plan usuniecia licza co innego, ale
// odpowiadaja na to samo pytanie: co ta operacja zmieni na hoscie.
const (
	ModeUpgrade = "upgrade"
	ModeRemove  = "remove"
	ModeInstall = "install"
)

// Options zawezaja zakres planu lub transakcji.
type Options struct {
	Packages     []string
	SecurityOnly bool
	// Mode wybiera rodzaj planu. Pusty oznacza plan aktualizacji.
	Mode string
	// Progress odbiera postep dlugiej transakcji. Nil oznacza brak odbiorcy
	// i wtedy narzedzie dziala jak dotad.
	Progress ProgressFunc
}

// Manager jest adapterem konkretnego menedzera pakietow.
type Manager interface {
	// Name zwraca nazwe menedzera, np. apt albo dnf.
	Name() string
	// Available mowi, czy menedzer jest obecny na hoscie.
	Available() bool
	// LockHeld sprawdza, czy trwa inna operacja pakietowa. Wymaga roota.
	LockHeld() (bool, string)
	// Plan liczy zmiany bez modyfikacji systemu.
	Plan(ctx context.Context, options Options) (Plan, error)
	// Refresh odswieza metadane repozytorium. Wymaga roota.
	Refresh(ctx context.Context) error
	// Upgrade wykonuje transakcje. Wymaga roota.
	Upgrade(ctx context.Context, options Options) (Apply, error)
	// DatabaseBroken sprawdza, czy baza pakietow wymaga naprawy.
	DatabaseBroken(ctx context.Context) bool
}

// Detect zwraca adapter wlasciwy dla hosta.
func Detect() (Manager, error) {
	for _, manager := range []Manager{&APT{}, &DNF{}} {
		if manager.Available() {
			return manager, nil
		}
	}
	return nil, fmt.Errorf("%s: nie rozpoznano menedzera pakietow", ErrorUnsupported)
}

// commandResult oddziela fakt uruchomienia procesu od jego wyniku.
type commandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Ran      bool
	Err      error
}

// Reason opisuje powod niepowodzenia w sposob czytelny w wyniku zadania.
func (r commandResult) Reason() string {
	if r.Err != nil && !r.Ran {
		return r.Err.Error()
	}
	if opis := opisBledu(r.Stderr, r.Stdout); opis != "" {
		return fmt.Sprintf("kod %d: %s", r.ExitCode, opis)
	}
	return fmt.Sprintf("kod %d", r.ExitCode)
}

// runtimeDir jest katalogiem zapisywalnym dla uzytkownika procesu. Narzedzia
// pakietowe tworza pliki w HOME i katalogach XDG; agent nie ma katalogu
// domowego, wiec bez tego dnf konczy sie bledem uprawnien, ktory latwo pomylic
// z brakiem aktualizacji.
var runtimeDir = os.TempDir()

// SetRuntimeDir wskazuje katalog roboczy dla uruchamianych narzedzi.
// Agent podaje swoj katalog stanu, helper katalog roota.
func SetRuntimeDir(dir string) error {
	if dir == "" {
		return nil
	}
	for _, sub := range []string{"", "state", "cache", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	runtimeDir = dir
	return nil
}

// run uruchamia narzedzie ze stala sciezka i tablica argumentow. Nigdy nie
// uzywamy sh -c, wiec nazwa pakietu nie moze stac sie poleceniem.
// LC_ALL=C stabilizuje output, ktory musimy parsowac.
// ErrInvalidAnswer odrzuca odpowiedz ze znakiem nowej linii: kazdy wiersz
// wejscia debconfa jest osobnym ustawieniem, wiec taka wartosc pozwalalaby
// dopisac ustawienia, o ktore nikt nie prosil.
var ErrInvalidAnswer = errors.New("odpowiedz zawiera znak nowej linii")

func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// runWithInput uruchamia polecenie, podajac mu tresc na standardowe wejscie.
func runWithInput(ctx context.Context, timeout time.Duration, input string,
	path string, args ...string) commandResult {
	return runCommand(ctx, timeout, input, path, args...)
}

func run(ctx context.Context, timeout time.Duration, path string, args ...string) commandResult {
	return runCommand(ctx, timeout, "", path, args...)
}

func runCommand(ctx context.Context, timeout time.Duration, input string,
	path string, args ...string) commandResult {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{ExitCode: -1, Err: fmt.Errorf("%s: brak narzedzia", path)}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, path, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	cmd.Env = srodowisko()

	runErr := cmd.Run()
	result := commandResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Err: runErr}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		result.Ran, result.ExitCode = true, 0
	case errors.As(runErr, &exitErr):
		result.Ran, result.ExitCode = true, exitErr.ExitCode()
	}
	if cmdCtx.Err() != nil {
		result.Ran = false
	}
	return result
}

// srodowisko jest jednakowe dla wszystkich wywolan narzedzi pakietowych.
func srodowisko() []string {
	return []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		// Tryb nieinteraktywny jest wymuszony: prompt w transakcji oznaczalby
		// zawieszenie zadania, a nie sukces.
		"DEBIAN_FRONTEND=noninteractive",
		// Dnf tnie wlasne komunikaty do szerokosci terminala, a bez terminala
		// przyjmuje osiemdziesiat kolumn - przyczyna bledu ginela wtedy
		// w polowie zdania ("scriptlet failed, exit stat").
		"COLUMNS=200",
		"HOME=" + runtimeDir,
		"XDG_STATE_HOME=" + filepath.Join(runtimeDir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeDir, "config"),
	}
}

// lockHeld sprawdza blokade pliku bez uruchamiania procesu. Zwraca falsz, gdy
// pliku nie da sie otworzyc: brak dostepu nie jest dowodem na brak blokady,
// ale nie moze tez blokowac operacji na zawsze.
func lockHeld(path string) (bool, bool) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, false
	}
	defer file.Close()

	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err != nil {
		// EWOULDBLOCK oznacza, ze blokade trzyma ktos inny.
		return true, true
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	return false, true
}

// modulesHidden sprawdza, czy drzewo modulow biezacego jadra jest widoczne dla
// procesu transakcji. Namespace z ProtectKernelModules=yes podstawia w to
// miejsce pusty katalog; update-initramfs zbuduje wtedy obraz bez sterownika
// dysku i host przestanie sie uruchamiac.
func modulesHidden() (bool, string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false, ""
	}
	release := strings.TrimRight(string(uts.Release[:]), "\x00")
	return modulesHiddenAt("/proc/modules", "/lib/modules", release)
}

// modulesHiddenAt jest sprawdzeniem oddzielonym od sciezek systemowych.
// Jadro monolityczne - bez zaladowanego modulu - nie jest przypadkiem
// podejrzanym i transakcji nie blokuje. Katalogu, ktorego nie da sie
// odczytac, tez nie uznajemy za ukryty: niewiedza nie moze zatrzymac
// aktualizacji calej floty.
func modulesHiddenAt(procModules, modulesRoot, release string) (bool, string) {
	if release == "" || !kernelIsModular(procModules) {
		return false, ""
	}
	dir := filepath.Join(modulesRoot, release)
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		return true, dir
	case err != nil:
		return false, ""
	case len(entries) == 0:
		return true, dir
	}
	return false, ""
}

// kernelIsModular mowi, czy jadro w ogole uzywa modulow.
func kernelIsModular(procModules string) bool {
	data, err := os.ReadFile(procModules)
	if err != nil {
		return false
	}
	return len(bytes.TrimSpace(data)) > 0
}

// diskAvailable zwraca wolne miejsce w podanym systemie plikow.
func diskAvailable(path string) uint64 {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize)
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}

// matchesFilter mowi, czy pakiet miesci sie w zawezeniu operacji.
func matchesFilter(change Change, options Options) bool {
	if options.SecurityOnly && !change.Security {
		return false
	}
	if len(options.Packages) == 0 {
		return true
	}
	for _, name := range options.Packages {
		if name == change.Name {
			return true
		}
	}
	return false
}

// Hash liczy skrot tresci planu. Wykonanie porownuje go ze swoim planem, wiec
// zmiana metadanych repozytorium miedzy planem a transakcja jest wykrywalna.
// Kolejnosc zmian nie moze wplywac na wynik.
func (p Plan) Hash() []byte {
	names := make([]string, 0, len(p.Changes))
	index := map[string]Change{}
	for _, change := range p.Changes {
		names = append(names, change.Name)
		index[change.Name] = change
	}
	sort.Strings(names)

	hasher := sha256.New()
	fmt.Fprintf(hasher, "%s\n", p.Manager)
	for _, name := range names {
		change := index[name]
		fmt.Fprintf(hasher, "%s\t%s\t%s\n", change.Name, change.CurrentVersion, change.CandidateVersion)
	}
	return hasher.Sum(nil)
}
