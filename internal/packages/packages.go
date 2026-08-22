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
)

// ErrLocked oznacza zajeta blokade menedzera pakietow. Blokady nie obchodzimy:
// druga transakcja na tej samej bazie pakietow moze ja uszkodzic.
var ErrLocked = errors.New("menedzer pakietow jest zajety")

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
}

// Options zawezaja zakres planu lub transakcji.
type Options struct {
	Packages     []string
	SecurityOnly bool
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
	if stderr := strings.TrimSpace(r.Stderr); stderr != "" {
		return fmt.Sprintf("kod %d: %s", r.ExitCode, firstLine(stderr))
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
func run(ctx context.Context, timeout time.Duration, path string, args ...string) commandResult {
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
	cmd.Env = []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		// Tryb nieinteraktywny jest wymuszony: prompt w transakcji oznaczalby
		// zawieszenie zadania, a nie sukces.
		"DEBIAN_FRONTEND=noninteractive",
		"HOME=" + runtimeDir,
		"XDG_STATE_HOME=" + filepath.Join(runtimeDir, "state"),
		"XDG_CACHE_HOME=" + filepath.Join(runtimeDir, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(runtimeDir, "config"),
	}

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
