package packages

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	aptGetPath     = "/usr/bin/apt-get"
	dpkgPath       = "/usr/bin/dpkg"
	dpkgQueryPath  = "/usr/bin/dpkg-query"
	dpkgStatusPath = "/var/lib/dpkg/status"
	// Narzedzia debconfa sluza wylacznie odblokowaniu pakietu, ktory czeka
	// na decyzje operatora.
	debconfShowPath = "/usr/bin/debconf-show"
	debconfSetPath  = "/usr/bin/debconf-set-selections"
)

// aptLockFiles to pliki, ktore APT i dpkg blokuja na czas operacji.
var aptLockFiles = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/cache/apt/archives/lock",
	"/var/lib/apt/lists/lock",
}

// APT jest adapterem Debiana i Ubuntu.
type APT struct{}

func (a *APT) Name() string { return "apt" }

func (a *APT) Available() bool {
	info, err := os.Stat(aptGetPath)
	return err == nil && !info.IsDir()
}

// LockHeld sprawdza blokady dpkg i APT. Blokady nie obchodzimy: rownolegla
// transakcja moze uszkodzic baze pakietow.
func (a *APT) LockHeld() (bool, string) {
	for _, path := range aptLockFiles {
		if held, checked := lockHeld(path); checked && held {
			return true, path
		}
	}
	return false, ""
}

// Plan liczy aktualizacje przez symulacje. Symulacja nie potrzebuje blokady
// ani roota, wiec planowanie nie koliduje z reczna praca administratora.
func (a *APT) Plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: a.Name(), DiskAvailableBytes: diskAvailable("/")}
	// Pakiet czekajacy na konfiguracje zatrzyma kazda transakcje, wiec plan
	// mowi o nim od razu. Bez tego operator dowiaduje sie o blokadzie dopiero
	// po nieudanej aktualizacji.
	plan.Blocked = a.BlockedPackages(ctx)

	result := run(ctx, 3*time.Minute, aptGetPath,
		"--simulate", "--quiet", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		return plan, fmt.Errorf("symulacja apt: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		change, ok := parseAptInstLine(line)
		if !ok || !matchesFilter(change, options) {
			continue
		}
		plan.Changes = append(plan.Changes, change)
	}

	plan.DownloadBytes = a.downloadSize(ctx, options)
	plan.RebootPredicted = a.rebootPredicted(plan.Changes)
	return plan, nil
}

// parseAptInstLine czyta linie postaci:
//
//	Inst libfoo [1.0-1] (1.0-2 Debian:12/stable [amd64])
//
// Format jest stabilny przy LC_ALL=C i nie zalezy od jezyka interfejsu.
func parseAptInstLine(line string) (Change, bool) {
	if !strings.HasPrefix(line, "Inst ") {
		return Change{}, false
	}
	rest := strings.TrimPrefix(line, "Inst ")
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return Change{}, false
	}

	change := Change{Name: fields[0]}
	if start := strings.Index(rest, "["); start >= 0 {
		if end := strings.Index(rest[start:], "]"); end > 0 {
			change.CurrentVersion = rest[start+1 : start+end]
		}
	}
	if start := strings.Index(rest, "("); start >= 0 {
		if end := strings.LastIndex(rest, ")"); end > start {
			inner := strings.Fields(rest[start+1 : end])
			if len(inner) > 0 {
				change.CandidateVersion = inner[0]
			}
			if len(inner) > 1 {
				change.Origin = strings.Join(inner[1:], " ")
			}
		}
	}
	// Repozytoria bezpieczenstwa Debiana i Ubuntu maja rozpoznawalny origin.
	origin := change.Origin
	change.Security = strings.Contains(origin, "-security") ||
		strings.Contains(origin, "Debian-Security") ||
		strings.Contains(origin, "Ubuntu:") && strings.Contains(origin, "security")
	return change, true
}

// downloadSize sumuje rozmiary pakietow do pobrania. Wartosc jest szacunkiem
// planu, a nie obietnica; przy bledzie zwracamy zero zamiast zgadywac.
func (a *APT) downloadSize(ctx context.Context, options Options) uint64 {
	result := run(ctx, 2*time.Minute, aptGetPath,
		"--print-uris", "--quiet", "--yes", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		return 0
	}
	var total uint64
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		// Format: 'uri' nazwa_pliku rozmiar SHA256:...
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "'") {
			continue
		}
		if size, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
			total += size
		}
	}
	return total
}

// rebootPredicted zgaduje potrzebe restartu na podstawie aktualizowanych
// pakietow. Jest to przewidywanie planu, a nie stan hosta.
func (a *APT) rebootPredicted(changes []Change) bool {
	for _, change := range changes {
		name := change.Name
		if strings.HasPrefix(name, "linux-image") || strings.HasPrefix(name, "linux-generic") ||
			name == "libc6" || strings.HasPrefix(name, "systemd") {
			return true
		}
	}
	return false
}

// Refresh odswieza metadane repozytorium. Wymaga roota i blokady.
func (a *APT) Refresh(ctx context.Context) error {
	if held, path := a.LockHeld(); held {
		return fmt.Errorf("%w: %s", ErrLocked, path)
	}
	result := run(ctx, 5*time.Minute, aptGetPath, "update", "--quiet")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("apt-get update: %s", result.Reason())
	}
	return nil
}

// Upgrade wykonuje transakcje. Zachowanie wobec conffiles jest zdefiniowane
// jawnie: zachowujemy plik administratora i nigdy nie pytamy interaktywnie.
// Prompt w tym trybie oznaczalby zawieszenie, a nie sukces.
func (a *APT) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: a.Name()}

	if held, path := a.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	// Transakcja moze pociagnac przebudowe initramfs. Gdy proces nie widzi
	// modulow jadra, obraz powstanie bez sterownika dysku i host nie wstanie
	// po restarcie - lepiej nie zaczynac.
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	// Wersje przed transakcja sa zapisywane zawsze, takze gdy transakcja padnie.
	before := a.installedVersions(ctx)

	args := []string{
		"--yes", "--quiet",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "APT::Get::Assume-Yes=true",
		"upgrade",
	}
	if len(options.Packages) > 0 {
		args = append([]string{"--yes", "--quiet",
			"-o", "Dpkg::Options::=--force-confold",
			"-o", "Dpkg::Options::=--force-confdef",
			"install", "--only-upgrade"}, options.Packages...)
	}

	// Apt melduje postep wlasnym, maszynowym kanalem na deskryptorze 3.
	if options.Progress != nil {
		args = append([]string{"-o", "APT::Status-Fd=3"}, args...)
	}
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, options.Progress != nil,
		aptGetPath, args...)

	// Uszkodzone archiwum w pamieci podrecznej naprawia sie samo, bo ma jedna
	// poprawna odpowiedz. Pytanie konfiguracyjne pakietu jej nie ma i zostaje
	// dla operatora - to granica miedzy naprawa a decydowaniem za czlowieka.
	if (!result.Ran || result.ExitCode != 0) && UszkodzonePobranie(result.Stderr, result.Stdout) {
		czyszczenie := run(ctx, 5*time.Minute, aptGetPath, "--quiet", "clean")
		if czyszczenie.Ran && czyszczenie.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"usunieto uszkodzone archiwa z pamieci podrecznej i ponowiono transakcje")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress,
				options.Progress != nil, aptGetPath, args...)
		}
	}

	after := a.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.PackagesNeedingAttention = a.PackagesNeedingAttention(ctx)
	apply.DatabaseBroken = len(apply.PackagesNeedingAttention) > 0
	apply.RebootRequired = fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required")
	apply.ServicesNeedingRestart = a.servicesNeedingRestart(ctx)

	if !result.Ran || result.ExitCode != 0 {
		// Nazwa pakietu wchodzi do komunikatu, bo bez niej operator wie tylko
		// tyle, ze transakcja padla, i musi zalogowac sie na host, zeby ustalic
		// przyczyne.
		apply.Output = linieKoncowe(result.Stderr, result.Stdout, maksymalnieLiniiWyniku)
		if len(apply.PackagesNeedingAttention) > 0 {
			return apply, fmt.Errorf("apt-get upgrade: %s; wymaga uwagi: %s",
				result.Reason(), strings.Join(apply.PackagesNeedingAttention, ", "))
		}
		return apply, fmt.Errorf("apt-get upgrade: %s", result.Reason())
	}
	return apply, nil
}

// installedVersions zwraca mape pakiet -> wersja.
func (a *APT) installedVersions(ctx context.Context) map[string]string {
	result := run(ctx, 2*time.Minute, dpkgQueryPath, "-W", "-f", "${binary:Package} ${Version}\n")
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	versions := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			versions[fields[0]] = fields[1]
		}
	}
	return versions
}

// DatabaseBroken sprawdza, czy dpkg zostal w stanie wymagajacym naprawy.
// Po takiej awarii kolejne kampanie na hoscie musza zostac wstrzymane.
func (a *APT) DatabaseBroken(ctx context.Context) bool {
	return len(a.PackagesNeedingAttention(ctx)) > 0
}

// PackagesNeedingAttention wypisuje pakiety, ktorych stan blokuje transakcje.
//
// Stan czytamy wprost z bazy dpkg, a nie przez "dpkg --audit": audyt wymaga
// dostepu do blokady katalogu bazy, ktorego agent bez uprawnien roota nie ma.
// Plik stanu jest czytelny dla wszystkich, wiec ta sama informacja jest
// dostepna zarowno agentowi, jak i helperowi - a plan operacji moze ostrzec
// o blokadzie, zanim ktokolwiek zleci aktualizacje.
func (a *APT) PackagesNeedingAttention(ctx context.Context) []string {
	blocked := a.blockedFromStatus()
	nazwy := make([]string, 0, len(blocked))
	for _, pakiet := range blocked {
		nazwy = append(nazwy, pakiet.Name)
	}
	return nazwy
}

// blockedFromStatus parsuje /var/lib/dpkg/status i zwraca pakiety w stanie
// innym niz w pelni zainstalowany albo calkiem usuniety.
func (a *APT) blockedFromStatus() []Blocked {
	return blockedFromStatusFile(dpkgStatusPath)
}

// blockedFromStatusFile jest wydzielone, zeby dalo sie sprawdzic parsowanie
// bez zmieniania bazy pakietow dzialajacego systemu.
func blockedFromStatusFile(path string) []Blocked {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var blocked []Blocked
	for _, stanza := range strings.Split(string(data), "\n\n") {
		var nazwa, status string
		for _, linia := range strings.Split(stanza, "\n") {
			switch {
			case strings.HasPrefix(linia, "Package: "):
				nazwa = strings.TrimSpace(strings.TrimPrefix(linia, "Package: "))
			case strings.HasPrefix(linia, "Status: "):
				status = strings.TrimSpace(strings.TrimPrefix(linia, "Status: "))
			}
		}
		if nazwa == "" || status == "" {
			continue
		}
		pola := strings.Fields(status)
		if len(pola) != 3 {
			continue
		}
		// Trzecie pole opisuje faktyczny stan pakietu. Zainstalowany i sam
		// plikami konfiguracyjnymi nie blokuja niczego; kazdy inny stan
		// znaczy, ze dpkg nie dokonczyl pracy i zrobi to przy nastepnej
		// transakcji - a wtedy moze na niej paść.
		switch pola[2] {
		case "installed", "config-files", "not-installed":
			continue
		}
		blocked = append(blocked, Blocked{Name: nazwa, Status: status})
	}
	return blocked
}

// servicesNeedingRestart czyta liste zapisana przez needrestart, jesli jest
// zainstalowany. Brak narzedzia oznacza pusta liste, a nie brak potrzeby.
func (a *APT) servicesNeedingRestart(ctx context.Context) []string {
	const path = "/var/run/reboot-required.pkgs"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var packages []string
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			packages = append(packages, trimmed)
		}
	}
	return packages
}

// diffVersions porownuje stan przed i po transakcji.
func diffVersions(before, after map[string]string) []Change {
	var changes []Change
	for name, newVersion := range after {
		oldVersion := before[name]
		if oldVersion != newVersion {
			changes = append(changes, Change{
				Name:             name,
				CurrentVersion:   oldVersion,
				CandidateVersion: newVersion,
			})
		}
	}
	return changes
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
