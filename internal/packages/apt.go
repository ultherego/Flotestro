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
	aptGetPath    = "/usr/bin/apt-get"
	dpkgPath      = "/usr/bin/dpkg"
	dpkgQueryPath = "/usr/bin/dpkg-query"
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

	result := run(ctx, 45*time.Minute, aptGetPath, args...)

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
// dpkg --audit opisuje problem zdaniami przeznaczonymi dla czlowieka, ale
// nazwy pakietow podaje w osobnych, wcietych wierszach. Bierzemy je stamtad,
// zeby operator dostal nazwe zamiast zdania o koniecznosci naprawy.
func (a *APT) PackagesNeedingAttention(ctx context.Context) []string {
	result := run(ctx, time.Minute, dpkgPath, "--audit")
	if !result.Ran || strings.TrimSpace(result.Stdout) == "" {
		return nil
	}
	var pakiety []string
	for _, linia := range strings.Split(result.Stdout, "\n") {
		if !strings.HasPrefix(linia, " ") {
			continue
		}
		pola := strings.Fields(linia)
		if len(pola) == 0 {
			continue
		}
		// Wiersz opisu zaczyna sie od nazwy pakietu; reszta to jego opis.
		pakiety = append(pakiety, pola[0])
	}
	return pakiety
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
