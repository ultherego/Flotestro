package packages

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	dnfPath = "/usr/bin/dnf"
	rpmPath = "/usr/bin/rpm"
)

// dnfLockFiles to pliki blokowane na czas transakcji RPM.
var dnfLockFiles = []string{
	"/var/lib/rpm/.rpm.lock",
	"/var/cache/dnf/metadata_lock.pid",
}

// DNF jest adapterem Fedory i systemow z rodziny RHEL.
type DNF struct{}

func (d *DNF) Name() string { return "dnf" }

func (d *DNF) Available() bool {
	info, err := os.Stat(dnfPath)
	return err == nil && !info.IsDir()
}

func (d *DNF) LockHeld() (bool, string) {
	for _, path := range dnfLockFiles {
		if held, checked := lockHeld(path); checked && held {
			return true, path
		}
	}
	return false, ""
}

// Plan liczy aktualizacje z lokalnego cache. check-update zwraca 100, gdy sa
// aktualizacje, i 0, gdy ich nie ma; kazdy inny kod jest bledem.
func (d *DNF) Plan(ctx context.Context, options Options) (Plan, error) {
	plan := Plan{Manager: d.Name(), DiskAvailableBytes: diskAvailable("/")}

	result := run(ctx, 5*time.Minute, dnfPath, "--quiet", "--cacheonly", "check-update")
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 100) {
		return plan, fmt.Errorf("dnf check-update: %s", result.Reason())
	}

	for _, line := range strings.Split(result.Stdout, "\n") {
		change, ok := parseDNFUpdateLine(line)
		if !ok || !matchesFilter(change, options) {
			continue
		}
		plan.Changes = append(plan.Changes, change)
	}
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	// Fedora nie publikuje spojnych metadanych o rozmiarze pobrania w tym
	// trybie, wiec nie zgadujemy wartosci.
	return plan, nil
}

// parseDNFUpdateLine czyta linie postaci:
//
//	NetworkManager.x86_64   1:1.52.2-1.fc42   updates
func parseDNFUpdateLine(line string) (Change, bool) {
	if strings.HasPrefix(line, " ") || strings.TrimSpace(line) == "" {
		return Change{}, false
	}
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.Contains(fields[0], ".") {
		return Change{}, false
	}
	name := fields[0]
	if index := strings.LastIndex(name, "."); index > 0 {
		name = name[:index]
	}
	return Change{
		Name:             name,
		CandidateVersion: fields[1],
		Origin:           fields[2],
		// Fedora nie publikuje spojnych metadanych security dla wszystkich
		// repozytoriow, wiec nie oznaczamy zmian jako bezpieczenstwa na
		// podstawie samej nazwy repozytorium.
		Security: false,
	}, true
}

func (d *DNF) rebootPredicted(changes []Change) bool {
	for _, change := range changes {
		name := change.Name
		if strings.HasPrefix(name, "kernel") || name == "glibc" || strings.HasPrefix(name, "systemd") {
			return true
		}
	}
	return false
}

func (d *DNF) Refresh(ctx context.Context) error {
	if held, path := d.LockHeld(); held {
		return fmt.Errorf("%w: %s", ErrLocked, path)
	}
	result := run(ctx, 10*time.Minute, dnfPath, "--quiet", "makecache")
	if !result.Ran || result.ExitCode != 0 {
		return fmt.Errorf("dnf makecache: %s", result.Reason())
	}
	return nil
}

// Upgrade wykonuje transakcje. Tryb jest nieinteraktywny, a wersje przed i po
// zapisujemy zawsze, takze gdy transakcja sie nie powiedzie.
func (d *DNF) Upgrade(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: d.Name()}

	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	// Dracut buduje initramfs z tego samego drzewa modulow co initramfs-tools,
	// wiec niewidoczne moduly grozza tu tym samym: hostem, ktory nie wstanie.
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := d.installedVersions(ctx)

	args := []string{"--assumeyes", "--quiet", "upgrade"}
	if options.SecurityOnly {
		args = append(args, "--security")
	}
	args = append(args, options.Packages...)

	result := run(ctx, 45*time.Minute, dnfPath, args...)

	// Uszkodzony plik w pamieci podrecznej ma dokladnie jedna poprawna
	// odpowiedz: pobrac go jeszcze raz. Czekanie z tym na czlowieka nie
	// dodaje bezpieczenstwa, a kosztuje przerwana kampanie.
	if (!result.Ran || result.ExitCode != 0) && UszkodzonePobranie(result.Stderr, result.Stdout) {
		czyszczenie := run(ctx, 5*time.Minute, dnfPath, "--assumeyes", "--quiet", "clean", "packages")
		if czyszczenie.Ran && czyszczenie.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"usunieto uszkodzone pakiety z pamieci podrecznej i ponowiono transakcje")
			result = run(ctx, 45*time.Minute, dnfPath, args...)
		}
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)

	if !result.Ran || result.ExitCode != 0 {
		return apply, fmt.Errorf("dnf upgrade: %s", result.Reason())
	}
	return apply, nil
}

func (d *DNF) installedVersions(ctx context.Context) map[string]string {
	result := run(ctx, 2*time.Minute, rpmPath, "-qa", "--qf", "%{NAME} %{EVR}\n")
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

// rebootRequired pyta dnf o potrzebe restartu. Kodowi 1 ufamy tylko wtedy, gdy
// narzedzie cokolwiek wypisalo: tym samym kodem konczy sie blad wykonania.
func (d *DNF) rebootRequired(ctx context.Context) bool {
	result := run(ctx, time.Minute, dnfPath, "needs-restarting", "-r")
	return result.Ran && result.ExitCode == 1 && strings.TrimSpace(result.Stdout) != ""
}

// DatabaseBroken sprawdza spojnosc bazy RPM.
func (d *DNF) DatabaseBroken(ctx context.Context) bool {
	result := run(ctx, 2*time.Minute, rpmPath, "--verifydb")
	return result.Ran && result.ExitCode != 0
}
