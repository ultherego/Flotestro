package agent

import (
	"context"
	"os"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/modules/docker"
	"github.com/ultherego/flotestro/internal/modules/schedules"
)

// privilegedIdentity jest opcjonalnym zrodlem danych wymagajacych roota.
// Bez niego inventory nadal powstaje, ale bez keytab i stanu SSSD.
var privilegedIdentity func(context.Context, string) (PrivilegedIdentity, error)

// SetPrivilegedIdentityProbe wskazuje funkcje odczytujaca uprzywilejowana
// czesc stanu domeny. Agent uzywa do tego helpera roota.
func SetPrivilegedIdentityProbe(probe func(context.Context, string) (PrivilegedIdentity, error)) {
	privilegedIdentity = probe
}

// privilegedAccounts uzupelnia konta o stan blokady i klucze SSH. Odczyt
// /etc/shadow i katalogow domowych nalezy do roota.
var privilegedAccounts func(context.Context, []string) (*helperv1.LocalAccountsResult, error)

// SetPrivilegedAccountProbe wskazuje funkcje odczytujaca uprzywilejowana
// czesc danych o kontach.
func SetPrivilegedAccountProbe(probe func(context.Context, []string) (*helperv1.LocalAccountsResult, error)) {
	privilegedAccounts = probe
}

// Collect zbiera pelny inventory. Ta funkcja moze uruchamiac procesy potomne,
// dlatego wolamy ja w cyklu inventory, nigdy w heartbeacie.
func Collect(ctx context.Context) (Facts, error) {
	return CollectFrom(ctx, "")
}

// CollectFrom zbiera inventory, znajac adres, ktorym host rozmawia z panelem.
// Bez tego adresu modul sieci nie potrafi wskazac interfejsu zarzadzania,
// a zgadywanie go z pierwszej pozycji listy konczy sie zmiana konfiguracji
// interfejsu, przez ktory wlasnie przyszlo polecenie.
func CollectFrom(ctx context.Context, adresZarzadzania string) (Facts, error) {
	machineID, err := MachineID()
	if err != nil {
		return Facts{}, err
	}
	hostname, _ := os.Hostname()
	caps := DetectCapabilities()

	facts := Facts{
		Hostname:     hostname,
		MachineID:    machineID,
		BootID:       BootID(),
		OS:           ReadOSInfo(),
		Hardware:     ReadHardware(),
		Capabilities: caps,
		Interfaces:   networkInterfaces(),
		CollectedAt:  time.Now().UTC(),
	}

	if caps.Available(CapSystemd) {
		facts.FailedUnits, facts.FailedUnitsKnown = failedUnits(ctx)
	}
	switch {
	case caps.Available(CapAPT):
		facts.Packages = aptSummary(ctx)
	case caps.Available(CapDNF):
		facts.Packages = dnfSummary(ctx)
	}
	facts.RebootRequired = rebootRequired(ctx, caps)
	// Stan domeny jest czescia inventory, wiec zbierany raz na cykl, a nie
	// przy kazdym heartbeacie.
	facts.Identity = ReadIdentityState(ctx)

	// Konta lokalne czytamy z pliku; stan blokady i klucze SSH wymagaja roota
	// i sa uzupelniane przez helpera.
	facts.LocalAccounts = ReadLocalAccounts()
	if privilegedAccounts != nil {
		names := make([]string, 0, len(facts.LocalAccounts))
		for _, account := range facts.LocalAccounts {
			if account.Source == SourceLocal {
				names = append(names, account.Name)
			}
		}
		if len(names) > 0 {
			if result, err := privilegedAccounts(ctx, names); err == nil {
				facts.LocalAccounts = mergePrivilegedAccounts(facts.LocalAccounts, result)
			}
		}
	}

	// Silnik kontenerow jest odpytywany raz na cykl inwentarza i tylko
	// o podsumowanie. Pelne listy pobiera operator, gdy otworzy zakladke -
	// odpytywanie silnika przy kazdym cyklu obciazaloby host bez powodu.
	if caps.Available(CapDocker) && dockerProbe != nil {
		if snapshot, err := dockerProbe(ctx, false); err == nil {
			podsumowanie := snapshot.Summary
			facts.Containers = &podsumowanie
		} else {
			// Nieodczytany silnik nie moze wygladac jak host bez kontenerow.
			facts.Containers = &docker.Summary{UnavailableReason: "helper: " + err.Error()}
		}
	}

	// Harmonogramy zmieniaja sie rzadko, wiec ida w cyklu inwentarza, a nie
	// na zadanie: pelna lista zadan cyklicznych hosta to kilkanascie wpisow,
	// a nie setki jak przy pakietach czy procesach.
	if caps.Available(CapSchedules) && scheduleProbe != nil {
		if snapshot, err := scheduleProbe(ctx); err == nil {
			facts.Schedules = &snapshot
		} else {
			facts.Schedules = &schedules.Snapshot{UnavailableReason: "helper: " + err.Error()}
		}
	}

	// Siec czytamy z jadra w kazdym cyklu: odczyt jest tani, a stan potrafi
	// zmienic sie bez udzialu panelu (DHCP, kabel, kontener).
	siec := ZbierzSiec(ctx, adresZarzadzania)
	facts.Network = &siec

	// Resolver czytamy razem z siecia: to jedna decyzja hosta o tym, dokad
	// ida jego pytania i ktora droga.
	resolver := ZbierzDNS(ctx)
	facts.DNS = &resolver

	if facts.Identity.Enrolled && privilegedIdentity != nil {
		privileged, err := privilegedIdentity(ctx, facts.Identity.Domain)
		if err != nil {
			// Brak danych uprzywilejowanych nie uniewaznia reszty inventory,
			// ale musi byc widoczny jako powod, a nie jako cisza.
			facts.Identity.UnavailableReason = "helper: " + err.Error()
		} else {
			facts.Identity = facts.Identity.Merge(privileged)
		}
	}
	return facts, nil
}

// failedUnits zwraca nazwy jednostek w stanie failed oraz informacje, czy w
// ogole udalo sie je ustalic. Nieudane zapytanie nie moze wygladac jak zero
// jednostek w bledzie.
func failedUnits(ctx context.Context) ([]string, bool) {
	result := runCommand(ctx, 15*time.Second,
		"/usr/bin/systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager")
	if !result.Ran || result.ExitCode != 0 {
		return nil, false
	}
	var units []string
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(fields[0], ".") {
			units = append(units, fields[0])
		}
	}
	return units, true
}

// aptSummary liczy pakiety do aktualizacji przez symulacje, ktora nie zmienia
// stanu systemu i nie potrzebuje blokady dpkg.
func aptSummary(ctx context.Context) Packages {
	summary := Packages{Manager: "apt"}

	if result := runCommand(ctx, 30*time.Second,
		"/usr/bin/dpkg-query", "-f", "${binary:Package}\n", "-W"); result.Ran && result.ExitCode == 0 {
		installed := uint32(len(strings.Fields(result.Stdout)))
		summary.Installed = &installed
	}

	result := runCommand(ctx, 120*time.Second,
		"/usr/bin/apt-get", "--simulate", "--quiet", "-o", "Debug::NoLocking=true", "upgrade")
	if !result.Ran || result.ExitCode != 0 {
		summary.UnavailableReason = result.Reason()
		return summary
	}

	var upgradable, security uint32
	for _, line := range strings.Split(result.Stdout, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		upgradable++
		// Origin jest w nawiasie na koncu linii; repozytorium bezpieczenstwa
		// Debiana i Ubuntu zawiera w nazwie "-security".
		if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
			security++
		}
	}
	summary.Upgradable = &upgradable
	summary.SecurityUpgradable = &security
	return summary
}

// dnfSummary liczy aktualizacje bez odswiezania metadanych.
// check-update zwraca 0 przy braku aktualizacji i 100, gdy jakies sa.
// Kazdy inny kod jest bledem wykonania, a nie liczba zero.
func dnfSummary(ctx context.Context) Packages {
	summary := Packages{Manager: "dnf"}

	if result := runCommand(ctx, 30*time.Second,
		"/usr/bin/rpm", "-qa", "--qf", "%{NAME}\n"); result.Ran && result.ExitCode == 0 {
		installed := uint32(len(strings.Fields(result.Stdout)))
		summary.Installed = &installed
	}

	result := runCommand(ctx, 180*time.Second,
		"/usr/bin/dnf", "--quiet", "--cacheonly", "check-update")
	if !result.Ran || (result.ExitCode != 0 && result.ExitCode != 100) {
		summary.UnavailableReason = result.Reason()
		return summary
	}

	var upgradable uint32
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		// Linia aktualizacji to: nazwa.arch  wersja  repozytorium.
		if len(fields) == 3 && strings.Contains(fields[0], ".") && !strings.HasPrefix(line, " ") {
			upgradable++
		}
	}
	summary.Upgradable = &upgradable
	// Fedora nie publikuje spojnych metadanych security dla wszystkich repo,
	// wiec licznik bezpieczenstwa zostaje nieustalony zamiast falszywego zera.
	return summary
}

// rebootRequired sprawdza wskaznik restartu wlasciwy dla dystrybucji.
// Zwraca nil, gdy stanu nie da sie ustalic.
func rebootRequired(ctx context.Context, caps Capabilities) *bool {
	if exists("/var/run/reboot-required") || exists("/run/reboot-required") {
		return boolPtr(true)
	}
	if caps.Available(CapAPT) {
		// Na Debianie brak pliku jest jednoznaczna odpowiedzia.
		return boolPtr(false)
	}
	if caps.Available(CapDNF) {
		return interpretNeedsRestarting(
			runCommand(ctx, 60*time.Second, "/usr/bin/dnf", "needs-restarting", "-r"))
	}
	return nil
}

// interpretNeedsRestarting tlumaczy wynik "dnf needs-restarting -r" na odpowiedz
// o restarcie. Narzedzie zwraca 0 przy braku potrzeby i 1, gdy restart jest
// wymagany - ale tym samym kodem konczy sie blad wykonania, na przyklad brak
// zapisywalnego HOME. Kodowi 1 ufamy wiec tylko wtedy, gdy narzedzie cokolwiek
// wypisalo na stdout; w bledzie milczy tam i pisze na stderr.
func interpretNeedsRestarting(result commandResult) *bool {
	switch {
	case !result.Ran:
		return nil
	case result.ExitCode == 0:
		return boolPtr(false)
	case result.ExitCode == 1 && strings.TrimSpace(result.Stdout) != "":
		return boolPtr(true)
	default:
		return nil
	}
}

func boolPtr(value bool) *bool { return &value }
