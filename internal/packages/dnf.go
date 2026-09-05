package packages

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
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

	// Plan usuniecia i plan instalacji odpowiadaja na inne pytanie niz plan
	// aktualizacji: nie "co sie zmieni samo", tylko "co zniknie albo dojdzie
	// razem z tym, o co prosze".
	switch options.Mode {
	case ModeRemove:
		return d.planRemove(ctx, plan, options)
	case ModeInstall:
		return d.planInstall(ctx, plan, options)
	}

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

	// Dnf numeruje kroki w swoim wyjsciu; postep jest z nich odczytywany.
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	// Uszkodzony plik w pamieci podrecznej ma dokladnie jedna poprawna
	// odpowiedz: pobrac go jeszcze raz. Czekanie z tym na czlowieka nie
	// dodaje bezpieczenstwa, a kosztuje przerwana kampanie.
	if (!result.Ran || result.ExitCode != 0) && UszkodzonePobranie(result.Stderr, result.Stdout) {
		czyszczenie := run(ctx, 5*time.Minute, dnfPath, "--assumeyes", "--quiet", "clean", "packages")
		if czyszczenie.Ran && czyszczenie.ExitCode == 0 {
			apply.SelfRepair = append(apply.SelfRepair,
				"usunieto uszkodzone pakiety z pamieci podrecznej i ponowiono transakcje")
			result = runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)
		}
	}

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)

	if !result.Ran || result.ExitCode != 0 {
		apply.Output = linieKoncowe(result.Stderr, result.Stdout, maksymalnieLiniiWyniku)
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

// Pelny cykl zycia pakietow dla dnf.
//
// Instalacja, usuniecie i wstrzymanie sa tu osobnymi decyzjami tak samo jak
// w apt, ale narzedzie odpowiada inaczej: dnf nie ma symulacji, ktora
// wypisalaby sam zbior zmian, wiec plan czytamy z jego wlasnej tabeli
// transakcji przerwanej przed wykonaniem. To jest odpowiedz dnf, a nie nasza
// rekonstrukcja jego zaleznosci - i tylko taka odpowiedz wolno pokazac
// czlowiekowi, ktory zaraz cos usunie.

// dnfVersionlock jest nazwa polecenia wtyczki blokujacej wersje.
const dnfVersionlock = "versionlock"

// planRemove liczy, co zniknie razem ze wskazanymi pakietami.
func (d *DNF) planRemove(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("plan usuniecia wymaga listy pakietow")
	}
	// --assumeno konczy sie kodem 1 i komunikatem o przerwaniu: to jest
	// sposob, w jaki dnf pokazuje transakcje, ktorej nie wykonuje.
	args := append([]string{"--assumeno", "remove"}, options.Packages...)
	result := run(ctx, 10*time.Minute, dnfPath, args...)
	if !result.Ran {
		return plan, fmt.Errorf("dnf remove: %s", result.Reason())
	}
	wyjscie := result.Stdout + "\n" + result.Stderr
	if BrakPakietuDNF(wyjscie) {
		// Pakiet, ktorego nie ma, nie jest bledem planu: nie ma czego usuwac.
		return plan, nil
	}
	// Transakcja, ktorej dnf nie potrafi ulozyc, nie jest planem pustym.
	// Pusty plan czytaloby sie jako "nic nie zniknie" - a to jest odpowiedz
	// na inne pytanie niz "tego sie nie da usunac".
	if powod := NierozwiazywalneDNF(wyjscie); powod != "" {
		return plan, fmt.Errorf("dnf nie potrafi ulozyc tej transakcji: %s", powod)
	}
	usuwane, zapowiedziane, err := ParsujPlanUsunieciaDNF(wyjscie)
	if err != nil {
		return plan, err
	}
	if zapowiedziane > 0 && len(usuwane) != zapowiedziane {
		// Cisza w tym miejscu bylaby najgorsza z mozliwych odpowiedzi:
		// operator zobaczylby krotsza liste, niz to, co naprawde zniknie.
		return plan, fmt.Errorf("nie rozpoznano planu usuniecia: dnf zapowiada %d pakietow, "+
			"a odczytano %d", zapowiedziane, len(usuwane))
	}
	if len(usuwane) == 0 {
		// Wyjscie, z ktorego nic nie odczytalismy, tez nie jest planem pustym:
		// znaczy, ze format sie zmienil i nie wiemy, co by zniknelo.
		return plan, fmt.Errorf("nie rozpoznano planu usuniecia z odpowiedzi dnf")
	}
	plan.Removals = usuwane
	plan.Protected = ChronioneWZbiorze(plan.Removals)
	return plan, nil
}

// planInstall liczy, co dojdzie razem ze wskazanymi pakietami.
func (d *DNF) planInstall(ctx context.Context, plan Plan, options Options) (Plan, error) {
	if len(options.Packages) == 0 {
		return plan, fmt.Errorf("plan instalacji wymaga listy pakietow")
	}
	args := append([]string{"--assumeno", "install"}, options.Packages...)
	result := run(ctx, 10*time.Minute, dnfPath, args...)
	if !result.Ran {
		return plan, fmt.Errorf("dnf install: %s", result.Reason())
	}
	wyjscie := result.Stdout + "\n" + result.Stderr
	// Pakiet, ktorego nie ma w zadnym zrodle, konczy sie kodem bledu
	// i komunikatem - i to jest odpowiedz, a nie plan pusty.
	if BrakPakietuDNF(wyjscie) {
		return plan, fmt.Errorf("dnf nie zna pakietu z tego zlecenia")
	}
	if powod := NierozwiazywalneDNF(wyjscie); powod != "" {
		return plan, fmt.Errorf("dnf nie potrafi ulozyc tej transakcji: %s", powod)
	}
	// Transakcje przerwana przed wykonaniem dnf konczy kodem niezerowym;
	// kod zero oznacza tu, ze nie bylo czego instalowac albo ze narzedzie
	// odpowiedzialo inaczej, niz zakladamy.
	zmiany := ParsujPlanInstalacjiDNF(wyjscie)
	if len(zmiany) == 0 {
		if result.ExitCode == 0 && CalaTransakcjaGotowa(wyjscie) {
			// Wszystko juz jest zainstalowane: plan pusty jest tu prawdziwy.
			return plan, nil
		}
		return plan, fmt.Errorf("nie rozpoznano planu instalacji z odpowiedzi dnf (kod %d)",
			result.ExitCode)
	}
	plan.Changes = append(plan.Changes, zmiany...)
	plan.RebootPredicted = d.rebootPredicted(plan.Changes)
	return plan, nil
}

// naglowkiUsuniecia wylicza sekcje tabeli transakcji, ktore znacza usuniecie.
// Kazda z nich znaczy co innego dla czlowieka - pakiet wskazany, pakiet
// zalezny i pakiet, ktory zostaje bez uzytkownika - ale wszystkie znikaja.
var naglowkiUsuniecia = []string{
	"removing:",
	"removing dependent packages:",
	"removing unused dependencies:",
	"removing dependencies:",
}

// Podsumowanie transakcji. Dnf5 pisze "Removing: 3 packages", dnf4 -
// "Remove  3 Packages"; ta liczba jest jedynym zabezpieczeniem przed
// niepelnym odczytem tabeli, wiec czytamy oba zapisy.
var (
	podsumowaniaUsuniecia  = []string{"removing:", "remove "}
	podsumowaniaInstalacji = []string{"installing:", "install "}
)

var naglowkiInstalacji = []string{
	"installing:",
	"installing dependencies:",
	"installing weak dependencies:",
	"upgrading:",
}

// ParsujPlanUsunieciaDNF czyta tabele transakcji przerwanej przed wykonaniem.
//
// Zwraca nazwy pakietow oraz liczbe, ktora dnf sam zapowiedzial w podsumowaniu.
// Rozbieznosc miedzy nimi jest bledem, a nie szczegolem: to znaczy, ze format
// wyjscia sie zmienil, a lista pokazana czlowiekowi bylaby niepelna.
func ParsujPlanUsunieciaDNF(wyjscie string) ([]string, int, error) {
	nazwy, zapowiedziane := sekcjeTransakcjiDNF(wyjscie, naglowkiUsuniecia, podsumowaniaUsuniecia)
	return nazwy, zapowiedziane, nil
}

// ParsujPlanInstalacjiDNF czyta z tabeli transakcji to, co dojdzie.
func ParsujPlanInstalacjiDNF(wyjscie string) []Change {
	nazwy, _ := sekcjeTransakcjiDNF(wyjscie, naglowkiInstalacji, podsumowaniaInstalacji)
	zmiany := make([]Change, 0, len(nazwy))
	for _, nazwa := range nazwy {
		zmiany = append(zmiany, Change{Name: nazwa})
	}
	return zmiany
}

// sekcjeTransakcjiDNF czyta nazwy pakietow z tabeli transakcji.
//
// Tabela ma naglowki sekcji przy lewej krawedzi i wpisy z wcieciem; kolumny to
// nazwa, architektura, wersja, repozytorium i rozmiar. Podsumowanie na koncu
// podaje liczby - i to one sluza do sprawdzenia, czy odczyt jest pelny.
func sekcjeTransakcjiDNF(wyjscie string, naglowki, podsumowania []string) ([]string, int) {
	var nazwy []string
	widziane := map[string]bool{}
	wSekcji := false
	wPodsumowaniu := false
	zapowiedziane := 0

	for _, linia := range strings.Split(wyjscie, "\n") {
		przycieta := strings.TrimSpace(linia)
		male := strings.ToLower(przycieta)
		if przycieta == "" {
			continue
		}
		if strings.HasPrefix(male, "transaction summary") {
			wSekcji, wPodsumowaniu = false, true
			continue
		}
		if wPodsumowaniu {
			// Dnf5 pisze "Removing: 3 packages", dnf4 - "Remove  3 Packages".
			// Czytamy oba, bo to ta liczba pilnuje, czy odczyt jest pelny.
			if pasujeDoPodsumowania(male, podsumowania) {
				for _, pole := range strings.Fields(male) {
					if liczba, err := strconv.Atoi(pole); err == nil {
						zapowiedziane = liczba
						break
					}
				}
			}
			continue
		}
		if zawiera(naglowki, male) {
			wSekcji = true
			continue
		}
		// Naglowek innej sekcji konczy poprzednia.
		if strings.HasSuffix(male, ":") && !strings.HasPrefix(linia, " ") {
			wSekcji = false
			continue
		}
		if !wSekcji || !strings.HasPrefix(linia, " ") {
			continue
		}
		pola := strings.Fields(przycieta)
		if len(pola) < 2 {
			continue
		}
		nazwa := pola[0]
		if widziane[nazwa] {
			continue
		}
		widziane[nazwa] = true
		nazwy = append(nazwy, nazwa)
	}
	return nazwy, zapowiedziane
}

// pasujeDoPodsumowania rozpoznaje wiersz podsumowania w obu pokoleniach dnf.
func pasujeDoPodsumowania(linia string, podsumowania []string) bool {
	for _, prefiks := range podsumowania {
		if strings.HasPrefix(linia, prefiks) {
			return true
		}
	}
	return false
}

func zawiera(lista []string, wartosc string) bool {
	for _, wpis := range lista {
		if wpis == wartosc {
			return true
		}
	}
	return false
}

// BrakPakietuDNF rozpoznaje odpowiedz "nie ma takiego pakietu".
func BrakPakietuDNF(wyjscie string) bool {
	male := strings.ToLower(wyjscie)
	return strings.Contains(male, "no packages to remove") ||
		strings.Contains(male, "no match for argument") ||
		strings.Contains(male, "unable to find a match")
}

// CalaTransakcjaGotowa rozpoznaje odpowiedz "nie ma czego robic".
//
// To jedyny przypadek, w ktorym pusty plan instalacji jest prawdziwy: wszystko
// z zlecenia jest juz zainstalowane w wersji, ktorej dnf nie zmienia.
func CalaTransakcjaGotowa(wyjscie string) bool {
	male := strings.ToLower(wyjscie)
	return strings.Contains(male, "nothing to do") ||
		strings.Contains(male, "package is already installed") ||
		strings.Contains(male, "already installed")
}

// Install doklada pakiety wraz z ich zaleznosciami.
func (d *DNF) Install(ctx context.Context, options Options) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("instalacja wymaga listy pakietow")
	}
	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}
	if hidden, dir := modulesHidden(); hidden {
		return apply, fmt.Errorf("%w: %s", ErrModulesHidden, dir)
	}

	before := d.installedVersions(ctx)
	args := append([]string{"--assumeyes", "--quiet", "install"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	apply.RebootRequired = d.rebootRequired(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = linieKoncowe(result.Stderr, result.Stdout, maksymalnieLiniiWyniku)
		return apply, fmt.Errorf("dnf install: %s", result.Reason())
	}
	return apply, nil
}

// Remove usuwa wskazane pakiety wraz z tym, co zniknie razem z nimi.
//
// Zbior jest liczony ponownie tuz przed operacja i porownywany z tym, co
// zatwierdzil operator: roznica oznacza, ze host zmienil sie od czasu planu.
func (d *DNF) Remove(ctx context.Context, options Options, oczekiwane []string) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(options.Packages) == 0 {
		return apply, fmt.Errorf("usuniecie wymaga listy pakietow")
	}
	if held, path := d.LockHeld(); held {
		return apply, fmt.Errorf("%w: %s", ErrLocked, path)
	}

	plan, err := d.planRemove(ctx, Plan{Manager: d.Name()}, options)
	if err != nil {
		return apply, err
	}
	if len(plan.Protected) > 0 {
		return apply, fmt.Errorf("%w: %s", ErrProtectedPackage, strings.Join(plan.Protected, ", "))
	}
	if roznica := porownajZbiory(oczekiwane, plan.Removals); roznica != "" {
		return apply, fmt.Errorf("%w: %s", ErrPlanChanged, roznica)
	}

	before := d.installedVersions(ctx)
	args := append([]string{"--assumeyes", "--quiet", "remove"}, options.Packages...)
	result := runWithProgress(ctx, 45*time.Minute, options.Progress, false, dnfPath, args...)

	after := d.installedVersions(ctx)
	apply.Applied = diffVersions(before, after)
	apply.DatabaseBroken = d.DatabaseBroken(ctx)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = linieKoncowe(result.Stderr, result.Stdout, maksymalnieLiniiWyniku)
		return apply, fmt.Errorf("dnf remove: %s", result.Reason())
	}
	return apply, nil
}

// SetHold wstrzymuje albo zwalnia aktualizacje pakietow.
//
// Dnf robi to wtyczka versionlock. Host bez niej nie umie wstrzymac pakietu -
// i to jest odpowiedz, a nie cicha zgoda: pakiet uznany za wstrzymany, a
// aktualizowany przy nastepnej kampanii, jest gorszy niz jawna odmowa.
func (d *DNF) SetHold(ctx context.Context, pakiety []string, hold bool) (Apply, error) {
	apply := Apply{Manager: d.Name()}
	if len(pakiety) == 0 {
		return apply, fmt.Errorf("wstrzymanie wymaga listy pakietow")
	}
	if !d.MaVersionlock(ctx) {
		return apply, fmt.Errorf("%s: ten host nie ma wtyczki versionlock, wiec dnf nie "+
			"potrafi wstrzymac pakietu", ErrorUnsupported)
	}
	operacja := "delete"
	if hold {
		operacja = "add"
	}
	args := append([]string{dnfVersionlock, operacja}, pakiety...)
	result := run(ctx, 5*time.Minute, dnfPath, args...)
	if !result.Ran || result.ExitCode != 0 {
		apply.Output = linieKoncowe(result.Stderr, result.Stdout, maksymalnieLiniiWyniku)
		return apply, fmt.Errorf("dnf versionlock %s: %s", operacja, result.Reason())
	}
	return apply, nil
}

// Holds zwraca pakiety wstrzymane na hoscie.
func (d *DNF) Holds(ctx context.Context) []string {
	// --quiet zdejmuje z wyjscia wiersze o metadanych; bez tego pierwsza
	// linia bywala pokazywana jako nazwa wstrzymanego pakietu.
	result := run(ctx, time.Minute, dnfPath, "--quiet", dnfVersionlock, "list")
	if !result.Ran || result.ExitCode != 0 {
		return nil
	}
	return ParsujVersionlock(result.Stdout)
}

// MaVersionlock mowi, czy host umie wstrzymywac pakiety.
func (d *DNF) MaVersionlock(ctx context.Context) bool {
	result := run(ctx, 30*time.Second, dnfPath, dnfVersionlock, "list")
	return result.Ran && result.ExitCode == 0
}

// ParsujVersionlock czyta liste blokad w obu formatach, ktore dnf wypisuje.
//
// Dnf5 pisze "Package name: <nazwa>", dnf4 - sam wzorzec "nazwa-0:wersja.*".
// Czytamy oba, bo panel ma dzialac na obu pokoleniach narzedzia.
func ParsujVersionlock(wyjscie string) []string {
	var nazwy []string
	widziane := map[string]bool{}
	dodaj := func(nazwa string) {
		nazwa = strings.TrimSpace(nazwa)
		if nazwa == "" || widziane[nazwa] {
			return
		}
		widziane[nazwa] = true
		nazwy = append(nazwy, nazwa)
	}
	for _, linia := range strings.Split(wyjscie, "\n") {
		przycieta := strings.TrimSpace(linia)
		if przycieta == "" || strings.HasPrefix(przycieta, "#") {
			continue
		}
		if nazwa, ok := strings.CutPrefix(przycieta, "Package name:"); ok {
			dodaj(nazwa)
			continue
		}
		// Wpis dnf4 jest wzorcem NEVRA: nazwa-epoka:wersja-wydanie.arch albo
		// nazwa-epoka:wersja-*. Cokolwiek innego - wiersz o metadanych,
		// nagłowek, komunikat - nie jest blokada i nie moze udawac nazwy
		// pakietu na liscie wstrzymanych.
		if nazwa := nazwaZWzorcaNEVRA(przycieta); nazwa != "" {
			dodaj(nazwa)
		}
	}
	return nazwy
}

// wzorzecNEVRA rozpoznaje wpis blokady w formacie dnf4.
//
// Wzorzec jest scisly celowo: wiersz, ktory nie jest blokada, ma zostac
// pominiety, a nie trafic na liste wstrzymanych pakietow. Lista z wpisem
// "Last metadata expiration check" mowilaby operatorowi, ze wstrzymano
// pakiet, ktory nie istnieje.
var wzorzecNEVRA = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._+-]*?)-([0-9]+:)?[0-9][^\s-]*-[^\s-]+$`)

// nazwaZWzorcaNEVRA wyciaga nazwe pakietu ze wzorca blokady albo zwraca
// pustke, gdy wiersz blokada nie jest.
func nazwaZWzorcaNEVRA(wzorzec string) string {
	dopasowanie := wzorzecNEVRA.FindStringSubmatch(strings.TrimSpace(wzorzec))
	if dopasowanie == nil {
		return ""
	}
	return dopasowanie[1]
}

// NierozwiazywalneDNF rozpoznaje transakcje, ktorej dnf nie potrafi ulozyc,
// i zwraca powod podany przez narzedzie.
//
// Najczestszy przypadek to pakiet, bez ktorego nie da sie zostawic systemu
// spojnym - dnf odmawia wtedy calej transakcji. Odmowa z powodem jest tu
// jedyna poprawna odpowiedzia: pusta lista znaczylaby "nic nie zniknie".
func NierozwiazywalneDNF(wyjscie string) string {
	male := strings.ToLower(wyjscie)
	markery := []string{
		"failed to resolve the transaction",
		"depsolve error",
		"error: depsolving problem",
		"protected packages",
		"the operation would result in removing",
	}
	znaleziony := false
	for _, marker := range markery {
		if strings.Contains(male, marker) {
			znaleziony = true
			break
		}
	}
	if !znaleziony {
		return ""
	}
	// Powod bierzemy z linii "Problem:" albo z konca wyjscia: to tam dnf
	// tlumaczy, czego nie da sie pogodzic.
	var powody []string
	for _, linia := range strings.Split(wyjscie, "\n") {
		przycieta := strings.TrimSpace(linia)
		male := strings.ToLower(przycieta)
		if strings.HasPrefix(male, "problem") || strings.Contains(male, "protected") ||
			strings.HasPrefix(male, "- ") {
			powody = append(powody, przycieta)
		}
	}
	if len(powody) == 0 {
		return "dnf odrzucil transakcje bez podania powodu"
	}
	if len(powody) > 3 {
		powody = powody[:3]
	}
	return strings.Join(powody, " / ")
}
