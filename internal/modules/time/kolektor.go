package czas

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Wykonawca uruchamia narzedzie hosta i zwraca jego wyjscie.
//
// Zbieranie stanu jest tu, a nie w agencie, bo potrzebuja go dwie strony:
// agent przy kazdym cyklu inventory i helper zaraz po zmianie, zeby
// powiedziec, czy zmiana doszla do skutku. Wstrzykniety wykonawca zostawia
// pakiet testowalnym bez uruchamiania czegokolwiek.
type Wykonawca func(ctx context.Context, sciezka string, argumenty ...string) (string, error)

const sciezkaSystemctl = "/usr/bin/systemctl"

// jednostkiCzasu wylicza jednostki demonow czasu w kolejnosci sprawdzania.
// Debian nazywa chronyego chrony.service, Fedora chronyd.service.
var jednostkiCzasu = []string{"chronyd.service", "chrony.service", "systemd-timesyncd.service"}

// Zbierz czyta stan czasu hosta.
//
// Odczyt nie wymaga roota: timedatectl pyta uslugi przez magistrale, chronyc
// rozmawia z demonem po petli zwrotnej, a pliki konfiguracyjne czasu sa
// czytelne dla wszystkich.
func Zbierz(ctx context.Context, uruchom Wykonawca) Snapshot {
	teraz := time.Now()
	_, przesuniecie := teraz.Zone()
	snapshot := Snapshot{
		Now:              teraz,
		UTCOffsetSeconds: &przesuniecie,
		ObservedAt:       teraz.UTC(),
	}

	if wyjscie, err := uruchom(ctx, SciezkaTimedatectl, "show"); err == nil {
		zTimedatectl := ParsujTimedatectl(wyjscie)
		snapshot.Timezone = zTimedatectl.Timezone
		snapshot.RTCInLocalTime = zTimedatectl.RTCInLocalTime
		snapshot.NTPEnabled = zTimedatectl.NTPEnabled
		snapshot.Synchronized = zTimedatectl.Synchronized
	} else {
		snapshot.Timezone = strefaZPlikow()
		snapshot.UnavailableReason = "timedatectl: " + err.Error()
	}

	snapshot.Unit, snapshot.ServiceActive = jednostkaDemona(ctx, uruchom)

	// Chrony pytamy zawsze, gdy jest jego klient: to on ma pomiar
	// przesuniecia, ktorego timesyncd nie liczy w ogole.
	if istnieje(SciezkaChronyc) {
		if wyjscie, err := uruchom(ctx, SciezkaChronyc, "-c", "tracking"); err == nil {
			zChronyego := ParsujTracking(wyjscie)
			przepiszChrony(&snapshot, zChronyego)
			if zrodla, err := uruchom(ctx, SciezkaChronyc, "-c", "sources"); err == nil {
				snapshot.Sources = ParsujZrodla(zrodla)
			}
			czytajKonfiguracjeChrony(&snapshot)
			return snapshot
		}
	}

	if wyjscie, err := uruchom(ctx, SciezkaTimedatectl, "show-timesync", "--all"); err == nil {
		snapshot.Service = DemonTimesyncd
		stan := ParsujTimesync(wyjscie, "timesyncd.conf")
		przepiszTimesyncd(&snapshot, stan)
		czytajKonfiguracjeTimesyncd(&snapshot)
		return snapshot
	}

	// Host bez demona czasu nie jest hostem zsynchronizowanym z nieznanym
	// zrodlem - jest hostem, ktorego zegar nikt nie pilnuje.
	snapshot.WriteReason = "this host runs neither chrony nor systemd-timesyncd"
	if snapshot.UnavailableReason == "" && snapshot.Service == "" {
		snapshot.UnavailableReason = snapshot.WriteReason
	}
	return snapshot
}

// przepiszChrony przenosi pomiar chronyego do obrazu hosta.
func przepiszChrony(snapshot *Snapshot, zChronyego Snapshot) {
	snapshot.Service = DemonChrony
	snapshot.ReferenceName = zChronyego.ReferenceName
	snapshot.Stratum = zChronyego.Stratum
	snapshot.OffsetSeconds = zChronyego.OffsetSeconds
	snapshot.FrequencyPPM = zChronyego.FrequencyPPM
	snapshot.RootDelaySeconds = zChronyego.RootDelaySeconds
	snapshot.RootDispersionSeconds = zChronyego.RootDispersionSeconds
	snapshot.LeapStatus = zChronyego.LeapStatus
	snapshot.LastSyncAt = zChronyego.LastSyncAt
	// Odpowiedz demona jest blizsza prawdzie niz odpowiedz timedatectl:
	// timedated mowi, czy jakakolwiek usluga zglasza synchronizacje, a chrony
	// wie, czy wybral zrodlo.
	if zChronyego.Synchronized != nil {
		snapshot.Synchronized = zChronyego.Synchronized
	}
}

func przepiszTimesyncd(snapshot *Snapshot, stan StanTimesyncd) {
	snapshot.ReferenceName = stan.ServerName
	if snapshot.ReferenceName == "" {
		snapshot.ReferenceName = stan.ServerAddress
	}
	snapshot.Stratum = stan.Stratum
	snapshot.RootDelaySeconds = stan.RootDelay
	snapshot.RootDispersionSeconds = stan.RootDispersio
	snapshot.LeapStatus = stan.LeapStatus
	snapshot.FrequencyPPM = stan.FrequencyPPM
	snapshot.Configured = append(snapshot.Configured, stan.Servers...)
}

// jednostkaDemona wskazuje jednostke demona czasu i jej stan.
//
// Pytamy o stan wczytania, a nie o "is-active": systemd odpowiada "inactive"
// takze na pytanie o jednostke, ktorej na hoscie nie ma, wiec sam ten stan
// kazalby panelowi nazywac chronyego na hoscie, gdzie chronyego nie ma.
// Jedno wywolanie obejmuje wszystkie kandydatki, bo inventory ma byc lekkie.
func jednostkaDemona(ctx context.Context, uruchom Wykonawca) (string, *bool) {
	argumenty := append([]string{"show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState"}, jednostkiCzasu...)
	wyjscie, err := uruchom(ctx, sciezkaSystemctl, argumenty...)
	if err != nil && strings.TrimSpace(wyjscie) == "" {
		return "", nil
	}

	// Rekordy sa rozdzielone pusta linia, a kolejnosc wlasciwosci w rekordzie
	// nie jest gwarantowana - dlatego czytamy rekordami, a nie wierszami.
	var pierwszaWczytana string
	for _, rekord := range strings.Split(strings.ReplaceAll(wyjscie, "\r\n", "\n"), "\n\n") {
		nazwa, wczytana, aktywna := czytajRekordJednostki(rekord)
		if nazwa == "" || !wczytana {
			continue
		}
		if aktywna {
			prawda := true
			return nazwa, &prawda
		}
		if pierwszaWczytana == "" {
			pierwszaWczytana = nazwa
		}
	}
	if pierwszaWczytana == "" {
		return "", nil
	}
	falsz := false
	return pierwszaWczytana, &falsz
}

func czytajRekordJednostki(rekord string) (nazwa string, wczytana, aktywna bool) {
	for _, linia := range strings.Split(rekord, "\n") {
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(linia), "=")
		if !ok {
			continue
		}
		switch klucz {
		case "Id":
			nazwa = wartosc
		case "LoadState":
			wczytana = wartosc != "not-found" && wartosc != "masked"
		case "ActiveState":
			aktywna = wartosc == "active" || wartosc == "activating"
		}
	}
	return nazwa, wczytana, aktywna
}

// czytajKonfiguracjeChrony wskazuje plik panelu i wylicza serwery z plikow.
func czytajKonfiguracjeChrony(snapshot *Snapshot) {
	glowny, tresc := glownaKonfiguracjaChrony()
	if glowny == "" {
		snapshot.WriteReason = "this host has no chrony configuration file"
		return
	}
	snapshot.ConfigPath = glowny
	snapshot.Configured = append(snapshot.Configured, ParsujSerwery(tresc, filepath.Base(glowny), false)...)

	katalog, rodzaj := KatalogDropIn(tresc)
	if katalog == "" {
		// Panel nie przepisuje glownego pliku chronyego, wiec host bez
		// katalogu wlaczanego jest dla panelu tylko do odczytu - i mowi to
		// wprost, zamiast zapisywac plik, ktorego demon nie przeczyta.
		snapshot.WriteReason = "chrony on this host includes no drop-in directory; " +
			"the panel does not rewrite " + glowny + " unless you let it add its own sources directory"
		snapshot.CanAddSourceDir = true
		return
	}
	snapshot.ManagedPath = filepath.Join(katalog, NazwaPlikuChrony(rodzaj))
	if zarzadzana, err := os.ReadFile(snapshot.ManagedPath); err == nil {
		snapshot.Managed = string(zarzadzana)
	}

	wpisy, err := os.ReadDir(katalog)
	if err != nil {
		return
	}
	nazwy := make([]string, 0, len(wpisy))
	for _, wpis := range wpisy {
		if !wpis.IsDir() {
			nazwy = append(nazwy, wpis.Name())
		}
	}
	sort.Strings(nazwy)
	for _, nazwa := range nazwy {
		sciezka := filepath.Join(katalog, nazwa)
		tresc, err := os.ReadFile(sciezka)
		if err != nil {
			continue
		}
		snapshot.Configured = append(snapshot.Configured,
			ParsujSerwery(string(tresc), nazwa, sciezka == snapshot.ManagedPath)...)
	}
}

// czytajKonfiguracjeTimesyncd oznacza wpisy panelu na liscie demona.
//
// Lista, ktora podaje timesyncd, jest lista obowiazujaca; plik panelu mowi
// tylko, kto ja napisal. Dopisywanie tych samych adresow drugi raz pokazywalo
// by kazdy serwer podwojnie. Wpis zapisany przez panel, ktorego demon nie
// wymienia, dokladamy osobno - to znaczy, ze zapis nie doszedl do skutku.
func czytajKonfiguracjeTimesyncd(snapshot *Snapshot) {
	snapshot.ManagedPath = PlikTimesyncd
	zarzadzana, err := os.ReadFile(PlikTimesyncd)
	if err != nil {
		return
	}
	snapshot.Managed = string(zarzadzana)
	nasze := map[string]bool{}
	for _, serwer := range ParsujNTPZTimesyncd(snapshot.Managed, filepath.Base(PlikTimesyncd), true) {
		nasze[serwer.Address] = true
	}
	for i := range snapshot.Configured {
		if nasze[snapshot.Configured[i].Address] {
			snapshot.Configured[i].Managed = true
			delete(nasze, snapshot.Configured[i].Address)
		}
	}
	for _, serwer := range ParsujNTPZTimesyncd(snapshot.Managed, filepath.Base(PlikTimesyncd), true) {
		if nasze[serwer.Address] {
			snapshot.Configured = append(snapshot.Configured, serwer)
		}
	}
}

// glownaKonfiguracjaChrony zwraca pierwszy istniejacy plik glowny i jego tresc.
func glownaKonfiguracjaChrony() (string, string) {
	for _, sciezka := range GlowneKonfiguracjeChrony {
		tresc, err := os.ReadFile(sciezka)
		if err == nil {
			return sciezka, string(tresc)
		}
	}
	return "", ""
}

// strefaZPlikow czyta strefe z konfiguracji hosta, gdy nie ma timedatectl.
func strefaZPlikow() string {
	if tresc, err := os.ReadFile("/etc/timezone"); err == nil {
		if strefa := strings.TrimSpace(string(tresc)); strefa != "" {
			return strefa
		}
	}
	cel, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	if _, strefa, ok := strings.Cut(cel, KatalogStref+"/"); ok {
		return strefa
	}
	return ""
}

func istnieje(sciezka string) bool {
	_, err := os.Stat(sciezka)
	return err == nil
}
