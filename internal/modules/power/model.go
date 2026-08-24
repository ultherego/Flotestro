// Package power opisuje stan zasilania, startu i okna serwisowego hosta.
//
// Restart nie konczy sie na wyslaniu polecenia: konczy sie wtedy, gdy host
// wraca z nowym identyfikatorem startu i zdrowymi jednostkami. Dlatego modul
// niesie boot_id, czas dzialania i to, co restart wstrzymuje - a nie sam
// przycisk.
package power

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Sciezki, z ktorych czytamy stan.
const (
	SciezkaUptime = "/proc/uptime"
	SciezkaBootID = "/proc/sys/kernel/random/boot_id"
	// PlikRestartuDebian powstaje, gdy pakiet wymaga restartu; obok niego
	// lezy lista pakietow, ktore o niego poprosily.
	PlikRestartu       = "/var/run/reboot-required"
	PlikRestartuRun    = "/run/reboot-required"
	PlikPakietow       = "/var/run/reboot-required.pkgs"
	PlikPakietowRun    = "/run/reboot-required.pkgs"
	PlikZaplanowanego  = "/run/systemd/shutdown/scheduled"
	SciezkaInhibit     = "/usr/bin/systemd-inhibit"
	SciezkaJournalctl  = "/usr/bin/journalctl"
	SciezkaSystemctl   = "/usr/bin/systemctl"
	LiczbaOstatnichBoo = 5
)

// Tryby wylaczenia, ktore panel rozroznia.
const (
	TrybRestart   = "reboot"
	TrybWylaczyc  = "poweroff"
	TrybZatrzymac = "halt"
)

// Blokada to inhibitor logind: proces, ktory prosi o zwloke albo blokuje
// wylaczenie hosta.
//
// Rozroznienie trybu jest tu istotne: "delay" opoznia wylaczenie o okreslony
// czas, "block" nie pozwala na nie w ogole. Panel, ktory ich nie rozroznia,
// obiecuje operatorowi restart, ktorego nie bedzie.
type Blokada struct {
	Who  string `json:"who"`
	User string `json:"user,omitempty"`
	PID  uint32 `json:"pid,omitempty"`
	What string `json:"what,omitempty"`
	Why  string `json:"why,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// Blokuje mowi, czy blokada nie pozwala na wylaczenie w ogole.
func (b Blokada) Blokuje() bool { return b.Mode == "block" }

// Uruchomienie to jeden wpis z listy startow hosta.
type Uruchomienie struct {
	Index      int       `json:"index"`
	BootID     string    `json:"boot_id"`
	FirstEntry time.Time `json:"first_entry"`
	LastEntry  time.Time `json:"last_entry"`
}

// Wylaczenie opisuje wylaczenie juz zaplanowane na hoscie.
type Wylaczenie struct {
	Mode string    `json:"mode"`
	At   time.Time `json:"at"`
	// Owner mowi, kto je zaplanowal: panel zaklada wlasna jednostke, wiec
	// potrafi odroznic swoje wylaczenie od cudzego.
	Owner string `json:"owner,omitempty"`
}

// Snapshot to obraz startu i zasilania hosta.
type Snapshot struct {
	BootID   string    `json:"boot_id,omitempty"`
	BootedAt time.Time `json:"booted_at,omitempty"`
	// UptimeSeconds jest pusty, gdy /proc/uptime nie dal sie odczytac -
	// host dzialajacy zero sekund nie istnieje.
	UptimeSeconds  *float64 `json:"uptime_seconds"`
	RunningKernel  string   `json:"running_kernel,omitempty"`
	RebootRequired *bool    `json:"reboot_required"`
	// RebootReasons wylicza pakiety albo powody, ktore o restart poprosily.
	RebootReasons     []string       `json:"reboot_reasons,omitempty"`
	Inhibitors        []Blokada      `json:"inhibitors,omitempty"`
	InhibitorsKnown   bool           `json:"inhibitors_known"`
	LastBoots         []Uruchomienie `json:"last_boots,omitempty"`
	Scheduled         *Wylaczenie    `json:"scheduled_shutdown,omitempty"`
	ObservedAt        time.Time      `json:"observed_at"`
	UnavailableReason string         `json:"unavailable_reason,omitempty"`
}

// Blokujace wylicza blokady, ktore nie pozwalaja na wylaczenie.
func (s Snapshot) Blokujace() []Blokada {
	var blokady []Blokada
	for _, blokada := range s.Inhibitors {
		if blokada.Blokuje() {
			blokady = append(blokady, blokada)
		}
	}
	return blokady
}

// LimitOpoznienia ogranicza opoznienie wylaczenia. Zlecenie, ktore ma sie
// wykonac za dobe, nie jest operacja - jest harmonogramem.
const LimitOpoznienia = 3600

// DlugoscPowodu ogranicza uzasadnienie. Powod jest zdaniem dla czlowieka,
// ktory bedzie czytal slad audytowy, a nie miejscem na zalacznik.
const DlugoscPowodu = 500

// WalidujPowodWylaczenia sprawdza uzasadnienie wylaczenia hosta.
//
// Wylaczenie zdalnego hosta wymaga jawnego powodu: nikt go potem nie wlaczy
// zdalnie, wiec slad audytowy jest jedyna rzecza, ktora zostaje.
func WalidujPowodWylaczenia(powod string) error {
	powod = strings.TrimSpace(powod)
	if len(powod) < 10 {
		return fmt.Errorf("wylaczenie hosta wymaga powodu; nikt go potem nie wlaczy zdalnie")
	}
	if len(powod) > DlugoscPowodu {
		return fmt.Errorf("powod jest dluzszy niz %d znakow", DlugoscPowodu)
	}
	if strings.ContainsAny(powod, "\n\r") {
		return fmt.Errorf("powod nie moze zawierac nowej linii")
	}
	return nil
}

// WalidujOpoznienie sprawdza opoznienie operacji.
func WalidujOpoznienie(sekundy uint32) error {
	if sekundy > LimitOpoznienia {
		return fmt.Errorf("opoznienie przekracza godzine")
	}
	return nil
}

// ParsujUptime czyta pierwsza liczbe z /proc/uptime.
func ParsujUptime(tresc string) *float64 {
	pola := strings.Fields(tresc)
	if len(pola) == 0 {
		return nil
	}
	sekundy, err := strconv.ParseFloat(pola[0], 64)
	if err != nil {
		return nil
	}
	return &sekundy
}

// ParsujPowodyRestartu czyta liste pakietow, ktore poprosily o restart.
func ParsujPowodyRestartu(tresc string) []string {
	var powody []string
	widziane := map[string]bool{}
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || widziane[linia] {
			continue
		}
		widziane[linia] = true
		powody = append(powody, linia)
	}
	return powody
}

// ParsujInhibitory czyta tabele "systemd-inhibit --list".
//
// Tabela jest wyrownana do szerokosci najdluzszej wartosci w kolumnie, wiec
// pozycje naglowkow wyznaczaja granice pol. Podzial po bialych znakach nie
// zadzialalby: kolumna z uzasadnieniem zawiera spacje.
func ParsujInhibitory(wyjscie string) ([]Blokada, bool) {
	linie := strings.Split(strings.ReplaceAll(wyjscie, "\r\n", "\n"), "\n")
	naglowek := -1
	for i, linia := range linie {
		if strings.HasPrefix(strings.TrimSpace(linia), "WHO") {
			naglowek = i
			break
		}
	}
	if naglowek < 0 {
		// "No inhibitors." jest odpowiedzia, a nie brakiem odpowiedzi.
		return nil, strings.Contains(wyjscie, "No inhibitors")
	}

	granice := granicePol(linie[naglowek], []string{"WHO", "UID", "USER", "PID", "COMM", "WHAT", "WHY", "MODE"})
	if granice == nil {
		return nil, false
	}

	var blokady []Blokada
	for _, linia := range linie[naglowek+1:] {
		if strings.TrimSpace(linia) == "" || strings.Contains(linia, "inhibitors listed") {
			continue
		}
		pola := tnijPola(linia, granice)
		if len(pola) < 8 || pola[0] == "" {
			continue
		}
		blokada := Blokada{Who: pola[0], User: pola[2], What: pola[5], Why: pola[6], Mode: pola[7]}
		if pid, err := strconv.ParseUint(pola[3], 10, 32); err == nil {
			blokada.PID = uint32(pid)
		}
		blokady = append(blokady, blokada)
	}
	return blokady, true
}

// granicePol wyznacza pozycje kolumn na podstawie wiersza naglowka.
func granicePol(naglowek string, kolumny []string) []int {
	granice := make([]int, 0, len(kolumny))
	szukajOd := 0
	for _, kolumna := range kolumny {
		pozycja := strings.Index(naglowek[szukajOd:], kolumna)
		if pozycja < 0 {
			return nil
		}
		granice = append(granice, szukajOd+pozycja)
		szukajOd += pozycja + len(kolumna)
	}
	return granice
}

func tnijPola(linia string, granice []int) []string {
	pola := make([]string, 0, len(granice))
	for i, poczatek := range granice {
		if poczatek > len(linia) {
			pola = append(pola, "")
			continue
		}
		koniec := len(linia)
		if i+1 < len(granice) && granice[i+1] < koniec {
			koniec = granice[i+1]
		}
		pola = append(pola, strings.TrimSpace(linia[poczatek:koniec]))
	}
	return pola
}

var wierszStartu = regexp.MustCompile(
	`^\s*(-?\d+)\s+([0-9a-f]{32})\s+(\S+ \S+ \S+ \S+)\s+(\S+ \S+ \S+ \S+)\s*$`)

// UkladCzasuDziennika jest postacia, w ktorej journalctl pisze daty.
const UkladCzasuDziennika = "Mon 2006-01-02 15:04:05 MST"

// ParsujListeStartow czyta wyjscie "journalctl --list-boots".
func ParsujListeStartow(wyjscie string) []Uruchomienie {
	var starty []Uruchomienie
	for _, linia := range strings.Split(wyjscie, "\n") {
		dopasowanie := wierszStartu.FindStringSubmatch(linia)
		if dopasowanie == nil {
			continue
		}
		indeks, err := strconv.Atoi(dopasowanie[1])
		if err != nil {
			continue
		}
		start := Uruchomienie{Index: indeks, BootID: dopasowanie[2]}
		if chwila, err := time.Parse(UkladCzasuDziennika, dopasowanie[3]); err == nil {
			start.FirstEntry = chwila.UTC()
		}
		if chwila, err := time.Parse(UkladCzasuDziennika, dopasowanie[4]); err == nil {
			start.LastEntry = chwila.UTC()
		}
		starty = append(starty, start)
	}
	return starty
}

// ParsujZaplanowane czyta /run/systemd/shutdown/scheduled.
//
// Plik mowi, ze host ma sie wylaczyc, choc nikt z panelu o to nie prosil.
// Operator ma to zobaczyc przed zleceniem czegokolwiek innego.
func ParsujZaplanowane(tresc string) *Wylaczenie {
	wylaczenie := Wylaczenie{}
	for _, linia := range strings.Split(tresc, "\n") {
		klucz, wartosc, ok := strings.Cut(strings.TrimSpace(linia), "=")
		if !ok {
			continue
		}
		switch klucz {
		case "USEC":
			mikro, err := strconv.ParseInt(wartosc, 10, 64)
			if err != nil {
				return nil
			}
			wylaczenie.At = time.UnixMicro(mikro).UTC()
		case "MODE":
			wylaczenie.Mode = wartosc
		}
	}
	if wylaczenie.At.IsZero() {
		return nil
	}
	return &wylaczenie
}
