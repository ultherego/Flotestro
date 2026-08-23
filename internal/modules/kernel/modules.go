package kernel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var nazwaModulu = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ParsujModuly czyta /proc/modules.
//
// Czytamy plik jadra, a nie wyjscie lsmod: lsmod jest tylko jego
// formatowaniem, a panel i tak potrzebuje pol, ktorych lsmod nie pokazuje.
func ParsujModuly(tresc string) []Modul {
	var moduly []Modul
	for _, linia := range strings.Split(tresc, "\n") {
		pola := strings.Fields(linia)
		if len(pola) < 4 {
			continue
		}
		modul := Modul{Name: pola[0]}
		if rozmiar, err := strconv.ParseUint(pola[1], 10, 64); err == nil {
			modul.SizeBytes = rozmiar
		}
		// Czwarte pole wylicza moduly zalezne, rozdzielone przecinkami.
		// Myslnik oznacza brak zaleznosci - i nie jest nazwa modulu.
		if pola[3] != "-" {
			for _, zalezny := range strings.Split(strings.TrimSuffix(pola[3], ","), ",") {
				if zalezny != "" {
					modul.UsedBy = append(modul.UsedBy, zalezny)
				}
			}
		}
		moduly = append(moduly, modul)
	}
	return moduly
}

// ParsujBlacklist czyta plik blokad modprobe.
func ParsujBlacklist(tresc string) []string {
	var nazwy []string
	for _, linia := range strings.Split(tresc, "\n") {
		pola := strings.Fields(strings.TrimSpace(linia))
		if len(pola) != 2 || pola[0] != "blacklist" {
			continue
		}
		nazwy = append(nazwy, pola[1])
	}
	return nazwy
}

// SkladajBlacklist sklada tresc pliku blokad.
//
// Blokada w modprobe.d dziala dla modulow ladowanych na zadanie. Modul
// wciagany przez initramfs jest ladowany, zanim ten plik w ogole istnieje
// w systemie plikow - dlatego pelna blokada wymaga odbudowy initramfs, a
// panel mowi to wprost zamiast udawac, ze wpis wystarczy.
func SkladajBlacklist(nazwy []string) (string, error) {
	if len(nazwy) == 0 {
		return NaglowekPliku + "\n", nil
	}
	wiersze := []string{NaglowekPliku}
	for _, nazwa := range nazwy {
		if err := WalidujModul(nazwa); err != nil {
			return "", err
		}
		// Sama blokada nie wystarczy, gdy modul jest zaleznoscia innego:
		// "install ... /bin/false" zatrzymuje takze ladowanie posrednie.
		wiersze = append(wiersze, "blacklist "+nazwa, "install "+nazwa+" /bin/false")
	}
	return strings.Join(wiersze, "\n") + "\n", nil
}

// WalidujModul sprawdza nazwe modulu.
func WalidujModul(nazwa string) error {
	if !nazwaModulu.MatchString(nazwa) {
		return fmt.Errorf("nieprawidlowa nazwa modulu %q", nazwa)
	}
	if powod, chroniony := chronioneModuly[nazwa]; chroniony {
		return fmt.Errorf("panel nie blokuje modulu %s: %s", nazwa, powod)
	}
	return nil
}

// chronioneModuly wylicza moduly, ktorych zablokowanie zatrzymuje host albo
// odcina go od panelu.
var chronioneModuly = map[string]string{
	"ext4":       "bez niego host nie zamontuje wlasnego korzenia",
	"xfs":        "bez niego host nie zamontuje wlasnego korzenia",
	"dm_mod":     "bez niego nie wstana wolumeny LVM, w tym korzen",
	"dm-mod":     "bez niego nie wstana wolumeny LVM, w tym korzen",
	"virtio_net": "bez niego maszyna wirtualna traci siec",
	"virtio_blk": "bez niego maszyna wirtualna traci dysk",
	"e1000":      "bez niego host moze stracic jedyna karte sieciowa",
	"nf_tables":  "bez niego przestaje dzialac zapora hosta",
}

// InitramfsWymagany mowi, czy blokada wymaga odbudowy initramfs.
//
// Zwracamy powod, a nie flage: operator ma przeczytac, dlaczego sam wpis
// w modprobe.d nie wystarczy.
func InitramfsWymagany(nazwa string, wZaladowanych bool) string {
	if !wZaladowanych {
		return ""
	}
	return "modul " + nazwa + " jest zaladowany; blokada zadziala dopiero po restarcie, " +
		"a dla modulow wciaganych przez initramfs takze po jego odbudowie"
}
