package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SciezkaFstab wskazuje plik montowan hosta.
const SciezkaFstab = "/etc/fstab"

var (
	// zrodloMontowania dopuszcza to, co da sie sprawdzic i co nie zalezy od
	// kolejnosci wykrywania dyskow: identyfikatory trwale i sciezki w /dev.
	// Nazwa sieciowa jest tu osobna forma, bo nie jest sciezka.
	identyfikatorTrwaly = regexp.MustCompile(`^(UUID|PARTUUID|LABEL|PARTLABEL)=[A-Za-z0-9._:-]{1,64}$`)
	sciezkaUrzadzenia   = regexp.MustCompile(`^/dev/[A-Za-z0-9/._-]{1,120}$`)
	opcjeMontowania     = regexp.MustCompile(`^[A-Za-z0-9=,._:/@%+-]{0,256}$`)
	typFilesystemu      = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

// WalidujZrodlo sprawdza zrodlo montowania.
//
// Panel woli identyfikator trwaly od /dev/sdX: nazwa urzadzenia zalezy od
// kolejnosci wykrywania i po restarcie potrafi wskazac inny dysk. Sciezke
// w /dev dopuszczamy, bo wolumeny LVM i macierze maja stabilne nazwy w
// /dev/mapper i /dev/md.
func WalidujZrodlo(zrodlo string) error {
	if identyfikatorTrwaly.MatchString(zrodlo) || sciezkaUrzadzenia.MatchString(zrodlo) {
		return nil
	}
	return fmt.Errorf("zrodlo %q ma byc identyfikatorem trwalym (UUID=, LABEL=) albo sciezka w /dev", zrodlo)
}

// WalidujCel sprawdza punkt montowania.
func WalidujCel(cel string) error {
	if !strings.HasPrefix(cel, "/") {
		return fmt.Errorf("punkt montowania %q nie jest sciezka bezwzgledna", cel)
	}
	if cel != filepath.Clean(cel) || strings.Contains(cel, "..") {
		return fmt.Errorf("punkt montowania %q nie jest sciezka znormalizowana", cel)
	}
	// Katalogi, ktorych przeslonienie odcina host od samego siebie.
	// Montowanie czegokolwiek na nich jest osobna decyzja, a nie operacja
	// z kreatora.
	for _, chroniony := range []string{"/", "/boot", "/dev", "/etc", "/proc", "/run",
		"/sys", "/usr", "/var", "/var/lib", "/var/log", "/bin", "/sbin", "/lib"} {
		if cel == chroniony {
			return fmt.Errorf("panel nie montuje niczego na %s", chroniony)
		}
	}
	if strings.ContainsAny(cel, "\n\t") {
		return fmt.Errorf("punkt montowania zawiera znak nowej linii")
	}
	return nil
}

// WalidujOpcje sprawdza opcje montowania.
func WalidujOpcje(opcje, typ string) error {
	if !typFilesystemu.MatchString(typ) {
		return fmt.Errorf("nieprawidlowy typ filesystemu %q", typ)
	}
	if !opcjeMontowania.MatchString(opcje) {
		return fmt.Errorf("opcje montowania zawieraja niedozwolony znak")
	}
	return nil
}

// WierszFstab sklada wpis dla /etc/fstab.
//
// Znaki specjalne zapisujemy osemkowo, tak jak robi to sam fstab: sciezka
// ze spacja zapisana wprost rozpadlaby sie na dwa pola i wpis wskazywalby
// zupelnie inne miejsce.
func WierszFstab(zrodlo, cel, typ, opcje string) string {
	if opcje == "" {
		opcje = "defaults"
	}
	return fmt.Sprintf("%s %s %s %s 0 0", zakoduj(zrodlo), zakoduj(cel), typ, opcje)
}

func zakoduj(sciezka string) string {
	var wynik strings.Builder
	for _, znak := range sciezka {
		switch znak {
		case ' ', '\t', '\\':
			fmt.Fprintf(&wynik, `\%03o`, znak)
		default:
			wynik.WriteRune(znak)
		}
	}
	return wynik.String()
}

// ZapiszWpisFstab dodaje albo zastepuje wpis panelu.
//
// Zapis jest atomowy: plik powstaje obok i dopiero gotowy zastepuje
// poprzedni. fstab czytany w polowie przez systemd przy restarcie oznaczalby
// host, ktory nie wstaje.
func ZapiszWpisFstab(sciezka, zrodlo, cel, typ, opcje string) error {
	tresc, err := os.ReadFile(sciezka)
	if err != nil {
		return err
	}
	linie := strings.Split(string(tresc), "\n")
	wynik := make([]string, 0, len(linie)+2)

	pomijaj := false
	for _, linia := range linie {
		przyciety := strings.TrimSpace(linia)
		if pomijaj {
			pomijaj = false
			// Wiersz po znaczniku panelu nalezy do panelu: zastepujemy go.
			if przyciety != "" && !strings.HasPrefix(przyciety, "#") {
				continue
			}
		}
		if strings.HasPrefix(przyciety, ZnacznikPanelu) {
			// Znacznik wlasnego wpisu o tym samym celu usuwamy razem z nim.
			if strings.Contains(przyciety, cel) {
				pomijaj = true
				continue
			}
		}
		wynik = append(wynik, linia)
	}

	// Usuwamy puste wiersze z konca, zeby plik nie rosl przy kazdej zmianie.
	for len(wynik) > 0 && strings.TrimSpace(wynik[len(wynik)-1]) == "" {
		wynik = wynik[:len(wynik)-1]
	}
	wynik = append(wynik, ZnacznikPanelu+": "+cel, WierszFstab(zrodlo, cel, typ, opcje), "")

	return zapiszAtomowo(sciezka, strings.Join(wynik, "\n"))
}

// UsunWpisFstab kasuje wpis panelu o podanym celu.
func UsunWpisFstab(sciezka, cel string) error {
	tresc, err := os.ReadFile(sciezka)
	if err != nil {
		return err
	}
	linie := strings.Split(string(tresc), "\n")
	wynik := make([]string, 0, len(linie))
	pomijaj := false
	for _, linia := range linie {
		przyciety := strings.TrimSpace(linia)
		if pomijaj {
			pomijaj = false
			if przyciety != "" && !strings.HasPrefix(przyciety, "#") {
				continue
			}
		}
		if strings.HasPrefix(przyciety, ZnacznikPanelu) && strings.Contains(przyciety, cel) {
			pomijaj = true
			continue
		}
		wynik = append(wynik, linia)
	}
	return zapiszAtomowo(sciezka, strings.Join(wynik, "\n"))
}

func zapiszAtomowo(sciezka, tresc string) error {
	tymczasowy := sciezka + ".flotestro-nowy"
	if err := os.WriteFile(tymczasowy, []byte(tresc), 0o644); err != nil {
		return err
	}
	// fsync pliku i katalogu: bez tego zmiana moze nie przetrwac zaniku
	// zasilania, a fstab jest plikiem, ktory czyta sie wlasnie po takim
	// zdarzeniu.
	plik, err := os.Open(tymczasowy)
	if err == nil {
		_ = plik.Sync()
		_ = plik.Close()
	}
	if err := os.Rename(tymczasowy, sciezka); err != nil {
		return err
	}
	katalog, err := os.Open(filepath.Dir(sciezka))
	if err != nil {
		return nil
	}
	defer katalog.Close()
	return katalog.Sync()
}
