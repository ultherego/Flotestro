// Package logs czyta logi hosta: dziennik systemowy i pliki z allowlisty.
//
// Odczyt pliku nie jest operacja ogolna "przeczytaj sciezke". Panel, ktory
// potrafi przeczytac dowolny plik roota, potrafi przeczytac klucze prywatne
// i /etc/shadow - dlatego zakres jest wyliczony przez administratora hosta,
// a nie podany w zadaniu.
package logs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// SciezkaAllowlisty wskazuje plik z dozwolonymi wzorcami. Jeden wzorzec na
// linie; linie puste i zaczynajace sie od # sa pomijane.
const SciezkaAllowlisty = "/etc/flotestro/logfiles.allow"

// domyslneWzorce obowiazuja, gdy administrator nie wskazal wlasnych.
//
// Lista jest celowo waska: obejmuje miejsca, w ktorych dystrybucje trzymaja
// logi, i nic poza nimi. Rozszerzenie jej jest decyzja administratora hosta
// i wymaga zapisu w /etc, a nie zmiany w panelu.
var domyslneWzorce = []string{
	"/var/log/*.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/kern.log",
	"/var/log/dpkg.log",
	"/var/log/apt/*.log",
	"/var/log/nginx/*.log",
	"/var/log/apache2/*.log",
	"/var/log/httpd/*.log",
}

var (
	// ErrPozaAllowlista oznacza sciezke spoza dozwolonego zakresu.
	ErrPozaAllowlista = errors.New("sciezka poza allowlista")
	// ErrDowiazanie oznacza sciezke prowadzaca przez dowiazanie.
	ErrDowiazanie = errors.New("sciezka prowadzi przez dowiazanie symboliczne")
)

// Allowlist opisuje dozwolony zakres odczytu.
type Allowlist struct {
	Wzorce []string
	// Zrodlo mowi, skad zakres pochodzi: plik administratora albo domyslna
	// lista wbudowana. Operator ma wiedziec, czym jest ograniczony.
	Zrodlo string
}

// WczytajAllowliste czyta zakres z pliku albo zwraca domyslny.
func WczytajAllowliste(sciezka string) Allowlist {
	plik, err := os.Open(sciezka)
	if err != nil {
		return Allowlist{Wzorce: domyslneWzorce, Zrodlo: "wbudowana lista domyslna"}
	}
	defer plik.Close()

	var wzorce []string
	skaner := bufio.NewScanner(plik)
	for skaner.Scan() {
		linia := strings.TrimSpace(skaner.Text())
		if linia == "" || strings.HasPrefix(linia, "#") {
			continue
		}
		// Wzorzec wzgledny nie da sie ocenic, wiec jest pomijany zamiast
		// dopasowywany do czegokolwiek.
		if !strings.HasPrefix(linia, "/") {
			continue
		}
		wzorce = append(wzorce, linia)
	}
	if len(wzorce) == 0 {
		return Allowlist{Wzorce: domyslneWzorce, Zrodlo: "wbudowana lista domyslna"}
	}
	sort.Strings(wzorce)
	return Allowlist{Wzorce: wzorce, Zrodlo: sciezka}
}

// Dozwolona sprawdza, czy sciezka miesci sie w zakresie.
//
// Sciezka jest najpierw czyszczona: ".." w srodku pozwalaloby wyjsc poza
// katalog, ktory wzorzec opisuje, mimo ze tekst dopasowuje sie do wzorca.
func (a Allowlist) Dozwolona(sciezka string) bool {
	if !strings.HasPrefix(sciezka, "/") {
		return false
	}
	czysta := filepath.Clean(sciezka)
	if czysta != sciezka {
		return false
	}
	for _, wzorzec := range a.Wzorce {
		if pasuje, err := filepath.Match(wzorzec, czysta); err == nil && pasuje {
			return true
		}
	}
	return false
}

// Fragment to odczytany kawalek pliku.
type Fragment struct {
	Path string `json:"path"`
	// Lines to koncowka pliku. Poczatek jest pomijany, bo przyczyna awarii
	// jest zwykle przy koncu logu.
	Lines []string `json:"lines"`
	// Truncated mowi, ze plik jest dluzszy niz zwrocony fragment.
	Truncated bool  `json:"truncated"`
	SizeBytes int64 `json:"size_bytes"`
	// Allowlist mowi, czym odczyt jest ograniczony.
	Allowlist string `json:"allowlist,omitempty"`
}

// maksymalnieLinii ogranicza jeden odczyt.
const maksymalnieLinii = 2000

// maksymalnieBajtow ogranicza rozmiar odczytanego ogona.
const maksymalnieBajtow = 1 << 20

// Czytaj zwraca koncowke pliku z allowlisty.
func Czytaj(allowlist Allowlist, sciezka string, linii uint32) (Fragment, error) {
	if !allowlist.Dozwolona(sciezka) {
		return Fragment{}, fmt.Errorf("%w: %s", ErrPozaAllowlista, sciezka)
	}
	if linii == 0 || linii > maksymalnieLinii {
		linii = 200
	}

	plik, err := otworzBezDowiazan(sciezka)
	if err != nil {
		return Fragment{}, err
	}
	defer plik.Close()

	info, err := plik.Stat()
	if err != nil {
		return Fragment{}, err
	}
	// Katalog i urzadzenie nie sa logiem; odczyt z gniazda albo potoku
	// zawisnalby na zawsze.
	if !info.Mode().IsRegular() {
		return Fragment{}, fmt.Errorf("%s nie jest zwyklym plikiem", sciezka)
	}

	fragment := Fragment{Path: sciezka, SizeBytes: info.Size(), Allowlist: allowlist.Zrodlo}
	poczatek := int64(0)
	if info.Size() > maksymalnieBajtow {
		poczatek = info.Size() - maksymalnieBajtow
		fragment.Truncated = true
	}
	if _, err := plik.Seek(poczatek, 0); err != nil {
		return fragment, err
	}

	skaner := bufio.NewScanner(plik)
	skaner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var linie []string
	for skaner.Scan() {
		linie = append(linie, skaner.Text())
		if len(linie) > int(linii) {
			linie = linie[1:]
			fragment.Truncated = true
		}
	}
	fragment.Lines = linie
	return fragment, skaner.Err()
}

// otworzBezDowiazan otwiera plik, odmawiajac podazania za dowiazaniami na
// kazdym poziomie sciezki.
//
// Dowiazanie w katalogu logow pozwoliloby przeczytac dowolny plik roota mimo
// poprawnej allowlisty: wzorzec opisuje sciezke, a nie to, gdzie ona
// naprawde prowadzi.
func otworzBezDowiazan(sciezka string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, sciezka, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
			return nil, fmt.Errorf("%w: %s", ErrDowiazanie, sciezka)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), sciezka), nil
}
