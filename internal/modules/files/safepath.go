package files

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// SciezkaAllowlisty wskazuje plik z zakresem wyznaczonym przez administratora
// hosta. Jeden wzorzec na linie; linie puste i zaczynajace sie od # sa
// pomijane.
const SciezkaAllowlisty = "/etc/flotestro/files.allow"

// domyslneWzorce obowiazuja, gdy administrator nie wskazal wlasnych.
//
// Lista jest waska i celowo omija katalogi, w ktorych trzymane sa sekrety.
// Rozszerzenie jej jest decyzja administratora hosta i wymaga zapisu w /etc,
// a nie zmiany w panelu.
var domyslneWzorce = []string{
	"/etc/*.conf",
	"/etc/sysctl.d/*.conf",
	"/etc/security/limits.d/*.conf",
	"/etc/logrotate.d/*",
	"/etc/systemd/system/*.conf",
	"/etc/systemd/system/*.d/*.conf",
	"/etc/nginx/conf.d/*.conf",
	"/etc/nginx/sites-available/*",
	"/etc/chrony/*.conf",
	"/etc/chrony.d/*.conf",
	"/etc/motd",
	"/etc/issue",
	"/etc/hosts",
	"/etc/resolv.conf.flotestro",
	"/opt/flotestro/etc/*",
}

// zakazaneWzorce wylicza sciezki, ktorych panel nie tyka nigdy - takze wtedy,
// gdy administrator hosta dopisze je do allowlisty.
//
// To nie jest ostroznosc na wszelki wypadek: plik z hashami hasel, klucz
// prywatny albo regula sudo wpuszczaja do systemu kazdego, kto potrafi je
// podmienic. Zmiana kazdej z tych rzeczy ma wlasny modul z wlasnymi
// zabezpieczeniami, a nie edytor tekstu.
var zakazaneWzorce = []string{
	"/etc/shadow*",
	"/etc/gshadow*",
	"/etc/passwd",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/ssh/*_key",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/pam.d/*",
	"/etc/krb5.keytab",
	"*.key",
	"*.pem",
	"/root/*",
	"/home/*",
	"/proc/*",
	"/sys/*",
	"/dev/*",
}

var (
	// ErrPozaAllowlista oznacza sciezke spoza dozwolonego zakresu.
	ErrPozaAllowlista = errors.New("sciezka poza allowlista")
	// ErrZakazana oznacza sciezke, ktorej panel nie tyka nigdy.
	ErrZakazana = errors.New("sciezka nalezy do innego modulu i nie jest edytowalna")
	// ErrDowiazanie oznacza sciezke prowadzaca przez dowiazanie.
	ErrDowiazanie = errors.New("sciezka prowadzi przez dowiazanie symboliczne")
)

// Allowlist opisuje dozwolony zakres zapisu.
type Allowlist struct {
	Wzorce []string
	// Zrodlo mowi, skad zakres pochodzi. Operator ma wiedziec, czym jest
	// ograniczony, zanim zapyta, dlaczego czegos nie moze zmienic.
	Zrodlo string
}

// WczytajAllowliste czyta zakres z pliku albo zwraca domyslny.
func WczytajAllowliste(sciezka string) Allowlist {
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return Allowlist{Wzorce: domyslneWzorce, Zrodlo: "wbudowana lista domyslna"}
	}
	var wzorce []string
	for _, linia := range strings.Split(string(dane), "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") {
			continue
		}
		wzorce = append(wzorce, linia)
	}
	if len(wzorce) == 0 {
		return Allowlist{Wzorce: domyslneWzorce, Zrodlo: "wbudowana lista domyslna"}
	}
	return Allowlist{Wzorce: wzorce, Zrodlo: sciezka}
}

// Zakazana mowi, czy sciezka nalezy do innego modulu i nie jest edytowalna.
//
// Sprawdzenie jest osobne od allowlisty, bo obowiazuje takze panel: zadanie
// z taka sciezka nie ma powstac, nawet jesli host odmowilby i tak.
func Zakazana(sciezka string) error {
	for _, wzorzec := range zakazaneWzorce {
		if pasuje(wzorzec, sciezka) {
			return fmt.Errorf("%w: %s", ErrZakazana, sciezka)
		}
	}
	return nil
}

// Dopuszcza sprawdza, czy sciezka miesci sie w zakresie.
func (a Allowlist) Dopuszcza(sciezka string) error {
	if !strings.HasPrefix(sciezka, "/") {
		return fmt.Errorf("%w: sciezka musi byc bezwzgledna", ErrPozaAllowlista)
	}
	if sciezka != filepath.Clean(sciezka) {
		return fmt.Errorf("%w: sciezka nie jest znormalizowana", ErrPozaAllowlista)
	}
	// Zakaz jest sprawdzany pierwszy i nie da sie go obejsc wpisem
	// w allowliscie: plik z hashami hasel albo klucz prywatny ma wlasny
	// modul, a nie edytor tekstu.
	if err := Zakazana(sciezka); err != nil {
		return err
	}
	for _, wzorzec := range a.Wzorce {
		if pasuje(wzorzec, sciezka) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s (zakres: %s)", ErrPozaAllowlista, sciezka, a.Zrodlo)
}

// pasuje porownuje sciezke ze wzorcem.
//
// Wzorzec bez ukosnika na koncu dopasowuje takze pliki w podkatalogach, gdy
// konczy sie gwiazdka obejmujaca caly ogon - inaczej "/root/*" nie objelby
// "/root/.ssh/id_rsa", a to jest dokladnie ten przypadek, ktory ma objac.
func pasuje(wzorzec, sciezka string) bool {
	if ok, _ := filepath.Match(wzorzec, sciezka); ok {
		return true
	}
	if strings.HasSuffix(wzorzec, "/*") {
		prefiks := strings.TrimSuffix(wzorzec, "*")
		return strings.HasPrefix(sciezka, prefiks)
	}
	return false
}

// OtworzBezDowiazan otwiera plik, odmawiajac przejscia przez dowiazanie.
//
// Dowiazanie w katalogu konfiguracji pozwoliloby nadpisac dowolny plik roota
// mimo poprawnej allowlisty: wzorzec opisuje sciezke, a nie to, gdzie ona
// naprawde prowadzi.
func OtworzBezDowiazan(sciezka string, flagi int, tryb uint32) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, sciezka, &unix.OpenHow{
		Flags:   uint64(flagi) | unix.O_CLOEXEC,
		Mode:    uint64(tryb),
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
