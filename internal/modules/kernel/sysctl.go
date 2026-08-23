// Package kernel opisuje ustawienia jadra i moduly hosta.
//
// Modul nie enumeruje calego /proc/sys: jest tam kilka tysiecy kluczy,
// z ktorych panel nie potrafi powiedziec nic sensownego, a ich odczyt przy
// kazdym cyklu byl by kosztem bez odpowiedzi. Panel pokazuje profil - zbior
// kluczy, o ktore ktos naprawde pyta - i pozwala doczytac reszte na zadanie.
package kernel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Sciezki narzedzi.
const (
	SciezkaSysctl   = "/usr/sbin/sysctl"
	SciezkaModprobe = "/usr/sbin/modprobe"
	SciezkaLsmod    = "/usr/sbin/lsmod"
	// KatalogSysctl trzyma ustawienia trwale panelu. Wlasny plik, a nie
	// wspolny: zmiana panelu nie moze przepisac tego, co ustawil ktos inny.
	KatalogSysctl   = "/etc/sysctl.d"
	PlikSysctl      = KatalogSysctl + "/90-flotestro.conf"
	KatalogModprobe = "/etc/modprobe.d"
	PlikBlacklisty  = KatalogModprobe + "/90-flotestro-blacklist.conf"
	NaglowekPliku   = "# Zarzadzane przez Flotestro. Recznych zmian nie zachowa kolejna operacja."
)

// ProfilDomyslny wylicza klucze, ktore panel pokazuje bez pytania.
//
// To nie jest lista wszystkiego, co wolno zmieniac - to lista tego, o co
// operator pyta najczesciej: pamiec, siec i limity procesow. Reszta jest
// dostepna na zadanie, o ile miesci sie w dozwolonych przestrzeniach nazw.
var ProfilDomyslny = []string{
	"vm.swappiness",
	"vm.dirty_ratio",
	"vm.max_map_count",
	"vm.overcommit_memory",
	"net.ipv4.ip_forward",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv6.conf.all.disable_ipv6",
	"net.core.somaxconn",
	"kernel.pid_max",
	"kernel.panic",
	"fs.file-max",
	"fs.inotify.max_user_watches",
}

// dozwolonePrzestrzenie wylicza galezie /proc/sys, ktore panel zmienia.
//
// Zakaz dowolnego zapisu jest tu istotny: /proc/sys zawiera takze przelaczniki,
// ktore wylaczaja ochrony jadra albo zatrzymuja host. Panel zmienia to, co
// da sie opisac i cofnac, a reszte zostawia administratorowi hosta.
var dozwolonePrzestrzenie = []string{"vm.", "net.", "fs.", "kernel.", "user."}

// zabronioneKlucze wylicza ustawienia, ktorych panel nie tyka mimo
// przynaleznosci do dozwolonej przestrzeni.
var zabronioneKlucze = map[string]string{
	"kernel.sysrq":                     "sysrq daje konsoli prawo restartu i zabijania procesow",
	"kernel.core_pattern":              "core_pattern uruchamia dowolny program przy kazdym zrzucie pamieci",
	"kernel.modprobe":                  "modprobe wskazuje program uruchamiany przez jadro",
	"kernel.poweroff_cmd":              "poweroff_cmd wskazuje program uruchamiany przy wylaczaniu",
	"kernel.panic_on_oops":             "zmiana zachowania przy panice jadra nalezy do decyzji o platformie",
	"kernel.unprivileged_userns_clone": "wylaczenie przestrzeni nazw psuje kontenery bez ostrzezenia",
	"kernel.kptr_restrict":             "kptr_restrict jest ochrona przed wyciekiem adresow jadra",
	"kernel.dmesg_restrict":            "dmesg_restrict jest ochrona przed wyciekiem stanu jadra",
}

var nazwaKlucza = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_*-]+){1,8}$`)

// Ustawienie to jedna wartosc sysctl.
type Ustawienie struct {
	Key string `json:"key"`
	// Current jest wartoscia obowiazujaca teraz, Desired - zapisana przez
	// panel. Rozne wartosci oznaczaja ustawienie, ktore czeka na restart
	// albo zostalo zmienione poza panelem.
	Current string `json:"current,omitempty"`
	Desired string `json:"desired,omitempty"`
	// Source mowi, ktory plik ustawia wartosc trwale. Pusty oznacza wartosc
	// domyslna jadra, a nie brak wartosci.
	Source string `json:"source,omitempty"`
	// Managed oznacza klucz zapisany przez panel.
	Managed bool `json:"managed"`
}

// Modul opisuje modul jadra.
type Modul struct {
	Name string `json:"name"`
	// SizeBytes i UsedBy pochodza z /proc/modules.
	SizeBytes uint64   `json:"size_bytes"`
	UsedBy    []string `json:"used_by,omitempty"`
	// Blacklisted oznacza modul zablokowany przez panel.
	Blacklisted bool `json:"blacklisted"`
}

// Snapshot to obraz ustawien jadra hosta.
type Snapshot struct {
	Release string `json:"release,omitempty"`
	// CommandLine jest linia polecen jadra: czesc ustawien da sie zmienic
	// wylacznie tam i dopiero po restarcie.
	CommandLine string       `json:"command_line,omitempty"`
	Settings    []Ustawienie `json:"settings,omitempty"`
	Modules     []Modul      `json:"modules,omitempty"`
	Blacklist   []string     `json:"blacklist,omitempty"`
	// Managed jest trescia pliku panelu.
	Managed           string    `json:"managed_config,omitempty"`
	ManagedPath       string    `json:"managed_path,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
}

// WalidujKlucz sprawdza, czy panel moze ustawic dany klucz.
func WalidujKlucz(klucz string) error {
	if !nazwaKlucza.MatchString(klucz) {
		return fmt.Errorf("nieprawidlowa nazwa ustawienia %q", klucz)
	}
	if powod, zabroniony := zabronioneKlucze[klucz]; zabroniony {
		return fmt.Errorf("panel nie zmienia %s: %s", klucz, powod)
	}
	for _, przestrzen := range dozwolonePrzestrzenie {
		if strings.HasPrefix(klucz, przestrzen) {
			return nil
		}
	}
	return fmt.Errorf("panel zmienia ustawienia w galeziach %s; %q jest poza nimi",
		strings.Join(dozwolonePrzestrzenie, " "), klucz)
}

// WalidujWartosc sprawdza wartosc ustawienia.
//
// Wartosci sysctl sa liczbami albo krotkimi listami liczb; wszystko inne
// wskazuje na proba wpisania czegos, czego jadro nie przyjmie - albo na
// probe przemycenia nowej linii do pliku konfiguracyjnego.
func WalidujWartosc(wartosc string) error {
	if wartosc == "" {
		return fmt.Errorf("ustawienie wymaga wartosci")
	}
	if len(wartosc) > 128 {
		return fmt.Errorf("wartosc jest dluzsza niz 128 znakow")
	}
	for _, znak := range wartosc {
		czyDozwolony := (znak >= '0' && znak <= '9') || znak == ' ' || znak == '\t' ||
			znak == '-' || znak == '.' || znak == ':' || znak == '/' ||
			(znak >= 'a' && znak <= 'z')
		if !czyDozwolony {
			return fmt.Errorf("wartosc %q zawiera niedozwolony znak", wartosc)
		}
	}
	return nil
}

// SkladajPlikSysctl sklada tresc pliku trwalych ustawien.
func SkladajPlikSysctl(ustawienia map[string]string) (string, error) {
	if len(ustawienia) == 0 {
		return "", fmt.Errorf("zmiana nie zawiera zadnego ustawienia")
	}
	klucze := make([]string, 0, len(ustawienia))
	for klucz := range ustawienia {
		if err := WalidujKlucz(klucz); err != nil {
			return "", err
		}
		if err := WalidujWartosc(ustawienia[klucz]); err != nil {
			return "", fmt.Errorf("%s: %w", klucz, err)
		}
		klucze = append(klucze, klucz)
	}
	sort.Strings(klucze)

	wiersze := []string{NaglowekPliku}
	for _, klucz := range klucze {
		wiersze = append(wiersze, klucz+" = "+ustawienia[klucz])
	}
	return strings.Join(wiersze, "\n") + "\n", nil
}

// ParsujPlikSysctl czyta plik ustawien.
func ParsujPlikSysctl(tresc string) map[string]string {
	wynik := map[string]string{}
	for _, linia := range strings.Split(tresc, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || strings.HasPrefix(linia, "#") || strings.HasPrefix(linia, ";") {
			continue
		}
		klucz, wartosc, ok := strings.Cut(linia, "=")
		if !ok {
			continue
		}
		wynik[strings.TrimSpace(klucz)] = strings.TrimSpace(wartosc)
	}
	return wynik
}

// ParsujWartosci czyta wyjscie "sysctl -n" dla wielu kluczy naraz.
func ParsujWartosci(wyjscie string) map[string]string {
	wynik := map[string]string{}
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" {
			continue
		}
		klucz, wartosc, ok := strings.Cut(linia, "=")
		if !ok {
			continue
		}
		// Jadro rozdziela wartosci tabulatorami; normalizujemy je do spacji,
		// zeby porownanie z zapisana wartoscia nie zalezalo od bialych znakow.
		wynik[strings.TrimSpace(klucz)] = strings.Join(strings.Fields(wartosc), " ")
	}
	return wynik
}
