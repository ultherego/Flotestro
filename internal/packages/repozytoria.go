package packages

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Repozytorium jest zrodlem pakietow, ktore host uzna za swoje.
//
// To jest operacja o najwiekszym zasiegu w calym module pakietow: dopisanie
// zrodla nie instaluje niczego dzisiaj, ale rozstrzyga, czyje pakiety host
// przyjmie jutro - razem z ich skryptami instalacyjnymi, ktore chodza jako
// root. Dlatego zrodlo bez podpisu wymaga jawnej zgody, a haslo do zrodla
// prywatnego nie jedzie w zleceniu.
type Repozytorium struct {
	// ID jest nazwa pliku i nazwa sekcji. Panel nie pozwala na nazwe, ktora
	// wyszlaby poza katalog zrodel.
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
	// Suites i Components opisuja zrodlo w formacie Debiana. DNF ich nie ma:
	// tam caly adres jest w URL.
	Suites        []string `json:"suites,omitempty"`
	Components    []string `json:"components,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	Enabled       bool     `json:"enabled"`
	// Priority rozstrzyga, ktore zrodlo wygrywa przy tej samej wersji pakietu.
	Priority int `json:"priority,omitempty"`
	// GPGKeyFingerprint jest odciskiem klucza, ktorym zrodlo podpisuje
	// metadane. Odcisk pokazujemy czlowiekowi, bo tylko on moze porownac go
	// z odciskiem podanym przez dostawce.
	GPGKeyFingerprint string `json:"gpg_key_fingerprint,omitempty"`
	// Signed mowi, czy host w ogole sprawdza podpisy tego zrodla.
	Signed bool `json:"signed"`
	// Username jest nazwa uzytkownika zrodla prywatnego; haslo nigdy tu nie
	// trafia - jest w magazynie sekretow i tylko tam.
	Username string `json:"username,omitempty"`
	// SecretName mowi, z ktorego sekretu pochodzi haslo. Nazwa, nie wartosc.
	SecretName string `json:"secret_name,omitempty"`
	// Managed oznacza zrodlo zapisane przez panel. Zrodla dystrybucji
	// pokazujemy, ale ich nie przepisujemy.
	Managed bool   `json:"managed"`
	Path    string `json:"path,omitempty"`
	// UnavailableReason opisuje plik, ktorego nie udalo sie odczytac.
	// Zrodlo z haslem ma prawa 0600 i agent bez roota go nie przeczyta -
	// a to inna odpowiedz niz "takiego zrodla nie ma".
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// ObrazRepozytoriow jest stanem zrodel pakietow na hoscie.
type ObrazRepozytoriow struct {
	Repositories []Repozytorium `json:"repositories,omitempty"`
	// Known mowi, czy liste w ogole udalo sie odczytac. Pusta lista i lista
	// nieodczytana to dwie rozne odpowiedzi.
	Known             bool      `json:"repositories_known"`
	Manager           string    `json:"manager,omitempty"`
	ObservedAt        time.Time `json:"repositories_observed_at,omitempty"`
	UnavailableReason string    `json:"repositories_unavailable_reason,omitempty"`
}

// Katalogi zrodel i kluczy.
const (
	KatalogZrodelAPT    = "/etc/apt/sources.list.d"
	PlikZrodelAPT       = "/etc/apt/sources.list"
	KatalogKluczyAPT    = "/etc/apt/keyrings"
	KatalogHaselAPT     = "/etc/apt/auth.conf.d"
	KatalogZrodelDNF    = "/etc/yum.repos.d"
	KatalogKluczyDNF    = "/etc/pki/rpm-gpg"
	prefiksPlikuFlotest = "flotestro-"
)

// znacznikPanelu stoi w pierwszej linii kazdego pliku pisanego przez panel.
// Po nim host rozpoznaje zrodlo zarzadzane - takze wtedy, gdy panel o nie
// akurat nie pyta.
const znacznikPanelu = "# flotestro: zrodlo zarzadzane przez panel"

// znacznikSekretu zapisuje nazwe sekretu z haslem. Nazwa, nie wartosc:
// dzieki temu panel widzi powiazanie, a plik nie zdradza niczego wiecej.
const znacznikSekretu = "# flotestro-secret: "

// znacznikUzytkownika zapisuje nazwe uzytkownika zrodla prywatnego. W APT
// nazwa lezy razem z haslem w pliku dla roota, wiec bez tego komentarza panel
// widzialby zrodlo z haslem, ale nie wiedzialby, kim sie przedstawia. Nazwa
// uzytkownika nie jest sekretem - jest w zleceniu i w audycie.
const znacznikUzytkownika = "# flotestro-user: "

// nazwaRepozytorium ogranicza identyfikator do tego, co moze byc nazwa pliku.
var nazwaRepozytorium = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

// Plik opisuje jeden plik do zapisania na hoscie.
type Plik struct {
	Path string
	// Tresc pliku z haslem nie trafia do wyniku ani do dziennika.
	Content []byte
	Mode    os.FileMode
	// Wrazliwy oznacza plik, ktorego tresci nie wolno pokazac nigdzie poza
	// nim samym.
	Wrazliwy bool
}

// WalidujRepozytorium sprawdza zrodlo przed zapisem.
//
// Sprawdzenie jest wspolne dla panelu i hosta: zlecenie, ktorego host i tak by
// nie przyjal, odpada juz przy zlecaniu, z tym samym powodem.
func WalidujRepozytorium(repo Repozytorium, menedzer string, zSekretem bool) error {
	if !nazwaRepozytorium.MatchString(repo.ID) {
		return fmt.Errorf("nieprawidlowy identyfikator zrodla %q", repo.ID)
	}
	if repo.Absent() {
		return nil
	}
	adres, err := url.Parse(repo.URL)
	if err != nil || adres.Host == "" {
		return fmt.Errorf("adres zrodla %q nie jest poprawnym URL", repo.URL)
	}
	switch adres.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("zrodlo moze byc pobierane wylacznie po http albo https")
	}
	if strings.ContainsAny(repo.URL, " \t\n\"'") {
		return fmt.Errorf("adres zrodla zawiera niedozwolony znak")
	}
	// Zrodlo bez sprawdzania podpisow oznacza, ze host zainstaluje wszystko,
	// co przyjdzie z tego adresu - razem ze skryptami pakietow, ktore chodza
	// jako root. Bez TLS oznacza dodatkowo, ze wystarczy byc po drodze.
	if !repo.Signed && adres.Scheme != "https" {
		return fmt.Errorf("zrodlo bez sprawdzania podpisow musi byc przynajmniej po https")
	}
	// Haslo wedrujace po zwyklym http odczyta kazdy, kto jest po drodze.
	if zSekretem && adres.Scheme != "https" {
		return fmt.Errorf("zrodlo z haslem musi byc pobierane po https")
	}
	if zSekretem && repo.Username == "" {
		return fmt.Errorf("zrodlo z haslem wymaga nazwy uzytkownika")
	}
	if repo.Username != "" && strings.ContainsAny(repo.Username, " \t\n:") {
		return fmt.Errorf("nazwa uzytkownika zawiera niedozwolony znak")
	}
	if repo.Priority < 0 || repo.Priority > 1000 {
		return fmt.Errorf("priorytet %d jest poza zakresem 0-1000", repo.Priority)
	}
	for _, pole := range append(append([]string{}, repo.Suites...), repo.Components...) {
		if pole == "" || strings.ContainsAny(pole, " \t\n\"'/") {
			return fmt.Errorf("nieprawidlowa wartosc %q w opisie zrodla", pole)
		}
	}
	for _, architektura := range repo.Architectures {
		if architektura == "" || strings.ContainsAny(architektura, " \t\n\"'/") {
			return fmt.Errorf("nieprawidlowa architektura %q", architektura)
		}
	}
	if repo.Name != "" && strings.ContainsAny(repo.Name, "\n\r") {
		return fmt.Errorf("nazwa zrodla zawiera znak nowej linii")
	}

	switch menedzer {
	case "apt":
		if len(repo.Suites) == 0 {
			return fmt.Errorf("zrodlo APT wymaga wskazania suite")
		}
	case "dnf":
		if len(repo.Suites) > 0 || len(repo.Components) > 0 {
			return fmt.Errorf("zrodlo DNF opisuje sie samym adresem, bez suite i komponentow")
		}
	default:
		return fmt.Errorf("%s: menedzer %q nie obsluguje zarzadzania zrodlami",
			ErrorUnsupported, menedzer)
	}
	return nil
}

// Absent mowi, czy zlecenie usuwa zrodlo. Zrodlo bez adresu nie jest zrodlem
// pustym - jest zrodlem, ktore ma zniknac.
func (r Repozytorium) Absent() bool { return r.URL == "" }

// PlikiZrodla sklada pliki opisujace zrodlo.
//
// Haslo dostajemy osobno, bo nie ma go w opisie zrodla i nie moze sie tam
// znalezc: przychodzi z magazynu tuz przed zapisem i zyje tylko tutaj.
func PlikiZrodla(repo Repozytorium, menedzer, klucz string, haslo []byte) ([]Plik, error) {
	switch menedzer {
	case "apt":
		return plikiAPT(repo, klucz, haslo)
	case "dnf":
		return plikiDNF(repo, klucz, haslo)
	}
	return nil, fmt.Errorf("%s: menedzer %q nie obsluguje zarzadzania zrodlami",
		ErrorUnsupported, menedzer)
}

// SciezkiZrodla wylicza pliki, ktore naleza do zrodla. Uzywamy ich takze przy
// usuwaniu: zrodlo usuniete musi zabrac ze soba klucz i haslo.
func SciezkiZrodla(id, menedzer string) []string {
	switch menedzer {
	case "apt":
		return []string{
			filepath.Join(KatalogZrodelAPT, id+".sources"),
			filepath.Join(KatalogKluczyAPT, prefiksPlikuFlotest+id+".asc"),
			filepath.Join(KatalogHaselAPT, prefiksPlikuFlotest+id+".conf"),
		}
	case "dnf":
		return []string{
			filepath.Join(KatalogZrodelDNF, id+".repo"),
			filepath.Join(KatalogKluczyDNF, "RPM-GPG-KEY-"+prefiksPlikuFlotest+id),
		}
	}
	return nil
}

// plikiAPT sklada zrodlo w formacie deb822.
//
// Format jednoliniowy zostawiamy dystrybucji: deb822 pozwala wskazac klucz
// przy zrodle (Signed-By), zamiast dodawac go do zaufania calego systemu.
// To jest roznica miedzy "temu zrodlu wierzymy w tym zakresie" a "temu
// kluczowi wierzymy wszedzie".
func plikiAPT(repo Repozytorium, klucz string, haslo []byte) ([]Plik, error) {
	sciezkaKlucza := filepath.Join(KatalogKluczyAPT, prefiksPlikuFlotest+repo.ID+".asc")
	var pliki []Plik

	var opis strings.Builder
	opis.WriteString(znacznikPanelu + "\n")
	if repo.SecretName != "" {
		opis.WriteString(znacznikSekretu + repo.SecretName + "\n")
	}
	if repo.Username != "" {
		opis.WriteString(znacznikUzytkownika + repo.Username + "\n")
	}
	opis.WriteString("Types: deb\n")
	opis.WriteString("URIs: " + repo.URL + "\n")
	opis.WriteString("Suites: " + strings.Join(repo.Suites, " ") + "\n")
	if len(repo.Components) > 0 {
		opis.WriteString("Components: " + strings.Join(repo.Components, " ") + "\n")
	}
	if len(repo.Architectures) > 0 {
		opis.WriteString("Architectures: " + strings.Join(repo.Architectures, " ") + "\n")
	}
	opis.WriteString("Enabled: " + takNie(repo.Enabled) + "\n")
	if repo.Signed {
		opis.WriteString("Signed-By: " + sciezkaKlucza + "\n")
		pliki = append(pliki, Plik{Path: sciezkaKlucza, Content: []byte(klucz), Mode: 0o644})
	} else {
		// Bez podpisu apt i tak zapyta, wiec zgode operatora trzeba zapisac
		// w pliku - razem z tym, ze to jest zgoda, a nie ustawienie domyslne.
		opis.WriteString("Trusted: yes\n")
	}
	pliki = append(pliki, Plik{
		Path:    filepath.Join(KatalogZrodelAPT, repo.ID+".sources"),
		Content: []byte(opis.String()), Mode: 0o644,
	})

	if len(haslo) > 0 {
		adres, err := url.Parse(repo.URL)
		if err != nil {
			return nil, err
		}
		// Haslo lezy osobno, w pliku dla roota. W pliku zrodla nie ma go
		// wcale: ten jest czytelny dla wszystkich i taki ma zostac.
		wpis := znacznikPanelu + "\nmachine " + adres.Host + strings.TrimSuffix(adres.Path, "/") +
			" login " + repo.Username + " password " + string(haslo) + "\n"
		pliki = append(pliki, Plik{
			Path:     filepath.Join(KatalogHaselAPT, prefiksPlikuFlotest+repo.ID+".conf"),
			Content:  []byte(wpis),
			Mode:     0o600,
			Wrazliwy: true,
		})
	}
	return pliki, nil
}

// plikiDNF sklada zrodlo w formacie ini.
func plikiDNF(repo Repozytorium, klucz string, haslo []byte) ([]Plik, error) {
	sciezkaKlucza := filepath.Join(KatalogKluczyDNF, "RPM-GPG-KEY-"+prefiksPlikuFlotest+repo.ID)
	var pliki []Plik

	nazwa := repo.Name
	if nazwa == "" {
		nazwa = repo.ID
	}
	var opis strings.Builder
	opis.WriteString(znacznikPanelu + "\n")
	if repo.SecretName != "" {
		opis.WriteString(znacznikSekretu + repo.SecretName + "\n")
	}
	opis.WriteString("[" + repo.ID + "]\n")
	opis.WriteString("name=" + nazwa + "\n")
	opis.WriteString("baseurl=" + repo.URL + "\n")
	opis.WriteString("enabled=" + jedenZero(repo.Enabled) + "\n")
	opis.WriteString("gpgcheck=" + jedenZero(repo.Signed) + "\n")
	if repo.Signed {
		opis.WriteString("gpgkey=file://" + sciezkaKlucza + "\n")
		pliki = append(pliki, Plik{Path: sciezkaKlucza, Content: []byte(klucz), Mode: 0o644})
	}
	if repo.Priority > 0 {
		opis.WriteString(fmt.Sprintf("priority=%d\n", repo.Priority))
	}
	tryb := os.FileMode(0o644)
	wrazliwy := false
	if len(haslo) > 0 {
		// DNF nie ma osobnego pliku hasel: dane logowania sa w opisie zrodla.
		// Dlatego caly plik dostaje prawa dla roota, a operator ma to wiedziec.
		opis.WriteString("username=" + repo.Username + "\n")
		opis.WriteString("password=" + string(haslo) + "\n")
		tryb, wrazliwy = 0o600, true
	}
	pliki = append(pliki, Plik{
		Path:    filepath.Join(KatalogZrodelDNF, repo.ID+".repo"),
		Content: []byte(opis.String()), Mode: tryb, Wrazliwy: wrazliwy,
	})
	return pliki, nil
}

func takNie(wartosc bool) string {
	if wartosc {
		return "yes"
	}
	return "no"
}

func jedenZero(wartosc bool) string {
	if wartosc {
		return "1"
	}
	return "0"
}

// CzytajRepozytoria wylicza zrodla widoczne na hoscie.
//
// Odczyt idzie bez roota: pliki zrodel sa jawne. Wyjatkiem jest zrodlo
// z haslem, ktore panel sam zapisal z prawami dla roota - takie zrodlo
// zostaje z powodem, a nie znika z listy.
func CzytajRepozytoria(menedzer string) ObrazRepozytoriow {
	obraz := ObrazRepozytoriow{Manager: menedzer, ObservedAt: time.Now().UTC()}
	switch menedzer {
	case "apt":
		obraz.Repositories = czytajAPT()
		obraz.Known = true
	case "dnf":
		obraz.Repositories = czytajDNF()
		obraz.Known = true
	default:
		obraz.UnavailableReason = "this package manager does not expose repositories"
	}
	sort.Slice(obraz.Repositories, func(i, j int) bool {
		return obraz.Repositories[i].ID < obraz.Repositories[j].ID
	})
	return obraz
}

// czytajAPT czyta zrodla w obu formatach, ktore apt rozumie.
func czytajAPT() []Repozytorium {
	var zrodla []Repozytorium
	wpisy, _ := os.ReadDir(KatalogZrodelAPT)
	for _, wpis := range wpisy {
		if wpis.IsDir() {
			continue
		}
		sciezka := filepath.Join(KatalogZrodelAPT, wpis.Name())
		switch filepath.Ext(wpis.Name()) {
		case ".sources":
			zrodla = append(zrodla, czytajZrodloDeb822(sciezka))
		case ".list":
			zrodla = append(zrodla, czytajZrodloListy(sciezka)...)
		}
	}
	if _, err := os.Stat(PlikZrodelAPT); err == nil {
		zrodla = append(zrodla, czytajZrodloListy(PlikZrodelAPT)...)
	}
	return zrodla
}

// czytajZrodloDeb822 czyta jeden plik w formacie deb822.
func czytajZrodloDeb822(sciezka string) Repozytorium {
	repo := Repozytorium{
		ID:   strings.TrimSuffix(filepath.Base(sciezka), ".sources"),
		Path: sciezka,
	}
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		repo.UnavailableReason = err.Error()
		return repo
	}
	// Enabled bez wpisu oznacza zrodlo wlaczone: taki jest domyslny stan apt.
	repo.Enabled = true
	for _, linia := range strings.Split(string(dane), "\n") {
		przycieta := strings.TrimSpace(linia)
		if przycieta == znacznikPanelu {
			repo.Managed = true
			continue
		}
		if strings.HasPrefix(przycieta, znacznikSekretu) {
			repo.SecretName = strings.TrimSpace(strings.TrimPrefix(przycieta, znacznikSekretu))
			continue
		}
		if strings.HasPrefix(przycieta, znacznikUzytkownika) {
			repo.Username = strings.TrimSpace(strings.TrimPrefix(przycieta, znacznikUzytkownika))
			continue
		}
		klucz, wartosc, ok := strings.Cut(przycieta, ":")
		if !ok {
			continue
		}
		wartosc = strings.TrimSpace(wartosc)
		switch strings.ToLower(strings.TrimSpace(klucz)) {
		case "uris":
			repo.URL = pierwszePole(wartosc)
		case "suites":
			repo.Suites = strings.Fields(wartosc)
		case "components":
			repo.Components = strings.Fields(wartosc)
		case "architectures":
			repo.Architectures = strings.Fields(wartosc)
		case "enabled":
			repo.Enabled = !strings.EqualFold(wartosc, "no") && !strings.EqualFold(wartosc, "false")
		case "signed-by":
			repo.Signed = wartosc != ""
		}
	}
	return repo
}

// czytajZrodloListy czyta zrodla w formacie jednoliniowym.
func czytajZrodloListy(sciezka string) []Repozytorium {
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return []Repozytorium{{
			ID:                strings.TrimSuffix(filepath.Base(sciezka), ".list"),
			Path:              sciezka,
			UnavailableReason: err.Error(),
		}}
	}
	return czytajZrodloListyZTresci(sciezka, string(dane))
}

// czytajZrodloListyZTresci rozbija tresc pliku na zrodla.
func czytajZrodloListyZTresci(sciezka, tresc string) []Repozytorium {
	var zrodla []Repozytorium
	numer := 0
	for _, linia := range strings.Split(tresc, "\n") {
		przycieta := strings.TrimSpace(linia)
		if przycieta == "" || strings.HasPrefix(przycieta, "#") {
			continue
		}
		pola := strings.Fields(przycieta)
		if len(pola) < 3 || (pola[0] != "deb" && pola[0] != "deb-src") {
			continue
		}
		numer++
		repo := Repozytorium{
			ID:      fmt.Sprintf("%s#%d", strings.TrimSuffix(filepath.Base(sciezka), ".list"), numer),
			Path:    sciezka,
			Enabled: true,
		}
		// Opcje w nawiasach kwadratowych stoja przed adresem; interesuje nas
		// z nich tylko to, czy zrodlo ma wskazany klucz.
		reszta := pola[1:]
		if strings.HasPrefix(reszta[0], "[") {
			for i, pole := range reszta {
				if strings.Contains(pole, "signed-by=") {
					repo.Signed = true
				}
				if strings.HasSuffix(pole, "]") {
					reszta = reszta[i+1:]
					break
				}
			}
		}
		if len(reszta) < 2 {
			continue
		}
		repo.URL = reszta[0]
		repo.Suites = reszta[1:2]
		if len(reszta) > 2 {
			repo.Components = reszta[2:]
		}
		zrodla = append(zrodla, repo)
	}
	return zrodla
}

// czytajDNF czyta pliki .repo. Jeden plik moze opisywac kilka zrodel.
func czytajDNF() []Repozytorium {
	var zrodla []Repozytorium
	wpisy, _ := os.ReadDir(KatalogZrodelDNF)
	for _, wpis := range wpisy {
		if wpis.IsDir() || filepath.Ext(wpis.Name()) != ".repo" {
			continue
		}
		sciezka := filepath.Join(KatalogZrodelDNF, wpis.Name())
		dane, err := os.ReadFile(sciezka)
		if err != nil {
			zrodla = append(zrodla, Repozytorium{
				ID:                strings.TrimSuffix(wpis.Name(), ".repo"),
				Path:              sciezka,
				UnavailableReason: err.Error(),
			})
			continue
		}
		zrodla = append(zrodla, czytajSekcjeDNF(sciezka, string(dane))...)
	}
	return zrodla
}

// czytajSekcjeDNF rozbija plik na sekcje i czyta z nich to, co widoczne.
func czytajSekcjeDNF(sciezka, tresc string) []Repozytorium {
	var zrodla []Repozytorium
	var biezace *Repozytorium
	zarzadzane, sekret := false, ""

	zapisz := func() {
		if biezace != nil {
			zrodla = append(zrodla, *biezace)
		}
		biezace = nil
	}
	for _, linia := range strings.Split(tresc, "\n") {
		przycieta := strings.TrimSpace(linia)
		if przycieta == znacznikPanelu {
			zarzadzane = true
			continue
		}
		if strings.HasPrefix(przycieta, znacznikSekretu) {
			sekret = strings.TrimSpace(strings.TrimPrefix(przycieta, znacznikSekretu))
			continue
		}
		if strings.HasPrefix(przycieta, "[") && strings.HasSuffix(przycieta, "]") {
			zapisz()
			biezace = &Repozytorium{
				ID: strings.Trim(przycieta, "[]"), Path: sciezka,
				Enabled: true, Managed: zarzadzane, SecretName: sekret,
			}
			continue
		}
		if biezace == nil {
			continue
		}
		klucz, wartosc, ok := strings.Cut(przycieta, "=")
		if !ok {
			continue
		}
		klucz, wartosc = strings.TrimSpace(klucz), strings.TrimSpace(wartosc)
		switch klucz {
		case "name":
			biezace.Name = wartosc
		case "baseurl", "metalink", "mirrorlist":
			if biezace.URL == "" {
				biezace.URL = pierwszePole(wartosc)
			}
		case "enabled":
			biezace.Enabled = wartosc == "1" || strings.EqualFold(wartosc, "true")
		case "gpgcheck":
			biezace.Signed = wartosc == "1" || strings.EqualFold(wartosc, "true")
		case "username":
			biezace.Username = wartosc
		case "priority":
			fmt.Sscanf(wartosc, "%d", &biezace.Priority)
		}
	}
	zapisz()
	return zrodla
}

func pierwszePole(wartosc string) string {
	pola := strings.Fields(wartosc)
	if len(pola) == 0 {
		return ""
	}
	return pola[0]
}

// OdswiezZrodlo pobiera metadane jednego zrodla.
//
// Jednego, a nie wszystkich: pelne odswiezenie sciaga takze zrodla, ktore
// z ta zmiana nie maja nic wspolnego, a ich awaria wygladalaby jak awaria
// naszego zapisu - i cofnelaby poprawna zmiane.
func OdswiezZrodlo(ctx context.Context, menedzer, id string, sciezkaZrodla string) error {
	switch menedzer {
	case "apt":
		// apt-get update czyta zrodla z katalogu, wiec podajemy mu katalog
		// tymczasowy, w ktorym lezy wylacznie nasze zrodlo.
		katalog, err := os.MkdirTemp("", "flotestro-repo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(katalog)
		dane, err := os.ReadFile(sciezkaZrodla)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(katalog, id+".sources"), dane, 0o644); err != nil {
			return err
		}
		// apt konczy sie kodem zero takze wtedy, gdy zrodla nie udalo sie
		// pobrac: nieudany indeks jest dla niego ostrzezeniem, ktore mozna
		// zignorowac. Dla panelu to nie jest ostrzezenie - to jest odpowiedz
		// "tego zrodla nie ma", a zrodlo, ktore nie odpowiada, zablokuje
		// kazda nastepna operacje pakietowa na tym hoscie.
		wynik := run(ctx, 5*time.Minute, aptGetPath, "update", "--quiet",
			"-o", "APT::Update::Error-Mode=any",
			"-o", "Dir::Etc::sourcelist=/dev/null",
			"-o", "Dir::Etc::sourceparts="+katalog)
		if !wynik.Ran || wynik.ExitCode != 0 {
			return fmt.Errorf("apt-get update: %s", wynik.Reason())
		}
		// Starszy apt nie zna tego ustawienia i przemilcza je razem z bledem,
		// wiec czytamy takze to, co napisal.
		if linia := pierwszyBladAPT(wynik.Stdout + "\n" + wynik.Stderr); linia != "" {
			return fmt.Errorf("apt-get update: %s", linia)
		}
		return nil
	case "dnf":
		wynik := run(ctx, 5*time.Minute, dnfPath, "--disablerepo=*",
			"--enablerepo="+id, "makecache", "--refresh")
		if !wynik.Ran || wynik.ExitCode != 0 {
			return fmt.Errorf("dnf makecache: %s", wynik.Reason())
		}
		// dnf, tak samo jak apt, konczy sie kodem zero i komunikatem
		// "Metadata cache created" takze wtedy, gdy zadnego adresu zrodla nie
		// dalo sie otworzyc. Kod wyjscia nie odpowiada wiec na pytanie,
		// ktore zadajemy, i trzeba przeczytac, co narzedzie napisalo.
		if linia := pierwszyBladDNF(wynik.Stdout + "\n" + wynik.Stderr); linia != "" {
			return fmt.Errorf("dnf makecache: %s", linia)
		}
		return nil
	}
	return fmt.Errorf("%s: menedzer %q nie obsluguje zarzadzania zrodlami",
		ErrorUnsupported, menedzer)
}

// pierwszyBladAPT wyciaga pierwsza linie bledu z wyjscia apt.
func pierwszyBladAPT(wyjscie string) string {
	for _, linia := range strings.Split(wyjscie, "\n") {
		przycieta := strings.TrimSpace(linia)
		if strings.HasPrefix(przycieta, "Err:") || strings.HasPrefix(przycieta, "E: ") {
			return przycieta
		}
	}
	return ""
}

// bledyDNF wylicza slady nieudanego pobrania metadanych. Zbior obejmuje oba
// pokolenia narzedzia: dnf4 pisze o bledach synchronizacji, dnf5 o bledach
// biblioteki curl i o braku uzytecznego adresu.
var bledyDNF = []string{
	"curl error",
	"usable url not found",
	"failed to download metadata",
	"errors during downloading metadata",
	"cannot download repomd.xml",
	"failed to synchronize cache",
}

// pierwszyBladDNF wyciaga pierwszy slad nieudanego pobrania z wyjscia dnf.
func pierwszyBladDNF(wyjscie string) string {
	for _, linia := range strings.Split(wyjscie, "\n") {
		przycieta := strings.TrimSpace(strings.TrimLeft(linia, "> "))
		male := strings.ToLower(przycieta)
		for _, slad := range bledyDNF {
			if strings.Contains(male, slad) {
				return przycieta
			}
		}
	}
	return ""
}
