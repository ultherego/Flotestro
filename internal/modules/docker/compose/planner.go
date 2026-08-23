package compose

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// nazwaProjektu dopuszcza to, co dopuszcza Compose. Nazwa trafia do argumentu
// polecenia i do nazw kontenerow, wiec nie moze niesc niczego wiecej.
var nazwaProjektu = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// PoprawnaNazwaProjektu sprawdza nazwe projektu.
func PoprawnaNazwaProjektu(nazwa string) bool {
	return nazwaProjektu.MatchString(nazwa)
}

// maksymalnyManifest ogranicza rozmiar manifestu. Plik wiekszy od tego nie
// jest juz konfiguracja projektu, tylko czyms, czego operator nie przeczyta
// przed zatwierdzeniem.
const maksymalnyManifest = 256 << 10

// Planner liczy plan wdrozenia na hoscie.
type Planner struct {
	// Runner wykonuje polecenie compose. Wydzielony, zeby plan dal sie
	// sprawdzic w tescie bez silnika kontenerow.
	Runner Runner
	// Dir jest katalogiem roboczym na manifesty. Nalezy do roota i nie jest
	// wspoldzielony z niczym innym.
	Dir string
}

// Runner uruchamia polecenie compose i zwraca jego wyjscie.
type Runner func(ctx context.Context, args ...string) (stdout string, stderr string, err error)

// Plan liczy roznice miedzy stanem projektu a manifestem.
func (p Planner) Plan(ctx context.Context, project, manifest string) (Plan, error) {
	plan := Plan{Project: project, ComputedAt: time.Now().UTC()}
	if !PoprawnaNazwaProjektu(project) {
		return plan, fmt.Errorf("nieprawidlowa nazwa projektu %q", project)
	}
	if len(manifest) == 0 {
		return plan, fmt.Errorf("manifest jest pusty")
	}
	if len(manifest) > maksymalnyManifest {
		return plan, fmt.Errorf("manifest jest zbyt duzy (%d bajtow)", len(manifest))
	}

	sciezka, sprzataj, err := p.zapiszManifest(project, manifest)
	if err != nil {
		return plan, err
	}
	defer sprzataj()

	// Normalizacja jest jednoczesnie walidacja: Compose odmawia, gdy manifest
	// jest niepoprawny, i robi to zanim cokolwiek ruszy na hoscie.
	stdout, stderr, err := p.Runner(ctx, "-p", project, "-f", sciezka, "config", "--format", "json")
	if err != nil {
		return plan, fmt.Errorf("manifest odrzucony przez compose: %s", pierwszaLinia(stderr))
	}

	uslugi, ostrzezenia, err := uslugiZKonfiguracji(stdout)
	if err != nil {
		return plan, err
	}
	plan.Services = uslugi
	plan.Warnings = ostrzezenia

	// Suchy przebieg mowi, co naprawde sie zmieni. Roznica liczona z samego
	// manifestu byłaby zgadywaniem: Compose bierze pod uwage takze to, czy
	// kontener wymaga odtworzenia z powodu zmiany obrazu albo konfiguracji.
	// Compose melduje suchy przebieg na strumieniu diagnostycznym, a nie na
	// wyjsciu, wiec czytamy oba - inaczej lista zmian wychodzi pusta i plan
	// wyglada, jakby wdrozenie niczego nie zmienialo.
	suchyOut, suchyErr, err := p.Runner(ctx, "-p", project, "-f", sciezka, "up", "-d", "--dry-run")
	if err == nil {
		plan.Changes = zmianyZSuchegoPrzebiegu(suchyOut + "\n" + suchyErr)
	} else {
		plan.Warnings = append(plan.Warnings,
			"compose could not compute a dry run; the change list may be incomplete")
	}

	plan.Digest = Digest(project, stdout, uslugi)
	return plan, nil
}

// Digest wiaze wdrozenie z planem.
//
// Liczony z calej znormalizowanej konfiguracji projektu, a nie z samej listy
// uslug. Manifest o tych samych uslugach i obrazach moze publikowac inny port
// albo uruchamiac inne polecenie - operator zatwierdzil konkretny plan, wiec
// digest musi objac wszystko, co ten plan opisuje.
//
// Podstawa jest wyjscie "compose config", bo Compose je kanonizuje: te same
// znaczenie zapisane inaczej daje ten sam tekst, a rozne znaczenie zawsze
// rozny.
func Digest(project string, konfiguracja string, uslugi []Service) string {
	posortowane := make([]Service, len(uslugi))
	copy(posortowane, uslugi)
	sort.Slice(posortowane, func(i, j int) bool { return posortowane[i].Name < posortowane[j].Name })

	suma := sha256.New()
	fmt.Fprintf(suma, "project=%s\n", project)
	fmt.Fprintf(suma, "config=%s\n", strings.TrimSpace(konfiguracja))
	// Digesty obrazow sa dopisywane osobno: konfiguracja niesie tag, a tag
	// jutro moze wskazywac inny obraz. Zmiana tego, co naprawde wstanie,
	// tez ma uniewazniac zatwierdzenie.
	for _, usluga := range posortowane {
		fmt.Fprintf(suma, "image=%s digest=%s\n", usluga.Image, usluga.ImageDigest)
	}
	return hex.EncodeToString(suma.Sum(nil))
}

// zapiszManifest zapisuje manifest w katalogu roboczym helpera.
func (p Planner) zapiszManifest(project, manifest string) (string, func(), error) {
	katalog := filepath.Join(p.Dir, project)
	if err := os.MkdirAll(katalog, 0o700); err != nil {
		return "", func() {}, err
	}
	sciezka := filepath.Join(katalog, "docker-compose.yml")
	// Manifest bywa nosnikiem poswiadczen, wiec plik jest czytelny wylacznie
	// dla roota i znika po operacji.
	if err := os.WriteFile(sciezka, []byte(manifest), 0o600); err != nil {
		return "", func() {}, err
	}
	return sciezka, func() { _ = os.Remove(sciezka) }, nil
}

// uslugiZKonfiguracji czyta znormalizowana konfiguracje projektu.
func uslugiZKonfiguracji(konfiguracja string) ([]Service, []string, error) {
	var dane struct {
		Services map[string]struct {
			Image       string         `json:"image"`
			Environment map[string]any `json:"environment"`
			Deploy      struct {
				Replicas *int `json:"replicas"`
			} `json:"deploy"`
			Labels map[string]string `json:"labels"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(konfiguracja), &dane); err != nil {
		return nil, nil, fmt.Errorf("nieczytelna konfiguracja projektu: %w", err)
	}

	uslugi := make([]Service, 0, len(dane.Services))
	var ostrzezenia []string
	for nazwa, usluga := range dane.Services {
		wpis := Service{Name: nazwa, Image: usluga.Image, Replicas: 1}
		if usluga.Deploy.Replicas != nil {
			wpis.Replicas = *usluga.Deploy.Replicas
		}
		// Obraz wskazany tagiem moze jutro znaczyc co innego. To nie blokuje
		// wdrozenia, ale operator ma wiedziec, ze zatwierdza ruchomy cel.
		if !strings.Contains(usluga.Image, "@sha256:") {
			ostrzezenia = append(ostrzezenia,
				fmt.Sprintf("service %s uses a mutable tag (%s); pin a digest to know what will run",
					nazwa, usluga.Image))
		}
		for klucz := range usluga.Environment {
			if wygladaNaSekret(klucz) {
				// Manifest jest zapisywany w panelu razem z historia wersji,
				// wiec wartosc wpisana w nim wprost przestaje byc sekretem.
				ostrzezenia = append(ostrzezenia,
					fmt.Sprintf("service %s sets %s inline; the manifest is stored in the panel, "+
						"so use env_file on the host instead", nazwa, klucz))
			}
		}
		uslugi = append(uslugi, wpis)
	}
	sort.Slice(uslugi, func(i, j int) bool { return uslugi[i].Name < uslugi[j].Name })
	sort.Strings(ostrzezenia)
	return uslugi, ostrzezenia, nil
}

// wzorzecSuchegoPrzebiegu czyta linie w rodzaju:
//
//	DRY-RUN MODE -  Container probny-web-1  Creating
var wzorzecSuchegoPrzebiegu = regexp.MustCompile(
	`(?i)(Container|Network|Volume|Image)\s+(\S+)\s+(Creating|Created|Recreate|Recreated|Starting|Started|Stopping|Stopped|Removing|Removed|Pulling|Pulled)`)

// zmianyZSuchegoPrzebiegu wyciaga liste zmian z wyjscia suchego przebiegu.
// Compose melduje kazdy krok dwa razy - w trakcie i po - wiec liczy sie
// pierwsze wystapienie obiektu.
func zmianyZSuchegoPrzebiegu(wyjscie string) []Change {
	widziane := map[string]bool{}
	var zmiany []Change
	for _, linia := range strings.Split(wyjscie, "\n") {
		dopasowanie := wzorzecSuchegoPrzebiegu.FindStringSubmatch(linia)
		if dopasowanie == nil {
			continue
		}
		klucz := dopasowanie[1] + "/" + dopasowanie[2]
		if widziane[klucz] {
			continue
		}
		widziane[klucz] = true
		zmiany = append(zmiany, Change{
			Kind:   strings.ToLower(dopasowanie[1]),
			Name:   dopasowanie[2],
			Action: strings.ToLower(strings.TrimSuffix(dopasowanie[3], "d")),
		})
	}
	return zmiany
}

func wygladaNaSekret(klucz string) bool {
	male := strings.ToLower(klucz)
	for _, wzorzec := range []string{"secret", "password", "passwd", "token", "apikey", "api_key", "credential"} {
		if strings.Contains(male, wzorzec) {
			return true
		}
	}
	return false
}

func pierwszaLinia(tekst string) string {
	tekst = strings.TrimSpace(tekst)
	if index := strings.IndexByte(tekst, '\n'); index >= 0 {
		return strings.TrimSpace(tekst[:index])
	}
	return tekst
}

// uslugiZListy czyta wyjscie "compose ps --format json". Compose wypisuje
// jeden obiekt na linie, a nie tablice, wiec czytamy strumieniowo.
func uslugiZListy(wyjscie string) []Service {
	var uslugi []Service
	for _, linia := range strings.Split(wyjscie, "\n") {
		linia = strings.TrimSpace(linia)
		if linia == "" || !strings.HasPrefix(linia, "{") {
			continue
		}
		var wpis struct {
			Service string `json:"Service"`
			Image   string `json:"Image"`
			State   string `json:"State"`
		}
		if err := json.Unmarshal([]byte(linia), &wpis); err != nil {
			continue
		}
		uslugi = append(uslugi, Service{Name: wpis.Service, Image: wpis.Image, Replicas: 1})
	}
	sort.Slice(uslugi, func(i, j int) bool { return uslugi[i].Name < uslugi[j].Name })
	return uslugi
}
