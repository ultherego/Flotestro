package compose

import (
	"context"
	"strings"
	"testing"
)

// runner udaje compose: zwraca przygotowane wyjscie dla kolejnych wywolan.
func runner(odpowiedzi map[string]string) Runner {
	return func(_ context.Context, args ...string) (string, string, error) {
		for wzorzec, odpowiedz := range odpowiedzi {
			if strings.Contains(strings.Join(args, " "), wzorzec) {
				return odpowiedz, "", nil
			}
		}
		return "", "nieznane polecenie", context.Canceled
	}
}

const konfiguracja = `{
  "services": {
    "web": {"image": "nginx@sha256:aaaa", "environment": {"PORT": "80"}},
    "db":  {"image": "postgres:16", "environment": {"POSTGRES_PASSWORD": "tajne"}}
  }
}`

// Digest wiaze wdrozenie z planem, wiec musi zalezec od tresci, a nie od
// kolejnosci uslug w manifescie.
func TestDigestNieZalezyOdKolejnosci(t *testing.T) {
	a := Digest("sklep", konfiguracja, []Service{
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	})
	b := Digest("sklep", konfiguracja, []Service{
		{Name: "db", Image: "postgres:16", Replicas: 1},
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
	})
	if a != b {
		t.Error("digest zalezy od kolejnosci uslug")
	}

	inny := Digest("sklep", konfiguracja, []Service{
		{Name: "web", Image: "nginx@sha256:bbbb", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	})
	if a == inny {
		t.Error("zmiana obrazu nie zmienila digestu")
	}
	if a == Digest("magazyn", konfiguracja, []Service{
		{Name: "web", Image: "nginx@sha256:aaaa", Replicas: 1},
		{Name: "db", Image: "postgres:16", Replicas: 1},
	}) {
		t.Error("zmiana projektu nie zmienila digestu")
	}
}

// Manifest o tych samych uslugach i obrazach moze publikowac inny port albo
// uruchamiac inne polecenie. Digest liczony z samej listy uslug przepuscilby
// wdrozenie planu, ktorego operator nie widzial.
func TestDigestObejmujeCalyManifest(t *testing.T) {
	uslugi := []Service{{Name: "web", Image: "nginx:alpine", Replicas: 1}}
	zPortem8083 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8083"}]}}}`
	zPortem8084 := `{"services":{"web":{"image":"nginx:alpine","ports":[{"published":"8084"}]}}}`

	if Digest("sklep", zPortem8083, uslugi) == Digest("sklep", zPortem8084, uslugi) {
		t.Error("zmiana portu nie zmienila digestu planu")
	}
}

// Manifest jest zapisywany w panelu razem z historia wersji, wiec wartosc
// wpisana w nim wprost przestaje byc sekretem. Operator ma to zobaczyc przed
// zatwierdzeniem, a nie po wycieku.
func TestPlanOstrzegaOSekretachWManifescie(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": konfiguracja,
		"up":     " DRY-RUN MODE -  Container sklep-web-1  Creating",
	})}
	plan, err := planner.Plan(context.Background(), "sklep", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	var oSekrecie, oTagu bool
	for _, ostrzezenie := range plan.Warnings {
		if strings.Contains(ostrzezenie, "POSTGRES_PASSWORD") {
			oSekrecie = true
		}
		if strings.Contains(ostrzezenie, "mutable tag") && strings.Contains(ostrzezenie, "db") {
			oTagu = true
		}
	}
	if !oSekrecie {
		t.Errorf("brak ostrzezenia o sekrecie w manifescie: %v", plan.Warnings)
	}
	// Obraz wskazany tagiem moze jutro znaczyc co innego.
	if !oTagu {
		t.Errorf("brak ostrzezenia o ruchomym tagu: %v", plan.Warnings)
	}
}

// Usluga przypieta digestem nie jest ruchomym celem i nie moze byc tak
// oznaczona - inaczej ostrzezenia przestaja cokolwiek znaczyc.
func TestPrzypietyObrazNieJestOstrzegany(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": `{"services": {"web": {"image": "nginx@sha256:aaaa"}}}`,
		"up":     "",
	})}
	plan, err := planner.Plan(context.Background(), "sklep", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, ostrzezenie := range plan.Warnings {
		if strings.Contains(ostrzezenie, "mutable tag") {
			t.Errorf("przypiety obraz zostal oznaczony jako ruchomy: %q", ostrzezenie)
		}
	}
}

// Compose melduje kazdy krok dwa razy - w trakcie i po. Podwojna lista zmian
// sugerowalaby operatorowi dwa razy wiecej pracy, niz wdrozenie wykona.
func TestZmianyNieSaLiczonePodwojnie(t *testing.T) {
	zmiany := zmianyZSuchegoPrzebiegu(strings.Join([]string{
		" DRY-RUN MODE -  Network sklep_default  Creating",
		" DRY-RUN MODE -  Network sklep_default  Created",
		" DRY-RUN MODE -  Container sklep-web-1  Creating",
		" DRY-RUN MODE -  Container sklep-web-1  Created",
	}, "\n"))
	if len(zmiany) != 2 {
		t.Fatalf("zmian = %d, oczekiwano 2: %+v", len(zmiany), zmiany)
	}
	if zmiany[0].Kind != "network" || zmiany[1].Name != "sklep-web-1" {
		t.Errorf("zmiany = %+v", zmiany)
	}
}

// Nazwa projektu trafia do argumentu polecenia i do nazw kontenerow.
func TestNazwaProjektuJestSprawdzana(t *testing.T) {
	for _, nazwa := range []string{"", "-sklep", "Sklep", "sklep;reboot", "sklep/../etc", strings.Repeat("a", 64)} {
		if PoprawnaNazwaProjektu(nazwa) {
			t.Errorf("przyjeto nazwe %q", nazwa)
		}
	}
	for _, nazwa := range []string{"sklep", "sklep-prod", "sklep_2", "a"} {
		if !PoprawnaNazwaProjektu(nazwa) {
			t.Errorf("odrzucono nazwe %q", nazwa)
		}
	}
}

// Wdrozenie idzie wylacznie z planem, ktory operator zatwierdzil. Rozny
// digest oznacza, ze wdrozenie przynioslo by cos innego, niz obejrzal.
func TestWdrozenieOdmawiaPrzyInnymPlanie(t *testing.T) {
	executor := Executor{Planner: Planner{Dir: t.TempDir(), Runner: runner(map[string]string{
		"config": konfiguracja,
		"up":     "",
		"ps":     "",
	})}}
	_, err := executor.Deploy(context.Background(), "sklep", "services: {}", "0000000000000000")
	if err == nil {
		t.Fatal("wdrozenie przeszlo mimo innego planu")
	}
	if !strings.Contains(err.Error(), "zmienil sie od zatwierdzenia") {
		t.Errorf("blad = %v", err)
	}
}

// Compose melduje suchy przebieg na strumieniu diagnostycznym. Czytanie
// samego wyjscia dawalo pusta liste zmian, czyli plan mowiacy, ze wdrozenie
// niczego nie zmieni - najgorsza z mozliwych odpowiedzi.
func TestZmianyCzytaneZObuStrumieni(t *testing.T) {
	planner := Planner{Dir: t.TempDir(), Runner: func(_ context.Context, args ...string) (string, string, error) {
		polecenie := strings.Join(args, " ")
		if strings.Contains(polecenie, "config") {
			return konfiguracja, "", nil
		}
		// Suchy przebieg trafia wylacznie na strumien diagnostyczny.
		return "", " DRY-RUN MODE -  Container sklep-web-1  Creating", nil
	}}
	plan, err := planner.Plan(context.Background(), "sklep", "services: {}")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Name != "sklep-web-1" {
		t.Fatalf("zmiany = %+v", plan.Changes)
	}
}
