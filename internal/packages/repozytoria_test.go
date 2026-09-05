package packages

import (
	"strings"
	"testing"
)

func TestWalidujRepozytoriumPilnujeZaufania(t *testing.T) {
	podstawa := Repozytorium{
		ID: "wewnetrzne", URL: "https://pakiety.example.test/debian",
		Suites: []string{"stable"}, Components: []string{"main"},
		Enabled: true, Signed: true,
	}
	if err := WalidujRepozytorium(podstawa, "apt", false); err != nil {
		t.Fatalf("poprawne zrodlo odrzucone: %v", err)
	}

	// Zrodlo bez sprawdzania podpisow po zwyklym http oznacza, ze wystarczy
	// byc po drodze, zeby host zainstalowal cudze pakiety.
	bezPodpisu := podstawa
	bezPodpisu.Signed = false
	bezPodpisu.URL = "http://pakiety.example.test/debian"
	if err := WalidujRepozytorium(bezPodpisu, "apt", false); err == nil {
		t.Fatal("zrodlo bez podpisow po http zostalo przyjete")
	}
	bezPodpisu.URL = "https://pakiety.example.test/debian"
	if err := WalidujRepozytorium(bezPodpisu, "apt", false); err != nil {
		t.Fatalf("zrodlo bez podpisow po https odrzucone: %v", err)
	}

	// Haslo po zwyklym http odczyta kazdy, kto jest po drodze.
	zHaslem := podstawa
	zHaslem.URL = "http://pakiety.example.test/debian"
	zHaslem.Username = "flota"
	if err := WalidujRepozytorium(zHaslem, "apt", true); err == nil {
		t.Fatal("zrodlo z haslem po http zostalo przyjete")
	}
	bezUzytkownika := podstawa
	if err := WalidujRepozytorium(bezUzytkownika, "apt", true); err == nil {
		t.Fatal("haslo bez nazwy uzytkownika zostalo przyjete")
	}

	zleNazwy := []string{"", "../ucieczka", "Wielkie", "z spacja", strings.Repeat("a", 80)}
	for _, nazwa := range zleNazwy {
		zla := podstawa
		zla.ID = nazwa
		if err := WalidujRepozytorium(zla, "apt", false); err == nil {
			t.Fatalf("identyfikator %q zostal przyjety", nazwa)
		}
	}

	// APT potrzebuje suite; DNF opisuje sie samym adresem.
	bezSuite := podstawa
	bezSuite.Suites = nil
	if err := WalidujRepozytorium(bezSuite, "apt", false); err == nil {
		t.Fatal("zrodlo APT bez suite zostalo przyjete")
	}
	if err := WalidujRepozytorium(podstawa, "dnf", false); err == nil {
		t.Fatal("zrodlo DNF z suite zostalo przyjete")
	}

	// Usuniecie zrodla nie potrzebuje adresu: opisuje je sam identyfikator.
	usuniecie := Repozytorium{ID: "wewnetrzne"}
	if err := WalidujRepozytorium(usuniecie, "apt", false); err != nil {
		t.Fatalf("usuniecie zrodla odrzucone: %v", err)
	}
}

func TestPlikiZrodlaTrzymajaHasloOsobno(t *testing.T) {
	repo := Repozytorium{
		ID: "wewnetrzne", Name: "Wewnetrzne", URL: "https://pakiety.example.test/debian",
		Suites: []string{"stable"}, Components: []string{"main"}, Enabled: true,
		Signed: true, Username: "flota", SecretName: "repo.haslo",
	}
	pliki, err := PlikiZrodla(repo, "apt", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", []byte("tajne"))
	if err != nil {
		t.Fatalf("PlikiZrodla: %v", err)
	}

	var zrodlo, haslo *Plik
	for i := range pliki {
		switch {
		case strings.HasSuffix(pliki[i].Path, ".sources"):
			zrodlo = &pliki[i]
		case strings.HasSuffix(pliki[i].Path, ".conf"):
			haslo = &pliki[i]
		}
	}
	if zrodlo == nil || haslo == nil {
		t.Fatalf("brak plikow zrodla albo hasla: %+v", pliki)
	}
	// Plik zrodla jest jawny i taki ma zostac - wiec nie moze byc w nim hasla.
	if strings.Contains(string(zrodlo.Content), "tajne") {
		t.Fatal("haslo trafilo do jawnego pliku zrodla")
	}
	if !strings.Contains(string(zrodlo.Content), "repo.haslo") {
		t.Fatal("plik zrodla nie mowi, z ktorego sekretu pochodzi haslo")
	}
	// Nazwa uzytkownika nie jest sekretem, a bez niej panel widzialby zrodlo
	// z haslem, nie wiedzac, kim sie ono przedstawia.
	if !strings.Contains(string(zrodlo.Content), znacznikUzytkownika+"flota") {
		t.Fatalf("plik zrodla nie mowi, kim sie przedstawia:\n%s", zrodlo.Content)
	}
	if zrodlo.Mode != 0o644 {
		t.Errorf("plik zrodla ma prawa %o", zrodlo.Mode)
	}
	if haslo.Mode != 0o600 || !haslo.Wrazliwy {
		t.Errorf("plik hasla ma prawa %o (wrazliwy=%v)", haslo.Mode, haslo.Wrazliwy)
	}
	if !strings.Contains(string(zrodlo.Content), "Signed-By: /etc/apt/keyrings/flotestro-wewnetrzne.asc") {
		t.Errorf("zrodlo nie wskazuje wlasnego klucza:\n%s", zrodlo.Content)
	}
}

func TestPlikiZrodlaDNFZamykajaPlikZHaslem(t *testing.T) {
	repo := Repozytorium{
		ID: "wewnetrzne", URL: "https://pakiety.example.test/rpm", Enabled: true,
		Signed: true, Username: "flota", SecretName: "repo.haslo", Priority: 10,
	}
	pliki, err := PlikiZrodla(repo, "dnf", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n", []byte("tajne"))
	if err != nil {
		t.Fatalf("PlikiZrodla: %v", err)
	}
	for _, plik := range pliki {
		if !strings.HasSuffix(plik.Path, ".repo") {
			continue
		}
		// DNF nie ma osobnego pliku hasel, wiec caly opis zrodla musi byc
		// zamkniety dla wszystkich poza rootem.
		if plik.Mode != 0o600 || !plik.Wrazliwy {
			t.Fatalf("plik zrodla z haslem ma prawa %o (wrazliwy=%v)", plik.Mode, plik.Wrazliwy)
		}
		if !strings.Contains(string(plik.Content), "gpgcheck=1") {
			t.Errorf("zrodlo nie sprawdza podpisow:\n%s", plik.Content)
		}
		if !strings.Contains(string(plik.Content), "priority=10") {
			t.Errorf("priorytet nie trafil do pliku:\n%s", plik.Content)
		}
		return
	}
	t.Fatalf("nie powstal plik zrodla: %+v", pliki)
}

func TestCzytajSekcjeDNFRozroznraStanZrodla(t *testing.T) {
	tresc := znacznikPanelu + "\n" + znacznikSekretu + "repo.haslo\n" +
		"[wewnetrzne]\nname=Wewnetrzne\nbaseurl=https://pakiety.example.test/rpm\n" +
		"enabled=1\ngpgcheck=1\nusername=flota\npriority=10\n\n" +
		"[stare]\nname=Stare\nbaseurl=https://stare.example.test/rpm\nenabled=0\ngpgcheck=0\n"

	zrodla := czytajSekcjeDNF("/etc/yum.repos.d/wewnetrzne.repo", tresc)
	if len(zrodla) != 2 {
		t.Fatalf("rozpoznano %d zrodel: %+v", len(zrodla), zrodla)
	}
	if !zrodla[0].Managed || zrodla[0].SecretName != "repo.haslo" {
		t.Errorf("zrodlo panelu opisane jako %+v", zrodla[0])
	}
	if !zrodla[0].Enabled || !zrodla[0].Signed || zrodla[0].Username != "flota" {
		t.Errorf("stan zrodla odczytany jako %+v", zrodla[0])
	}
	if zrodla[1].Enabled || zrodla[1].Signed {
		t.Errorf("wylaczone zrodlo bez podpisow odczytane jako %+v", zrodla[1])
	}
}

func TestCzytajZrodloListyRozpoznajeKlucz(t *testing.T) {
	// Wpis jednoliniowy zostawiamy dystrybucji, ale musimy go umiec
	// przeczytac: to on opisuje zrodla, ktorych panel nie zapisywal.
	zrodla := czytajZrodloListyZTresci("/etc/apt/sources.list.d/obce.list",
		"# komentarz\ndeb [signed-by=/usr/share/keyrings/obce.gpg] https://obce.example.test/debian stable main contrib\n"+
			"deb http://bez-klucza.example.test/debian stable main\n")
	if len(zrodla) != 2 {
		t.Fatalf("rozpoznano %d zrodel: %+v", len(zrodla), zrodla)
	}
	if !zrodla[0].Signed || zrodla[0].URL != "https://obce.example.test/debian" {
		t.Errorf("zrodlo z kluczem odczytane jako %+v", zrodla[0])
	}
	if zrodla[0].Suites[0] != "stable" || len(zrodla[0].Components) != 2 {
		t.Errorf("suite i komponenty odczytane jako %+v", zrodla[0])
	}
	if zrodla[1].Signed {
		t.Errorf("zrodlo bez klucza odczytane jako podpisane: %+v", zrodla[1])
	}
}

func TestPierwszyBladAPTCzytaOstrzezenieJakoBlad(t *testing.T) {
	// apt konczy sie kodem zero takze wtedy, gdy indeksu nie udalo sie
	// pobrac. Dla panelu to nie jest ostrzezenie: zrodlo, ktore nie
	// odpowiada, zablokuje kazda nastepna operacje pakietowa na hoscie.
	wyjscie := "Get:1 https://pakiety.example.test/debian stable InRelease\n" +
		"Err:1 https://pakiety.example.test/debian stable InRelease\n" +
		"  Temporary failure resolving 'pakiety.example.test'\n" +
		"W: Some index files failed to download.\n"
	if linia := pierwszyBladAPT(wyjscie); linia == "" {
		t.Fatal("nieudane pobranie indeksu zostalo przemilczane")
	}
	if pierwszyBladAPT("Get:1 https://pakiety.example.test/debian stable InRelease\nFetched 1 B\n") != "" {
		t.Fatal("poprawne pobranie uznano za blad")
	}
}

func TestPierwszyBladDNFCzytaOstrzezenieJakoBlad(t *testing.T) {
	// dnf konczy sie kodem zero i komunikatem "Metadata cache created" takze
	// wtedy, gdy zadnego adresu zrodla nie dalo sie otworzyc.
	dnf5 := ">>> Curl error (6): Could not resolve hostname for https://pakiety.example.test/\n" +
		">>> Usable URL not found\nRepositories loaded.\nMetadata cache created.\n"
	if pierwszyBladDNF(dnf5) == "" {
		t.Fatal("nieudane pobranie metadanych (dnf5) zostalo przemilczane")
	}
	dnf4 := "Errors during downloading metadata for repository 'wewnetrzne':\n" +
		"  - Curl error (6): Couldn't resolve host name\n"
	if pierwszyBladDNF(dnf4) == "" {
		t.Fatal("nieudane pobranie metadanych (dnf4) zostalo przemilczane")
	}
	if pierwszyBladDNF("Repositories loaded.\nMetadata cache created.\n") != "" {
		t.Fatal("poprawne pobranie uznano za blad")
	}
}
