package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefinicjaWalidujePodstawy(t *testing.T) {
	podstawa := Definicja{
		ID: "nocna", Tool: NarzedzieRestic, Repository: "/srv/backup",
		Paths: []string{"/etc", "/var/lib/app"}, KeepLast: 7,
	}
	if err := podstawa.Waliduj(); err != nil {
		t.Fatalf("poprawna definicja odrzucona: %v", err)
	}

	zle := map[string]Definicja{
		"bez identyfikatora":         {Tool: NarzedzieRestic, Repository: "/srv/backup"},
		"identyfikator z ukosnikiem": {ID: "a/b", Tool: NarzedzieRestic, Repository: "/srv/backup"},
		"nieznane narzedzie":         {ID: "nocna", Tool: "tar", Repository: "/srv/backup"},
		"bez repozytorium":           {ID: "nocna", Tool: NarzedzieRestic},
		"sciezka wzgledna":           {ID: "nocna", Tool: NarzedzieRestic, Repository: "/srv/backup", Paths: []string{"etc"}},
		"runbook bez nazwy":          {ID: "nocna", Tool: NarzedzieRunbook},
		"runbook z ukosnikiem":       {ID: "nocna", Tool: NarzedzieRunbook, Runbook: "../etc/passwd"},
	}
	for nazwa, definicja := range zle {
		if err := definicja.Waliduj(); err == nil {
			t.Errorf("%s: definicja zostala przyjeta", nazwa)
		}
	}
}

func TestWalidujOdtworzenieWymagaCeluIPlanu(t *testing.T) {
	dobre := Odtworzenie{SnapshotID: "abc123", Target: "/srv/odtworzenie", Overwrite: NadpisaniePuste}
	if err := WalidujOdtworzenie(dobre); err != nil {
		t.Fatalf("poprawne odtworzenie odrzucone: %v", err)
	}

	// Odtworzenie wprost do systemu plikow hosta rozpakowuje stary stan na
	// dzialajacym systemie - i to jest inna operacja niz odtworzenie kopii.
	// Osobno stoi prywatny /tmp pomocnika: tam operacja konczy sie sukcesem
	// i pustym katalogiem, czyli najgorsza z mozliwych odpowiedzi.
	for _, cel := range []string{
		"/", "/etc", "/etc/nginx", "/usr/local", "/var", "/home", "/root",
		"/tmp/kopia", "/var/tmp/kopia", "/var/lib/flotestro/dane",
	} {
		zle := dobre
		zle.Target = cel
		if err := WalidujOdtworzenie(zle); err == nil {
			t.Errorf("odtworzenie do %s zostalo przyjete", cel)
		}
	}
	// Wnetrze katalogow domowych i /srv jest zwyczajnym miejscem na dane.
	for _, cel := range []string{"/home/anna/kopia", "/srv/odtworzenie", "/var/lib/kopie"} {
		dobry := dobre
		dobry.Target = cel
		if err := WalidujOdtworzenie(dobry); err != nil {
			t.Errorf("odtworzenie do %s odrzucone: %v", cel, err)
		}
	}
	// Bez planu nadpisania skutek operacji jest nieznany.
	bezPlanu := dobre
	bezPlanu.Overwrite = ""
	if err := WalidujOdtworzenie(bezPlanu); err == nil {
		t.Error("odtworzenie bez planu nadpisania zostalo przyjete")
	}
	bezKopii := dobre
	bezKopii.SnapshotID = ""
	if err := WalidujOdtworzenie(bezKopii); err == nil {
		t.Error("odtworzenie bez wskazania kopii zostalo przyjete")
	}
	wzgledny := dobre
	wzgledny.Target = "var/tmp/x"
	if err := WalidujOdtworzenie(wzgledny); err == nil {
		t.Error("odtworzenie do sciezki wzglednej zostalo przyjete")
	}
	wyzej := dobre
	wyzej.Target = "/var/tmp/../../etc"
	if err := WalidujOdtworzenie(wyzej); err == nil {
		t.Error("cel wychodzacy poza katalog zostal przyjety")
	}
}

func TestSprawdzCelPilnujePlanuNadpisania(t *testing.T) {
	katalog := t.TempDir()
	pusty := filepath.Join(katalog, "pusty")
	if err := os.Mkdir(pusty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SprawdzCel(Odtworzenie{Target: pusty, Overwrite: NadpisaniePuste}); err != nil {
		t.Fatalf("pusty katalog odrzucony: %v", err)
	}

	zajety := filepath.Join(katalog, "zajety")
	if err := os.Mkdir(zajety, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(zajety, "plik"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SprawdzCel(Odtworzenie{Target: zajety, Overwrite: NadpisaniePuste}); err == nil {
		t.Fatal("odtworzenie do niepustego katalogu przeszlo mimo planu 'pusty'")
	}
	if err := SprawdzCel(Odtworzenie{Target: zajety, Overwrite: NadpisanieDozwolone}); err != nil {
		t.Fatalf("odtworzenie z jawna zgoda na nadpisanie odrzucone: %v", err)
	}

	// Katalogu nie tworzymy w polowie drzewa: literowka nie moze zalozyc
	// katalogu w losowym miejscu.
	if err := SprawdzCel(Odtworzenie{
		Target: filepath.Join(katalog, "nie", "ma", "takiego"), Overwrite: NadpisaniePuste,
	}); err == nil {
		t.Fatal("cel z nieistniejacym rodzicem zostal przyjety")
	}
}

func TestZaslonUsuwaPoswiadczeniaZWyjscia(t *testing.T) {
	wyjscie := "repository /srv/backup opened with password tajne-haslo-repozytorium\n" +
		"pushing to https://uzytkownik:tajne-haslo-repozytorium@backup.example.test/repo\n"
	zaslonione := Zaslon(wyjscie, [][]byte{[]byte("tajne-haslo-repozytorium")})
	if strings.Contains(zaslonione, "tajne-haslo-repozytorium") {
		t.Fatalf("haslo zostalo w wyjsciu:\n%s", zaslonione)
	}
	if !strings.Contains(zaslonione, "https://uzytkownik:[zasloniete]@backup.example.test/repo") {
		t.Fatalf("adres z poswiadczeniami nie zostal zasloniety:\n%s", zaslonione)
	}

	// Poswiadczenia w adresie zaslaniamy takze wtedy, gdy panel ich nie zna:
	// haslo moze byc wpisane w sam adres repozytorium.
	nieznane := Zaslon("https://user:sekret-z-adresu@host/repo", nil)
	if strings.Contains(nieznane, "sekret-z-adresu") {
		t.Fatalf("haslo z adresu zostalo w wyjsciu: %s", nieznane)
	}
}

func TestOgraniczZostawiaKoniecWyjscia(t *testing.T) {
	// Koniec wyjscia jest wazniejszy niz poczatek: tam sa bledy
	// i podsumowanie operacji.
	dlugie := strings.Repeat("a", MaksymalneWyjscie) + "KONIEC"
	przyciete := Ogranicz(dlugie)
	if len(przyciete) > MaksymalneWyjscie+64 {
		t.Fatalf("wyjscie po przycieciu ma %d bajtow", len(przyciete))
	}
	if !strings.HasSuffix(przyciete, "KONIEC") {
		t.Fatal("przyciete wyjscie nie konczy sie tam, gdzie oryginal")
	}
}

func TestOstatniUdanyBierzeNajnowszaKopie(t *testing.T) {
	teraz := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	snapshoty := []Snapshot{
		{ID: "a", Time: teraz.Add(-72 * time.Hour)},
		{ID: "c", Time: teraz.Add(-2 * time.Hour)},
		{ID: "b", Time: teraz.Add(-24 * time.Hour)},
	}
	PosortujSnapshoty(snapshoty)
	if snapshoty[0].ID != "a" || snapshoty[2].ID != "c" {
		t.Fatalf("kopie posortowane jako %+v", snapshoty)
	}
	ostatni := OstatniUdany(snapshoty)
	if ostatni == nil || !ostatni.Equal(teraz.Add(-2*time.Hour)) {
		t.Fatalf("ostatnia kopia = %v", ostatni)
	}
	// Repozytorium bez kopii nie ma daty ostatniej kopii - i to nie jest
	// data zerowa, tylko jej brak.
	if OstatniUdany(nil) != nil {
		t.Fatal("puste repozytorium dostalo date ostatniej kopii")
	}
}

func TestWalidujSrodowiskoPilnujeNazwZmiennych(t *testing.T) {
	if err := WalidujSrodowisko([]string{"AWS_ACCESS_KEY_ID", "B2_ACCOUNT_KEY"}); err != nil {
		t.Fatalf("poprawne nazwy odrzucone: %v", err)
	}
	for _, nazwa := range []string{"", "male", "ZE SPACJA", "PATH=x", "A;B"} {
		if err := WalidujSrodowisko([]string{nazwa}); err == nil {
			t.Errorf("nazwa %q zostala przyjeta", nazwa)
		}
	}
}

func TestRunbookOdmawiaSkryptowiZapisywalnemuPozaRootem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test sprawdza odmowe dla cudzego pliku; jako root kazdy plik jest wlasny")
	}
	runbook := &Runbook{}
	// Nazwa spoza wzorca odpada bez dotykania dysku.
	if _, err := runbook.Sciezka("../../etc/shadow"); err == nil {
		t.Fatal("nazwa wychodzaca z katalogu zostala przyjeta")
	}
	// Plik, ktorego nie ma, tez jest odmowa - panel nie tworzy runbookow.
	if _, err := runbook.Sciezka("na-pewno-nie-ma-takiego"); err == nil {
		t.Fatal("nieistniejacy runbook zostal przyjety")
	}
}
