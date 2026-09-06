package redhat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestZmianyBioraTylkoNowszePliki(t *testing.T) {
	spis := `"2026/cve-2026-0003.json","2026-09-06T08:35:48+00:00"
"2026/cve-2026-0002.json","2026-09-05T10:00:00+00:00"
"2025/cve-2025-0001.json","2026-08-01T10:00:00+00:00"
`
	po, _ := time.Parse(time.RFC3339, "2026-09-05T00:00:00Z")
	pliki, najnowszy, err := Zmiany(strings.NewReader(spis), po)
	if err != nil {
		t.Fatalf("spis zmian: %v", err)
	}
	if len(pliki) != 2 {
		t.Fatalf("plikow do pobrania = %v", pliki)
	}
	if !najnowszy.Equal(time.Date(2026, 9, 6, 8, 35, 48, 0, time.UTC)) {
		t.Fatalf("najnowszy znacznik = %s", najnowszy)
	}
	// Znacznik zerowy znaczy "nie mamy nic": wtedy bierzemy caly spis.
	wszystkie, _, err := Zmiany(strings.NewReader(spis), time.Time{})
	if err != nil || len(wszystkie) != 3 {
		t.Fatalf("caly spis = %v (%v)", wszystkie, err)
	}
}

func TestSciezkaDokumentuNieWychodziZKatalogu(t *testing.T) {
	przypadki := map[string]string{
		"2026/cve-2026-0001.json":          "2026/cve-2026-0001.json",
		"./2026/cve-2026-0001.json":        "2026/cve-2026-0001.json",
		"csaf/v2/vex/2026/cve-2026-1.json": "2026/cve-2026-1.json",
		"../../etc/passwd.json":            "",
		"/etc/passwd.json":                 "",
		"2026/cve-2026-0001.txt":           "",
		"cve-2026-0001.json":               "",
		"2026/../../etc/cve-x.json":        "",
		"changes.csv":                      "",
	}
	for wejscie, chcemy := range przypadki {
		if mamy := sciezkaDokumentu(wejscie); mamy != chcemy {
			t.Errorf("%q -> %q, chcemy %q", wejscie, mamy, chcemy)
		}
	}
}

func TestDataArchiwumZNazwy(t *testing.T) {
	chwila := DataArchiwum("csaf_vex_2026-08-30.tar.zst")
	if !chwila.Equal(time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("data archiwum = %s", chwila)
	}
	// Nazwa bez daty ma dac czas zerowy, a nie dzisiejszy: inaczej panel
	// uznalby za odczytane wszystko, czego nigdy nie widzial.
	if !DataArchiwum("csaf_vex_latest.tar.zst").IsZero() {
		t.Fatal("nazwa bez daty dala niezerowy znacznik")
	}
}

func TestZapisPrzezywaRestart(t *testing.T) {
	katalog := t.TempDir()
	zrodlo := Nowe("", katalog, time.Minute)
	zrodlo.wydania = map[string]bool{"9": true}
	if err := zrodlo.przyjmij("2026/cve-2026-1234.json", []byte(przykladVEX)); err != nil {
		t.Fatalf("czytanie dokumentu: %v", err)
	}
	zrodlo.archiwum = "csaf_vex_2026-08-30.tar.zst"
	zrodlo.znacznik = time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	if err := zrodlo.zapisz(); err != nil {
		t.Fatalf("zapis stanu: %v", err)
	}
	pierwsze, _, err := zrodlo.zbierz()
	if err != nil {
		t.Fatalf("odczyt ustalen: %v", err)
	}
	if len(pierwsze) == 0 {
		t.Fatal("zapis nie ma ani jednego ustalenia")
	}

	drugie := Nowe("", katalog, time.Minute)
	stan, err := drugie.wczytajStan()
	if err != nil {
		t.Fatalf("odczyt stanu: %v", err)
	}
	if stan.Archiwum != zrodlo.archiwum || !stan.Znacznik.Equal(zrodlo.znacznik) {
		t.Fatalf("stan po restarcie = %+v", stan)
	}
	if !pokrywa(zbiorWydan(stan.Wydania), map[string]bool{"9": true}) {
		t.Fatalf("stan nie mowi, dla ktorych wydan zbudowano zapis: %+v", stan)
	}
	drugie.wydania = map[string]bool{"9": true}
	po, objete, err := drugie.zbierz()
	if err != nil {
		t.Fatalf("odczyt po restarcie: %v", err)
	}
	if len(po) != len(pierwsze) || !objete["9"] {
		t.Fatalf("po restarcie ustalen = %d, wydania = %v", len(po), objete)
	}
}

func TestDokumentBezRHELaNieZajmujeMiejsca(t *testing.T) {
	katalog := t.TempDir()
	zrodlo := Nowe("", katalog, time.Minute)
	// Dokument o dziewiatce czytany dla dziesiatki nie ma nic do powiedzenia.
	zrodlo.wydania = map[string]bool{"10": true}
	if err := zrodlo.przyjmij("2026/cve-2026-1234.json", []byte(przykladVEX)); err != nil {
		t.Fatalf("czytanie dokumentu: %v", err)
	}
	if _, err := os.Stat(filepath.Join(katalog, "dokumenty", "2026", "cve-2026-1234.json")); !os.IsNotExist(err) {
		t.Fatal("dokument bez ustalen zajal miejsce w zapisie")
	}
}

func TestUszkodzonyZapisNieUdajeKompletu(t *testing.T) {
	katalog := t.TempDir()
	zrodlo := Nowe("", katalog, time.Minute)
	zrodlo.wydania = map[string]bool{"9": true}
	if err := zrodlo.przyjmij("2026/cve-2026-1234.json", []byte(przykladVEX)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(katalog, "dokumenty", "2026", "cve-2026-9999.json"),
		[]byte("[{urwane"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Polowa danych wygladalaby jak komplet i host wyszedlby czysty, wiec
	// uszkodzony zapis jest bledem pobrania, a nie mniejszym zestawem.
	if _, _, err := zrodlo.zbierz(); err == nil {
		t.Fatal("uszkodzony zapis przeszedl jako komplet")
	}
}

func TestPamiecDlaWezszychWydanNieWystarcza(t *testing.T) {
	// Pamiec zbudowana dla dziewiatki nie opisuje dziesiatki - i nie wolno
	// jej uznac za pelna, bo hosty nowego wydania wygladalyby na czyste.
	if pokrywa(map[string]bool{"9": true}, map[string]bool{"9": true, "10": true}) {
		t.Error("wezszy zbior wydan uznany za wystarczajacy")
	}
	if !pokrywa(map[string]bool{"9": true, "10": true}, map[string]bool{"9": true}) {
		t.Error("szerszy zbior wydan uznany za niewystarczajacy")
	}
	if pokrywa(nil, map[string]bool{"9": true}) {
		t.Error("pusta pamiec uznana za wystarczajaca")
	}
}

func TestCzytamyTylkoWskazaneWydania(t *testing.T) {
	ustalenia, err := Ustalenia([]byte(przykladVEX), map[string]bool{"10": true})
	if err != nil {
		t.Fatalf("czytanie dokumentu: %v", err)
	}
	if len(ustalenia) != 0 {
		t.Fatalf("dokument o dziewiatce dal %d ustalen dla dziesiatki", len(ustalenia))
	}
	dziewiatka, err := Ustalenia([]byte(przykladVEX), map[string]bool{"9": true})
	if err != nil {
		t.Fatalf("czytanie dokumentu: %v", err)
	}
	if len(dziewiatka) == 0 {
		t.Fatal("dokument o dziewiatce nie dal ani jednego ustalenia")
	}
}
