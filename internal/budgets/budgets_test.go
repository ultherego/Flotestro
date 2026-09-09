package budgets

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/opspec"
)

// TestPotrzebyRozrozniajaOdczytIMutacje pilnuje granicy, dla ktorej te budzety
// w ogole istnieja: sto odczytow stanu to nie to samo obciazenie co sto
// transakcji pakietowych.
func TestPotrzebyRozrozniajaOdczytIMutacje(t *testing.T) {
	odczyt := Potrzeby(opspec.ActionPackageList, "warsaw")
	if len(odczyt) != 1 || odczyt[0].Klucz != KluczGlobalneOdczyty {
		t.Fatalf("odczyt obciaza budzety %+v", odczyt)
	}

	mutacja := Potrzeby(opspec.ActionPackageUpgrade, "warsaw")
	if len(mutacja) != 2 {
		t.Fatalf("transakcja pakietowa obciaza budzety %+v", mutacja)
	}
	if mutacja[0].Klucz != KluczGlobalneMutacje {
		t.Errorf("transakcja poza budzetem mutacji: %+v", mutacja)
	}
	if mutacja[1].Klucz != "site:warsaw:packages" {
		t.Errorf("transakcja poza budzetem lokalizacji: %+v", mutacja)
	}
}

// TestRestartMaWlasnaRodzineLokalizacji pilnuje operacji, ktora nie ma klasy
// blokady, bo zabiera caly host - a mimo to jest tym, czego w jednej
// lokalizacji nie chcemy robic dziesiec razy naraz.
func TestRestartMaWlasnaRodzineLokalizacji(t *testing.T) {
	if rodzina := RodzinaLokalizacji(opspec.ActionSystemReboot); rodzina != "reboot" {
		t.Fatalf("restart w rodzinie %q", rodzina)
	}
	potrzeby := Potrzeby(opspec.ActionSystemReboot, "warsaw")
	if len(potrzeby) != 2 || potrzeby[1].Klucz != "site:warsaw:reboot" {
		t.Fatalf("restart obciaza budzety %+v", potrzeby)
	}
}

// TestHostBezLokalizacjiNieDostajeKluczaZDziura pilnuje, zeby brak lokalizacji
// nie zamienil sie w klucz "site::packages" - czyli w jeden wspolny budzet
// dla wszystkich hostow, ktorych nikt nie przypisal.
func TestHostBezLokalizacjiNieDostajeKluczaZDziura(t *testing.T) {
	potrzeby := Potrzeby(opspec.ActionPackageUpgrade, "")
	if len(potrzeby) != 1 || potrzeby[0].Klucz != KluczGlobalneMutacje {
		t.Fatalf("host bez lokalizacji obciaza budzety %+v", potrzeby)
	}
}

// TestWzorzecOpisujeKazdaLokalizacje pilnuje polityki domyslnej: lokalizacji
// jest tyle, ile ich zalozono, i nikt nie opisuje kazdej z osobna.
func TestWzorzecOpisujeKazdaLokalizacje(t *testing.T) {
	if wzorzec := Wzorzec("site:warsaw:packages"); wzorzec != "site:*:packages" {
		t.Errorf("wzorzec = %q", wzorzec)
	}
	// Klucz globalny nie ma czesci zmiennej, wiec nie ma tez wzorca.
	if wzorzec := Wzorzec(KluczGlobalneMutacje); wzorzec != "" {
		t.Errorf("klucz globalny dostal wzorzec %q", wzorzec)
	}
}

// TestAwansZalezyOdKlasy pilnuje, ze priorytet naprawde cos znaczy: operacja
// pilna przestaje byc ograniczana udzialem szybciej niz kampania w tle.
func TestAwansZalezyOdKlasy(t *testing.T) {
	kolejnosc := []Klasa{KlasaIncydent, KlasaInterakcja, KlasaUtrzymanie, KlasaTlo}
	poprzedni := time.Duration(-1)
	for _, klasa := range kolejnosc {
		wiek := klasa.WiekAwansu()
		if wiek <= poprzedni {
			t.Errorf("klasa %s czeka %s, a mniej pilna %s", klasa, wiek, poprzedni)
		}
		poprzedni = wiek
	}
	if KlasaIncydent.WiekAwansu() != 0 {
		t.Error("incydent czeka na awans, zamiast dostac go od razu")
	}
}

// TestOdmowaNazywaPrzeszkode pilnuje doktryny: odmowa bez powodu jest cisza,
// a cisza jest najgorsza odpowiedzia.
func TestOdmowaNazywaPrzeszkode(t *testing.T) {
	if !(Odmowa{}).Pusta() {
		t.Fatal("pusta odmowa nie jest pusta")
	}
	pojemnosc := Odmowa{Klucz: "site:warsaw:packages", Powod: PowodPojemnosc,
		Zajete: 5, Pojemnosc: 5, Czeka: 12 * time.Second}
	opis := pojemnosc.Opis()
	for _, fragment := range []string{"site:warsaw:packages", "5", "12s"} {
		if !zawiera(opis, fragment) {
			t.Errorf("opis %q nie mowi o %q", opis, fragment)
		}
	}

	udzial := Odmowa{Klucz: KluczGlobalneMutacje, Powod: PowodUdzial,
		Pojemnosc: 50, Udzial: 25, Trzymane: 25}
	// Odmowa udzialu i odmowa pojemnosci to dwie rozne sytuacje: przy
	// pierwszej tokeny sa wolne, tylko nie dla tego roszczacego.
	if udzial.Opis() == pojemnosc.Opis() {
		t.Error("obie odmowy brzmia tak samo")
	}
	if !zawiera(udzial.Opis(), "25") {
		t.Errorf("odmowa udzialu nie podaje liczb: %q", udzial.Opis())
	}
}

func zawiera(tekst, fragment string) bool {
	for i := 0; i+len(fragment) <= len(tekst); i++ {
		if tekst[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
