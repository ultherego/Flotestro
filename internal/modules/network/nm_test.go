package network

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Wyjscie przepisane z hosta floty testowej.
const wyjsciePolaczen = `enp0s3:4a0293d8-8529-4912-947a-ad53f52d9c76:enp0s3:802-3-ethernet:activated
enp0s8:071696f0-9e5f-477c-a92c-0da64a4e0fd9:enp0s8:802-3-ethernet:activated
lo:b4b1089d-07af-4228-8df8-5d3e9342825c:lo:loopback:activated`

const wyjscieProfilu = `connection.id:enp0s8
connection.interface-name:enp0s8
ipv4.method:manual
ipv4.addresses:192.168.56.40/24
ipv4.gateway:192.168.56.1
ipv4.dns:
ipv4.routes:
802-3-ethernet.mtu:auto`

func TestProfilCzytaUstawieniaPolaczenia(t *testing.T) {
	profil := ParsujProfil(wyjscieProfilu)
	if profil.Polaczenie != "enp0s8" || profil.Metoda != "manual" {
		t.Fatalf("profil = %+v", profil)
	}
	if len(profil.Adresy) != 1 || profil.Adresy[0] != "192.168.56.40/24" {
		t.Errorf("adresy = %v", profil.Adresy)
	}
	// Puste pole to brak ustawienia, a nie pusty napis w konfiguracji.
	if len(profil.DNS) != 0 || len(profil.Trasy) != 0 {
		t.Errorf("puste pola zamienione w wartosci: %+v", profil)
	}
	// "auto" jest rownoprawna wartoscia MTU i nie moze stac sie zerem.
	if profil.MTU != MTUAuto {
		t.Errorf("MTU = %q", profil.MTU)
	}
}

// Adres IPv6 zawiera dwukropki, wiec wartosc jest wszystkim po pierwszym
// z nich. Podzial po kazdym rozbilby adres na kawalki.
func TestWartoscZDwukropkamiNieJestDzielona(t *testing.T) {
	profil := ParsujProfil("ipv4.dns:fd00::1,fd00::2\nconnection.id:test")
	if len(profil.DNS) != 2 || profil.DNS[0] != "fd00::1" {
		t.Fatalf("DNS = %v", profil.DNS)
	}
}

func TestPolaczenieJestSzukanePoUrzadzeniu(t *testing.T) {
	polaczenia := ParsujPolaczenia(wyjsciePolaczen)
	if len(polaczenia) != 3 {
		t.Fatalf("polaczen = %d", len(polaczenia))
	}
	if polaczenie := PolaczenieUrzadzenia(polaczenia, "enp0s8"); polaczenie == nil ||
		polaczenie.Nazwa != "enp0s8" {
		t.Errorf("polaczenie enp0s8 = %+v", polaczenie)
	}
	if PolaczenieUrzadzenia(polaczenia, "eth9") != nil {
		t.Error("znaleziono polaczenie dla nieistniejacego urzadzenia")
	}
}

// Wartosci, ktore odcielyby host albo nie sa konfiguracja, maja byc odrzucone
// przed dotknieciem hosta.
func TestZlaKonfiguracjaJestOdrzucana(t *testing.T) {
	if err := WalidujMTU("900"); err == nil {
		t.Error("przyjeto MTU ponizej progu IPv6")
	}
	if err := WalidujMTU(MTUAuto); err != nil {
		t.Errorf("odrzucono MTU auto: %v", err)
	}
	if err := WalidujTrase("192.168.9.0/24 192.168.56.1 extra"); err == nil {
		t.Error("przyjeto trase z nadmiarowym polem")
	}
	if err := WalidujTrase("192.168.9.0 192.168.56.1"); err == nil {
		t.Error("przyjeto cel trasy bez maski")
	}
	if err := WalidujTrase("192.168.9.0/24"); err != nil {
		t.Errorf("odrzucono trase bez bramy: %v", err)
	}
	// Metoda manual bez adresu zostawilaby interfejs bez adresu - to nie
	// jest konfiguracja, tylko pomylka.
	if _, err := ArgumentyProfilu(Profil{Polaczenie: "enp0s8", Metoda: "manual"}); err == nil {
		t.Error("przyjeto profil manual bez adresow")
	}
}

func TestArgumentyZmianyIdaPrzezProfil(t *testing.T) {
	kroki, err := ArgumentyMTU("enp0s8", "1400")
	if err != nil {
		t.Fatal(err)
	}
	if len(kroki) != 2 {
		t.Fatalf("krokow = %d", len(kroki))
	}
	// Zmiana ustawiona wprost na urzadzeniu znika przy przelaczeniu
	// polaczenia; profil przezywa restart hosta.
	if strings.Join(kroki[0], " ") !=
		SciezkaNmcli+" connection modify enp0s8 802-3-ethernet.mtu 1400" {
		t.Errorf("krok modyfikacji = %v", kroki[0])
	}
	if kroki[1][len(kroki[1])-1] != "enp0s8" || kroki[1][2] != "up" {
		t.Errorf("krok aktywacji = %v", kroki[1])
	}
}

// Plan wycofania opisuje stan, a nie polecenia: plik, ktorym da sie sterowac
// wykonaniem, bylby furtka do roota.
func TestPlanWycofaniaWracaDoStanuSprzedZmiany(t *testing.T) {
	katalog := t.TempDir()
	plan := PlanWycofania{
		ID:        "test-planu",
		Interfejs: "enp0s8",
		Profil:    ParsujProfil(wyjscieProfilu),
		Utworzony: time.Now().UTC(),
		Termin:    time.Now().UTC().Add(2 * time.Minute),
	}
	if err := ZapiszPlan(katalog, plan); err != nil {
		t.Fatal(err)
	}
	odczytany, err := WczytajPlan(katalog, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	kroki, err := KrokiWycofania(odczytany)
	if err != nil {
		t.Fatal(err)
	}
	polecenie := strings.Join(kroki[0], " ")
	if !strings.Contains(polecenie, "ipv4.addresses 192.168.56.40/24") ||
		!strings.Contains(polecenie, "ipv4.method manual") {
		t.Errorf("wycofanie nie przywraca stanu: %v", kroki[0])
	}

	if err := UsunPlan(katalog, plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := WczytajPlan(katalog, plan.ID); err == nil {
		t.Error("plan przetrwal usuniecie")
	}
}

// Identyfikator planu jest czescia nazwy pliku, wiec nie moze wyprowadzic
// sciezki poza katalog planow.
func TestIdentyfikatorPlanuNieWychodziZKatalogu(t *testing.T) {
	for _, id := range []string{"", "../etc/passwd", "plan/../../x", "PLAN", "plan.json"} {
		if PoprawnyIdentyfikatorPlanu(id) {
			t.Errorf("przyjeto identyfikator %q", id)
		}
		if _, err := SciezkaPlanu("/var/lib", id); err == nil {
			t.Errorf("zlozono sciezke dla %q", id)
		}
	}
	sciezka, err := SciezkaPlanu("/var/lib", "plan-1")
	if err != nil || filepath.Dir(sciezka) != "/var/lib" {
		t.Errorf("sciezka = %q, err = %v", sciezka, err)
	}
}
