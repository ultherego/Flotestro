package firewall

import (
	"strings"
	"testing"
)

func TestRegulaSkladaSieZPolAKtorePanelRozumie(t *testing.T) {
	regula := RuleSpec{
		ID: "panel-8443", Chain: LancuchWejscie, Action: DzialanieAccept,
		Protocol: "tcp", Ports: []string{"8443", "9000-9010"},
		Sources: []string{"192.168.56.0/24"}, Comment: "kanal zarzadzania",
	}
	argumenty, err := ArgumentyReguly(regula)
	if err != nil {
		t.Fatal(err)
	}
	polecenie := strings.Join(argumenty, " ")
	// Regula trafia wylacznie do tablicy panelu: cudze lancuchy sa
	// przepisywane bez naszego udzialu.
	if !strings.Contains(polecenie, "add rule inet flotestro wejscie") {
		t.Errorf("polecenie = %q", polecenie)
	}
	if !strings.Contains(polecenie, "ip saddr 192.168.56.0/24") {
		t.Errorf("brak dopasowania zrodla: %q", polecenie)
	}
	if !strings.Contains(polecenie, "tcp dport { 8443, 9000-9010 }") {
		t.Errorf("brak portow: %q", polecenie)
	}
	// Licznik jest zawsze: bez niego regula nie odpowiada na pytanie, czy
	// cokolwiek przez nia przeszlo.
	if !strings.Contains(polecenie, "counter accept") {
		t.Errorf("brak licznika: %q", polecenie)
	}
	if !strings.Contains(polecenie, PrefiksKomentarza) {
		t.Errorf("regula bez znacznika wlasnosci: %q", polecenie)
	}
}

func TestZlaRegulaJestOdrzucana(t *testing.T) {
	przypadki := []struct {
		regula   RuleSpec
		dlaczego string
	}{
		{RuleSpec{ID: "Zla Nazwa", Chain: LancuchWejscie, Action: DzialanieAccept, Protocol: "tcp", Ports: []string{"22"}}, "nazwa z odstepem"},
		{RuleSpec{ID: "test", Chain: "PREROUTING", Action: DzialanieAccept, Protocol: "tcp", Ports: []string{"22"}}, "cudzy lancuch"},
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: "log", Protocol: "tcp", Ports: []string{"22"}}, "nieznane dzialanie"},
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: DzialanieDrop, Protocol: "tcp", Ports: []string{"0"}}, "port zero"},
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: DzialanieDrop, Protocol: "tcp", Ports: []string{"100-50"}}, "pusty zakres"},
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: DzialanieDrop, Sources: []string{"10.0.0.1"}}, "zrodlo bez maski"},
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: DzialanieDrop, Protocol: "tcp", Ports: []string{"22"}, Comment: `a" drop; #`}, "komentarz z cudzyslowem"},
		// Regula bez dopasowania obejmuje caly ruch; to osobna decyzja,
		// a nie skutek pustego formularza.
		{RuleSpec{ID: "test", Chain: LancuchWejscie, Action: DzialanieDrop}, "regula bez dopasowania"},
	}
	for _, przypadek := range przypadki {
		if _, err := ArgumentyReguly(przypadek.regula); err == nil {
			t.Errorf("przyjeto regule: %s", przypadek.dlaczego)
		}
	}
}

// Kanal zarzadzania jest jedyna rzecza, ktorej nie wolno stracic: bez niego
// host przestaje odpowiadac i nie ma czym cofnac zmiany.
func TestRegulaNieMozeOdciacPanelu(t *testing.T) {
	const panel = "192.168.56.10"
	const port = 8443

	blokujacePort := RuleSpec{ID: "blok", Chain: LancuchWejscie, Action: DzialanieDrop,
		Protocol: "tcp", Ports: []string{"8000-9000"}}
	if err := ChroniKanalZarzadzania(blokujacePort, panel, port); err == nil {
		t.Error("przyjeto regule obejmujaca port zarzadzania")
	}

	blokujaceZrodlo := RuleSpec{ID: "blok", Chain: LancuchWejscie, Action: DzialanieDrop,
		Sources: []string{"192.168.56.0/24"}}
	if err := ChroniKanalZarzadzania(blokujaceZrodlo, panel, port); err == nil {
		t.Error("przyjeto regule obejmujaca adres panelu")
	}

	// Regula przepuszczajaca niczego nie odcina.
	przepuszczajaca := RuleSpec{ID: "ok", Chain: LancuchWejscie, Action: DzialanieAccept,
		Protocol: "tcp", Ports: []string{"8443"}}
	if err := ChroniKanalZarzadzania(przepuszczajaca, panel, port); err != nil {
		t.Errorf("odrzucono regule przepuszczajaca: %v", err)
	}

	// Blokada innego portu z innej sieci nie dotyka kanalu zarzadzania.
	inna := RuleSpec{ID: "ok", Chain: LancuchWejscie, Action: DzialanieDrop,
		Protocol: "tcp", Ports: []string{"25"}, Sources: []string{"10.10.0.0/16"}}
	if err := ChroniKanalZarzadzania(inna, panel, port); err != nil {
		t.Errorf("odrzucono regule niezwiazana z panelem: %v", err)
	}
}

func TestUsuniecieDotyczyTylkoWlasnychLancuchow(t *testing.T) {
	if _, err := ArgumentyUsuniecia("POSTROUTING", 5); err == nil {
		t.Error("przyjeto usuniecie z cudzego lancucha")
	}
	if _, err := ArgumentyUsuniecia(LancuchWejscie, 0); err == nil {
		t.Error("przyjeto usuniecie bez uchwytu")
	}
	argumenty, err := ArgumentyUsuniecia(LancuchWejscie, 7)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argumenty, " ") != SciezkaNft+" delete rule inet flotestro wejscie handle 7" {
		t.Errorf("polecenie = %v", argumenty)
	}
}

// Wyjscie przepisane z hosta floty testowej.
const wyjscieStref = `FedoraServer (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 
  rich rules: 

block
  target: %%REJECT%%
  interfaces: 
  services: 
  ports: 8443/tcp 9000/udp
`

func TestStrefyOpisujaDostepPoInterfejsach(t *testing.T) {
	strefy := ParsujStrefy(wyjscieStref, "FedoraServer")
	if len(strefy) != 2 {
		t.Fatalf("stref = %d", len(strefy))
	}
	domyslna := strefy[0]
	if !domyslna.Default || !domyslna.Active {
		t.Errorf("strefa domyslna = %+v", domyslna)
	}
	if len(domyslna.Interfaces) != 2 || domyslna.Interfaces[1] != "enp0s8" {
		t.Errorf("interfejsy = %v", domyslna.Interfaces)
	}
	if len(domyslna.Services) != 3 {
		t.Errorf("uslugi = %v", domyslna.Services)
	}
	// Puste pole zostaje puste, a nie staje sie lista z pustym napisem.
	if len(domyslna.Ports) != 0 || len(domyslna.Sources) != 0 {
		t.Errorf("puste pola = %v / %v", domyslna.Ports, domyslna.Sources)
	}
	if strefy[1].Target != "%%REJECT%%" || len(strefy[1].Ports) != 2 {
		t.Errorf("strefa block = %+v", strefy[1])
	}
	if strefy[1].Default || strefy[1].Active {
		t.Errorf("strefa nieaktywna oznaczona jako aktywna: %+v", strefy[1])
	}
}

// Zmiana firewalld musi trafic do stanu trwalego i zostac przeladowana:
// zmiana tylko w jednym z nich znika, ale za kazdym razem w innej chwili.
func TestZmianaFirewalldJestTrwalaIPrzeladowana(t *testing.T) {
	kroki, err := ArgumentyOtwarciaPortu("FedoraServer", "8443", "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(kroki) != 2 {
		t.Fatalf("krokow = %d", len(kroki))
	}
	if !strings.Contains(strings.Join(kroki[0], " "), "--permanent") {
		t.Errorf("zmiana nietrwala: %v", kroki[0])
	}
	if kroki[1][1] != "--reload" {
		t.Errorf("brak przeladowania: %v", kroki[1])
	}
	for _, zla := range []struct{ strefa, port, protokol string }{
		{"zla strefa", "8443", "tcp"},
		{"FedoraServer", "0", "tcp"},
		{"FedoraServer", "8443", "sctp"},
	} {
		if _, err := ArgumentyOtwarciaPortu(zla.strefa, zla.port, zla.protokol, true); err == nil {
			t.Errorf("przyjeto %+v", zla)
		}
	}
}

// Rejestr jest zrodlem prawdy o regulach panelu: uchwyt nadaje jadro i
// zmienia sie przy kazdym przeladowaniu tablicy.
func TestRejestrOdtwarzaTabliceOdZera(t *testing.T) {
	rejestr := Rejestr{}
	rejestr = rejestr.Ustaw(RuleSpec{ID: "panel", Chain: LancuchWejscie,
		Action: DzialanieAccept, Protocol: "tcp", Ports: []string{"8443"}})
	rejestr = rejestr.Ustaw(RuleSpec{ID: "poczta", Chain: LancuchWejscie,
		Action: DzialanieDrop, Protocol: "tcp", Ports: []string{"25"}})
	// Ta sama nazwa oznacza te sama regule: powtorzenie niczego nie dubluje.
	rejestr = rejestr.Ustaw(RuleSpec{ID: "panel", Chain: LancuchWejscie,
		Action: DzialanieAccept, Protocol: "tcp", Ports: []string{"8443", "8080"}})
	if len(rejestr.Rules) != 2 {
		t.Fatalf("regul = %d", len(rejestr.Rules))
	}
	if len(rejestr.Rules[0].Ports) != 2 {
		t.Errorf("regula nie zostala zastapiona: %+v", rejestr.Rules[0])
	}

	kroki, err := ArgumentyPrzebudowy(rejestr)
	if err != nil {
		t.Fatal(err)
	}
	polecenia := make([]string, 0, len(kroki))
	for _, krok := range kroki {
		polecenia = append(polecenia, strings.Join(krok, " "))
	}
	razem := strings.Join(polecenia, "\n")
	// Tablica jest budowana od zera, bo kolejnosc regul decyduje o tym,
	// ktora zadziala pierwsza.
	if !strings.Contains(razem, "flush table inet flotestro") {
		t.Errorf("brak czyszczenia tablicy:\n%s", razem)
	}
	if strings.Index(razem, "flush table") > strings.Index(razem, "add rule") {
		t.Errorf("czyszczenie po dodaniu regul:\n%s", razem)
	}

	rejestr, znaleziona := rejestr.Usun("panel")
	if !znaleziona || len(rejestr.Rules) != 1 || rejestr.Rules[0].ID != "poczta" {
		t.Errorf("po usunieciu = %+v", rejestr.Rules)
	}
	if _, znaleziona := rejestr.Usun("nie-ma"); znaleziona {
		t.Error("usunieto regule, ktorej nie ma")
	}
}
