package network

import (
	"strings"
	"testing"
)

func profilTestowy() Profil {
	return Profil{
		Polaczenie: "Wired connection 1", Interfejs: "eth1", Metoda: "auto",
		Trasy: []string{"10.9.0.0/24 192.168.56.1"}, MTU: "1500",
	}
}

func TestPlanMTUOdrozniaZmianeOdBrakuZmian(t *testing.T) {
	obecny := profilTestowy()
	zmiana := ZaplanujMTU("eth1", obecny, "9000")
	if zmiana.Action != PlanZmienia || len(zmiana.Changes) != 1 ||
		!strings.Contains(zmiana.Changes[0], "MTU z 1500 na 9000") {
		t.Errorf("plan MTU: %+v", zmiana)
	}
	bez := ZaplanujMTU("eth1", obecny, "1500")
	if bez.Action != PlanBezZmian || len(bez.Changes) != 0 {
		t.Errorf("plan bez zmian: %+v", bez)
	}
	if zmiana.PlanHash == bez.PlanHash || zmiana.PlanHash == "" {
		t.Error("odciski planow nie roznia sie")
	}
	if zla := ZaplanujMTU("eth1", obecny, "12"); zla.Refusal == "" {
		t.Error("MTU 12 przeszlo bez odmowy")
	}
}

func TestPlanTrasPorownujeJakoZbior(t *testing.T) {
	obecny := profilTestowy()
	obecny.Trasy = []string{"10.9.0.0/24 192.168.56.1", "10.8.0.0/24 192.168.56.1"}
	plan := ZaplanujTrasy("eth1", obecny, []string{"10.8.0.0/24 192.168.56.1", "10.9.0.0/24 192.168.56.1"})
	if plan.Action != PlanBezZmian {
		t.Errorf("kolejnosc tras policzona jako zmiana: %+v", plan)
	}
	pusta := ZaplanujTrasy("eth1", obecny, []string{})
	if pusta.Action != PlanZmienia || !strings.Contains(pusta.Changes[0], "na brak") {
		t.Errorf("skasowanie tras: %+v", pusta)
	}
}

func TestPlanProfiluZostawiaTrasyIMTU(t *testing.T) {
	obecny := profilTestowy()
	plan := ZaplanujProfil("eth1", obecny, "manual", []string{"192.168.56.61/24"}, "", nil)
	if plan.Action != PlanZmienia {
		t.Fatalf("plan profilu: %+v", plan)
	}
	if plan.Desired.MTU != "1500" || len(plan.Desired.Trasy) != 1 {
		t.Errorf("profil adresowy ruszyl trasy albo MTU: %+v", plan.Desired)
	}
	for _, zmiana := range plan.Changes {
		if strings.HasPrefix(zmiana, "trasy") || strings.HasPrefix(zmiana, "MTU") {
			t.Errorf("zmiana spoza zamowienia: %s", zmiana)
		}
	}
	if odmowa := ZaplanujProfil("eth1", obecny, "manual", nil, "", nil); odmowa.Refusal == "" {
		t.Error("manual bez adresu przeszedl bez odmowy")
	}
}

func TestOdmowaPlanuMaOdcisk(t *testing.T) {
	plan := OdmowaPlanu("eth9", PlanMTU, "interfejs eth9 nie ma profilu NetworkManagera")
	if plan.Refusal == "" || plan.PlanHash == "" || plan.Current != nil {
		t.Errorf("odmowa: %+v", plan)
	}
	zmiana := ZaplanujMTU("eth1", profilTestowy(), "9000")
	przed := zmiana.PlanHash
	zmiana.Odmow("kanal zarzadzania")
	if zmiana.PlanHash == przed {
		t.Error("odmowa nie zmienila odcisku")
	}
}

func TestPlanResolveraZmieniaTylkoResolver(t *testing.T) {
	obecny := profilTestowy()
	obecny.DNS = []string{"192.168.56.50"}
	plan := ZaplanujDNS("eth1", obecny, []string{"192.168.56.50"}, []string{"flotestro.test"}, true)
	if plan.Action != PlanZmienia || plan.Operation != PlanDNS {
		t.Fatalf("plan resolvera: %+v", plan)
	}
	if len(plan.Changes) != 2 {
		t.Errorf("zmiany resolvera: %v", plan.Changes)
	}
	if plan.Desired.MTU != obecny.MTU || len(plan.Desired.Trasy) != len(obecny.Trasy) ||
		plan.Desired.Metoda != obecny.Metoda {
		t.Errorf("plan resolvera ruszyl reszte profilu: %+v", plan.Desired)
	}
	bez := ZaplanujDNS("eth1", obecny, []string{"192.168.56.50"}, nil, false)
	if bez.Action != PlanBezZmian {
		t.Errorf("resolver w stanie docelowym policzony jako zmiana: %+v", bez)
	}
	if pusty := ZaplanujDNS("eth1", obecny, nil, nil, false); pusty.Refusal == "" {
		t.Error("resolver bez serwera przeszedl bez odmowy")
	}
}
