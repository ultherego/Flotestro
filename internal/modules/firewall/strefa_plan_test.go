package firewall

import (
	"strings"
	"testing"
)

func strefyTestowe() []Zone {
	return []Zone{
		{Name: "public", Active: true, Default: true, Services: []string{"ssh", "dhcpv6-client"},
			Ports: []string{"8080/tcp"}},
		{Name: "trusted", Active: false},
	}
}

func TestPlanPortuOdrozniaOtwarcieOdStanuDocelowego(t *testing.T) {
	otwarcie := ZaplanujPort(strefyTestowe(), "public", "9090", "tcp", true, "h1", AdapterFirewalld)
	if otwarcie.Action != PlanTworzy || otwarcie.Present || !otwarcie.ZoneExists {
		t.Errorf("otwarcie nowego portu: %+v", otwarcie)
	}
	juz := ZaplanujPort(strefyTestowe(), "public", "8080", "tcp", true, "h1", AdapterFirewalld)
	if juz.Action != PlanBezZmian || !juz.Present {
		t.Errorf("port juz otwarty: %+v", juz)
	}
	zamkniecie := ZaplanujPort(strefyTestowe(), "public", "8080", "tcp", false, "h1", AdapterFirewalld)
	if zamkniecie.Action != PlanUsuwa {
		t.Errorf("zamkniecie otwartego portu: %+v", zamkniecie)
	}
	if otwarcie.PlanHash == juz.PlanHash || otwarcie.PlanHash == zamkniecie.PlanHash {
		t.Error("rozne plany maja ten sam odcisk")
	}
}

func TestPlanStrefyOdmawiaBezStrefyIBezSensu(t *testing.T) {
	brak := ZaplanujUsluge(strefyTestowe(), "dmz", "http", true, "h1", AdapterFirewalld)
	if !strings.Contains(brak.Refusal, "strefy dmz") || brak.ZoneExists {
		t.Errorf("strefa, ktorej nie ma: %+v", brak)
	}
	zly := ZaplanujPort(strefyTestowe(), "public", "99999", "tcp", true, "h1", AdapterFirewalld)
	if zly.Refusal == "" {
		t.Error("port spoza zakresu przeszedl bez odmowy")
	}
	nieaktywna := ZaplanujUsluge(strefyTestowe(), "trusted", "http", true, "h1", AdapterFirewalld)
	if nieaktywna.Action != PlanTworzy || len(nieaktywna.Changes) != 2 ||
		!strings.Contains(nieaktywna.Changes[1], "nie jest aktywna") {
		t.Errorf("strefa nieaktywna bez ostrzezenia: %+v", nieaktywna)
	}
}

func TestOdmowaZmieniaOdciskPlanuStrefy(t *testing.T) {
	plan := ZaplanujPort(strefyTestowe(), "public", "22", "tcp", false, "h1", AdapterFirewalld)
	przed := plan.PlanHash
	plan.Odmow("port 22 jest kanalem zarzadzania")
	if plan.PlanHash == przed || plan.Refusal == "" {
		t.Error("odmowa nie zmienila odcisku")
	}
}
