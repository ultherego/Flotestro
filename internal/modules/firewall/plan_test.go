package firewall

import (
	"strings"
	"testing"
)

func regulaSMTP() RuleSpec {
	return RuleSpec{ID: "smtp", Chain: "wejscie", Action: "drop", Protocol: "tcp",
		Ports: []string{"25"}, Sources: []string{"10.10.0.0/16"}}
}

// TestPlanRozrozniaBrakRegulyOdInnejReguly pilnuje sedna planu per host: ta sama
// regula zamowiona na dwoch hostach to dwie rozne zmiany.
func TestPlanRozrozniaBrakRegulyOdInnejReguly(t *testing.T) {
	brak := ZaplanujRegule(Rejestr{}, regulaSMTP(), "aaa", AdapterNftables)
	if brak.Action != PlanTworzy || brak.Current != nil {
		t.Errorf("host bez reguly ma plan %q (current=%v)", brak.Action, brak.Current)
	}

	inna := regulaSMTP()
	inna.Ports = []string{"587"}
	zmiana := ZaplanujRegule(Rejestr{Rules: []RuleSpec{inna}}, regulaSMTP(), "aaa", AdapterNftables)
	if zmiana.Action != PlanZmienia {
		t.Errorf("host z inna regula ma plan %q", zmiana.Action)
	}
	if !zawiera(zmiana.Changes, "porty") {
		t.Errorf("plan nie nazywa zmiany portow: %+v", zmiana.Changes)
	}
	if brak.PlanHash == zmiana.PlanHash {
		t.Error("dwa rozne stany zastane daly ten sam odcisk planu")
	}
}

// TestPlanBezZmianIgnorujeKolejnosc pilnuje, ze kolejnosc portow i zrodel nie
// jest decyzja operatora - ta sama regula zapisana inaczej to nadal ta sama.
func TestPlanBezZmianIgnorujeKolejnosc(t *testing.T) {
	obecna := regulaSMTP()
	obecna.Ports = []string{"25", "465"}
	obecna.Sources = []string{"10.10.0.0/16", "10.20.0.0/16"}
	zadana := regulaSMTP()
	zadana.Ports = []string{"465", "25"}
	zadana.Sources = []string{"10.20.0.0/16", "10.10.0.0/16"}

	plan := ZaplanujRegule(Rejestr{Rules: []RuleSpec{obecna}}, zadana, "aaa", AdapterNftables)
	if plan.Action != PlanBezZmian {
		t.Fatalf("ta sama regula w innej kolejnosci ma plan %q (%+v)", plan.Action, plan.Changes)
	}
}

// TestOdciskPlanuZalezyOdZestawuRegul pilnuje, ze ten sam diff wobec innego
// zestawu jest inna zmiana: wchodzi w inne sasiedztwo regul.
func TestOdciskPlanuZalezyOdZestawuRegul(t *testing.T) {
	pierwszy := ZaplanujRegule(Rejestr{}, regulaSMTP(), "zestaw-a", AdapterNftables)
	drugi := ZaplanujRegule(Rejestr{}, regulaSMTP(), "zestaw-b", AdapterNftables)
	if pierwszy.PlanHash == drugi.PlanHash {
		t.Error("plan wobec innego zestawu regul ma ten sam odcisk")
	}
	if pierwszy.RulesetHash != "zestaw-a" {
		t.Errorf("plan nie niesie odcisku zestawu: %q", pierwszy.RulesetHash)
	}
}

// TestPlanUsunieciaOdrozniaRegulePanelu pilnuje, ze usuniecie reguly, ktorej
// host nie zna, jest widoczne przed zatwierdzeniem, a nie po.
func TestPlanUsunieciaOdrozniaRegulePanelu(t *testing.T) {
	jest := ZaplanujUsuniecie(Rejestr{Rules: []RuleSpec{regulaSMTP()}}, "smtp", "aaa", AdapterNftables)
	if jest.Action != PlanUsuwa || jest.Current == nil {
		t.Errorf("usuniecie istniejacej reguly ma plan %q", jest.Action)
	}
	niema := ZaplanujUsuniecie(Rejestr{}, "smtp", "aaa", AdapterNftables)
	if niema.Action != PlanJuzUsuniety {
		t.Errorf("usuniecie nieznanej reguly ma plan %q", niema.Action)
	}
}

func zawiera(lista []string, fragment string) bool {
	for _, wpis := range lista {
		if strings.Contains(wpis, fragment) {
			return true
		}
	}
	return false
}
