package czas

import (
	"strings"
	"testing"
)

func TestPlanCzasuOdrozniaDemonyIStanZastany(t *testing.T) {
	chrony := Snapshot{Service: DemonChrony,
		ManagedPath: "/etc/chrony/sources.d/flotestro.sources"}
	plan := Zaplanuj(chrony, []string{"192.168.56.50"}, false)
	if plan.Action != PlanZmienia || plan.Restart || plan.Refusal != "" {
		t.Errorf("chrony z katalogiem zrodel: %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Changes, ";"), "bez restartu") {
		t.Errorf("zmiany chrony: %v", plan.Changes)
	}

	chrony.Managed, _ = SkladajChrony([]string{"192.168.56.50"}, RodzajZrodel)
	chrony.Configured = []Serwer{{Address: "192.168.56.50", Managed: true}}
	bez := Zaplanuj(chrony, []string{"192.168.56.50"}, false)
	if bez.Action != PlanBezZmian || len(bez.Changes) != 0 {
		t.Errorf("stan docelowy policzony jako zmiana: %+v", bez)
	}

	timesyncd := Snapshot{Service: DemonTimesyncd}
	ts := Zaplanuj(timesyncd, []string{"192.168.56.50"}, false)
	if ts.Action != PlanZmienia || !ts.Restart || ts.ManagedPath != PlikTimesyncd {
		t.Errorf("timesyncd: %+v", ts)
	}
	if plan.PlanHash == ts.PlanHash || plan.PlanHash == bez.PlanHash {
		t.Error("odciski planow nie roznia sie")
	}
}

func TestPlanCzasuOdmawiaBezKataloguIBezDemona(t *testing.T) {
	bezKatalogu := Snapshot{Service: DemonChrony, ConfigPath: "/etc/chrony/chrony.conf",
		CanAddSourceDir: true, WriteReason: "chrony nie wlacza katalogu"}
	odmowa := Zaplanuj(bezKatalogu, []string{"192.168.56.50"}, false)
	if odmowa.Refusal != "chrony nie wlacza katalogu" {
		t.Errorf("brak katalogu bez odmowy: %+v", odmowa)
	}
	zgoda := Zaplanuj(bezKatalogu, []string{"192.168.56.50"}, true)
	if zgoda.Refusal != "" || !zgoda.EnablesSourceDir || !zgoda.Restart {
		t.Errorf("zgoda na katalog: %+v", zgoda)
	}
	bezDemona := Zaplanuj(Snapshot{}, []string{"192.168.56.50"}, false)
	if !strings.Contains(bezDemona.Refusal, "demona czasu") {
		t.Errorf("brak demona bez odmowy: %+v", bezDemona)
	}
	if pusty := Zaplanuj(bezKatalogu, nil, true); pusty.Refusal == "" {
		t.Error("pusta lista serwerow przeszla bez odmowy")
	}
}
