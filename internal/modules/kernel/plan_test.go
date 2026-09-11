package kernel

import (
	"strings"
	"testing"
)

func TestPlanBlokadyOdrozniaStanZastany(t *testing.T) {
	stan := Snapshot{
		Modules:   []Modul{{Name: "pcspkr", UsedBy: []string{"snd"}}},
		Blacklist: []string{"floppy"},
		Managed:   "# plik\nblacklist floppy\n",
	}
	nowa := ZaplanujBlokade(stan, "pcspkr", true)
	if nowa.Action != PlanTworzy || !nowa.Loaded || nowa.Blacklisted || len(nowa.Changes) != 3 {
		t.Errorf("blokada zaladowanego modulu: %+v", nowa)
	}
	if !strings.Contains(nowa.Changes[1], "po restarcie") || !strings.Contains(nowa.Changes[2], "snd") {
		t.Errorf("zmiany bez ostrzezen: %v", nowa.Changes)
	}
	juz := ZaplanujBlokade(stan, "floppy", true)
	if juz.Action != PlanBezZmian || !juz.Blacklisted {
		t.Errorf("blokada juz obecna: %+v", juz)
	}
	zdjecie := ZaplanujBlokade(stan, "floppy", false)
	if zdjecie.Action != PlanUsuwa {
		t.Errorf("zdjecie blokady: %+v", zdjecie)
	}
	if nowa.PlanHash == juz.PlanHash || juz.PlanHash == zdjecie.PlanHash || nowa.ManagedHash == "" {
		t.Error("odciski planow nie roznia sie albo brak odcisku pliku")
	}
}

func TestPlanBlokadyOdmawiaChronionegoModulu(t *testing.T) {
	plan := ZaplanujBlokade(Snapshot{}, "ext4", true)
	if !strings.Contains(plan.Refusal, "nie blokuje") || plan.PlanHash == "" {
		t.Errorf("chroniony modul bez odmowy: %+v", plan)
	}
	if zla := ZaplanujBlokade(Snapshot{}, "../x", true); zla.Refusal == "" {
		t.Error("zla nazwa przeszla bez odmowy")
	}
}
