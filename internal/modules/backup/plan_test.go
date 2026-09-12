package backup

import (
	"strings"
	"testing"
	"time"
)

func definicjaTestowa() Definicja {
	return Definicja{
		ID: "dane", Tool: NarzedzieRestic, Repository: "/srv/kopie",
		Paths: []string{"/etc/flotestro", "/srv/dane"}, KeepLast: 7, Prune: true,
	}
}

func rozmiarTestowy(istniejace map[string]uint64) func(string) (uint64, bool) {
	return func(sciezka string) (uint64, bool) {
		bajty, jest := istniejace[sciezka]
		return bajty, jest
	}
}

func TestPlanKopiiOpisujeZakresZTegoHosta(t *testing.T) {
	teraz := time.Now()
	stan := Stan{Tool: NarzedzieRestic, Repository: "/srv/kopie",
		Snapshots: []Snapshot{{ID: "a"}, {ID: "b"}}, LastSuccessAt: &teraz}
	plan := Zaplanuj(stan, definicjaTestowa(), false, false,
		rozmiarTestowy(map[string]uint64{"/etc/flotestro": 3 << 20}))

	if plan.Action != PlanKopia || plan.Refusal != "" || !plan.RepositoryReady {
		t.Fatalf("plan kopii: %+v", plan)
	}
	if len(plan.Paths) != 1 || len(plan.MissingPaths) != 1 || plan.MissingPaths[0] != "/srv/dane" {
		t.Errorf("zakres: %+v / %+v", plan.Paths, plan.MissingPaths)
	}
	if plan.BytesOnHost == nil || *plan.BytesOnHost != 3<<20 {
		t.Errorf("rozmiar zakresu: %v", plan.BytesOnHost)
	}
	if !plan.Verified || !strings.Contains(strings.Join(plan.Changes, ";"), "sprawdzi repozytorium") {
		t.Errorf("kopia bez sprawdzenia: %+v", plan.Changes)
	}
	if !strings.Contains(plan.Retention, "7 ostatnich") || !strings.Contains(plan.Retention, "przesprzatane") {
		t.Errorf("retencja: %q", plan.Retention)
	}

	// Host bez zadnego z katalogow zapisalby pusta kopie - to jest odmowa.
	pusty := Zaplanuj(stan, definicjaTestowa(), false, false,
		rozmiarTestowy(map[string]uint64{}))
	if !strings.Contains(pusty.Refusal, "zadnego z wskazanych katalogow") {
		t.Errorf("host bez danych: %+v", pusty)
	}
	if plan.PlanHash == pusty.PlanHash || plan.PlanHash == "" {
		t.Error("odciski planow nie roznia sie")
	}
}

func TestPlanKopiiOdrozniaRepozytoriumNieodczytane(t *testing.T) {
	nieodczytane := Stan{UnavailableReason: "repository does not exist"}
	bezZgody := Zaplanuj(nieodczytane, definicjaTestowa(), false, false,
		rozmiarTestowy(map[string]uint64{"/etc/flotestro": 1}))
	if !strings.Contains(bezZgody.Refusal, "wymaga jawnej zgody") || bezZgody.WillInitialize {
		t.Errorf("repozytorium bez zgody: %+v", bezZgody)
	}

	zgoda := definicjaTestowa()
	zgoda.Initialize = true
	zZgoda := Zaplanuj(nieodczytane, zgoda, false, false,
		rozmiarTestowy(map[string]uint64{"/etc/flotestro": 1}))
	if zZgoda.Refusal != "" || !zZgoda.WillInitialize {
		t.Errorf("repozytorium ze zgoda: %+v", zZgoda)
	}

	// Sprawdzenia nie da sie zrobic na repozytorium, ktore nie odpowiada.
	sprawdzenie := Zaplanuj(nieodczytane, zgoda, true, false, nil)
	if !strings.Contains(sprawdzenie.Refusal, "nie odpowiedzialo") {
		t.Errorf("sprawdzenie bez repozytorium: %+v", sprawdzenie)
	}
	ok := Zaplanuj(Stan{Snapshots: []Snapshot{{ID: "a"}}}, definicjaTestowa(), true, true, nil)
	if ok.Action != PlanSprawdzenie || len(ok.Changes) != 2 || !ok.ReadData {
		t.Errorf("sprawdzenie z odczytem danych: %+v", ok)
	}
}
