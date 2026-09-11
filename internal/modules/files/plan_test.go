package files

import (
	"strings"
	"testing"
)

// TestPlanRozrozniaBrakPlikuOdInnejTresci pilnuje sedna planu per host: dwa
// hosty z tym samym stanem docelowym maja dwie rozne odpowiedzi.
func TestPlanRozrozniaBrakPlikuOdInnejTresci(t *testing.T) {
	docelowa := []byte("nowa tresc\n")

	brak := Zaplanuj(Plik{Path: "/etc/x.conf"}, docelowa, "0644", "root", "root", false, false)
	if brak.Action != PlanTworzy {
		t.Errorf("plik nieistniejacy ma plan %q", brak.Action)
	}
	if brak.Exists {
		t.Error("plan mowi, ze plik istnieje, choc go nie ma")
	}

	inny := Zaplanuj(Plik{
		Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644",
		Owner: "root", Group: "root",
	}, docelowa, "0644", "root", "root", false, false)
	if inny.Action != PlanZmienia {
		t.Errorf("plik o innej tresci ma plan %q", inny.Action)
	}
	if !zawieraZmiane(inny.Changes, "tresc") {
		t.Errorf("plan nie nazywa zmiany tresci: %+v", inny.Changes)
	}

	// Dwa rozne stany zastane musza dac dwa rozne odciski - inaczej zgoda
	// na jeden plan obejmowalaby drugi.
	if brak.PlanHash == inny.PlanHash {
		t.Error("plan pliku nieistniejacego i plan zmiany maja ten sam odcisk")
	}
}

// TestPlanBezZmianJestOdpowiedzia pilnuje, ze host juz zgodny ze stanem
// docelowym mowi to wprost. Bez tego operator nie wie, ile hostow kampania
// naprawde ruszy.
func TestPlanBezZmianJestOdpowiedzia(t *testing.T) {
	docelowa := []byte("ta sama tresc\n")
	odcisk := Odcisk(docelowa)

	plan := Zaplanuj(Plik{
		Path: "/etc/x.conf", Exists: true, SHA256: odcisk, Mode: "0644",
		Owner: "root", Group: "root",
	}, docelowa, "0644", "root", "root", false, false)

	if plan.Action != PlanBezZmian {
		t.Fatalf("plan identycznego pliku to %q (%+v)", plan.Action, plan.Changes)
	}
	if len(plan.Changes) != 0 {
		t.Errorf("plan bez zmian wylicza zmiany: %+v", plan.Changes)
	}
}

// TestPlanWidziSameUprawnienia pilnuje zmiany, ktorej odcisk tresci nie
// pokazuje: ta sama tresc z innymi prawami to nadal zmiana.
func TestPlanWidziSameUprawnienia(t *testing.T) {
	docelowa := []byte("tresc\n")
	plan := Zaplanuj(Plik{
		Path: "/etc/x.conf", Exists: true, SHA256: Odcisk(docelowa), Mode: "0644",
		Owner: "root", Group: "root",
	}, docelowa, "0600", "root", "root", false, false)

	if plan.Action != PlanZmienia {
		t.Fatalf("zmiana praw dala plan %q", plan.Action)
	}
	if !zawieraZmiane(plan.Changes, "prawa z 0644 na 0600") {
		t.Errorf("plan nie nazywa zmiany praw: %+v", plan.Changes)
	}
}

// TestPlanPlikuZSekretuNieNiesieTresci pilnuje granicy, ktorej plan nie moze
// przekroczyc: wartosc z magazynu nie ma prawa pojawic sie w opisie zmiany
// ani w jego odcisku.
func TestPlanPlikuZSekretuNieNiesieTresci(t *testing.T) {
	plan := Zaplanuj(Plik{
		Path: "/etc/tajne.conf", Exists: true, SHA256: "aaa", Mode: "0600",
	}, []byte("haslo-z-magazynu"), "0600", "root", "root", true, false)

	if plan.DesiredSHA256 != "" {
		t.Error("plan pliku z sekretu niesie odcisk tresci docelowej")
	}
	if !zawieraZmiane(plan.Changes, "magazynu sekretow") {
		t.Errorf("plan nie mowi, ze tresci nie da sie porownac: %+v", plan.Changes)
	}
}

// TestPlanUsunieciaOdrozniaPlikIstniejacy pilnuje, ze usuniecie pliku,
// ktorego nie ma, jest widoczne przed zatwierdzeniem, a nie po.
func TestPlanUsunieciaOdrozniaPlikIstniejacy(t *testing.T) {
	jest := Zaplanuj(Plik{Path: "/etc/x.conf", Exists: true, SHA256: "aaa"},
		nil, "", "", "", false, true)
	if jest.Action != PlanUsuwa {
		t.Errorf("usuniecie istniejacego pliku ma plan %q", jest.Action)
	}

	niema := Zaplanuj(Plik{Path: "/etc/x.conf"}, nil, "", "", "", false, true)
	if niema.Action != PlanJuzUsuniety {
		t.Errorf("usuniecie nieistniejacego pliku ma plan %q", niema.Action)
	}
}

// TestOdciskPlanuNieZalezyOdWynikuWalidatora pilnuje powtarzalnosci: ten sam
// diff ma dac ten sam odcisk, takze gdy walidator wypisze co innego.
func TestOdciskPlanuNieZalezyOdWynikuWalidatora(t *testing.T) {
	docelowa := []byte("tresc\n")
	obecny := Plik{Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644"}

	plan := Zaplanuj(obecny, docelowa, "0644", "", "", false, false)

	// Odcisk liczymy wprost na dwoch planach roznicych sie wylacznie wyjsciem
	// walidatora. Ustawienie pola po Zaplanuj niczego by nie sprawdzilo:
	// odcisk powstaje w srodku, zanim walidator w ogole ruszy.
	zWyjsciem := plan
	zWyjsciem.ValidatorOutput = "nginx: configuration file test is successful"
	bezWyjscia := plan
	bezWyjscia.ValidatorOutput = ""

	if odciskPlanu(zWyjsciem) != odciskPlanu(bezWyjscia) {
		t.Error("odcisk planu zmienia sie razem z wyjsciem walidatora")
	}
	// Sama roznica musi natomiast odcisk zmieniac - inaczej nie wiazalby
	// zgody z niczym.
	innaTresc := plan
	innaTresc.DesiredSHA256 = "inny"
	if odciskPlanu(innaTresc) == odciskPlanu(bezWyjscia) {
		t.Error("odcisk planu nie zmienil sie mimo innej tresci docelowej")
	}
}

func zawieraZmiane(zmiany []string, fragment string) bool {
	for _, zmiana := range zmiany {
		if strings.Contains(zmiana, fragment) {
			return true
		}
	}
	return false
}
