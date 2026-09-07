package opspec

import "testing"

// TestOdczytZdarzenMaGranice pilnuje, ze panel odmawia zlecenia spoza okna,
// zamiast po cichu przycinac je na hoscie. Operator, ktory prosil o dobe
// sledzenia, ma sie dowiedziec, ze taka operacja nie istnieje.
func TestOdczytZdarzenMaGranice(t *testing.T) {
	przypadki := map[string]DockerEventsPayload{
		"okno wstecz":     {SinceSeconds: maksymalneOknoZdarzen + 1},
		"sledzenie":       {FollowSeconds: maksymalneSledzenieZdarzen + 1},
		"limit zdarzen":   {MaxEvents: maksymalnieZdarzen + 1},
		"nieznany rodzaj": {Types: []string{"daemon"}},
		"rodzaj dwa razy": {Types: []string{"container", "container"}},
	}
	for nazwa, payload := range przypadki {
		t.Run(nazwa, func(t *testing.T) {
			if err := Validate(ActionDockerEvents, Payload{DockerEvents: &payload}); err == nil {
				t.Fatal("zlecenie spoza granic przyjete")
			}
		})
	}
}

// TestOdczytZdarzenBezZamowieniaJestPoprawny pilnuje, ze domyslne okno jest
// droga bez parametrow: operator pyta "co sie tu dzialo", a nie uzupelnia
// formularz.
func TestOdczytZdarzenBezZamowieniaJestPoprawny(t *testing.T) {
	if err := Validate(ActionDockerEvents, Payload{}); err != nil {
		t.Fatalf("odczyt bez zamowienia odrzucony: %v", err)
	}
	err := Validate(ActionDockerEvents, Payload{DockerEvents: &DockerEventsPayload{
		SinceSeconds: 900, FollowSeconds: 30, MaxEvents: 100,
		Types: []string{"container", "network"},
	}})
	if err != nil {
		t.Fatalf("poprawne zamowienie odrzucone: %v", err)
	}
}

// TestOdczytZdarzenNieBierzeBlokady pilnuje wlasciwosci, bez ktorej ta
// operacja byla by pulapka: odczyt trwajacy okno sledzenia nie moze
// wstrzymywac restartu, ktory operator wlasnie w nim chce zobaczyc.
func TestOdczytZdarzenNieBierzeBlokady(t *testing.T) {
	spec := ActionDockerEvents.Describe()
	if spec.Mutating {
		t.Error("odczyt dziennika oznaczony jako zmieniajacy host")
	}
	if spec.LockClass != LockNone {
		t.Errorf("klasa blokady = %q", spec.LockClass)
	}
	if spec.Risk != RiskLow {
		t.Errorf("ryzyko = %q", spec.Risk)
	}
}
