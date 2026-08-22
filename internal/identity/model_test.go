package identity

import (
	"bytes"
	"testing"
)

func TestCzesciowySukcesMaWlasnyStan(t *testing.T) {
	// Dokument zabrania przedstawiania czesciowego sukcesu jako powodzenia:
	// operator musialby sam odkryc, ze czesc zmian zostala zastosowana.
	phases := []Phase{
		{Name: "utworzenie konta", Status: "succeeded"},
		{Name: "dodanie do grupy", Status: "failed"},
	}
	if got := StateFor(phases); got != StatePartiallyApplied {
		t.Fatalf("stan = %s, oczekiwano partially_applied", got)
	}
}

func TestStanKoncowyZalezyOdWynikuFaz(t *testing.T) {
	cases := map[string]struct {
		phases []Phase
		want   State
	}{
		"wszystkie udane": {
			[]Phase{{Status: "succeeded"}, {Status: "succeeded"}}, StateSucceeded},
		"wszystkie nieudane": {
			[]Phase{{Status: "failed"}, {Status: "failed"}}, StateFailed},
		"pierwsza faza padla": {
			[]Phase{{Status: "failed"}}, StateFailed},
		"brak faz": {
			nil, StateFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := StateFor(tc.phases); got != tc.want {
				t.Fatalf("stan = %s, oczekiwano %s", got, tc.want)
			}
		})
	}
}

func TestPlanZKonfliktemBlokujeWykonanie(t *testing.T) {
	blocked := Plan{Conflicts: []string{"konto juz istnieje"}}
	if !blocked.Blocked() {
		t.Fatal("plan z konfliktem nie blokuje wykonania")
	}
	// Ostrzezenie opisuje skutek, ktory latwo przeoczyc, ale nie zatrzymuje
	// zmiany; konflikt oznacza, ze wykonanie nie ma sensu.
	warned := Plan{Warnings: []string{"konto traci 3 reguly sudo"}}
	if warned.Blocked() {
		t.Fatal("samo ostrzezenie zablokowalo wykonanie")
	}
}

func TestWalidacjaWymagaPayloaduZgodnegoZTypem(t *testing.T) {
	cases := map[string]struct {
		action  ActionType
		payload Payload
		wantErr bool
	}{
		"utworzenie bez payloadu":  {ActionUserCreate, Payload{}, true},
		"utworzenie bez nazwiska":  {ActionUserCreate, Payload{User: &UserPayload{UID: "jan"}}, true},
		"utworzenie poprawne":      {ActionUserCreate, Payload{User: &UserPayload{UID: "jan", LastName: "Kowalski"}}, false},
		"blokada bez konta":        {ActionUserDisable, Payload{}, true},
		"blokada poprawna":         {ActionUserDisable, Payload{Reference: &ReferencePayload{UID: "jan"}}, false},
		"pusta zmiana czlonkostwa": {ActionGroupMembers, Payload{Group: &GroupPayload{Group: "grupa"}}, true},
		"zmiana czlonkostwa":       {ActionGroupMembers, Payload{Group: &GroupPayload{Group: "grupa", Add: []string{"jan"}}}, false},
		"nieznany typ":             {"identity.user.delete", Payload{}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := Validate(tc.action, tc.payload)
			if tc.wantErr && err == nil {
				t.Fatal("nieprawidlowa zmiana przeszla walidacje")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("poprawna zmiana odrzucona: %v", err)
			}
		})
	}
}

func TestPayloadHashWykrywaPodmiane(t *testing.T) {
	original := Payload{User: &UserPayload{UID: "jan", LastName: "Kowalski",
		Groups: []string{"flotestro-viewers"}}}
	approved, err := PayloadHash(ActionUserCreate, original)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Podmiana grupy po zatwierdzeniu jest podniesieniem uprawnien, wiec musi
	// zmienic hash planu.
	tampered := Payload{User: &UserPayload{UID: "jan", LastName: "Kowalski",
		Groups: []string{"flotestro-platform-admins"}}}
	changed, err := PayloadHash(ActionUserCreate, tampered)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if bytes.Equal(approved, changed) {
		t.Fatal("podmiana grupy nie zmienila hasha planu")
	}

	// Ten sam plan musi dac ten sam hash.
	again, _ := PayloadHash(ActionUserCreate, original)
	if !bytes.Equal(approved, again) {
		t.Fatal("ten sam plan dal rozne hashe")
	}
}

func TestUprawnieniaSaRozdzielonePerTypZmiany(t *testing.T) {
	if ActionGroupMembers.Permission() == ActionUserCreate.Permission() {
		t.Error("zmiana czlonkostwa ma to samo uprawnienie co tworzenie konta")
	}
	for _, action := range []ActionType{ActionUserCreate, ActionUserDisable, ActionSSHKeys} {
		if action.Permission() != "identity.user.write" {
			t.Errorf("%s ma uprawnienie %s", action, action.Permission())
		}
	}
}

func TestStanKoncowyJestRozpoznawany(t *testing.T) {
	for _, state := range []State{StateSucceeded, StatePartiallyApplied, StateFailed, StateCanceled} {
		if !state.Terminal() {
			t.Errorf("%s powinien byc stanem koncowym", state)
		}
	}
	for _, state := range []State{StatePlanned, StateAwaitingApproval, StateRunning} {
		if state.Terminal() {
			t.Errorf("%s nie jest stanem koncowym", state)
		}
	}
}
