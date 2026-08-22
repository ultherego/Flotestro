package jobs

import "testing"

func TestAgentNieMozeOminacLease(t *testing.T) {
	// Agent nie moze samodzielnie przeniesc joba do running: musi istniec
	// wazny lease, czyli droga przez leased i dispatched.
	if StatePlanned.CanTransition(StateRunning) {
		t.Fatal("planned -> running jest dozwolone, a nie powinno byc")
	}
	if StateQueued.CanTransition(StateRunning) {
		t.Fatal("queued -> running omija lease")
	}
	if StateQueued.CanTransition(StateSucceeded) {
		t.Fatal("queued -> succeeded omija wykonanie")
	}
}

func TestWygasleLeaseWracaDoKolejki(t *testing.T) {
	for _, from := range []State{StateLeased, StateDispatched, StateRunning} {
		if !from.CanTransition(StateQueued) {
			t.Errorf("%s -> queued musi byc mozliwe po utracie lease", from)
		}
	}
}

func TestStanKoncowyJestOstateczny(t *testing.T) {
	terminal := []State{StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired}
	for _, state := range terminal {
		if !state.Terminal() {
			t.Errorf("%s powinien byc stanem koncowym", state)
		}
		// Ze stanu koncowego nie ma wyjscia; pozny wynik nie nadpisuje decyzji.
		for _, to := range terminal {
			if state != to && state.CanTransition(to) {
				t.Errorf("ze stanu koncowego %s da sie przejsc do %s", state, to)
			}
		}
		if state.CanTransition(StateRunning) {
			t.Errorf("stan koncowy %s da sie wznowic", state)
		}
	}
}

func TestValidatePrzepuszczaPowtorzenieTegoSamegoStanu(t *testing.T) {
	// Ponowne dostarczenie wyniku nie jest bledem przejscia.
	if err := StateSucceeded.Validate(StateSucceeded); err != nil {
		t.Fatalf("powtorzony stan koncowy odrzucony: %v", err)
	}
	if err := StateQueued.Validate(StateSucceeded); err == nil {
		t.Fatal("niedozwolone przejscie przeszlo walidacje")
	}
}
