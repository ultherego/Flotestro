// Package jobs zawiera model operacji typowanych: maszyne stanow, kolejke
// z lease oraz zapis prob. Pakiet nie zna warstwy HTTP ani protokolu agenta.
package jobs

import "fmt"

// State jest stanem joba. Przejscia sa walidowane w domenie, a nie w handlerze.
type State string

const (
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateQueued           State = "queued"
	StateLeased           State = "leased"
	StateDispatched       State = "dispatched"
	StateRunning          State = "running"
	StateSucceeded        State = "succeeded"
	StateFailed           State = "failed"
	StateTimedOut         State = "timed_out"
	StateCanceled         State = "canceled"
	StateExpired          State = "expired"
)

// transitions opisuje dozwolone przejscia. Agent nie moze samodzielnie
// przeniesc joba z planned do running - musi przejsc przez lease.
var transitions = map[State][]State{
	StatePlanned:          {StateAwaitingApproval, StateQueued, StateCanceled, StateExpired},
	StateAwaitingApproval: {StateQueued, StateCanceled, StateExpired},
	StateQueued:           {StateLeased, StateCanceled, StateExpired},
	// Powrot do queued jest normalna sciezka po wygasnieciu lease.
	StateLeased:     {StateDispatched, StateQueued, StateCanceled, StateExpired, StateFailed},
	StateDispatched: {StateRunning, StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired, StateQueued},
	StateRunning:    {StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateQueued},
}

// Terminal mowi, czy stan jest koncowy.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateTimedOut, StateCanceled, StateExpired:
		return true
	default:
		return false
	}
}

// CanTransition sprawdza, czy przejscie jest dozwolone.
func (s State) CanTransition(to State) bool {
	for _, allowed := range transitions[s] {
		if allowed == to {
			return true
		}
	}
	return false
}

// Validate zwraca blad opisujacy niedozwolone przejscie.
func (s State) Validate(to State) error {
	if s == to {
		return nil
	}
	if !s.CanTransition(to) {
		return fmt.Errorf("niedozwolone przejscie %s -> %s", s, to)
	}
	return nil
}
