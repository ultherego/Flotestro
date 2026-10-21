package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ultherego/flotestro/internal/gateway"
)

func TestOnlyTheFirstAgentsOfABatchWork(t *testing.T) {
	sim := simulation{working: 3}
	for index, want := range []bool{true, true, true, false, false} {
		if got := sim.works(index); got != want {
			t.Errorf("agent %d: works = %v, want %v", index, got, want)
		}
	}
	if (simulation{}).works(0) {
		t.Error("a fleet without working agents has one")
	}
}

// The match is on the words the door really answers with.
func TestTheDoorsRequestToWaitIsRecognised(t *testing.T) {
	if !throttled(fmt.Errorf("enrolling: %w", gateway.ErrTooManyAttempts)) {
		t.Error("the answer of the enrollment door was not recognised")
	}
	if throttled(errors.New("the token was refused")) || throttled(nil) {
		t.Error("an ordinary failure was taken for a request to wait")
	}
}
