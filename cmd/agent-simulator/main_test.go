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

// The engine and the container sit on the first hosts only, and each holder keeps an
// identifier of its own for the one name.
func TestOnlyTheFirstHostsHoldTheContainerWithTheirOwnIdentifier(t *testing.T) {
	sim := simulation{working: 4, docker: 3, holders: 2, container: "web"}
	ids := map[string]bool{}
	for index, want := range []int{1, 1, 0, 0} {
		host := sim.host(index, fmt.Sprintf("sim-h%04d", index))
		if len(host.Containers) != want {
			t.Fatalf("host %d holds %d containers, want %d", index, len(host.Containers), want)
		}
		for _, container := range host.Containers {
			ids[container.ID] = true
		}
	}
	if len(ids) != 2 {
		t.Fatalf("the holders share an identifier: %v", ids)
	}
}
