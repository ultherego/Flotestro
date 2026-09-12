package opspec

import "testing"

// TestAnEventReadHasBoundaries guards that the panel refuses an order outside
// the window instead of silently trimming it on the host. An operator who
// asked for a day of following is to learn that no such operation exists.
func TestAnEventReadHasBoundaries(t *testing.T) {
	cases := map[string]DockerEventsPayload{
		"window back":   {SinceSeconds: maxEventWindow + 1},
		"following":     {FollowSeconds: maxEventFollow + 1},
		"event limit":   {MaxEvents: maxEvents + 1},
		"unknown kind":  {Types: []string{"daemon"}},
		"kind repeated": {Types: []string{"container", "container"}},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate(ActionDockerEvents, Payload{DockerEvents: &payload}); err == nil {
				t.Fatal("an order outside the boundaries was accepted")
			}
		})
	}
}

// TestAnEventReadWithoutARequestIsValid guards that the default window is a
// way without parameters: the operator asks "what happened here" instead of
// filling in a form.
func TestAnEventReadWithoutARequestIsValid(t *testing.T) {
	if err := Validate(ActionDockerEvents, Payload{}); err != nil {
		t.Fatalf("a read without a request was rejected: %v", err)
	}
	err := Validate(ActionDockerEvents, Payload{DockerEvents: &DockerEventsPayload{
		SinceSeconds: 900, FollowSeconds: 30, MaxEvents: 100,
		Types: []string{"container", "network"},
	}})
	if err != nil {
		t.Fatalf("a valid request was rejected: %v", err)
	}
}

// TestAnEventReadTakesNoLock guards a property without which this operation
// would be a trap: a read lasting the follow window must not hold back the
// restart the operator wants to see in it.
func TestAnEventReadTakesNoLock(t *testing.T) {
	spec := ActionDockerEvents.Describe()
	if spec.Mutating {
		t.Error("a journal read is marked as changing the host")
	}
	if spec.LockClass != LockNone {
		t.Errorf("lock class = %q", spec.LockClass)
	}
	if spec.Risk != RiskLow {
		t.Errorf("risk = %q", spec.Risk)
	}
}
