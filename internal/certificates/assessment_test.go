package certificates

import (
	"testing"
	"time"
)

func TestStateAssessesTheDateAgainstTheThresholds(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	moment := func(offset time.Duration) *time.Time {
		value := now.Add(offset)
		return &value
	}
	cases := []struct {
		name     string
		notAfter *time.Time
		state    string
	}{
		{"a missing date", nil, StateUnknown},
		{"expired yesterday", moment(-24 * time.Hour), StateExpired},
		{"expires tomorrow", moment(24 * time.Hour), StateCritical},
		{"expires in two weeks", moment(14 * 24 * time.Hour), StateWarning},
		{"expires in a year", moment(365 * 24 * time.Hour), StateValid},
	}
	for _, c := range cases {
		if state := State(c.notAfter, now); state != c.state {
			t.Fatalf("%s: state %q, expected %q", c.name, state, c.state)
		}
	}
}

func TestWorsePutsMissingKnowledgeAboveAWarning(t *testing.T) {
	// Not knowing about the certificate of a service is not good news: the
	// host is then described by a state worse than one with a distant date.
	if Worse(StateValid, StateUnknown) != StateUnknown {
		t.Fatal("unknown lost against valid")
	}
	if Worse(StateUnknown, StateWarning) != StateUnknown {
		t.Fatal("a warning hid the missing knowledge")
	}
	if Worse(StateUnknown, StateExpired) != StateExpired {
		t.Fatal("expired lost against unknown")
	}
	if Worse("", StateCritical) != StateCritical {
		t.Fatal("an empty state was not replaced")
	}
}

func TestStaleDescribesAnOldRead(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if Stale(now.Add(-time.Hour), now) {
		t.Fatal("a read from an hour ago was treated as stale")
	}
	if !Stale(now.Add(-48*time.Hour), now) {
		t.Fatal("a read from two days ago was treated as fresh")
	}
	if !Stale(time.Time{}, now) {
		t.Fatal("a missing read was treated as fresh")
	}
}
