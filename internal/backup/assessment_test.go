package backup

import (
	"testing"
	"time"
)

func TestStateAssessesTheAgeOfACopy(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	moment := func(offset time.Duration) *time.Time {
		value := now.Add(offset)
		return &value
	}
	cases := []struct {
		name  string
		last  *time.Time
		state string
	}{
		// No copy at all is a separate state rather than a very old copy:
		// those are two different situations and two different decisions by
		// the operator.
		{"never", nil, StateNever},
		{"an hour ago", moment(-time.Hour), StateOK},
		{"a day ago", moment(-24 * time.Hour), StateOK},
		{"two days ago", moment(-48 * time.Hour), StateWarning},
		{"a week ago", moment(-7 * 24 * time.Hour), StateCritical},
	}
	for _, testCase := range cases {
		if state := State(testCase.last, now); state != testCase.state {
			t.Fatalf("%s: state %q, expected %q", testCase.name, state, testCase.state)
		}
	}
}

func TestWorsePutsAMissingCopyHighest(t *testing.T) {
	if Worse(StateOK, StateNever) != StateNever {
		t.Fatal("a missing copy lost to a fresh copy")
	}
	if Worse(StateCritical, StateNever) != StateNever {
		t.Fatal("a missing copy lost to an old copy")
	}
	if Worse(StateWarning, StateOK) != StateWarning {
		t.Fatal("a warning lost to the good state")
	}
	if Worse("", StateWarning) != StateWarning {
		t.Fatal("an empty state was not replaced")
	}
}

func TestAnUnverifiedCopyIsAPromise(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	recently := now.Add(-24 * time.Hour)
	longAgo := now.Add(-60 * 24 * time.Hour)
	if Unverified(&recently, now) {
		t.Fatal("a copy verified yesterday was treated as unverified")
	}
	if !Unverified(&longAgo, now) {
		t.Fatal("a copy verified two months ago was treated as verified")
	}
	if !Unverified(nil, now) {
		t.Fatal("a copy nobody verified was treated as verified")
	}
}
