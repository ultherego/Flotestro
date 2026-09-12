package backup

import "time"

// The freshness thresholds of a copy. The assessment is made in the panel,
// exactly like the assessment of conformance and of certificate deadlines: it
// is policy rather than a fact about the host. The host says when the last
// copy succeeded; the panel says whether that is already a problem.
const (
	// WarningThreshold is the age of a copy at which it is worth asking why
	// there is no newer one. A day and a bit fits a daily schedule plus one
	// stumble.
	WarningThreshold = 26 * time.Hour
	// CriticalThreshold is the age at which a copy stops being a safeguard.
	CriticalThreshold = 72 * time.Hour
	// VerificationThreshold is the age of the last verification of a copy. A
	// backup nobody has ever read back is a promise rather than a safeguard.
	VerificationThreshold = 30 * 24 * time.Hour
)

// The states of a copy as the panel sees them.
const (
	StateUnknown  = "unknown"
	StateNever    = "never"
	StateCritical = "critical"
	StateWarning  = "warning"
	StateOK       = "ok"
)

// State assesses the age of the last successful copy.
//
// No copy at all is a separate state rather than "an old copy": a host
// without any copy and a host with a copy from a week ago are two different
// situations and two different decisions.
func State(last *time.Time, now time.Time) string {
	if last == nil {
		return StateNever
	}
	age := now.Sub(*last)
	switch {
	case age >= CriticalThreshold:
		return StateCritical
	case age >= WarningThreshold:
		return StateWarning
	}
	return StateOK
}

// severity orders the states from the worst one.
var severity = map[string]int{
	StateNever:    4,
	StateCritical: 3,
	StateUnknown:  2,
	StateWarning:  1,
	StateOK:       0,
}

// Worse returns the worse of two states. A host is described by its worst
// definition: one copy that does not exist is enough for data to be
// unprotected.
func Worse(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// Unverified says whether nobody has verified the copies for long enough.
func Unverified(last *time.Time, now time.Time) bool {
	return last == nil || now.Sub(*last) > VerificationThreshold
}
