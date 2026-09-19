package backup

import "time"

// The freshness thresholds of a copy.
const (
	// WarningThreshold is the age of a copy at which it is worth asking why there
	// is no newer one.
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

// Worse returns the worse of two states.
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
