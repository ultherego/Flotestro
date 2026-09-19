package certificates

import "time"

// The thresholds of expiry.
const (
	// CriticalThreshold is the date at which a renewal stops being a plan for
	// next week.
	CriticalThreshold = 7 * 24 * time.Hour
	// WarningThreshold is the moment at which a renewal can still be planned
	// calmly - together with a maintenance window and the approval of a second
	// person.
	WarningThreshold = 30 * 24 * time.Hour
)

// MaxReadAge says after how long the image stops describing the host.
const MaxReadAge = 36 * time.Hour

// The states of a certificate as the panel sees them.
const (
	StateUnknown  = "unknown"
	StateExpired  = "expired"
	StateCritical = "critical"
	StateWarning  = "warning"
	StateValid    = "valid"
)

// State assesses the validity date against a moment.
func State(notAfter *time.Time, now time.Time) string {
	if notAfter == nil {
		return StateUnknown
	}
	left := notAfter.Sub(now)
	switch {
	case left <= 0:
		return StateExpired
	case left <= CriticalThreshold:
		return StateCritical
	case left <= WarningThreshold:
		return StateWarning
	}
	return StateValid
}

// weight orders the states from the worst.
var weight = map[string]int{
	StateExpired:  4,
	StateCritical: 3,
	StateUnknown:  2,
	StateWarning:  1,
	StateValid:    0,
}

// Worse returns the worse of two states.
func Worse(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if weight[b] > weight[a] {
		return b
	}
	return a
}

// Stale says whether the image is older than the read policy describes.
func Stale(observed time.Time, now time.Time) bool {
	return observed.IsZero() || now.Sub(observed) > MaxReadAge
}
