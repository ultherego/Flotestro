package certificates

import "time"

// The thresholds of expiry. The assessment is made in the panel for the same
// reason as the compliance assessment: it is policy rather than a fact about
// the host. The host reports the date, the panel says whether that date is
// already a problem - and says it the same way about every host of the fleet,
// also when the hosts run different versions of the agent.
const (
	// CriticalThreshold is the date at which a renewal stops being a plan for
	// next week. A certificate that expires at night stops a service in the
	// morning.
	CriticalThreshold = 7 * 24 * time.Hour
	// WarningThreshold is the moment at which a renewal can still be planned
	// calmly - together with a maintenance window and the approval of a second
	// person.
	WarningThreshold = 30 * 24 * time.Hour
)

// MaxReadAge says after how long the image stops describing the host.
//
// The metadata of the certificates are collected every few to a dozen or so
// hours - a validity date does not change on its own. The file can change,
// though: a certificate replaced by hand is visible only at the next read, so
// an image older than a day and a bit is described as stale rather than as
// current.
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
//
// A missing date is an unknown state rather than a valid one: a certificate
// that could not be read is not a certificate in order.
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

// weight orders the states from the worst. Unknown stands next to critical
// rather than next to valid: not knowing about the certificate of a service is
// not good news.
var weight = map[string]int{
	StateExpired:  4,
	StateCritical: 3,
	StateUnknown:  2,
	StateWarning:  1,
	StateValid:    0,
}

// Worse returns the worse of two states. A host is described by its worst
// certificate: one expired certificate is enough for a service to stop
// answering.
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
