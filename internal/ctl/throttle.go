package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ForcedRenewalFile records when the operator last forced a renewal.
const ForcedRenewalFile = "renew-forced-at"

// ForcedRenewalInterval is the least time between two forced renewals.
const ForcedRenewalInterval = 10 * time.Minute

// Throttle keeps the record of forced renewals in a state directory.
type Throttle struct {
	StateDir string
}

// Last reads the time of the previous forced renewal.
func (t Throttle) Last() (time.Time, bool) {
	content, err := os.ReadFile(filepath.Join(t.StateDir, ForcedRenewalFile))
	if err != nil {
		return time.Time{}, false
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(content)))
	if err != nil {
		return time.Time{}, false
	}
	return last, true
}

// Record writes the time of this forced renewal.
func (t Throttle) Record(now time.Time) error {
	return os.WriteFile(filepath.Join(t.StateDir, ForcedRenewalFile),
		[]byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// TooSoon says whether a forced renewal now would come before the interval
// has passed, and how long is left.
func (t Throttle) TooSoon(now time.Time) (last time.Time, wait time.Duration, tooSoon bool) {
	last, ok := t.Last()
	if !ok || now.Sub(last) >= ForcedRenewalInterval {
		return last, 0, false
	}
	return last, ForcedRenewalInterval - now.Sub(last), true
}
