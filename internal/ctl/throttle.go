package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ForcedRenewalFile records when the operator last forced a renewal.
//
// It lies in the state directory next to the identity: the limit is a
// property of the machine, and a reinstall of the tool must not reset it.
const ForcedRenewalFile = "renew-forced-at"

// ForcedRenewalInterval is the least time between two forced renewals.
//
// The gateway rate-limits renewals as well, but the refusal has to come
// before the network: a renewal repeated in a loop by a script is exactly
// what the limit is for, and every attempt costs a new key pair.
const ForcedRenewalInterval = 10 * time.Minute

// Throttle keeps the record of forced renewals in a state directory.
type Throttle struct {
	StateDir string
}

// Last reads the time of the previous forced renewal.
//
// An unreadable record counts as none: the file is a courtesy to the
// operator, not a lock, and a damaged one must not block the renewal for
// good.
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
