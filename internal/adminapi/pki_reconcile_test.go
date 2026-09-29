package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/audit"
)

// The reconciler closes a beginning nothing answered, and the mapping from what
// the trust store shows to what it writes is the whole decision: a beginning
// says a change may have happened, and only the state says whether it did.
func TestTheReconcilerReadsTheStateRatherThanAssuming(t *testing.T) {
	const mine = "aa11"
	const other = "bb22"
	for _, test := range []struct {
		name    string
		action  string
		target  string
		active  string
		pending string
		known   bool
		outcome audit.Outcome
	}{
		{"a preparation that left a prepared CA", "pki.ca.prepare", "", mine, other, true, audit.OutcomeSuccess},
		{"a preparation that left none", "pki.ca.prepare", "", mine, "", false, audit.OutcomeFailure},
		{"a handover the named CA completed", "pki.ca.activate", mine, mine, "", true, audit.OutcomeSuccess},
		{"a handover somebody else's CA holds", "pki.ca.activate", mine, other, "", true, audit.OutcomeFailure},
		{"a handover with nothing signing", "pki.ca.activate", mine, "", "", false, audit.OutcomeFailure},
		{"a retirement that took the CA out", "pki.ca.retire", mine, other, "", false, audit.OutcomeSuccess},
		{"a retirement that left it in", "pki.ca.retire", mine, other, "", true, audit.OutcomeFailure},
		{"an action this panel does not reconcile", "pki.ca.nonsense", mine, mine, "", true, audit.OutcomeFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome, found := trustOutcome(test.action, test.target, test.active, test.pending, test.known)
			if outcome != test.outcome {
				t.Errorf("outcome = %q, expected %q (found %q)", outcome, test.outcome, found)
			}
			if found == "" {
				t.Error("the reconciler wrote no account of what it found")
			}
		})
	}
}

// A prepared authority has signed nothing, so nothing can be using it. The
// count that guards a removal attributed a relay to an authority by subject
// alone, and a prepared authority carries the subject of the one it would
// replace - so on any installation with a relay it inherited that relay and
// could never be abandoned, though the panel's own listing said nobody used it.
func TestAPreparedAuthorityIsNotHeldByTheRelaysOfTheOneItWouldReplace(t *testing.T) {
	const subject = "Flotestro Root CA"
	usage := map[string]int{subject + " 111": 24}
	relays := map[string]int{subject: 1, "": 1}

	for _, test := range []struct {
		name   string
		state  string
		serial string
		want   int
	}{
		{"the authority that signs carries its hosts and its relays", "active", "111", 26},
		{"a retired authority carries what still trusts it", "retired", "222", 2},
		{"a prepared authority carries nothing", "pending", "333", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := authorityUsage(test.state, subject, test.serial, usage, relays)
			if got != test.want {
				t.Errorf("usage = %d, expected %d", got, test.want)
			}
		})
	}
}
