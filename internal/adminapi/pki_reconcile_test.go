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
