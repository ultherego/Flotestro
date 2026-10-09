package gateway

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/enrollment"
)

// A machine the panel already knows, offered a new-host order, was refused
// with "the enrollment token is invalid". The token was not the problem: the
// order had been issued seconds earlier and was still pending. It sent an
// operator to look at the order, at the clock and at the panel's log - which
// said nothing - while the panel's own record of the refusal named
// duplicate_machine_id all along. Measured on 08.10 on three hosts in a row.
//
// So every refusal a purpose check can produce has to be a sentence that says
// what to do next, and the default must not swallow one.
func TestEveryPurposeRefusalSaysWhatItIs(t *testing.T) {
	// The errors checkPurpose returns, each as it writes it.
	refusals := []string{
		"machine_id_known",
		"machine_id_other_host",
		enrollment.DenialMachineRetired,
		"recovery_without_host",
		"recovery_host_missing",
		"host_retired",
		"relay_purpose_for_host",
		"unknown_purpose",
	}
	generic := denialMessage("a code no branch names")
	for _, refusal := range refusals {
		code := purposeDenialCode(errorOf(refusal))
		message := denialMessage(code)
		if message == generic {
			t.Errorf("the refusal %q reaches the host as %q, which names neither the cause "+
				"nor the next step", refusal, message)
		}
		// The token is valid in every one of these: it was issued, it is
		// pending and it is bound to this machine. A message that calls it
		// invalid or expired sends the reader to the order's screen, which is
		// where this hunt went on 08.10.
		for _, wrong := range []string{"invalid", "expired", "revoked", "used up"} {
			if strings.Contains(message, wrong) {
				t.Errorf("the refusal %q says the token is %q, and it is not: %q",
					refusal, wrong, message)
			}
		}
	}
}

// The refusal an operator meets after reinstalling a machine has to point at
// the recovery, because that is the order that does fit.
func TestAKnownMachineIsToldToRecoverTheIdentity(t *testing.T) {
	message := denialMessage(purposeDenialCode(errorOf("machine_id_known")))
	for _, want := range []string{"already a host", "recover the identity"} {
		if !strings.Contains(message, want) {
			t.Errorf("the refusal for a known machine does not say %q: %s", want, message)
		}
	}
}

// errorOf is the shape checkPurpose returns: the code as the error's text.
func errorOf(code string) error { return constError(code) }

type constError string

func (c constError) Error() string { return string(c) }
