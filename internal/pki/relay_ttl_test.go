package pki

import (
	"testing"
	"time"
)

// The relay certificate was the only lifetime an operator could not set, and it
// is the shortest one: seven days against the agent's thirty. An installation
// that wants shorter credentials for the component standing between the panel
// and a site had nowhere to say so, and the laboratory could not exercise the
// renewal without waiting four and a half days for the threshold.
//
// Asked of both halves, because an override that is ignored and a default that
// is lost are the same bug from two sides.
func TestTheRelayCertificateLifetimeIsADefaultAndNotARule(t *testing.T) {
	var ca CA
	if got := ca.relayCertTTL(); got != RelayCertTTL {
		t.Errorf("with nothing set the lifetime is %s, and the default is %s", got, RelayCertTTL)
	}
	ca.RelayTTL = time.Hour
	if got := ca.relayCertTTL(); got != time.Hour {
		t.Errorf("the override says an hour and the lifetime is %s", got)
	}
	// Zero is "nothing was set", not "a certificate valid for no time at all".
	ca.RelayTTL = 0
	if got := ca.relayCertTTL(); got != RelayCertTTL {
		t.Errorf("an unset override gives %s instead of the default", got)
	}
	// And it is independent of the agent's: setting one must not move the other.
	ca.AgentTTL = 2 * time.Hour
	if got := ca.relayCertTTL(); got != RelayCertTTL {
		t.Errorf("the agent's lifetime moved the relay's to %s", got)
	}
	if got := ca.agentCertTTL(); got != 2*time.Hour {
		t.Errorf("the agent's own override gives %s", got)
	}
}
