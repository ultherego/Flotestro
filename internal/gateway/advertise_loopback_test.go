package gateway

import "testing"

// reach is what the service asks of the advertised address. It changes without
// being handed over again, the way the installation's own setting does when an
// administrator confirms an address on this replica or on another one.
type reach struct{ loopback bool }

func (r *reach) LoopbackOnly() bool { return r.loopback }

// A default that serves a trial on one machine must not quietly become a
// production setting: a panel advertised as loopback admits a host on this
// machine and nobody else, because the certificate it hands out names an
// address a remote host cannot reach.
//
// The condition is asked of the store per attempt rather than recorded once at
// the start: an administrator confirms an address while the panel runs, and the
// door has to open at that moment - and, just as much, close again if the panel
// goes back to advertising loopback alone.
func TestTheLoopbackRefusalFollowsTheAdvertisedAddress(t *testing.T) {
	service := &EnrollmentService{}
	// A service that was given no source does not refuse: the refusal guards a
	// configuration known to be bad, and is not a state to sit in by default.
	if service.advertisedLoopback() {
		t.Error("a service with no advertised address refuses every remote host")
	}
	// The source is handed over once, at the start, and never again: what follows
	// is the value in force changing underneath it.
	advertised := &reach{loopback: true}
	service.SetAdvertised(advertised)
	if !service.advertisedLoopback() {
		t.Error("a panel advertised as loopback admits a host it cannot serve")
	}
	// The confirmation of a reachable address opens the door without a restart.
	advertised.loopback = false
	if service.advertisedLoopback() {
		t.Error("the panel advertises a reachable address and the door stayed shut")
	}
	// And the reverse: nothing about the flip is one-way, so a panel that goes
	// back to loopback alone goes back to refusing.
	advertised.loopback = true
	if !service.advertisedLoopback() {
		t.Error("the refusal did not come back with the loopback-only address")
	}
}

func TestLoopbackPeerIsRecognised(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:52000":   true,
		"[::1]:52000":       true,
		"192.168.56.30:443": false,
		"10.0.0.1:443":      false,
		// An address the runtime could not split is not a loopback claim.
		"not-an-address": false,
	}
	for addr, loopback := range cases {
		if got := isLoopbackPeer(addr); got != loopback {
			t.Errorf("isLoopbackPeer(%q) = %v, want %v", addr, got, loopback)
		}
	}
}

// The refusal carries a code of its own, so the installation screen can say
// what to change instead of showing a handshake failure a minute later.
func TestLoopbackRefusalHasItsOwnMessage(t *testing.T) {
	message := denialMessage("advertise_is_loopback")
	if message == "the token was refused" {
		t.Fatal("the loopback refusal fell through to the default message")
	}
}
