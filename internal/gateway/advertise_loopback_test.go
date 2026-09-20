package gateway

import "testing"

// A default that serves a trial on one machine must not quietly become a
// production setting: a panel advertised as loopback admits a host on this
// machine and nobody else, because the certificate it hands out names an
// address a remote host cannot reach.
func TestAdvertisedLoopbackIsRecognised(t *testing.T) {
	cases := []struct {
		names    []string
		loopback bool
	}{
		// Nothing set at all: the packaged control-plane.env ships
		// FLOTESTRO_ADVERTISE empty, and the certificate is then issued for
		// 127.0.0.1 alone - the very case this refusal exists for.
		{nil, true},
		{[]string{}, true},
		{[]string{""}, true},
		{[]string{"127.0.0.1"}, true},
		{[]string{"::1"}, true},
		{[]string{"localhost"}, true},
		{[]string{"LocalHost"}, true},
		{[]string{"127.0.0.1", "localhost", "::1"}, true},
		{[]string{"127.0.0.1", "panel.example.org"}, false},
		{[]string{"192.168.1.10"}, false},
		{[]string{"panel.example.org"}, false},
		// An empty entry of a comma-separated list decides nothing.
		{[]string{"127.0.0.1", ""}, true},
		{[]string{"", "panel.example.org"}, false},
	}
	for _, test := range cases {
		if got := allLoopback(test.names); got != test.loopback {
			t.Errorf("allLoopback(%q) = %v, want %v", test.names, got, test.loopback)
		}
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
