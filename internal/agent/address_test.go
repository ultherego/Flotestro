package agent

import "testing"

// The address towards the panel is picked by the routing table, not by a list
// of interfaces. The loopback is always reachable, so the test does not depend
// on the lab network.
func TestPanelAddressPicksTheRouteAddress(t *testing.T) {
	if got := panelAddress("https://127.0.0.1:8443"); got != "127.0.0.1" {
		t.Errorf("address = %q, expected 127.0.0.1", got)
	}
}

// An address that was not determined stays empty. The panel prefers not to know
// the address over showing the operator an address the host is not at.
func TestPanelAddressDoesNotGuess(t *testing.T) {
	for _, url := range []string{"", "://without-a-scheme", "https://"} {
		if got := panelAddress(url); got != "" {
			t.Errorf("panelAddress(%q) = %q, expected empty", url, got)
		}
	}
}
