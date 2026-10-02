package pki

import (
	"strings"
	"testing"
)

// The names of a relay come from its own first certificate request and stay in
// the registry from then on. A wildcard among them would be a certificate that
// stands for every host and every other relay of the domain, renewed for as long
// as the record lives.
func TestARelayIsRefusedAWildcardName(t *testing.T) {
	// A CA with no reserved source: reservedNames answers nothing and the only
	// refusals left are the ones this test is about.
	ca := &CA{}
	for _, name := range []string{"*.flotestro.test", "*", "relay.*.test"} {
		err := ca.checkRelayNames([]string{name}, nil)
		if err == nil {
			t.Errorf("the name %q was accepted for a relay", name)
			continue
		}
		if !strings.Contains(err.Error(), "wildcard") {
			t.Errorf("the refusal of %q does not say it is a wildcard: %v", name, err)
		}
	}
	if err := ca.checkRelayNames([]string{"relay.flotestro.test"}, nil); err != nil {
		t.Errorf("an ordinary name was refused: %v", err)
	}
}
