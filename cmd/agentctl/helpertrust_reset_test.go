package main

import (
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/helpercap"
)

// The reset said the next bundle "is taken on trust" whatever the host held.
// The shipped policy is pinned, so on an ordinary host that sentence promised
// an enrollment the helper then refused with trust_bundle_untrusted - which is
// exactly what happened on agent-fedora on 09.10, twice, after the reset had
// said it would work.
func TestTheResetSaysWhatTheNextSessionWillReallyDo(t *testing.T) {
	cases := []struct {
		name      string
		bootstrap helpercap.Bootstrap
		pins      []string
		wants     []string
	}{
		{"a pinned panel", helpercap.BootstrapPinned, []string{"ab12"},
			[]string{"held to the 1 panel", "/etc/flotestro/panel-trust.pin", "no other"}},
		{"pinned with nothing pinned", helpercap.BootstrapPinned, nil,
			[]string{"enrolls with nobody", "helper-trust pin"}},
		{"a laboratory on trust", helpercap.BootstrapTOFU, nil,
			[]string{"takes on trust"}},
		// An empty policy is pinned, and the sentence must follow that and not
		// the absence of a value.
		{"no policy at all", "", nil, []string{"enrolls with nobody"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resetOutcome(c.bootstrap, "/etc/flotestro/panel-trust.pin", c.pins)
			if !strings.HasPrefix(got, "The helper's identity and keys were forgotten;") {
				t.Errorf("the sentence no longer says what was forgotten: %s", got)
			}
			for _, want := range c.wants {
				if !strings.Contains(got, want) {
					t.Errorf("want %q in: %s", want, got)
				}
			}
		})
	}
}
