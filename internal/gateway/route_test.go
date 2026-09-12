package gateway

import (
	"testing"

	"github.com/ultherego/flotestro/internal/enrollment"
)

// TestTheRouteOfARegistrationIsPartOfTheScope guards the property an order
// carries a relay_id for at all: a token carried out of an isolated site must
// not register a host somewhere else.
//
// A relay terminates TLS and sees the token of its site. That is the price of
// registering in an isolated site, and that is why the scope of a token is to
// be narrow.
func TestTheRouteOfARegistrationIsPartOfTheScope(t *testing.T) {
	cases := []struct {
		name   string
		scope  enrollment.Scope
		relay  relayAttestation
		passes bool
	}{
		{
			name:   "an ordinary token directly",
			scope:  enrollment.Scope{Site: "lab"},
			passes: true,
		},
		{
			name:   "a token tied to a relay will not pass directly",
			scope:  enrollment.Scope{Site: "lab", RelayID: "r1"},
			passes: false,
		},
		{
			name:   "a token tied to a relay through that relay",
			scope:  enrollment.Scope{Site: "lab", RelayID: "r1"},
			relay:  relayAttestation{ID: "r1", Site: "lab"},
			passes: true,
		},
		{
			name:   "a token tied to a relay through another relay",
			scope:  enrollment.Scope{Site: "lab", RelayID: "r1"},
			relay:  relayAttestation{ID: "r2", Site: "lab"},
			passes: false,
		},
		{
			name:   "a token of another site through a relay",
			scope:  enrollment.Scope{Site: "warsaw"},
			relay:  relayAttestation{ID: "r1", Site: "lab"},
			passes: false,
		},
		{
			name:   "a token without a tie through the relay of its own site",
			scope:  enrollment.Scope{Site: "lab"},
			relay:  relayAttestation{ID: "r1", Site: "lab"},
			passes: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkRoute(c.scope, c.relay)
			if passes := err == nil; passes != c.passes {
				t.Fatalf("checkRoute = %v, expected a pass = %v", err, c.passes)
			}
		})
	}
}
