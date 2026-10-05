package helpercap

import (
	"testing"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

// WŁ-11. The addresses and the resolvers of an interface were compared as
// sets, so a request naming the same elements in another order satisfied a
// capability signed for the first order. The first address is the one the host
// answers from and the one its services bind by default; the resolvers are
// asked in the order they are written. Another order is another configuration.
func TestAnotherOrderOfAddressesOrResolversIsAnotherProfile(t *testing.T) {
	approved := &opspec.NetworkPayload{
		Method:     "manual",
		Addresses:  []string{"192.168.56.40/24", "10.0.0.5/24"},
		DNS:        []string{"192.168.56.50", "1.1.1.1"},
		Addresses6: []string{"fd00::40/64", "fd00::41/64"},
		Routes:     []string{"10.1.0.0/16 via 10.0.0.1", "10.2.0.0/16 via 10.0.0.1"},
	}
	honest := func() *helperv1.NetworkRequest {
		return &helperv1.NetworkRequest{
			Method:     approved.Method,
			Addresses:  []string{"192.168.56.40/24", "10.0.0.5/24"},
			Dns:        []string{"192.168.56.50", "1.1.1.1"},
			Addresses6: []string{"fd00::40/64", "fd00::41/64"},
			Routes:     []string{"10.1.0.0/16 via 10.0.0.1", "10.2.0.0/16 via 10.0.0.1"},
		}
	}
	if err := sameProfile(honest(), approved); err != nil {
		t.Fatalf("the approved profile was refused: %v", err)
	}

	for name, spoil := range map[string]func(*helperv1.NetworkRequest){
		"the primary address swapped": func(r *helperv1.NetworkRequest) {
			r.Addresses = []string{"10.0.0.5/24", "192.168.56.40/24"}
		},
		"the first resolver swapped": func(r *helperv1.NetworkRequest) {
			r.Dns = []string{"1.1.1.1", "192.168.56.50"}
		},
		"the primary IPv6 address swapped": func(r *helperv1.NetworkRequest) {
			r.Addresses6 = []string{"fd00::41/64", "fd00::40/64"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := honest()
			spoil(request)
			if err := sameProfile(request, approved); err == nil {
				t.Error("another order satisfied the capability")
			}
		})
	}

	// Routes stay a set: the kernel matches them by prefix and metric, so the
	// order they are written in is not what the host will do.
	reordered := honest()
	reordered.Routes = []string{"10.2.0.0/16 via 10.0.0.1", "10.1.0.0/16 via 10.0.0.1"}
	if err := sameProfile(reordered, approved); err != nil {
		t.Errorf("routes in another order were refused: %v", err)
	}
}
