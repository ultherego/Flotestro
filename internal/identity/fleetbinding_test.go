package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultherego/flotestro/internal/hosts"
)

// A decommissioned record carries no name in the fleet.
//
// Counting it as a candidate made one live host beside one retired namesake
// ambiguous, and the binding was lost for as long as the record existed: on
// 05.10 the laboratory held a retired agent-ubuntu beside the live one, the
// service principal HTTP/agent-ubuntu.flotestro.test read as bound to nothing,
// and the condition that needs a keytab on a fleet host could not be met. For a
// customer it is worse than a laboratory nuisance: a machine that was
// decommissioned shadows its own replacement under the same name, for ever.
func TestARetiredRecordCarriesNoNameInTheFleet(t *testing.T) {
	live := hosts.Host{ID: "live", Hostname: "agent-ubuntu", LifecycleState: hosts.StateActive}
	gone := hosts.Host{ID: "gone", Hostname: "agent-ubuntu", LifecycleState: hosts.StateRetired}

	host, err := ResolveFleetHost([]hosts.Host{gone, live}, "agent-ubuntu.flotestro.test", "flotestro.test")
	if err != nil {
		t.Fatalf("a live host beside a retired namesake did not resolve: %v", err)
	}
	if host.ID != "live" {
		t.Errorf("the name resolved to %q", host.ID)
	}

	// Two live hosts of one name are still ambiguous: the fix is about records
	// of machines that are gone, not about giving up on telling two apart.
	second := hosts.Host{ID: "second", Hostname: "agent-ubuntu", LifecycleState: hosts.StateActive}
	if _, err := ResolveFleetHost([]hosts.Host{live, second},
		"agent-ubuntu.flotestro.test", "flotestro.test"); !errors.Is(err, ErrFleetHostAmbiguous) {
		t.Errorf("two live hosts of one name gave %v", err)
	}

	// And a name whose only record is retired is a different answer from a name
	// no host ever carried, because what to do about it differs.
	_, err = ResolveFleetHost([]hosts.Host{gone}, "agent-ubuntu.flotestro.test", "flotestro.test")
	if !errors.Is(err, ErrHostNotInFleet) {
		t.Fatalf("a retired-only name gave %v", err)
	}
	if !strings.Contains(err.Error(), "decommissioned") {
		t.Errorf("the refusal does not say the record was decommissioned: %v", err)
	}

	// Every other state is in service and still resolves: quarantined and
	// recovering hosts are present machines, and a host in the decommission
	// handshake has not finished leaving.
	for _, state := range []string{hosts.StateActive, hosts.StateQuarantined,
		hosts.StateRecovery, hosts.StateRetiring} {
		one := hosts.Host{ID: state, Hostname: "agent-ubuntu", LifecycleState: state}
		if _, err := ResolveFleetHost([]hosts.Host{one},
			"agent-ubuntu.flotestro.test", "flotestro.test"); err != nil {
			t.Errorf("a host in state %s did not resolve: %v", state, err)
		}
	}
}
