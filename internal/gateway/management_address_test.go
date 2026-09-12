package gateway

import (
	"testing"

	"github.com/ultherego/flotestro/internal/hosts"
)

// The address the panel sees at its own end of a connection is the strongest
// fact it has about a host - but only when there is nobody between them.
func TestTheAddressFromADirectConnection(t *testing.T) {
	address, source := managementAddress("192.168.56.30:41234", "10.0.0.5", "")
	if address != "192.168.56.30" {
		t.Errorf("address = %q, expected the address from the connection", address)
	}
	if source != hosts.AddressFromSession {
		t.Errorf("source = %q, expected %q", source, hosts.AddressFromSession)
	}
}

// Behind a relay the panel sees the address of the relay. Giving it as the
// address of the host would be a falsehood, so only the declaration of the
// host counts.
func TestBehindARelayTheDeclarationOfTheHostCounts(t *testing.T) {
	address, source := managementAddress("192.168.56.60:9000", "10.20.4.17", "b7c0-relay")
	if address != "10.20.4.17" {
		t.Errorf("address = %q, expected the address declared by the host", address)
	}
	if source != hosts.AddressFromAgent {
		t.Errorf("source = %q, expected %q", source, hosts.AddressFromAgent)
	}
}

// Missing both sources leaves the address undetermined. The address of a relay
// must not impersonate the address of a host just because there is no other.
func TestMissingSourcesLeaveTheAddressUndetermined(t *testing.T) {
	address, source := managementAddress("192.168.56.60:9000", "", "b7c0-relay")
	if address != "" || source != "" {
		t.Fatalf("address = %q, source = %q; expected an undetermined state", address, source)
	}
}

// An address without a port cannot be split. Instead of recording rubbish what
// stays is the declaration of the host or an undetermined state.
func TestAnInvalidConnectionAddressIsNotRecorded(t *testing.T) {
	address, source := managementAddress("without-a-port", "", "")
	if address != "" || source != "" {
		t.Fatalf("address = %q, source = %q; expected an undetermined state", address, source)
	}

	address, source = managementAddress("without-a-port", "10.20.4.17", "")
	if address != "10.20.4.17" || source != hosts.AddressFromAgent {
		t.Fatalf("address = %q, source = %q; expected the declaration of the host", address, source)
	}
}
