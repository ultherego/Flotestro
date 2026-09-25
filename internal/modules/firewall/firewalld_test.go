package firewall

import "testing"

// A service is a name for a set of ports. Removing it closes every one of
// them, and the guard on the management channel compared one number with one
// number - so "remove service https" took 443 away without a word.
func TestTheServicePortsAreReadFromWhatFirewalldSays(t *testing.T) {
	ports := ParseServicePorts("443/tcp 8443/tcp\n")
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Fatalf("the ports read as %v", ports)
	}
	// A service with no ports of its own - one built of protocols or modules -
	// reads as none rather than as a number nobody wrote.
	if got := ParseServicePorts("\n"); len(got) != 0 {
		t.Errorf("an empty answer read as %v", got)
	}
	if got := ParseServicePorts("not-a-port/tcp 70000/tcp 0/tcp"); len(got) != 0 {
		t.Errorf("a nonsense answer read as %v", got)
	}
}

// The way back from a zone change is the same command with the direction
// reversed, which is what the rollback runs.
func TestAZoneChangeHasAnInverse(t *testing.T) {
	forward, err := ServiceArguments("public", "https", false)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ServiceArguments("public", "https", true)
	if err != nil {
		t.Fatal(err)
	}
	if forward[0][3] != "--remove-service=https" || back[0][3] != "--add-service=https" {
		t.Fatalf("the pair is %v and %v", forward[0], back[0])
	}
	if len(back) != 2 || back[1][1] != "--reload" {
		t.Errorf("the way back does not reload: %v", back)
	}
}
