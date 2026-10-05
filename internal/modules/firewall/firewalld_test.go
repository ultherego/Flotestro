package firewall

import (
	"slices"
	"testing"
)

// One configuration, named by both sides. The executor's arguments and the
// reader's arguments are written out here, so a change to either that parts
// them stops this test rather than a host. That the two were never named
// together is why the guard watched the running configuration for two months.
func TestTheZoneReaderAndTheZoneWriterNameOneConfiguration(t *testing.T) {
	port, err := PortArguments("public", "8080", "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := ServiceArguments("public", "http", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		why   string
		steps [][]string
		write []string
	}{
		{why: "opening a port", steps: port,
			write: []string{"/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--add-port=8080/tcp"}},
		{why: "disabling a service", steps: service,
			write: []string{"/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--remove-service=http"}},
	} {
		t.Run(tc.why, func(t *testing.T) {
			reload := []string{"/usr/bin/firewall-cmd", "--reload"}
			if len(tc.steps) != 2 || !slices.Equal(tc.steps[0], tc.write) ||
				!slices.Equal(tc.steps[1], reload) {
				t.Fatalf("the executor runs %v", tc.steps)
			}
			// The listing of the configuration those arguments write.
			kept := []string{"/usr/bin/firewall-cmd", "--permanent", "--list-all-zones"}
			if !slices.Equal(ZoneListArguments(true), kept) {
				t.Fatalf("the reader of what the host keeps runs %v", ZoneListArguments(true))
			}
			if tc.steps[0][1] != ZoneListArguments(true)[1] {
				t.Errorf("the write %v and the reading %v are not of one configuration",
					tc.steps[0], ZoneListArguments(true))
			}
			// And the other reading is of the other configuration, which no
			// write of the panel touches.
			running := []string{"/usr/bin/firewall-cmd", "--list-all-zones"}
			if !slices.Equal(ZoneListArguments(false), running) {
				t.Errorf("the reader of what the host filters with runs %v", ZoneListArguments(false))
			}
			if slices.Contains(ZoneListArguments(false), PermanentFlag) {
				t.Error("the reading of the running configuration carries " + PermanentFlag)
			}
			// The service a change names is asked about in the same
			// configuration the change is written into.
			if !slices.Contains(ServicePortsArguments("http"), PermanentFlag) {
				t.Errorf("the ports of a service are read elsewhere: %v", ServicePortsArguments("http"))
			}
		})
	}
}

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
