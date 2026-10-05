package firewall

import "testing"

func sealed(snapshot Snapshot) string {
	SealFingerprint(&snapshot)
	return snapshot.Hash
}

// The fingerprint is what a zone plan is made against, so a change to a zone
// has to move it. It did not: the fingerprint came from the running ruleset,
// and firewall-cmd --permanent leaves that ruleset alone until a reload. The
// plan's precondition therefore held while the zone had already moved.
func TestAZoneChangeMovesTheFingerprint(t *testing.T) {
	base := Snapshot{Hash: "deadbeef", Zones: []Zone{
		{Name: "public", Active: true, Default: true, Target: "default",
			Interfaces: []string{"eth0"}, Services: []string{"ssh"}, Ports: []string{"8443/tcp"}},
	}}
	reference := sealed(base)

	for name, change := range map[string]func(*Snapshot){
		"a port opened":        func(s *Snapshot) { s.Zones[0].Ports = []string{"8443/tcp", "80/tcp"} },
		"a port closed":        func(s *Snapshot) { s.Zones[0].Ports = nil },
		"a service added":      func(s *Snapshot) { s.Zones[0].Services = []string{"ssh", "http"} },
		"the target changed":   func(s *Snapshot) { s.Zones[0].Target = "DROP" },
		"an interface moved":   func(s *Snapshot) { s.Zones[0].Interfaces = []string{"eth1"} },
		"a source added":       func(s *Snapshot) { s.Zones[0].Sources = []string{"10.0.0.0/8"} },
		"another zone":         func(s *Snapshot) { s.Zones = append(s.Zones, Zone{Name: "dmz"}) },
		"the default zone":     func(s *Snapshot) { s.Zones[0].Default = false },
		"the zone deactivated": func(s *Snapshot) { s.Zones[0].Active = false },
		"the zone renamed":     func(s *Snapshot) { s.Zones[0].Name = "internal" },
	} {
		altered := Snapshot{Hash: base.Hash, Zones: []Zone{base.Zones[0]}}
		altered.Zones[0].Interfaces = append([]string(nil), base.Zones[0].Interfaces...)
		altered.Zones[0].Services = append([]string(nil), base.Zones[0].Services...)
		altered.Zones[0].Ports = append([]string(nil), base.Zones[0].Ports...)
		change(&altered)
		if got := sealed(altered); got == reference {
			t.Errorf("%s leaves the fingerprint unchanged", name)
		}
	}
}

// The ruleset still decides as well: the zones were added to the fingerprint,
// not put in place of it.
func TestARulesetChangeStillMovesTheFingerprint(t *testing.T) {
	zones := []Zone{{Name: "public", Active: true}}
	if sealed(Snapshot{Hash: "aaaa", Zones: zones}) == sealed(Snapshot{Hash: "bbbb", Zones: zones}) {
		t.Error("two rule sets share a fingerprint")
	}
}

// Not knowing the zones is a third state. Reading it as a host with no zones
// would let a plan made while they were readable match a run that could not
// read them - and the zones are what the plan's reversibility rests on.
func TestNotKnowingTheZonesIsNotTheSameAsHavingNone(t *testing.T) {
	unknown := sealed(Snapshot{Hash: "deadbeef", ZonesReason: "firewall-cmd: exit status 1"})
	none := sealed(Snapshot{Hash: "deadbeef"})
	if unknown == none {
		t.Error("an unread zone list reads as a host with no zones")
	}
	other := sealed(Snapshot{Hash: "deadbeef", ZonesReason: "firewall-cmd: timed out"})
	if unknown == other {
		t.Error("two different reasons share a fingerprint")
	}
	// And a half-read list left behind beside the reason does not quietly
	// become the answer: the reason is what the state is.
	withZones := sealed(Snapshot{Hash: "deadbeef", ZonesReason: "firewall-cmd: exit status 1",
		Zones: []Zone{{Name: "public"}}})
	if withZones != unknown {
		t.Error("a half-read zone list changes the fingerprint of an unknown state")
	}
}

// A host whose firewall could not be read used to leave the fingerprint empty,
// and an empty expected fingerprint is how a plan says it has no precondition.
// The apply then went ahead with nothing to check against.
func TestAnUnreadableFirewallStillHasAFingerprint(t *testing.T) {
	unavailable := sealed(Snapshot{UnavailableReason: "this host has no nftables (nft) binary"})
	if unavailable == "" {
		t.Fatal("the fingerprint of an unreadable firewall is empty, which reads as no precondition")
	}
	if unavailable == sealed(Snapshot{}) {
		t.Error("an unreadable firewall reads as an empty one")
	}
	if unavailable == sealed(Snapshot{UnavailableReason: "nft list ruleset: exit status 1"}) {
		t.Error("two reasons for not knowing share a fingerprint")
	}
}

// The length prefixes are there so no rearrangement of names and lists can be
// read as another zone.
func TestZonePartsCannotBeReadAsOneAnother(t *testing.T) {
	first := sealed(Snapshot{Hash: "x", Zones: []Zone{{Name: "pub", Services: []string{"lic"}}}})
	second := sealed(Snapshot{Hash: "x", Zones: []Zone{{Name: "public", Services: nil}}})
	if first == second {
		t.Error("a name and a service run together into the same fingerprint")
	}
	split := sealed(Snapshot{Hash: "x", Zones: []Zone{{Name: "z", Ports: []string{"80/tcp", "443/tcp"}}}})
	joined := sealed(Snapshot{Hash: "x", Zones: []Zone{{Name: "z", Ports: []string{"80/tcp443/tcp"}}}})
	if split == joined {
		t.Error("two ports read as one")
	}
}
