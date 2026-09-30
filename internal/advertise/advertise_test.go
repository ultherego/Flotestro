package advertise

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// A default that serves a trial on one machine must not quietly become a
// production setting: the enrolment door reads this to admit a host on this
// machine and nobody else.
func TestLoopbackOnlyIsRecognised(t *testing.T) {
	cases := []struct {
		names    []string
		loopback bool
	}{
		// Nothing set at all: the packaged control-plane.env ships
		// FLOTESTRO_ADVERTISE empty, and the certificate is then issued for
		// 127.0.0.1 alone - the very case the refusal exists for.
		{nil, true},
		{[]string{}, true},
		{[]string{""}, true},
		{[]string{"127.0.0.1"}, true},
		{[]string{"::1"}, true},
		{[]string{"localhost"}, true},
		{[]string{"LocalHost"}, true},
		{[]string{"localhost."}, true},
		{[]string{"127.0.0.1", "localhost", "::1"}, true},
		{[]string{"127.0.0.1", "panel.example.org"}, false},
		{[]string{"192.168.1.10"}, false},
		{[]string{"panel.example.org"}, false},
		// An empty entry of a comma-separated list decides nothing.
		{[]string{"127.0.0.1", ""}, true},
		{[]string{"", "panel.example.org"}, false},
	}
	for _, test := range cases {
		if got := Of(test.names).LoopbackOnly(); got != test.loopback {
			t.Errorf("Of(%q).LoopbackOnly() = %v, want %v", test.names, got, test.loopback)
		}
	}
}

// Whatever the fleet is told, the panel is reached over loopback from the
// machine it runs on: the administrator's own browser and a check inside the
// container both do it.
func TestTheCertificateAlwaysCarriesLoopback(t *testing.T) {
	dnsNames, ips := Parse("panel.example.org,192.0.2.10").CertificateNames()
	if len(dnsNames) != 2 || dnsNames[0] != "panel.example.org" || dnsNames[1] != "localhost" {
		t.Errorf("the DNS names = %v", dnsNames)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("127.0.0.1")) ||
		!ips[1].Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("the addresses = %v", ips)
	}
	// An administrator who names loopback themselves gets one entry, not two: a
	// repeated name in a certificate is noise a reader has to explain away.
	_, ips = Parse("127.0.0.1").CertificateNames()
	if len(ips) != 1 {
		t.Errorf("127.0.0.1 confirmed by hand appears %d times in the certificate", len(ips))
	}
	dnsNames, _ = Parse("localhost").CertificateNames()
	if len(dnsNames) != 1 {
		t.Errorf("localhost confirmed by hand appears %d times in the certificate", len(dnsNames))
	}
}

// These names go into a certificate, into a YAML file and into the command an
// operator pastes on a host, so they are checked before they are stored.
func TestValidateRefusesWhatCannotNameThePanel(t *testing.T) {
	for _, value := range []string{
		"https://panel.example.org",
		"panel.example.org:8443",
		"panel example org",
		"panel..example.org",
		"-panel.example.org",
		"panel.example.org-",
		"0.0.0.0",
		"224.0.0.1",
		strings.Repeat("a", 254),
	} {
		if err := Of([]string{value}).Validate(); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q was accepted as a name of the panel: %v", value, err)
		}
	}
	if err := Of(nil).Validate(); !errors.Is(err, ErrNoName) {
		t.Errorf("a confirmation that names nothing was accepted: %v", err)
	}
	for _, value := range []string{"panel.example.org", "panel", "192.0.2.10", "2001:db8::1",
		"panel.example.org.", "host_name.example.org"} {
		if err := Of([]string{value}).Validate(); err != nil {
			t.Errorf("%q was refused: %v", value, err)
		}
	}
}

// A single-machine installation still gets an instruction it can run there
// rather than an empty one.
func TestReachablePrefersWhatAnotherMachineCanUse(t *testing.T) {
	if got := Parse("127.0.0.1,panel.example.org,localhost").Reachable(); len(got) != 1 ||
		got[0] != "panel.example.org" {
		t.Errorf("the reachable addresses = %v", got)
	}
	if got := Parse("127.0.0.1,localhost").Reachable(); len(got) != 2 {
		t.Errorf("a loopback-only panel offers %v", got)
	}
}

// Detection proposes and nothing else. This asserts the shape of a proposal,
// because everything that makes it safe is that it is only ever read as one.
func TestDetectionProposesTheAddressesOfThisMachine(t *testing.T) {
	candidates := Detect()
	if len(candidates) == 0 {
		t.Fatal("no candidate at all; even loopback should be found")
	}
	reachableFirst := true
	for i, candidate := range candidates {
		if candidate.Name == "" {
			t.Errorf("candidate %d has no name", i)
		}
		if candidate.Kind != "address" && candidate.Kind != "hostname" {
			t.Errorf("candidate %q is of kind %q", candidate.Name, candidate.Kind)
		}
		if candidate.Kind == "address" && candidate.Interface == "" {
			t.Errorf("the address %q names no interface; it has to be read off the host",
				candidate.Name)
		}
		if candidate.Loopback != IsLoopback(candidate.Name) {
			t.Errorf("candidate %q is marked loopback=%v", candidate.Name, candidate.Loopback)
		}
		if !candidate.Loopback && !reachableFirst {
			t.Errorf("candidate %q comes after a loopback one", candidate.Name)
		}
		reachableFirst = reachableFirst && !candidate.Loopback
	}
}

// A name means the same host whatever its case, and the trailing dot of an
// absolute name says nothing about which host is meant. Two sets that differ
// only in that are the same choice, and a certificate must not be issued again
// for it.
func TestTheSameChoiceWrittenDifferentlyIsTheSameChoice(t *testing.T) {
	if !Parse("Panel.Example.ORG.").Equal(Parse("panel.example.org")) {
		t.Error("the same name in another case counts as a change of address")
	}
	if Parse("panel.example.org,192.0.2.10").Equal(Parse("192.0.2.10,panel.example.org")) {
		t.Error("the order the agents try the addresses in is part of the choice")
	}
}
