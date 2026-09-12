package freeipa

import (
	"strings"
	"testing"
)

func TestRecordSpecValidatesTheTypeAndTheValue(t *testing.T) {
	dobre := []RecordSpec{
		{Zone: "flotestro.test", Name: "web", Type: RecordA, Value: "10.0.0.5"},
		{Zone: "flotestro.test", Name: "web6", Type: RecordAAAA, Value: "2001:db8::5"},
		{Zone: "flotestro.test", Name: "alias", Type: RecordCNAME, Value: "web.flotestro.test."},
		{Zone: "flotestro.test", Name: "@", Type: RecordTXT, Value: "v=spf1 -all"},
		{Zone: "flotestro.test", Name: "_ldap._tcp", Type: RecordSRV, Value: "0 100 389 ipa.flotestro.test."},
	}
	for _, spec := range dobre {
		if err := spec.Validate(); err != nil {
			t.Errorf("the valid record %+v was rejected: %v", spec, err)
		}
	}

	bad := map[string]RecordSpec{
		// The address in an A record has to be an IPv4 address: a name in
		// this place creates a record that will never work.
		"A with a name":          {Zone: "flotestro.test", Name: "web", Type: RecordA, Value: "web.example.test"},
		"A with an IPv6 address": {Zone: "flotestro.test", Name: "web", Type: RecordA, Value: "2001:db8::5"},
		"AAAA with IPv4":         {Zone: "flotestro.test", Name: "web", Type: RecordAAAA, Value: "10.0.0.5"},
		"an empty value":         {Zone: "flotestro.test", Name: "web", Type: RecordA},
		"an unknown type":        {Zone: "flotestro.test", Name: "web", Type: "NS", Value: "ipa.flotestro.test."},
		"a bad zone":             {Zone: "flotestro test", Name: "web", Type: RecordA, Value: "10.0.0.5"},
		"a name with a space":    {Zone: "flotestro.test", Name: "we b", Type: RecordA, Value: "10.0.0.5"},
		"a TTL out of range":     {Zone: "flotestro.test", Name: "web", Type: RecordA, Value: "10.0.0.5", TTL: -1},
		"SRV without fields":     {Zone: "flotestro.test", Name: "_ldap._tcp", Type: RecordSRV, Value: "389 ipa"},
		"a new line":             {Zone: "flotestro.test", Name: "web", Type: RecordTXT, Value: "a\nb"},
	}
	for name, spec := range bad {
		if err := spec.Validate(); err == nil {
			t.Errorf("%s: the record was accepted", name)
		}
	}
}

func TestReverseZoneComputesTheNameAndTheZone(t *testing.T) {
	zone, name, err := ReverseZone("192.168.56.10")
	if err != nil {
		t.Fatalf("ReverseZone: %v", err)
	}
	if zone != "56.168.192.in-addr.arpa" || name != "10" {
		t.Fatalf("IPv4: zone=%q name=%q", zone, name)
	}

	zone, name, err = ReverseZone("2001:db8::1")
	if err != nil {
		t.Fatalf("ReverseZone IPv6: %v", err)
	}
	// The zone covers the first 64 bits, the name - the rest.
	if zone != "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatalf("IPv6: zone=%q", zone)
	}
	if name != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" {
		t.Fatalf("IPv6: name=%q", name)
	}

	if _, _, err := ReverseZone("this is not an address"); err == nil {
		t.Fatal("a name was accepted as an address")
	}
}

func TestRecordFQDNBuildsTheName(t *testing.T) {
	record := Record{Zone: "flotestro.test", Name: "web"}
	if record.FQDN() != "web.flotestro.test" {
		t.Fatalf("FQDN = %q", record.FQDN())
	}
	// An entry at the root of a zone is written as "@" and must not give a
	// name starting with a dot.
	root := Record{Zone: "flotestro.test", Name: "@"}
	if root.FQDN() != "flotestro.test" {
		t.Fatalf("the FQDN of the root = %q", root.FQDN())
	}
}

func TestTheDNSCommandsAreOnTheAllowedList(t *testing.T) {
	// The adapter has no way of calling an arbitrary directory command, so
	// every new operation has to be added deliberately.
	for _, method := range []string{"dnszone_find", "dnsrecord_find", "dnsrecord_add", "dnsrecord_del"} {
		if !allowedMethod(method) {
			t.Errorf("the command %s is not allowed", method)
		}
	}
	// There are no commands that change the zone itself, and there should be none.
	for _, method := range []string{"dnszone_add", "dnszone_del", "dnszone_mod", "dnsconfig_mod"} {
		if allowedMethod(method) {
			t.Errorf("the command %s should not be allowed", method)
		}
	}
}

func TestFullNameHandlesTheRootOfAZone(t *testing.T) {
	// The PTR target "@.flotestro.test." points at nothing while looking like
	// a valid record - that is why the root of a zone has a shared function.
	if FullName("flotestro.test", "@") != "flotestro.test" {
		t.Fatalf("the root of the zone = %q", FullName("flotestro.test", "@"))
	}
	if FullName("flotestro.test.", "") != "flotestro.test" {
		t.Fatalf("an empty name = %q", FullName("flotestro.test.", ""))
	}
	if FullName("flotestro.test", "web") != "web.flotestro.test" {
		t.Fatalf("name = %q", FullName("flotestro.test", "web"))
	}
}

func TestNameInZoneComputesTheNameAgainstTheNamedZone(t *testing.T) {
	// A /24 split: the name is one label.
	name, err := NameInZone("192.168.56.10", "56.168.192.in-addr.arpa")
	if err != nil || name != "10" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// A split wider than /24: the name is longer. Computing it for a /24 gave
	// a record for an entirely different address.
	name, err = NameInZone("192.168.56.10", "168.192.in-addr.arpa")
	if err != nil || name != "10.56" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// A zone that does not cover this address is an error rather than a
	// record written somewhere else.
	if _, err := NameInZone("192.168.56.10", "57.168.192.in-addr.arpa"); err == nil {
		t.Fatal("a zone outside the address was accepted")
	}
	// IPv6 against a /48 zone.
	name, err = NameInZone("2001:db8:1::1", "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
	if err != nil {
		t.Fatalf("IPv6: %v", err)
	}
	if !strings.HasSuffix(name, ".0.0.0.0") || strings.Contains(name, "ip6.arpa") {
		t.Fatalf("IPv6: name=%q", name)
	}
}
