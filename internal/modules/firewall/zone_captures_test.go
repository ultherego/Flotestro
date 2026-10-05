package firewall

import (
	"errors"
	"strings"
	"testing"
)

// The same measured listings the field comparison is tested on, read the way a
// laboratory check reads them: as two captured texts of one host, compared by
// the product rather than by a script written next to it.
func TestTheMeasuredCapturesAgreeAndNameTheirZones(t *testing.T) {
	comparison, err := CompareZoneCaptures(measured(t, measuredRuntime), measured(t, measuredPermanent), "FedoraServer")
	if err != nil {
		t.Fatalf("the measured pair could not be compared: %v", err)
	}
	if !comparison.Agree() {
		t.Fatalf("the measured clean pair does not agree: %s", comparison.Disagreement())
	}
	if comparison.Disagreement() != "" {
		t.Errorf("an agreeing pair still reported %q", comparison.Disagreement())
	}
	// The consequence the property is about: on a host whose configurations
	// agree the panel takes a zone change. A family where one routine field
	// differs is a family where every zone change is refused.
	if comparison.Refusal != "" {
		t.Errorf("a zone change on an untouched host was refused: %s", comparison.Refusal)
	}
	if len(comparison.RuntimeZones) != 12 {
		t.Fatalf("the host has 12 zones; the comparison names %d: %v",
			len(comparison.RuntimeZones), comparison.RuntimeZones)
	}
	if comparison.RuntimeZones[0] != "FedoraServer" {
		t.Errorf("the first zone reads as %q", comparison.RuntimeZones[0])
	}
}

// The port planted on the live host, through the same entry point: the kept
// configuration moves, and the difference quotes the port so an operator reading
// the panel learns which one.
func TestAPlantedPortMovesTheKeptDigestAndIsNamed(t *testing.T) {
	clean, err := CompareZoneCaptures(measured(t, measuredRuntime), measured(t, measuredPermanent), "FedoraServer")
	if err != nil {
		t.Fatal(err)
	}
	planted, err := CompareZoneCaptures(measured(t, measuredRuntime), measured(t, measuredPlantedPort), "FedoraServer")
	if err != nil {
		t.Fatal(err)
	}
	if planted.PermanentDigest == clean.PermanentDigest {
		t.Fatal("the planted port leaves the fingerprint of the kept configuration still")
	}
	if planted.RuntimeDigest != clean.RuntimeDigest {
		t.Error("a --permanent change moved the running configuration's fingerprint")
	}
	if planted.Agree() {
		t.Fatal("a host with a planted port reads as one whose configurations agree")
	}
	if !planted.Names("9999/tcp") {
		t.Fatalf("the difference does not name the planted port: %s", planted.Disagreement())
	}
	if planted.Refusal == "" {
		t.Error("a zone change was taken on a host carrying a port nobody ordered")
	}
	if !strings.Contains(planted.Refusal, "9999/tcp") {
		t.Errorf("the refusal does not say which port it is about: %s", planted.Refusal)
	}
	if planted.Names("59999/tcp") {
		t.Error("the difference names a port that was never planted")
	}
}

// The false pass this entry point exists to refuse. Two listings that name no
// zone have one fingerprint and nothing between them, so a check that only
// compared them would call an unreadable capture an agreeing host - and
// "unknown is not zero" is the rule a firewall check is held to.
func TestACaptureThatNamesNoZoneIsRefusedRatherThanCompared(t *testing.T) {
	// First the mechanism, so the refusal is not guarding a danger that is not
	// there: without it, these two would agree.
	if ZoneListingsDigest(ZoneListings("")) != ZoneListingsDigest(ZoneListings("")) {
		t.Fatal("two empty listings have different fingerprints; this test guards nothing")
	}
	if drift := ZoneFieldDrift(ZoneListings(""), ZoneListings("")); len(drift) != 0 {
		t.Fatalf("two empty listings already drift: %+v", drift)
	}

	// What a firewall-cmd that did not answer leaves behind: nothing, blank
	// lines, or a message of its own that is no zone listing. A bare zone
	// header is not here on purpose - it does name a zone, and it is checked
	// below as an input one step outside this set.
	good := measured(t, measuredPermanent)
	for _, unreadable := range []string{
		"", "\n\n  \n", "Error: COMMAND_FAILED: '/usr/sbin/nft' failed\n",
		"  target: default\n  services: ssh\n",
	} {
		if _, err := CompareZoneCaptures(unreadable, good, "FedoraServer"); !errors.Is(err, ErrZoneCaptureEmpty) {
			t.Errorf("an unreadable running capture %q was compared, not refused: %v", unreadable, err)
		}
		if _, err := CompareZoneCaptures(good, unreadable, "FedoraServer"); !errors.Is(err, ErrZoneCaptureEmpty) {
			t.Errorf("an unreadable kept capture %q was compared, not refused: %v", unreadable, err)
		}
	}
	// And the message says which of the two configurations could not answer,
	// because the two commands are two answers.
	_, err := CompareZoneCaptures("", measured(t, measuredPermanent), "FedoraServer")
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("the refusal does not name the running configuration: %v", err)
	}
	_, err = CompareZoneCaptures(measured(t, measuredRuntime), "", "FedoraServer")
	if err == nil || !strings.Contains(err.Error(), "kept") {
		t.Errorf("the refusal does not name the kept configuration: %v", err)
	}
}

// One step outside the refused set, from the legitimate side: a host with a
// single zone, and a zone whose fields firewalld printed as a bare header.
// Neither is an unreadable capture, and refusing either would make this check
// unusable on a host that is simply small.
func TestASingleZoneCaptureIsCompared(t *testing.T) {
	one := "public (default, active)\n  target: default\n  interfaces: eth0\n  services: ssh\n"
	kept := "public (default)\n  target: default\n  interfaces: \n  services: ssh\n"
	comparison, err := CompareZoneCaptures(one, kept, "public")
	if err != nil {
		t.Fatalf("a one-zone host was refused: %v", err)
	}
	if !comparison.Agree() {
		t.Fatalf("a one-zone host whose only difference is its interfaces does not agree: %s",
			comparison.Disagreement())
	}
	bare, err := CompareZoneCaptures("public (default, active)\n", "public (default)\n", "public")
	if err != nil {
		t.Fatalf("a zone printed as a bare header was refused: %v", err)
	}
	if !bare.Agree() || len(bare.RuntimeZones) != 1 {
		t.Fatalf("a bare header read as %+v", bare)
	}
}

// A zone one configuration has and the other does not is a disagreement, even
// where every zone they share is identical: the fingerprints alone would miss
// nothing here, but the sentence has to say what the operator is looking at.
func TestADifferentSetOfZonesDoesNotAgree(t *testing.T) {
	running := "public (default, active)\n  target: default\n  services: ssh\n"
	kept := running + "\ninternal (default)\n  target: default\n  services: ssh\n"
	comparison, err := CompareZoneCaptures(running, kept, "public")
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Agree() {
		t.Fatal("a configuration keeping a zone the other does not have reads as agreement")
	}
	if !strings.Contains(comparison.Disagreement(), "internal") {
		t.Errorf("the sentence does not name the zone only one side has: %s", comparison.Disagreement())
	}
}
