package firewall

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The listings in testdata were taken from a live Fedora host with firewalld
// running, not written from an example. The permanent one was taken twice: once
// with the host untouched, and once after a --permanent --add-port=9999/tcp
// planted in FedoraServer behind the panel's back. The runtime listing was
// byte-identical before and after that, which is the defect measured instead
// of argued.
const (
	measuredRuntime        = "fedora_zones_runtime.txt"
	measuredPermanent      = "fedora_zones_permanent.txt"
	measuredPlantedPort    = "fedora_zones_permanent_pending.txt"
	plantedRichRuleListing = "fedora_zones_permanent_rich.txt"
)

// typedForm is the modelled zones as the fingerprint sees them, which is what
// the panel could compare before the fields were read.
func typedForm(zones []Zone) string {
	var out strings.Builder
	for _, zone := range zones {
		out.WriteString(canonicalZone(zone))
	}
	return out.String()
}

// measured reads one of those listings.
func measured(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading the measured listing: %v", err)
	}
	return string(content)
}

// What a live firewalld prints, read whole. The zone header of the permanent
// listing is not bare: it carries "(default)" where the running one carries
// "(default, active)".
func TestTheMeasuredListingsAreReadWholeAndTyped(t *testing.T) {
	kept := ZoneListings(measured(t, measuredPermanent))
	running := ZoneListings(measured(t, measuredRuntime))
	if len(kept) != 12 || len(running) != 12 {
		t.Fatalf("the host has 12 zones; read %d kept and %d running", len(kept), len(running))
	}
	first, _ := zoneListingNamed(kept, "FedoraServer")
	if first.Markers != "default" {
		t.Errorf("the permanent header carried %q", first.Markers)
	}
	if runningFirst, _ := zoneListingNamed(running, "FedoraServer"); runningFirst.Markers != "default, active" {
		t.Errorf("the running header carried %q", runningFirst.Markers)
	}
	// Every field the host printed is read, the ten the Zone struct does not
	// model included.
	for _, field := range []string{"target", "ingress-priority", "egress-priority",
		"icmp-block-inversion", "interfaces", "sources", "services", "ports", "protocols",
		"forward", "masquerade", "forward-ports", "source-ports", "icmp-blocks", "rich rules"} {
		if _, printed := first.Field(field); !printed {
			t.Errorf("the field %q was not read", field)
		}
	}
	// A rich rule is printed under its field on a tab-indented line of its own,
	// and belongs to that field rather than becoming one.
	shared, _ := zoneListingNamed(kept, "nm-shared")
	if rules, _ := shared.Field("rich rules"); rules != `rule priority="32767" reject` {
		t.Errorf("the rich rule of nm-shared read as %q", rules)
	}
	if protocols, _ := shared.Field("protocols"); protocols != "icmp ipv6-icmp" {
		t.Errorf("the protocols of nm-shared read as %q", protocols)
	}
	for _, field := range shared.Fields {
		if strings.HasPrefix(field.Name, "rule ") {
			t.Errorf("a rich rule became a field of its own: %q", field.Name)
		}
	}

	// And the typed zones come out of the same text by the same reader.
	typed := ParseZones(measured(t, measuredPermanent), "FedoraServer")
	zone, ok := zoneNamed(typed, "FedoraServer")
	if !ok || !zone.Default || zone.Active || len(zone.Interfaces) != 0 ||
		zone.Target != "default" || len(zone.Services) != 3 {
		t.Fatalf("the typed permanent zone is %+v", zone)
	}
	zone, _ = zoneNamed(ParseZones(measured(t, measuredRuntime), "FedoraServer"), "FedoraServer")
	if !zone.Default || !zone.Active || !slices.Equal(zone.Interfaces, []string{"enp0s3", "enp0s8", "enp0s9"}) {
		t.Fatalf("the typed running zone is %+v", zone)
	}
}

// An untouched host does not drift. Measured: the two clean listings differ in
// exactly two things, the header marker and the interfaces line, and
// zoneListingNormalisation drops exactly those two - so the digest of what the
// host filters with and the digest of what it keeps are one string.
func TestTheMeasuredCleanPairDoesNotDrift(t *testing.T) {
	running := ZoneListings(measured(t, measuredRuntime))
	kept := ZoneListings(measured(t, measuredPermanent))

	if ZoneListingsDigest(running) != ZoneListingsDigest(kept) {
		t.Fatal("the two configurations of an untouched host have different digests")
	}
	if drift := ZoneFieldDrift(running, kept); len(drift) != 0 {
		t.Fatalf("a field of an untouched host reads as differing: %+v", drift)
	}
	typedDrift := ZoneDrift(ParseZones(measured(t, measuredRuntime), "FedoraServer"),
		ParseZones(measured(t, measuredPermanent), "FedoraServer"), "", "")
	if len(typedDrift) != 0 {
		t.Fatalf("an untouched host reads as drifting: %+v", typedDrift)
	}
	if refusal := ZoneReloadRefusal(append(typedDrift, ZoneFieldDrift(running, kept)...)); refusal != "" {
		t.Errorf("an untouched host was refused a zone change: %s", refusal)
	}
	// The digest is of the configuration and not of the reading: two readings
	// of one text are one digest.
	if ZoneListingsDigest(kept) != ZoneListingsDigest(ZoneListings(measured(t, measuredPermanent))) {
		t.Error("two readings of one listing have different digests")
	}
}

// The port planted on the live host, caught by the typed comparison and by the
// digest. The running listing was byte-identical across the planting, so
// nothing read from it could have seen this.
func TestTheMeasuredPlantedPortIsCaught(t *testing.T) {
	clean := measured(t, measuredPermanent)
	planted := measured(t, measuredPlantedPort)
	if clean == planted {
		t.Fatal("the two measured permanent listings are the same text")
	}
	if ZoneListingsDigest(ZoneListings(clean)) == ZoneListingsDigest(ZoneListings(planted)) {
		t.Fatal("the planted port leaves the digest of the kept configuration still")
	}
	drift := ZoneDrift(ParseZones(measured(t, measuredRuntime), "FedoraServer"),
		ParseZones(planted, "FedoraServer"), "", "")
	if len(drift) != 1 || drift[0].Reason != DriftZonePending || drift[0].Rule != "port 9999/tcp" ||
		drift[0].Zone != "FedoraServer" {
		t.Fatalf("the planted port reads as %+v", drift)
	}
	if refusal := ZoneReloadRefusal(drift); !strings.Contains(refusal, "9999/tcp") {
		t.Errorf("the refusal does not name the planted port: %s", refusal)
	}
}

// A rich rule written into the permanent configuration and not reloaded. The
// panel does not model rich rules, so the typed zones of the two listings are
// identical and the committed version of this change could not see it: the
// digest moves and the field comparison names the field.
func TestAPlantedRichRuleIsCaughtAndNamed(t *testing.T) {
	clean := measured(t, measuredPermanent)
	planted := measured(t, plantedRichRuleListing)

	// What the typed comparison can say about it: nothing.
	cleanZones := ParseZones(clean, "FedoraServer")
	plantedZones := ParseZones(planted, "FedoraServer")
	if typedForm(cleanZones) != typedForm(plantedZones) {
		t.Fatal("the typed zones differ, so this does not exercise an unmodelled field")
	}
	if drift := ZoneDrift(ParseZones(measured(t, measuredRuntime), "FedoraServer"),
		plantedZones, "", ""); len(drift) != 0 {
		t.Fatalf("the typed comparison reported %+v, so this proves nothing about the fields", drift)
	}

	// And the fingerprint as it was computed before the fields were read - over
	// the modelled zones alone - does not move either. That is the version of
	// this change that was committed first, failing on this case.
	running := ParseZones(measured(t, measuredRuntime), "FedoraServer")
	beforeModelled := Snapshot{Hash: "ruleset", Zones: running, PermanentZones: cleanZones}
	afterModelled := Snapshot{Hash: "ruleset", Zones: running, PermanentZones: plantedZones}
	if sealed(beforeModelled) != sealed(afterModelled) {
		t.Fatal("the modelled zones saw the rich rule, so this proves nothing about the fields")
	}

	// What the digest and the field comparison say about it.
	if ZoneListingsDigest(ZoneListings(clean)) == ZoneListingsDigest(ZoneListings(planted)) {
		t.Fatal("a rich rule written and not reloaded leaves the digest still")
	}
	drift := ZoneFieldDrift(ZoneListings(measured(t, measuredRuntime)), ZoneListings(planted))
	if len(drift) != 1 || drift[0].Reason != DriftZoneFieldDiffers ||
		drift[0].Rule != "rich rules" || drift[0].Zone != "public" {
		t.Fatalf("the planted rich rule reads as %+v", drift)
	}
	// Named, and with both values, because a field the panel cannot describe
	// still has to be settled by somebody reading the message.
	if !strings.Contains(drift[0].Detail, "10.0.0.0/8") || !strings.Contains(drift[0].Detail, "nothing") {
		t.Errorf("the difference does not carry the two values: %s", drift[0].Detail)
	}
	refusal := ZoneReloadRefusal(drift)
	if !strings.Contains(refusal, "rich rules") || !strings.Contains(refusal, "public") {
		t.Errorf("the refusal does not name the field: %s", refusal)
	}

	// With the digest in it, the same two readings do move the fingerprint, so
	// a plan made before the rich rule was written does not apply after it.
	beforeModelled.PermanentZonesDigest = ZoneListingsDigest(ZoneListings(clean))
	afterModelled.PermanentZonesDigest = ZoneListingsDigest(ZoneListings(planted))
	if sealed(beforeModelled) == sealed(afterModelled) {
		t.Fatal("a rich rule written and not reloaded leaves the fingerprint still")
	}
}

// The field a lab finding would add goes in one list, and what that list drops
// is dropped by both the digest and the comparison. Measured: interfaces is
// the one entry, and it is why an ordinary host passes.
func TestTheNormalisationDropsAFieldFromBothTheDigestAndTheComparison(t *testing.T) {
	for _, field := range zoneListingNormalisation {
		clean := ZoneListings(measured(t, measuredPermanent))
		altered := ZoneListings(strings.Replace(measured(t, measuredPermanent),
			"  "+field+": ", "  "+field+": planted", 1))
		if ZoneListingsDigest(clean) != ZoneListingsDigest(altered) {
			t.Errorf("a change to %s moved the digest although the list drops it", field)
		}
		if drift := ZoneFieldDrift(altered, clean); len(drift) != 0 {
			t.Errorf("a change to %s was reported although the list drops it: %+v", field, drift)
		}
	}
	// A field outside that list is not dropped: the direction chosen is to
	// refuse with the field named rather than to carry it unannounced.
	altered := ZoneListings(strings.Replace(measured(t, measuredPermanent),
		"  masquerade: no", "  masquerade: yes", 1))
	drift := ZoneFieldDrift(ZoneListings(measured(t, measuredRuntime)), altered)
	if len(drift) != 1 || drift[0].Rule != "masquerade" {
		t.Fatalf("a field outside the list reads as %+v", drift)
	}
}

// allDifferences is everything the panel can say about one pair of listings:
// the entries it models and the fields it does not.
func allDifferences(runtimeText, permanentText string) []Drift {
	drift := ZoneDrift(ParseZones(runtimeText, "FedoraServer"),
		ParseZones(permanentText, "FedoraServer"), "", "")
	return append(drift, ZoneFieldDrift(ZoneListings(runtimeText), ZoneListings(permanentText))...)
}

// Nothing that moves the fingerprint goes unnamed. A refusal the operator
// cannot act on is no better than a change carried without telling them, so
// every planted difference here has to do both: move the digest, and come out
// of one of the two comparisons with a name on it.
func TestEveryDifferenceThatMovesTheDigestIsNamed(t *testing.T) {
	runtimeText := measured(t, measuredRuntime)
	clean := measured(t, measuredPermanent)
	if drift := allDifferences(runtimeText, clean); len(drift) != 0 {
		t.Fatalf("the measured pair differs before anything is planted: %+v", drift)
	}

	for _, tc := range []struct {
		why     string
		planted string
		names   string
	}{
		{why: "a port written on the live host", planted: measured(t, measuredPlantedPort),
			names: "9999/tcp"},
		{why: "a rich rule", planted: measured(t, plantedRichRuleListing), names: "rich rules"},
		{why: "a protocol", names: "protocols",
			planted: strings.Replace(clean, "  protocols: \n", "  protocols: icmp\n", 1)},
		{why: "masquerade turned on", names: "masquerade",
			planted: strings.Replace(clean, "  masquerade: no", "  masquerade: yes", 1)},
		{why: "a field no longer printed", names: "masquerade",
			planted: strings.Replace(clean, "  masquerade: no\n", "", 1)},
		{why: "a line below a field the panel models", names: "ports",
			planted: strings.Replace(clean, "  ports: \n", "  ports: \n\tsomething unexpected\n", 1)},
		{why: "a zone", names: "planted", planted: clean + "planted\n  target: default\n"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			if tc.planted == clean {
				t.Fatal("the planted listing is the clean one, so nothing is exercised")
			}
			if ZoneListingsDigest(ZoneListings(tc.planted)) == ZoneListingsDigest(ZoneListings(clean)) {
				t.Error("the difference leaves the digest still, so a plan made before it still applies")
			}
			drift := allDifferences(runtimeText, tc.planted)
			if len(drift) == 0 {
				t.Fatal("the difference has no name, so a refusal over it could not be acted on")
			}
			named := false
			for _, entry := range drift {
				if entry.Detail == "" {
					t.Errorf("a difference says nothing about what it means: %+v", entry)
				}
				if strings.Contains(entry.Rule, tc.names) || strings.Contains(entry.Zone, tc.names) ||
					strings.Contains(entry.Detail, tc.names) {
					named = true
				}
			}
			if !named {
				t.Errorf("no difference names %s: %+v", tc.names, drift)
			}
			if ZoneReloadRefusal(drift) == "" {
				t.Error("the change was allowed to reload a configuration nobody approved")
			}
			// One difference, one entry: a line below a modelled field must not
			// be reported twice over, once as an entry and once as a field.
			if len(drift) > 2 {
				t.Errorf("one difference produced %d entries: %+v", len(drift), drift)
			}
		})
	}
}

// What a rich rule may look like cannot be measured on one host, so the parse
// rule does not depend on its shape: a line that is not a field of its own
// belongs to the field above it, whatever it is indented with and whatever it
// contains.
func TestARichRuleIsReadWhateverItIsIndentedWithAndWhateverItContains(t *testing.T) {
	const listing = `public (default, active)
  services: ssh
  rich rules:
	rule family="ipv6" source address="2001:db8::/32" service name="ssh" accept
  rule family="ipv4" source address="10.0.0.0/8" drop
`
	zones := ZoneListings(listing)
	if len(zones) != 1 || len(zones[0].Fields) != 2 {
		t.Fatalf("the listing read as %+v", zones)
	}
	rules, printed := zones[0].Field("rich rules")
	if !printed || !strings.Contains(rules, "2001:db8::/32") || !strings.Contains(rules, "10.0.0.0/8") {
		t.Fatalf("the rich rules read as %q", rules)
	}
	// An address with colons in it did not become a field name, and the two
	// rules did not run together into one word.
	for _, field := range zones[0].Fields {
		if !zoneFieldName.MatchString(field.Name) {
			t.Errorf("a rule was read as the field %q", field.Name)
		}
	}
	if strings.Contains(rules, "accept  rule") || strings.Contains(rules, "acceptrule") {
		t.Errorf("two rules ran together: %q", rules)
	}
	// And the services above the rich rules kept their own value.
	if services, _ := zones[0].Field("services"); services != "ssh" {
		t.Errorf("the field above the rules read as %q", services)
	}
}

// A field one configuration does not print at all is not a field printed
// empty - an older firewalld on one side of an upgrade prints fewer of them.
func TestAFieldNotPrintedIsNotAFieldPrintedEmpty(t *testing.T) {
	withField := ZoneListings("public\n  services: ssh\n  masquerade: no\n")
	without := ZoneListings("public\n  services: ssh\n")
	drift := ZoneFieldDrift(without, withField)
	if len(drift) != 1 || drift[0].Rule != "masquerade" {
		t.Fatalf("a field on one side only reads as %+v", drift)
	}
	if !strings.Contains(drift[0].Detail, "nothing of the kind") {
		t.Errorf("an unprinted field reads as an empty one: %s", drift[0].Detail)
	}
	// From the good side: a field neither of them prints is no difference.
	if drift := ZoneFieldDrift(without, without); len(drift) != 0 {
		t.Fatalf("two identical listings read as differing: %+v", drift)
	}
	// And a zone only one configuration has is left to ZoneDrift, which
	// reports it whole rather than field by field.
	extra := ZoneListings("public\n  services: ssh\ndmz\n  services: http\n")
	if drift := ZoneFieldDrift(extra, without); len(drift) != 0 {
		t.Fatalf("a zone the other configuration has not reads as %+v", drift)
	}
}
