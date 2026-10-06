package opspec

import "testing"

func TestPackageSetDigestNamesTheSetAndNotItsOrder(t *testing.T) {
	first := PackageSetDigest(Payload{PackageChange: &PackageChangePayload{
		Packages: []string{"openssl", "curl", "openssl"},
	}})
	second := PackageSetDigest(Payload{PackageChange: &PackageChangePayload{
		Packages: []string{"curl", "openssl"},
	}})
	if first == "" {
		t.Fatal("a set of two packages has no digest")
	}
	if first != second {
		t.Errorf("the same set in another order digests differently:\n%s\n%s", first, second)
	}
	third := PackageSetDigest(Payload{PackageChange: &PackageChangePayload{
		Packages: []string{"curl"},
	}})
	if third == first {
		t.Error("a smaller set has the same digest as the set it came from")
	}
	// An upgrade names its packages in its own payload, and it is the same set.
	upgrade := PackageSetDigest(Payload{PackageUpgrade: &PackageUpgradePayload{
		Packages: []string{"openssl", "curl"},
	}})
	if upgrade != first {
		t.Errorf("an upgrade of the same set digests differently: %s", upgrade)
	}
}

func TestAnOrderThatNamesNoPackageHasNoDigest(t *testing.T) {
	for name, payload := range map[string]Payload{
		"nothing at all":    {},
		"an empty list":     {PackageChange: &PackageChangePayload{}},
		"blanks only":       {PackageChange: &PackageChangePayload{Packages: []string{"", "  "}}},
		"an upgrade of all": {PackageUpgrade: &PackageUpgradePayload{SecurityOnly: true}},
	} {
		if digest := PackageSetDigest(payload); digest != "" {
			t.Errorf("%s has the digest %s", name, digest)
		}
	}
}

// The trail tells two orders of one campaign apart by this digest, so two
// different sets must not share one. The comment here used to assert that a
// package name cannot carry the separator, and nothing enforced it.
func TestTwoDifferentPackageSetsDoNotShareOneDigest(t *testing.T) {
	set := func(names ...string) string {
		return PackageSetDigest(Payload{PackageChange: &PackageChangePayload{Packages: names}})
	}
	if one, two := set("nginx\nsudo"), set("nginx", "sudo"); one == two {
		t.Errorf("a name carrying the separator shares a digest with two names: %s", one)
	}
	if one, two := set("ngin", "xsudo"), set("nginx", "sudo"); one == two {
		t.Errorf("two sets whose names run together share a digest: %s", one)
	}
	// And the properties the digest is for still hold: it is a set, so order
	// and repetition do not change it.
	if set("a", "b") != set("b", "a") {
		t.Error("the same two packages in another order give another digest")
	}
	if set("a", "a", "b") != set("a", "b") {
		t.Error("a name repeated gives another digest")
	}
	if set() != "" {
		t.Error("an order naming no package has a digest")
	}
}
