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
