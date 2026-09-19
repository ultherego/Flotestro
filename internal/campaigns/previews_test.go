package campaigns

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/selector"
)

// The binding is a promise about one picture of the fleet, so what it is made
// of has to be exactly what changes it: the hosts, the selector, the scopes,
// the identity.

func TestASetOfHostsHashesTheSameWhateverOrderItComesIn(t *testing.T) {
	first := SnapshotHash([]string{"b", "a", "c"})
	second := SnapshotHash([]string{"c", "b", "a"})
	if first != second {
		t.Errorf("the same hosts in another order hash differently: %s and %s", first, second)
	}
	if SnapshotHash([]string{"a", "b"}) == first {
		t.Error("a snapshot of two hosts hashes like a snapshot of three")
	}
	// A host named twice is one host: a list that repeats one is the same
	// set, and an order is not refused for a duplicate.
	if SnapshotHash([]string{"a", "a", "b", "c"}) != first {
		t.Error("a repeated identifier changes the snapshot")
	}
}

func TestTheReasonForAnExclusionIsNotPartOfWhichHostsAreChosen(t *testing.T) {
	chosen := Selector{Site: "lab", Exclude: []string{"host-a"}, ExcludeReason: "being rebuilt"}
	other := chosen
	other.ExcludeReason = "the operator wrote something else"
	first, err := SelectorHash(chosen)
	if err != nil {
		t.Fatalf("hashing the selector: %v", err)
	}
	second, err := SelectorHash(other)
	if err != nil {
		t.Fatalf("hashing the selector: %v", err)
	}
	if first != second {
		t.Error("the wording of an exclusion changes the selector's fingerprint")
	}
	// What hosts are excluded is part of it.
	third, err := SelectorHash(Selector{Site: "lab", Exclude: []string{"host-b"}})
	if err != nil {
		t.Fatalf("hashing the selector: %v", err)
	}
	if third == first {
		t.Error("excluding another host leaves the selector's fingerprint unchanged")
	}
}

func TestATypedExpressionIsPartOfTheSelectorFingerprint(t *testing.T) {
	first, err := SelectorHash(Selector{Expression: &selector.Expression{Tag: "web"}})
	if err != nil {
		t.Fatalf("hashing the selector: %v", err)
	}
	second, err := SelectorHash(Selector{Expression: &selector.Expression{Tag: "database"}})
	if err != nil {
		t.Fatalf("hashing the selector: %v", err)
	}
	if first == second {
		t.Error("two expressions naming different hosts hash alike")
	}
}

func TestEachDifferenceBetweenAPreviewAndAnOrderIsNamed(t *testing.T) {
	expires := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	shown := PreviewBinding{
		PrincipalID: "principal-1", Permission: "packages.upgrade", Action: "packages.upgrade",
		SelectorHash: "sha256:selector", ScopeHash: "sha256:scope", SnapshotHash: "sha256:snapshot",
		TargetCount: 12, ExpiresAt: expires,
	}
	if err := shown.compare(shown); err != nil {
		t.Fatalf("an order matching its preview was refused: %v", err)
	}

	for name, change := range map[string]func(*PreviewBinding){
		"preview_principal_mismatch":  func(b *PreviewBinding) { b.PrincipalID = "principal-2" },
		"preview_permission_mismatch": func(b *PreviewBinding) { b.Permission = "unit.restart" },
		"preview_action_mismatch":     func(b *PreviewBinding) { b.Action = "unit.restart" },
		"preview_selector_changed":    func(b *PreviewBinding) { b.SelectorHash = "sha256:other" },
		"preview_scope_changed":       func(b *PreviewBinding) { b.ScopeHash = "sha256:other" },
		"preview_targets_changed":     func(b *PreviewBinding) { b.SnapshotHash = "sha256:other" },
	} {
		order := shown
		change(&order)
		err := shown.compare(order)
		if err == nil {
			t.Errorf("%s: the difference was not noticed", name)
			continue
		}
		if code := PreviewRefusalCode(err); code != name {
			t.Errorf("%s: the refusal came back as %s", name, code)
		}
	}

	// The count alone is enough: a fleet that swapped one host for another
	// would hash differently, and one that simply grew says how much by.
	order := shown
	order.TargetCount = 13
	if code := PreviewRefusalCode(shown.compare(order)); code != "preview_targets_changed" {
		t.Errorf("a changed number of hosts came back as %s", code)
	}
}

func TestTheDigestCoversEveryPartOfTheBinding(t *testing.T) {
	binding := PreviewBinding{
		PrincipalID: "principal-1", Permission: "packages.upgrade", Action: "packages.upgrade",
		SelectorHash: "sha256:selector", ScopeHash: "sha256:scope", SnapshotHash: "sha256:snapshot",
		TargetCount: 12, ExpiresAt: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
	}
	first, err := binding.Digest()
	if err != nil {
		t.Fatalf("the digest was not computed: %v", err)
	}
	again, err := binding.Digest()
	if err != nil || again != first {
		t.Fatalf("the same binding digests differently: %s and %s (%v)", first, again, err)
	}
	for name, change := range map[string]func(*PreviewBinding){
		"the principal":  func(b *PreviewBinding) { b.PrincipalID = "principal-2" },
		"the permission": func(b *PreviewBinding) { b.Permission = "unit.restart" },
		"the operation":  func(b *PreviewBinding) { b.Action = "unit.restart" },
		"the selector":   func(b *PreviewBinding) { b.SelectorHash = "sha256:other" },
		"the scopes":     func(b *PreviewBinding) { b.ScopeHash = "sha256:other" },
		"the snapshot":   func(b *PreviewBinding) { b.SnapshotHash = "sha256:other" },
		"the count":      func(b *PreviewBinding) { b.TargetCount = 13 },
		"the expiry":     func(b *PreviewBinding) { b.ExpiresAt = b.ExpiresAt.Add(time.Minute) },
	} {
		other := binding
		change(&other)
		digest, err := other.Digest()
		if err != nil {
			t.Fatalf("%s: the digest was not computed: %v", name, err)
		}
		if digest == first {
			t.Errorf("%s changed and the digest did not", name)
		}
	}
}

func TestTheRolloutStageIsReadStrictly(t *testing.T) {
	for value, want := range map[string]PreviewMode{
		"": PreviewPrefer, "observe": PreviewObserve, "prefer": PreviewPrefer,
		"enforce": PreviewEnforce, " ENFORCE ": PreviewEnforce,
	} {
		mode, err := ParsePreviewMode(value)
		if err != nil {
			t.Errorf("%q was refused: %v", value, err)
			continue
		}
		if mode != want {
			t.Errorf("%q was read as %q", value, mode)
		}
	}
	// A misspelt stage is a misconfiguration: an installation that meant to
	// enforce must not silently observe.
	if _, err := ParsePreviewMode("enforced"); err == nil {
		t.Error("a word that is not a stage was accepted")
	}
}
