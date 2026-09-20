package vuln

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/packages"
)

// A family no tracker describes is named for what it is. Told "no feed yet",
// an operator of a SUSE or an Alpine host would wait for one for ever.
func TestAFamilyWithoutATrackerIsUnsupportedRatherThanWaitingForAFeed(t *testing.T) {
	pkgs := []packages.InstalledPackage{debPackage("openssl", "3.0.11-1", "openssl")}
	cases := map[string]struct {
		distribution string
		release      string
		// The panel has no reader for zypper or apk, so these hosts report no
		// package list at all - and must not be told one is on its way.
		listMissing bool
	}{
		"a SUSE host":          {"sles", "15.6", true},
		"an openSUSE host":     {"opensuse", "15.6", true},
		"an Alpine host":       {"alpine", "3.20", true},
		"a Rocky host":         {"rocky", "9", false},
		"an Amazon Linux host": {"amzn", "2023", false},
		"an Arch host":         {"arch", "", true},
	}
	for name, c := range cases {
		input := debianInput(pkgs...)
		input.Distribution, input.Release = c.distribution, c.release
		input.ListMissing = c.listMissing

		evaluation := Evaluate(input, Snapshot{}, nil, 6*time.Hour, now)
		if evaluation.State.CoverageReason != ReasonFamilyUnsupported {
			t.Errorf("%s: coverage reason = %q, expected %q", name,
				evaluation.State.CoverageReason, ReasonFamilyUnsupported)
		}
		if len(evaluation.Findings) != 0 {
			t.Errorf("%s: %d findings for a family nothing describes", name,
				len(evaluation.Findings))
		}
	}
	// The code is the one the panel and the runbooks name.
	if ReasonFamilyUnsupported != "family_unsupported" {
		t.Fatalf("a reason code changed: %q", ReasonFamilyUnsupported)
	}
}

// The other half of the distinction: a family we do support keeps its
// transient reasons, whatever the state of its feed today.
func TestASupportedFamilyKeepsItsFeedAndListReasons(t *testing.T) {
	pkgs := []packages.InstalledPackage{debPackage("openssl", "3.0.11-1", "openssl")}
	stale := debianSnapshot("trixie")
	stale.FetchedAt = now.Add(-48 * time.Hour)

	cases := map[string]struct {
		snapshot    Snapshot
		listMissing bool
		want        string
	}{
		"a feed never fetched":           {Snapshot{Provider: "debian"}, false, ReasonFeedMissing},
		"a feed from two days ago":       {stale, false, ReasonFeedStale},
		"a release outside the feed":     {debianSnapshot("bookworm"), false, ReasonReleaseUnsupported},
		"a package list not fetched yet": {debianSnapshot("trixie"), true, ReasonPackageListMissing},
	}
	for name, c := range cases {
		input := debianInput(pkgs...)
		input.ListMissing = c.listMissing

		evaluation := Evaluate(input, c.snapshot, nil, 6*time.Hour, now)
		if evaluation.State.CoverageReason != c.want {
			t.Errorf("%s: coverage reason = %q, expected %q", name,
				evaluation.State.CoverageReason, c.want)
		}
	}
}

// The trackers, not a list of spellings, say which families are supported.
func TestTheTrackersDecideWhichFamiliesAreSupported(t *testing.T) {
	for _, distribution := range []string{"debian", "Ubuntu", " fedora ", "rhel"} {
		if FamilyWithoutFeed(distribution) {
			t.Errorf("%q has a tracker and was called unsupported", distribution)
		}
	}
	for _, distribution := range []string{
		"suse", "opensuse", "opensuse-leap", "sles", "alpine", "gentoo", "void",
		"centos", "rocky", "almalinux", "amzn", "ol", "manjaro", "cachyos",
	} {
		if !FamilyWithoutFeed(distribution) {
			t.Errorf("%q has no tracker and was not called unsupported", distribution)
		}
	}
	// A host whose system nobody has read yet is unknown, and unknown is not a
	// refusal to support it.
	if FamilyWithoutFeed("") || FamilyWithoutFeed("   ") {
		t.Error("a host with no distribution was called an unsupported family")
	}
}
