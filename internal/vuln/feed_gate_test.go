package vuln

import (
	"errors"
	"testing"
)

// The sanity gate is what stands between a broken download and a fleet
// reported as clean.
func TestTheGateRefusesAFetchThatLostMostOfWhatIsInForce(t *testing.T) {
	inForce := Snapshot{AdvisoryCount: 12000, Releases: []string{"bookworm", "trixie"}}
	cases := []struct {
		name     string
		count    int
		releases []string
		share    float64
		want     string
	}{
		{
			name: "a fetch with nothing in it", count: 0,
			releases: []string{"bookworm", "trixie"}, want: ReasonFeedEmpty,
		},
		{
			name: "a fetch that kept a fifth", count: 2400,
			releases: []string{"bookworm", "trixie"}, want: ReasonFeedShrank,
		},
		{
			// Exactly at the allowance: two fifths lost is still allowed, so the fetch
			// passes.
			name: "a fetch at the edge of the allowance", count: 7200,
			releases: []string{"bookworm", "trixie"}, want: "",
		},
		{
			name: "a fetch that lost a release", count: 11000,
			releases: []string{"bookworm"}, want: ReasonFeedReleaseMissing,
		},
		{
			// A whole family gone is the same statement as every release
			// of it gone, so the same reason covers it.
			name: "a fetch that lost every release", count: 11500,
			releases: []string{"sid"}, want: ReasonFeedReleaseMissing,
		},
		{
			name: "a fetch that grew", count: 13000,
			releases: []string{"bookworm", "trixie"}, want: "",
		},
		{
			name: "a fetch that stayed about the same", count: 11900,
			releases: []string{"bookworm", "trixie", "forky"}, want: "",
		},
		{
			// A stricter installation refuses a movement the default
			// allows.
			name: "a tighter allowance", count: 11000, share: 0.05,
			releases: []string{"bookworm", "trixie"}, want: ReasonFeedShrank,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := feedRefusal(inForce, c.count, c.releases, c.share); got != c.want {
				t.Fatalf("feedRefusal = %q, expected %q", got, c.want)
			}
		})
	}
}

// A provider with nothing in force has no previous answer to protect, so the
// first fetch of a feed is let through however small it is.
func TestTheGateLetsTheFirstFetchOfAProviderThrough(t *testing.T) {
	var nothing Snapshot
	if got := feedRefusal(nothing, 0, nil, 0); got != "" {
		t.Fatalf("an empty first fetch was refused as %q", got)
	}
	if got := feedRefusal(nothing, 3, []string{"trixie"}, 0); got != "" {
		t.Fatalf("a small first fetch was refused as %q", got)
	}
}

// A feed that does not enumerate its releases is not a feed that lost them.
func TestAnAbsentReleaseListIsNotALostRelease(t *testing.T) {
	inForce := Snapshot{AdvisoryCount: 100, Releases: []string{"9", "10"}}
	if got := feedRefusal(inForce, 100, nil, 0); got != "" {
		t.Fatalf("a fetch that names no releases was refused as %q", got)
	}
	if missing := missingReleases(nil, []string{"9"}); len(missing) != 0 {
		t.Fatalf("missingReleases against an unknown list returned %v", missing)
	}
}

// The refusal is typed on both counts: errors.
func TestTheGateRefusalIsTyped(t *testing.T) {
	err := shrinkError(ReasonFeedReleaseMissing, "debian",
		Snapshot{AdvisoryCount: 12000, Releases: []string{"bookworm", "trixie"}},
		11000, []string{"bookworm"})
	if !errors.Is(err, ErrFeedShrank) {
		t.Fatal("the refusal of the gate is not recognised as ErrFeedShrank")
	}
	var refusal *FeedRefusal
	if !errors.As(err, &refusal) {
		t.Fatal("the refusal of the gate carries no typed reason")
	}
	if refusal.Reason != ReasonFeedReleaseMissing {
		t.Fatalf("reason = %q", refusal.Reason)
	}
	if len(refusal.MissingReleases) != 1 || refusal.MissingReleases[0] != "trixie" {
		t.Fatalf("the refusal does not name the lost release: %v", refusal.MissingReleases)
	}
	if refusal.ActiveCount != 12000 || refusal.FetchedCount != 11000 {
		t.Fatalf("the refusal does not carry both counts: %+v", refusal)
	}
	// The codes are the ones the panel and the runbooks name; changing
	// them breaks a screen and a guide at once.
	if ReasonFeedShrank != "feed_shrank" || ReasonFeedReleaseMissing != "feed_release_missing" {
		t.Fatalf("a reason code changed: %q, %q", ReasonFeedShrank, ReasonFeedReleaseMissing)
	}
}

// A share outside the sensible range is not an invitation to refuse everything
// or nothing: it falls back to the default, so a mistyped setting cannot
// switch the gate off.
func TestAnImpossibleShareFallsBackToTheDefault(t *testing.T) {
	for _, share := range []float64{0, -1, 1, 7} {
		if !feedShrankTooFar(1000, 100, share) {
			t.Fatalf("share %v let a fetch through that lost nine tenths", share)
		}
		if feedShrankTooFar(1000, 900, share) {
			t.Fatalf("share %v refused a fetch that lost a tenth", share)
		}
	}
}
