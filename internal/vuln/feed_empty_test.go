package vuln

import (
	"errors"
	"testing"
)

// An empty fetch never replaces a snapshot that carried findings: the
// vendors do not fix everything at once, and a feed that went from
// thousands to zero is a broken download. A provider that never had
// findings may start from an empty one - the assessment says how much the
// feed covers.
func TestAnEmptyFeedDoesNotReplaceTheLastGoodSnapshot(t *testing.T) {
	cases := []struct {
		previous, fetched int
		refused           bool
	}{
		{previous: 12000, fetched: 0, refused: true},
		{previous: 1, fetched: 0, refused: true},
		{previous: 0, fetched: 0, refused: false},
		{previous: 12000, fetched: 3, refused: false},
		{previous: 0, fetched: 500, refused: false},
	}
	for _, c := range cases {
		if got := feedReplacementRefused(c.previous, c.fetched); got != c.refused {
			t.Errorf("previous %d, fetched %d: refused=%v, expected %v", c.previous, c.fetched, got, c.refused)
		}
	}
}

// The refusal is typed so the scheduler can mark the source with the
// reason rather than log an unrecognised failure, and the reason it writes
// is the code the panel shows next to a stale feed.
func TestTheEmptyFeedRefusalIsTyped(t *testing.T) {
	wrapped := errors.Join(ErrFeedEmpty, errors.New("context"))
	if !errors.Is(wrapped, ErrFeedEmpty) {
		t.Fatal("the empty-feed error does not survive wrapping")
	}
	if ReasonFeedEmpty != "feed_empty" {
		t.Fatalf("the reason code changed: %q", ReasonFeedEmpty)
	}
}
