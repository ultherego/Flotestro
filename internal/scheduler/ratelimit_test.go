package scheduler

import (
	"testing"
	"time"
)

// fakeClock stands still until the test moves it.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time { return c.at }

func (c *fakeClock) advance(d time.Duration) { c.at = c.at.Add(d) }

// TestBucketStartsFullAndHoldsItsCapacity guards the burst: a bucket
// starts with its capacity, gives up to that much at once, and no more
// than that however long the fleet was quiet.
func TestBucketStartsFullAndHoldsItsCapacity(t *testing.T) {
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0)}
	bucket := NewBucket(100, 100, clock.now)

	if got := bucket.Available(); got != 100 {
		t.Fatalf("a new bucket holds %d tokens, want the capacity", got)
	}
	if took := bucket.Take(30); took != 30 {
		t.Fatalf("took %d of 30 from a full bucket", took)
	}
	if took := bucket.Take(100); took != 70 {
		t.Fatalf("took %d of 100 from a bucket of 70", took)
	}
	if took := bucket.Take(1); took != 0 {
		t.Fatalf("an empty bucket gave %d tokens", took)
	}
	// An hour of quiet earns one capacity, not an hour of rate.
	clock.advance(time.Hour)
	if got := bucket.Available(); got != 100 {
		t.Fatalf("after an hour the bucket holds %d, want the capacity", got)
	}
}

// TestBucketRefillsAtItsRate guards the pacing itself: the tokens come
// back at the rate per second, in fractions that add up, and a clock that
// went back earns nothing.
func TestBucketRefillsAtItsRate(t *testing.T) {
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0)}
	bucket := NewBucket(10, 20, clock.now)
	if took := bucket.Take(20); took != 20 {
		t.Fatalf("took %d of 20", took)
	}

	clock.advance(500 * time.Millisecond)
	if got := bucket.Available(); got != 5 {
		t.Fatalf("half a second at 10/s earned %d tokens, want 5", got)
	}
	// A quarter of a second is two and a half tokens; the half is not a
	// token until the next quarter completes it.
	clock.advance(250 * time.Millisecond)
	if got := bucket.Available(); got != 7 {
		t.Fatalf("a fraction of a token counted as a whole one: %d", got)
	}
	clock.advance(250 * time.Millisecond)
	if got := bucket.Available(); got != 10 {
		t.Fatalf("two fractions did not add up to a token: %d", got)
	}

	clock.advance(-time.Minute)
	if got := bucket.Available(); got != 10 {
		t.Fatalf("a clock that went back changed the tokens to %d", got)
	}
	// Time counts from the new moment: a second from here earns ten more,
	// and that is the capacity.
	clock.advance(time.Second)
	if got := bucket.Available(); got != 20 {
		t.Fatalf("a second after the clock went back earned %d, want 20", got)
	}
	if took := bucket.Take(0); took != 0 {
		t.Fatalf("asking for nothing took %d", took)
	}
}

// TestNoBucketForARateOfZero guards the switch: a rate of zero is the
// pacing turned off, not a bucket that never fills.
func TestNoBucketForARateOfZero(t *testing.T) {
	if NewBucket(0, 100, nil) != nil || NewBucket(-1, 100, nil) != nil || NewBucket(10, 0, nil) != nil {
		t.Fatal("a rate or a capacity of zero made a bucket")
	}
	if NewBucket(10, 10, nil) == nil {
		t.Fatal("a real rate made no bucket")
	}
}
