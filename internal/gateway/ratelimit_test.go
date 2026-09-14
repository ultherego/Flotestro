package gateway

import (
	"testing"
	"time"
)

// The bucket lets the burst through, refuses beyond it, fills back at the
// rate, and records one refusal a minute per key so that a flood leaves
// one event on the trail rather than one per attempt.
func TestRateLimiterBurstsRefillsAndRecordsOnce(t *testing.T) {
	clock := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(3)
	limiter.now = func() time.Time { return clock }

	for i := 0; i < 3; i++ {
		if allowed, _ := limiter.allow("10.0.0.1"); !allowed {
			t.Fatalf("attempt %d of the burst was refused", i+1)
		}
	}
	allowed, record := limiter.allow("10.0.0.1")
	if allowed || !record {
		t.Fatalf("the fourth attempt: allowed=%v record=%v", allowed, record)
	}
	if allowed, record := limiter.allow("10.0.0.1"); allowed || record {
		t.Fatalf("the fifth attempt: allowed=%v record=%v", allowed, record)
	}
	// Another key has a bucket of its own.
	if allowed, _ := limiter.allow("10.0.0.2"); !allowed {
		t.Fatal("a second key was refused on its first attempt")
	}

	// Twenty seconds at three a minute is one token.
	clock = clock.Add(20 * time.Second)
	if allowed, _ := limiter.allow("10.0.0.1"); !allowed {
		t.Fatal("the bucket did not refill")
	}
	if allowed, record := limiter.allow("10.0.0.1"); allowed || record {
		t.Fatalf("after the refill: allowed=%v record=%v", allowed, record)
	}
	// A minute after the first refusal the next one is recorded again.
	clock = clock.Add(45 * time.Second)
	drained := limiter.buckets["10.0.0.1"]
	drained.tokens, drained.last = 0, clock
	if allowed, record := limiter.allow("10.0.0.1"); allowed || !record {
		t.Fatalf("a minute later: allowed=%v record=%v", allowed, record)
	}

	// An idle key is forgotten, and comes back with a full bucket.
	clock = clock.Add(limiterIdle + time.Minute)
	limiter.allow("other")
	if _, kept := limiter.buckets["10.0.0.1"]; kept {
		t.Fatal("the idle key was not swept")
	}
}
