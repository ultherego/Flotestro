package scheduler

import (
	"math"
	"sync"
	"time"
)

// Bucket paces the envelopes leaving the scheduler: a token bucket that
// fills at a fixed rate up to its capacity, and every envelope sent takes
// one token out.
//
// Without it a pass delivers every leased job at once. A panel coming back
// after an outage finds a queue of thousands, and a thousand envelopes in
// one second is the thundering herd the document's dispatch rate exists to
// prevent: the hosts all start at the same moment, and the database takes
// their acknowledgements and results in one wave. The bucket lets the
// queue drain at a rate the fleet and the panel can carry, with a burst of
// one capacity for the pass that follows a quiet moment.
//
// The clock is a function so the pacing can be checked without waiting.
type Bucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewBucket makes a bucket that fills at rate tokens per second up to
// capacity, full at the start: a panel that has just started has waited
// long enough. A rate or a capacity of zero or less is not a bucket - the
// caller is to keep no bucket at all rather than one that never fills.
func NewBucket(rate float64, capacity int, now func() time.Time) *Bucket {
	if rate <= 0 || capacity <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &Bucket{rate: rate, capacity: float64(capacity), tokens: float64(capacity),
		last: now(), now: now}
}

// refill adds the tokens the clock has earned since the last look. The
// caller holds the lock.
func (b *Bucket) refill() {
	moment := b.now()
	elapsed := moment.Sub(b.last).Seconds()
	// A clock that went back earns nothing and loses nothing: the tokens
	// stay, and the next look counts from the new moment.
	if elapsed > 0 {
		b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.rate)
	}
	b.last = moment
}

// Available says how many whole tokens the bucket holds now.
func (b *Bucket) Available() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return int(b.tokens)
}

// Take takes up to n tokens and says how many it took: all of them when
// the bucket has room, fewer when it does not, none when it is empty. It
// never waits - the scheduler leases what the tokens cover and leaves the
// rest queued for the next pass.
func (b *Bucket) Take(n int) int {
	if n <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	taken := min(n, int(b.tokens))
	b.tokens -= float64(taken)
	return taken
}
