package scheduler

import (
	"math"
	"sync"
	"time"
)

// Bucket paces the envelopes leaving the scheduler: a token bucket that fills
// at a fixed rate up to its capacity, and every envelope sent takes one token
// out.
type Bucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewBucket makes a bucket that fills at rate tokens per second up to
// capacity, full at the start: a panel that has just started has waited long
// enough.
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

// Take takes up to n tokens and says how many it took: all of them when the
// bucket has room, fewer when it does not, none when it is empty.
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
