package gateway

import (
	"sync"
	"time"
)

// The enrollment endpoint answers strangers: it is the one door open without a
// client certificate, and the token that opens it is short.
const (
	enrollPerIPPerMinute      = 10
	enrollPerMachinePerMinute = 3
	// limiterIdle is how long an idle key stays in memory before it is
	// forgotten; a bucket that has filled back up carries no information.
	limiterIdle = 10 * time.Minute
)

// rateLimiter is a set of token buckets keyed by a string, filling at a fixed
// rate up to a burst.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
	// swept is when the idle buckets were last dropped.
	swept time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	// refused is the minute in which a refusal was last recorded on the
	// trail, so that a flood of refusals leaves one event a minute.
	refused time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		rate: float64(perMinute) / 60, burst: float64(perMinute),
		buckets: map[string]*bucket{}, now: time.Now,
	}
}

// allow takes one token of the key.
func (l *rateLimiter) allow(key string) (allowed, recordRefusal bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	if b.refused.IsZero() || now.Sub(b.refused) >= time.Minute {
		b.refused = now
		return false, true
	}
	return false, false
}

// refund gives the key its token back.
func (l *rateLimiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return
	}
	if b.tokens += 1; b.tokens > l.burst {
		b.tokens = l.burst
	}
}

// sweep forgets the keys that have been idle long enough to be full again.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	for key, b := range l.buckets {
		if now.Sub(b.last) > limiterIdle {
			delete(l.buckets, key)
		}
	}
}
