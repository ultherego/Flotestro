package scheduler

import (
	"errors"
	"testing"
	"time"
)

// TestConfiguredRateIsTheEffectiveRate pins the relation a fourth knob would
// break: the configured pace is what the loop delivers, because the batch and
// the burst are derived from it rather than left at a default that caps it.
func TestConfiguredRateIsTheEffectiveRate(t *testing.T) {
	tests := []struct {
		name      string
		options   Options
		interval  time.Duration
		batchSize int
		burst     int
		effective float64
	}{
		{
			// The panel's own configuration: only the rate is named.
			name: "the default rate of the panel", options: Options{DispatchRate: 100},
			interval: 2 * time.Second, batchSize: 200, burst: 200, effective: 100,
		},
		{
			// A rate below the default batch leaves the batch alone: the bucket
			// is what paces, and a batch of 32 every two seconds is above it.
			name: "a rate the default batch already carries", options: Options{DispatchRate: 1},
			interval: 2 * time.Second, batchSize: 32, burst: 2, effective: 1,
		},
		{
			// Without a rate nothing is paced and the batch sets the ceiling.
			name: "no pacing at all", options: Options{},
			interval: 2 * time.Second, batchSize: 32, burst: 0, effective: 16,
		},
		{
			// A rate whose pass would not fit one query shortens the pass
			// instead of growing the batch past what a statement carries.
			name: "a rate above one pass", options: Options{DispatchRate: 2000},
			interval: 500 * time.Millisecond, batchSize: 1000, burst: 2000, effective: 2000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filled := test.options.withDefaults()
			if filled.Interval != test.interval {
				t.Errorf("interval = %s, want %s", filled.Interval, test.interval)
			}
			if filled.BatchSize != test.batchSize {
				t.Errorf("batch size = %d, want %d", filled.BatchSize, test.batchSize)
			}
			if got := filled.burst(); got != test.burst {
				t.Errorf("burst = %d, want %d", got, test.burst)
			}
			if got := test.options.EffectiveRate(); got != test.effective {
				t.Errorf("effective rate = %g, want %g", got, test.effective)
			}
			if err := test.options.Validate(); err != nil {
				t.Errorf("a configuration that reaches its rate was refused: %v", err)
			}
		})
	}
}

// TestKnobsThatContradictTheRateAreRefused guards the other half of the
// promise: a rate the knobs cannot reach does not start quietly at a fraction
// of itself.
func TestKnobsThatContradictTheRateAreRefused(t *testing.T) {
	// The batch and the interval the scheduler used to run with at the default
	// rate: 32 tasks every two seconds is sixteen envelopes per second.
	pinned := Options{DispatchRate: 100, Interval: 2 * time.Second, BatchSize: 32}
	if got := pinned.EffectiveRate(); got != 16 {
		t.Fatalf("a batch of 32 every 2s delivers %g per second, want 16", got)
	}
	err := pinned.Validate()
	if !errors.Is(err, ErrDispatchRateUnreachable) {
		t.Fatalf("a batch of 32 at 100 per second was accepted: %v", err)
	}

	// A named interval is the caller's latency, so a rate that needs a larger
	// pass than one statement carries is refused rather than quietly reduced.
	tooFast := Options{DispatchRate: 2000, Interval: time.Second}
	if err := tooFast.Validate(); !errors.Is(err, ErrDispatchRateUnreachable) {
		t.Fatalf("2000 per second with a pass of one second was accepted: %v", err)
	}
}

// TestNewAppliesTheDerivedKnobs keeps the derivation on the path the panel
// takes: the loop reads its interval and its batch from what New stored.
func TestNewAppliesTheDerivedKnobs(t *testing.T) {
	dispatcher := New(nil, nil, nil, nil, nil, Options{GatewayID: "gateway", DispatchRate: 100})
	if dispatcher.options.BatchSize != 200 {
		t.Errorf("New kept a batch of %d at 100 per second, want 200", dispatcher.options.BatchSize)
	}
	if dispatcher.options.Interval != 2*time.Second {
		t.Errorf("New kept an interval of %s, want 2s", dispatcher.options.Interval)
	}
	if got := dispatcher.bucket.Available(); got != 200 {
		t.Errorf("the burst holds %d tokens, want a whole pass of 200", got)
	}
}
