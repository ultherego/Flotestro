// Package integrations connects the panel with the systems already present in
// an installation: with Prometheus, Alertmanager and a log system. The panel
// neither replaces them nor copies their data into itself - it shows what they
// say, together with the time range and the name of the source.
//
// Each of these connections can fail and the panel is to work on: a failure of
// the monitoring must not take the ability to manage a host away from the
// operator. Hence the shared breaker: a short time limit on every question and
// a pause after a run of errors, so that the screen of a host does not wait
// for a system that does not answer.
package integrations

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBreakerOpen means the breaker is open and the questions do not go
// further. That is not a failure of the panel: it is the answer "this source
// does not answer right now", given without waiting.
var ErrBreakerOpen = errors.New("the integration does not answer; the questions are held back")

const (
	// ErrorThreshold is the number of successive errors after which we stop
	// asking.
	ErrorThreshold = 3
	// BreakerPause is the time after which we try again - one question, to
	// check whether the source is back.
	BreakerPause = 30 * time.Second
	// DefaultTimeout holds for a single question to an integration. The screen
	// of a host is to be drawn also when the monitoring says nothing.
	DefaultTimeout = 5 * time.Second
)

// Breaker is the circuit breaker of one integration.
type Breaker struct {
	mu        sync.Mutex
	errors_   int
	openUntil time.Time
	// clock allows checking the behaviour without waiting.
	clock func() time.Time
}

// NewBreaker creates a breaker.
func NewBreaker() *Breaker {
	return &Breaker{clock: time.Now}
}

// now returns the current moment according to the clock of the breaker.
func (o *Breaker) now() time.Time {
	if o.clock == nil {
		return time.Now()
	}
	return o.clock()
}

// Do lets a call through or refuses it outright.
//
// The refusal is immediate and carries an error of its own: a screen that
// waits five seconds for each of eight panels is a screen nobody opens a
// second time.
func (o *Breaker) Do(call func() error) error {
	if err := o.allow(); err != nil {
		return err
	}
	err := call()
	o.record(err)
	return err
}

func (o *Breaker) allow() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.openUntil.IsZero() || o.now().After(o.openUntil) {
		return nil
	}
	return ErrBreakerOpen
}

func (o *Breaker) record(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err == nil {
		// One successful answer closes the breaker: the source is back.
		o.errors_ = 0
		o.openUntil = time.Time{}
		return
	}
	o.errors_++
	if o.errors_ >= ErrorThreshold {
		o.openUntil = o.now().Add(BreakerPause)
		o.errors_ = 0
	}
}

// Open says whether the breaker is holding the questions back right now.
func (o *Breaker) Open() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.openUntil.IsZero() && !o.now().After(o.openUntil)
}

// State describes the availability of an integration.
//
// Three answers, not two: an integration that is not configured is not the
// same as an integration that does not answer. The first is a decision of the
// installation, the second a failure - and the operator is to tell them apart
// without reading the configuration.
type State struct {
	Name string `json:"name"`
	// Configured says whether the installation named this source at all.
	Configured bool `json:"configured"`
	// Healthy says whether the source answered the last question.
	Healthy bool   `json:"healthy"`
	URL     string `json:"url,omitempty"`
	// Reason describes why the source does not answer.
	Reason string `json:"reason,omitempty"`
	// LatencyMillis says how long the answer took.
	LatencyMillis *int64     `json:"latency_millis,omitempty"`
	CheckedAt     *time.Time `json:"checked_at,omitempty"`
}

// WithTimeout narrows the context to the time limit of an integration.
func WithTimeout(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if limit <= 0 {
		limit = DefaultTimeout
	}
	return context.WithTimeout(ctx, limit)
}
