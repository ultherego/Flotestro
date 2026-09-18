package notify

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/metrics"
)

// The settings of the worker and their defaults.
const (
	// DefaultLease is how long a claimed row is one worker's. A send is
	// bounded by sendTimeout, half of it; the lease is renewed while a
	// send runs, so a slow receiver does not hand the row to a second
	// worker while the first still waits for it.
	DefaultLease = 30 * time.Second
	// DefaultBaseBackoff is the pause before the second attempt; each
	// attempt after it doubles the pause, up to DefaultMaxBackoff.
	DefaultBaseBackoff = 30 * time.Second
	DefaultMaxBackoff  = time.Hour
	// DefaultMaxAttempts is how many attempts a row gets before it is a
	// dead letter: with the backoff, about a day of a receiver being
	// down.
	DefaultMaxAttempts = 20
	// DefaultBatch is how many rows one claim takes.
	DefaultBatch = 50
	// DefaultPoll is how often the worker looks for due rows when
	// nothing woke it.
	DefaultPoll = 2 * time.Second
	// sweepInterval is how often the settled rows past their retention
	// are deleted, and the summaries of ended silences are written.
	sweepInterval = 10 * time.Minute
)

// Options tune the worker; a zero field takes its default.
type Options struct {
	Lease       time.Duration
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	MaxAttempts int
	Batch       int
	Poll        time.Duration
}

func (o Options) withDefaults() Options {
	if o.Lease <= 0 {
		o.Lease = DefaultLease
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = DefaultBaseBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = DefaultMaxAttempts
	}
	if o.Batch <= 0 {
		o.Batch = DefaultBatch
	}
	if o.Poll <= 0 {
		o.Poll = DefaultPoll
	}
	return o
}

// Worker sends the rows of the queue. Every instance of the panel runs
// one; the claim locks the rows it takes and skips the ones another
// instance holds, so two workers never send the same row at once, and a
// row whose worker died is reclaimed when its lease runs out. The
// worker owns nothing in memory: a restart of the panel resumes from
// the rows.
type Worker struct {
	store     *Store
	senders   map[string]Sender
	publicURL string
	log       *slog.Logger
	options   Options
	// owner is this worker's lease identity.
	owner string
	wake  chan struct{}
	// random is the jitter draw; replaced in tests.
	random func() float64
}

// NewWorker creates the worker over the store and the senders of the
// router, so the test button and the queue send the same way.
func NewWorker(store *Store, router *Router, options Options, log *slog.Logger) *Worker {
	return &Worker{
		store: store, senders: router.senders, publicURL: router.publicURL, log: log,
		options: options.withDefaults(), owner: uuid.NewString(),
		wake: make(chan struct{}, 1), random: rand.Float64,
	}
}

// Wake asks for a round now.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run sends until the context ends.
func (w *Worker) Run(ctx context.Context) {
	poll := time.NewTicker(w.options.Poll)
	defer poll.Stop()
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()
	w.housekeep(ctx)
	for {
		for {
			sent, err := w.Round(ctx)
			if err != nil {
				if ctx.Err() == nil {
					w.log.Error("the notification queue was not worked", "err", err)
				}
				break
			}
			if sent < w.options.Batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		case <-w.wake:
		case <-sweep.C:
			w.housekeep(ctx)
		}
	}
}

// housekeep sweeps the settled rows past their retention and writes the
// summaries of the silences that ended.
func (w *Worker) housekeep(ctx context.Context) {
	if err := w.store.SweepDeliveries(ctx); err != nil && ctx.Err() == nil {
		w.log.Error("the notification queue was not swept", "err", err)
	}
	if err := w.Summarize(ctx); err != nil && ctx.Err() == nil {
		w.log.Error("the summaries of the ended silences were not written", "err", err)
	}
}

// Round reclaims the rows whose lease ran out, claims a batch of due
// rows and sends them one after another. It returns how many rows it
// took; an error is the database's.
func (w *Worker) Round(ctx context.Context) (int, error) {
	reclaimed, err := w.store.ReclaimStale(ctx)
	if err != nil {
		return 0, err
	}
	if reclaimed > 0 {
		w.log.Warn("notification deliveries whose lease ran out were returned to the queue", "count", reclaimed)
	}
	claimed, err := w.store.Claim(ctx, w.owner, w.options.Lease, w.options.Batch)
	if err != nil {
		return 0, err
	}
	for _, row := range claimed {
		if ctx.Err() != nil {
			return len(claimed), ctx.Err()
		}
		if err := w.send(ctx, row); err != nil {
			return len(claimed), err
		}
	}
	return len(claimed), nil
}

// send delivers one claimed row and settles it. The lease is renewed
// right before the send - the row may have waited behind the rest of
// the batch - and while the send runs; a renewal that finds the row
// taken by another worker stops this one, and the other settles it.
func (w *Worker) send(ctx context.Context, row Delivery) error {
	held, err := w.store.Renew(ctx, row.ID, w.owner, w.options.Lease)
	if err != nil {
		return err
	}
	if !held {
		return nil
	}
	outcome, held := w.attempt(ctx, row)
	if !held {
		return nil
	}
	if err := w.store.Settle(ctx, row.ID, w.owner, outcome); err != nil {
		return err
	}
	metrics.NotificationDeliveries.Inc(outcome.State)
	if outcome.State != StateDelivered {
		w.log.Warn("a notification was not delivered",
			"delivery", row.ID, "channel", row.ChannelID, "event", row.EventType,
			"attempt", row.Attempt, "state", outcome.State, "code", outcome.ErrorCode, "err", outcome.Error)
	}
	return nil
}

// attempt sends the row once and classifies what happened. The second
// result is false when the row stopped being this worker's during the
// send: the worker that took it settles it.
func (w *Worker) attempt(ctx context.Context, row Delivery) (Outcome, bool) {
	channel, err := w.store.get(ctx, row.ChannelID)
	if err != nil {
		return w.classify(SendError{Code: CodeInvalidConfig, Err: err}, row.Attempt), true
	}
	if !channel.Enabled {
		// A channel disabled while its rows waited does not send them:
		// the operator said "nothing through here", and the rows say
		// why they went nowhere.
		return Outcome{State: StateDeadLetter, ErrorCode: CodeChannelMisconfigured, Error: "the channel is disabled"}, true
	}
	sender, ok := w.senders[channel.Kind]
	if !ok {
		return Outcome{State: StateDeadLetter, ErrorCode: CodeChannelMisconfigured, Error: "no sender for the kind " + channel.Kind}, true
	}
	message, err := row.Message()
	if err != nil {
		return Outcome{State: StateDeadLetter, ErrorCode: CodeChannelMisconfigured, Error: "the row carries no message: " + err.Error()}, true
	}
	message.DeliveryID = row.ID
	loaded, err := w.store.withSecret(ctx, *channel)
	if err != nil {
		return w.classify(err, row.Attempt), true
	}
	sendCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The renewal runs beside the send: a receiver that answers slowly
	// keeps the row this worker's for as long as it takes.
	lost := make(chan struct{})
	go w.renewWhile(sendCtx, row.ID, lost)
	err = sender.Send(sendCtx, loaded, message)
	cancel()
	select {
	case <-lost:
		// Another worker holds the row now; whatever this send did, the
		// other settles it.
		return Outcome{}, false
	default:
	}
	return w.classify(err, row.Attempt), true
}

// renewWhile renews the lease every third of it until the context ends;
// it closes lost when the row is no longer this worker's.
func (w *Worker) renewWhile(ctx context.Context, id string, lost chan<- struct{}) {
	ticker := time.NewTicker(w.options.Lease / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			held, err := w.store.Renew(ctx, id, w.owner, w.options.Lease)
			if err != nil && ctx.Err() == nil {
				w.log.Warn("the lease of a notification delivery was not renewed", "delivery", id, "err", err)
				continue
			}
			if err == nil && !held {
				close(lost)
				return
			}
		}
	}
}

// classify turns the error of an attempt into the outcome, with the
// worker's own attempt cap and backoff.
func (w *Worker) classify(err error, attempt int) Outcome {
	outcome := Classify(err, attempt, w.options.MaxAttempts)
	if outcome.State == StateRetryWait {
		outcome.NextAttempt = Backoff(attempt, w.options.BaseBackoff, w.options.MaxBackoff, w.random())
	}
	return outcome
}

// Classify is the classification of the document, without the worker:
// nothing wrong is delivered; a receiver that answered 408, 429 or 5xx,
// or that could not be reached at all, gets another attempt until the
// attempts run out; 401 and 403 are the credential's fault and a dead
// letter at once; any other status is a dead letter as a permanent
// error of the address or the body. A mail relay follows the same lines
// by its reply codes: a refused login is the credential's fault, a 4xx
// reply passes, a 5xx reply is permanent.
func Classify(err error, attempt, maxAttempts int) Outcome {
	if err == nil {
		return Outcome{State: StateDelivered}
	}
	failure := classify(err)
	sentence := failure.Error()
	retry := func() Outcome {
		if attempt >= maxAttempts {
			// The delivery keeps the reason it failed for, not the fact
			// that the queue stopped trying: the state already says that,
			// and an operator reading "attempts exhausted" learns nothing
			// about the receiver. A test of a channel is one attempt, so
			// the reason would otherwise be lost exactly where it is the
			// whole answer.
			return Outcome{State: StateDeadLetter, ErrorCode: failure.Code,
				Error: fmt.Sprintf("%d attempts; last: %s", attempt, sentence)}
		}
		return Outcome{State: StateRetryWait, ErrorCode: failure.Code, Error: sentence}
	}
	switch failure.Code {
	case CodeReceiverStatus:
		status := failure.Status
		switch {
		case status == 408 || status == 429 || status >= 500:
			return retry()
		case status == 401 || status == 403:
			return Outcome{State: StateDeadLetter, ErrorCode: CodeCredentialsRejected, Error: sentence}
		default:
			return Outcome{State: StateDeadLetter, ErrorCode: CodePermanentHTTP, Error: sentence}
		}
	case CodeSMTPAuthFailed:
		return Outcome{State: StateDeadLetter, ErrorCode: CodeCredentialsRejected, Error: sentence}
	case CodeSMTPRejected:
		if failure.Status >= 500 {
			return Outcome{State: StateDeadLetter, ErrorCode: CodePermanentSMTP, Error: sentence}
		}
		return retry()
	case CodeInvalidConfig:
		return Outcome{State: StateDeadLetter, ErrorCode: CodeChannelMisconfigured, Error: sentence}
	case CodeConnectionRefused, CodeDNSFailure, CodeTimeout, CodeTLSFailure, CodeUnreachable, CodeSecretUnavailable:
		// A network error, and a secret store that did not answer, pass:
		// the receiver may be back, the key may be back, and the operator
		// who replaces a retired secret wants the waiting rows to go out
		// with the new one.
		return retry()
	}
	return retry()
}

// Backoff is the pause before the next attempt after the given one:
// exponential from the base, capped, with full jitter - a uniform draw
// between nothing and the exponential pause, so a thousand rows that
// failed together do not come back together. The draw is the caller's
// number in [0, 1).
func Backoff(attempt int, base, ceiling time.Duration, draw float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	exponent := math.Min(float64(attempt-1), 30)
	pause := time.Duration(float64(base) * math.Pow(2, exponent))
	if pause > ceiling || pause <= 0 {
		pause = ceiling
	}
	if draw < 0 {
		draw = 0
	}
	if draw >= 1 {
		draw = 1
	}
	return time.Duration(float64(pause) * draw)
}

// Summarize writes, for every silence with send_summary that ended, one
// summary row per channel that had rows kept back, and marks those rows
// as summarized. The kept rows themselves stay suppressed: the end of a
// silence is never a flood.
func (w *Worker) Summarize(ctx context.Context) error {
	work, err := w.store.EndedSilences(ctx)
	if err != nil {
		return err
	}
	for _, item := range work {
		message := SummaryMessage(item.Titles, item.Until, item.Reason, w.publicURL)
		if err := w.store.EnqueueSummary(ctx, item, message); err != nil {
			return err
		}
	}
	if len(work) > 0 {
		w.Wake()
	}
	return nil
}
