package policy

import (
	"context"
	"log/slog"
	"time"
)

// Loop judges the published policies at their intervals. The loop never reads
// a host: it judges what the inventory holds.
type Loop struct {
	store     *Store
	evaluator *Evaluator
	log       *slog.Logger
	interval  time.Duration
}

// NewLoop builds the loop; interval is the tick, not the check interval
// of the policies, which every policy carries itself.
func NewLoop(store *Store, evaluator *Evaluator, log *slog.Logger, interval time.Duration) *Loop {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Loop{store: store, evaluator: evaluator, log: log, interval: interval}
}

// Run ticks until the context ends.
func (l *Loop) Run(ctx context.Context) {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.tick(ctx)
		}
	}
}

// tick evaluates every policy that is due.
func (l *Loop) tick(ctx context.Context) {
	due, err := l.store.Due(ctx, time.Now().UTC())
	if err != nil {
		l.log.Error("the due policies were not listed", "err", err)
		return
	}
	for _, policy := range due {
		if ctx.Err() != nil {
			return
		}
		outcome, err := l.evaluator.Evaluate(ctx, policy)
		if err != nil {
			l.log.Error("a policy was not evaluated", "policy_id", policy.ID, "name", policy.Name, "err", err)
			continue
		}
		l.log.Info("a policy was evaluated", "policy_id", policy.ID, "name", policy.Name,
			"version", outcome.Version, "hosts", outcome.Hosts, "drift", outcome.Counts[VerdictDrift],
			"error", outcome.Counts[VerdictError], "campaign_id", outcome.CampaignID)
	}
}
