package campaigns

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ScheduleOrderer places the order of a schedule: the door of the campaign
// API, given the schedule instead of a request.
type ScheduleOrderer interface {
	OrderFromSchedule(ctx context.Context, schedule Schedule, runAt time.Time) (*Campaign, error)
}

// ScheduleRefusal is the door's answer when it would not place the order: the
// code and the sentence the request would have got.
type ScheduleRefusal struct {
	Code   string
	Detail string
}

func (r ScheduleRefusal) Error() string { return r.Code + ": " + r.Detail }

// ScheduleLoop places the orders of the schedules whose moment has come.
type ScheduleLoop struct {
	store    *Store
	orderer  ScheduleOrderer
	log      *slog.Logger
	interval time.Duration
}

// NewScheduleLoop builds the loop; interval is the tick.
func NewScheduleLoop(store *Store, orderer ScheduleOrderer, log *slog.Logger, interval time.Duration) *ScheduleLoop {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &ScheduleLoop{store: store, orderer: orderer, log: log, interval: interval}
}

// Run ticks until the context ends.
func (l *ScheduleLoop) Run(ctx context.Context) {
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

// tick places the order of every due schedule.
func (l *ScheduleLoop) tick(ctx context.Context) {
	now := time.Now().UTC()
	due, err := l.store.DueSchedules(ctx, now)
	if err != nil {
		l.log.Error("the due schedules were not listed", "err", err)
		return
	}
	for _, schedule := range due {
		if ctx.Err() != nil {
			return
		}
		runAt := *schedule.NextRunAt
		next := NextRun(nil, schedule.Rule(), schedule.Location(), runAt.Add(time.Minute))
		claimed, err := l.store.ClaimSchedule(ctx, schedule.ID, runAt, next)
		if err != nil {
			l.log.Error("a schedule was not claimed", "schedule_id", schedule.ID, "err", err)
			continue
		}
		if !claimed {
			continue
		}
		campaign, err := l.orderer.OrderFromSchedule(ctx, schedule, runAt)
		var refusal ScheduleRefusal
		switch {
		case errors.As(err, &refusal):
			l.log.Warn("a scheduled order was refused", "schedule_id", schedule.ID, "name", schedule.Name,
				"code", refusal.Code, "detail", refusal.Detail)
			if err := l.store.RecordScheduleRun(ctx, schedule.ID, "", refusal.Error()); err != nil {
				l.log.Error("a schedule run was not recorded", "schedule_id", schedule.ID, "err", err)
			}
		case err != nil:
			l.log.Error("a scheduled order was not placed", "schedule_id", schedule.ID, "name", schedule.Name, "err", err)
			if err := l.store.RecordScheduleRun(ctx, schedule.ID, "", "internal_error: "+err.Error()); err != nil {
				l.log.Error("a schedule run was not recorded", "schedule_id", schedule.ID, "err", err)
			}
		default:
			l.log.Info("a schedule placed its order", "schedule_id", schedule.ID, "name", schedule.Name,
				"campaign_id", campaign.ID, "next_run_at", next)
			if err := l.store.RecordScheduleRun(ctx, schedule.ID, campaign.ID, ""); err != nil {
				l.log.Error("a schedule run was not recorded", "schedule_id", schedule.ID, "err", err)
			}
		}
	}
}
