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

// occurrenceGrace is how long a claimed moment may stay unsettled before the
// loop takes it for recovery. It is longer than one ordering takes and shorter
// than anybody would wait for a campaign: what it keeps apart is a tick that is
// still working from one that stopped.
const occurrenceGrace = time.Minute

// recover places the orders of the moments that were claimed and never
// settled. Ordering again is safe: the key of the order is
// "schedule:<id>:<moment>", written for exactly this.
func (l *ScheduleLoop) recover(ctx context.Context) {
	pending, err := l.store.PendingOccurrences(ctx, occurrenceGrace)
	if err != nil {
		l.log.Error("the claimed moments were not read", "err", err)
		return
	}
	for _, occurrence := range pending {
		if ctx.Err() != nil {
			return
		}
		schedule, err := l.store.GetSchedule(ctx, occurrence.ScheduleID)
		if err != nil || schedule == nil {
			// A schedule that is gone takes its moments with it; the row goes
			// with the schedule by the foreign key, so there is nothing to do.
			continue
		}
		l.log.Warn("a moment was claimed and its campaign never placed; placing it now",
			"schedule_id", occurrence.ScheduleID, "due_at", occurrence.DueAt)
		l.place(ctx, *schedule, occurrence.DueAt)
	}
}

// tick places the order of every due schedule.
func (l *ScheduleLoop) tick(ctx context.Context) {
	// First the moments somebody claimed and never settled. A one-shot
	// schedule has no next moment, so losing this one loses it for good.
	l.recover(ctx)

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
		l.place(ctx, schedule, runAt)
	}
}

// place orders the campaign of one claimed moment and records what became of
// it, in the schedule and in the occurrence. A refusal settles the moment too:
// an order the panel would not place is an answer, not work to retry for ever.
func (l *ScheduleLoop) place(ctx context.Context, schedule Schedule, runAt time.Time) {
	campaign, err := l.orderer.OrderFromSchedule(ctx, schedule, runAt)
	var refusal ScheduleRefusal
	switch {
	case errors.As(err, &refusal):
		l.log.Warn("a scheduled order was refused", "schedule_id", schedule.ID, "name", schedule.Name,
			"code", refusal.Code, "detail", refusal.Detail)
		l.record(ctx, schedule.ID, runAt, "", refusal.Error())
	case err != nil:
		// Not settled: an error of the panel's own is something to try again at
		// the next tick, which is what the pending occurrence is for.
		l.log.Error("a scheduled order was not placed", "schedule_id", schedule.ID, "name", schedule.Name, "err", err)
		if err := l.store.RecordScheduleRun(ctx, schedule.ID, "", "internal_error: "+err.Error()); err != nil {
			l.log.Error("a schedule run was not recorded", "schedule_id", schedule.ID, "err", err)
		}
	default:
		l.log.Info("a schedule placed its order", "schedule_id", schedule.ID, "name", schedule.Name,
			"campaign_id", campaign.ID)
		l.record(ctx, schedule.ID, runAt, campaign.ID, "")
	}
}

// record writes the outcome where the operator reads it and where the recovery
// reads it.
func (l *ScheduleLoop) record(ctx context.Context, scheduleID string, runAt time.Time,
	campaignID, refusal string) {
	if err := l.store.RecordScheduleRun(ctx, scheduleID, campaignID, refusal); err != nil {
		l.log.Error("a schedule run was not recorded", "schedule_id", scheduleID, "err", err)
	}
	if err := l.store.SettleOccurrence(ctx, scheduleID, runAt, campaignID, refusal); err != nil {
		l.log.Error("a claimed moment was not settled", "schedule_id", scheduleID,
			"due_at", runAt, "err", err)
	}
}
