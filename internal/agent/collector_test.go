package agent

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Ordering a collection must not wait for its result. The message receive loop
// orders the inventory and has to come back for the next tasks at once -
// otherwise a slow read stops the management of the host.
func TestOrderingACollectionDoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	running := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	k := newCollector()
	// Only the first collection is meant to last: the second one is the one
	// folded together from the orders placed meanwhile and ends at once.
	go k.run(ctx, func(context.Context, []string) (Facts, error) {
		first.Do(func() {
			close(running)
			<-release
		})
		return Facts{}, nil
	}, func(Facts) (Refresh, error) { return Refresh{}, nil }, quietLogger())

	k.request()
	<-running // the collection started and is running

	ordered := make(chan struct{})
	go func() { k.request(); close(ordered) }()
	select {
	case <-ordered:
	case <-time.After(2 * time.Second):
		t.Fatal("ordering a collection blocked on the read in progress")
	}
	close(release)
}

// Orders placed during a collection in progress fold into one: each of them
// would return the same state of the host.
func TestOrdersFoldTogether(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	running := make(chan struct{})
	release := make(chan struct{})
	var collections atomic.Int32
	done := make(chan struct{}, 8)

	k := newCollector()
	go k.run(ctx, func(context.Context, []string) (Facts, error) {
		if collections.Add(1) == 1 {
			close(running)
			<-release
		}
		return Facts{}, nil
	}, func(Facts) (Refresh, error) { done <- struct{}{}; return Refresh{}, nil }, quietLogger())

	k.request()
	<-running
	for i := 0; i < 5; i++ {
		k.request()
	}
	close(release)

	// The first collection plus exactly one folded from the five orders.
	<-done
	<-done
	select {
	case <-done:
		t.Fatalf("collections = %d, expected two", collections.Load())
	case <-time.After(300 * time.Millisecond):
	}
}

// A failed read does not end the work of the collector: a source that is
// unavailable for the moment is no reason to break the session of the agent.
func TestAFailedCollectionDoesNotEndTheWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	done := make(chan struct{}, 2)
	k := newCollector()
	go k.run(ctx, func(context.Context, []string) (Facts, error) {
		if attempts.Add(1) == 1 {
			return Facts{}, context.DeadlineExceeded
		}
		return Facts{}, nil
	}, func(Facts) (Refresh, error) { done <- struct{}{}; return Refresh{}, nil }, quietLogger())

	k.request()
	time.Sleep(50 * time.Millisecond)
	k.request()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the collector did not serve an order after a failed read")
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
