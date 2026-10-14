package cryptostate

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The lock that serialises transitions is taken by commands an operator is
// waiting on. What is tested here is the waiting itself: that a command which
// cannot have the lock is told so, that one which can have it a moment later
// gets it, and that neither answer is given for the wrong reason.

func TestATransitionThatCannotHaveTheLockIsToldAndNotLeftWaiting(t *testing.T) {
	tries := 0
	taken, err := awaitLock(context.Background(), 0, func(context.Context) (bool, error) {
		tries++
		return false, nil
	})
	if err != nil {
		t.Fatalf("awaitLock: %v", err)
	}
	if taken {
		t.Fatal("the lock was reported taken by a try that said it was not")
	}
	// No wait at all is still one question: the answer "somebody holds it" has
	// to come from having asked.
	if tries != 1 {
		t.Errorf("asked %d times, want exactly one", tries)
	}
}

func TestATransitionTakesTheLockThatFreesWhileItWaits(t *testing.T) {
	tries := 0
	taken, err := awaitLock(context.Background(), 10*transitionPoll, func(context.Context) (bool, error) {
		tries++
		return tries > 1, nil
	})
	if err != nil {
		t.Fatalf("awaitLock: %v", err)
	}
	if !taken {
		t.Fatalf("the lock was free on the second try and was not taken; asked %d times", tries)
	}
}

func TestATransitionStopsWaitingWhenTheCommandIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(transitionPoll / 2)
		cancel()
	}()
	taken, err := awaitLock(ctx, time.Minute, func(context.Context) (bool, error) {
		return false, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("awaitLock = %v, want the cancellation", err)
	}
	if taken {
		t.Error("a cancelled wait reported the lock taken")
	}
}

// A database that cannot answer is not a database that says the lock is held:
// the first is an error the operator has to see, the second is a refusal with
// a repair of its own.
func TestATransitionDoesNotMistakeADatabaseErrorForABusyLock(t *testing.T) {
	refused := errors.New("the connection went away")
	taken, err := awaitLock(context.Background(), time.Minute, func(context.Context) (bool, error) {
		return false, refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("awaitLock = %v, want the database's own error", err)
	}
	if taken {
		t.Error("a failed try reported the lock taken")
	}
}
