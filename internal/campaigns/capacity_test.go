package campaigns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/ultherego/flotestro/internal/budgets"
)

// renewerStub stands in for the capacity budgets: it answers one renewal and
// keeps what it was asked to renew.
type renewerStub struct {
	err    error
	leases []budgets.Fenced
	calls  int
}

func (r *renewerStub) RenewFenced(_ context.Context, leases []budgets.Fenced) error {
	r.calls++
	r.leases = leases
	return r.err
}

func silentLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// working is a host in the middle of its change: the state the renewal is
// about.
func working(id string, token int64) Target {
	return Target{ID: id, HostID: "host-" + id, State: TargetRunning, ClaimToken: token}
}

// TestARunnerThatLostTheTokensOfItsHostsLaunchesNothingMore pins the fence:
// the moment the capacity leases of the hosts at work carry another runner's
// token, the pass is over - it starts nobody and hands the campaign back.
func TestARunnerThatLostTheTokensOfItsHostsLaunchesNothingMore(t *testing.T) {
	campaign := Campaign{ID: "c1"}
	targets := []Target{working("t1", 7), working("t2", 7)}

	t.Run("the tokens changed hands", func(t *testing.T) {
		renewer := &renewerStub{err: budgets.ErrFenceStale}
		mayLaunch, err := capacityHolds(context.Background(), renewer, campaign, targets, silentLog())
		if mayLaunch {
			t.Error("a runner whose hosts were taken from it must start nobody")
		}
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("err = %v, expected the runner lease to be reported lost", err)
		}
		// tick reads this error to forget the campaign, so the reason has to
		// survive the wrapping as well.
		if !errors.Is(err, budgets.ErrFenceStale) {
			t.Errorf("the stale fence was not carried out of the renewal: %v", err)
		}
	})

	t.Run("the grants merely ran out", func(t *testing.T) {
		renewer := &renewerStub{err: budgets.ErrLeaseLost}
		mayLaunch, err := capacityHolds(context.Background(), renewer, campaign, targets, silentLog())
		if err != nil {
			t.Fatalf("err = %v, expected the pass to go on settling", err)
		}
		if mayLaunch {
			t.Error("hosts the fleet no longer counts must not be joined by new ones")
		}
	})

	t.Run("the database did not answer", func(t *testing.T) {
		renewer := &renewerStub{err: errors.New("the connection was refused")}
		mayLaunch, err := capacityHolds(context.Background(), renewer, campaign, targets, silentLog())
		if err != nil {
			t.Fatalf("err = %v, expected a renewal that failed to hold the launches, not the pass", err)
		}
		if mayLaunch {
			t.Error("a renewal nobody could read must not be taken as a renewal that held")
		}
	})

	t.Run("the leases held", func(t *testing.T) {
		renewer := &renewerStub{}
		mayLaunch, err := capacityHolds(context.Background(), renewer, campaign, targets, silentLog())
		if err != nil || !mayLaunch {
			t.Fatalf("mayLaunch = %v, err = %v", mayLaunch, err)
		}
	})
}

// The renewal names the hosts that carry a change and the token each of them
// was claimed under: a settled host has given its tokens back and a waiting
// one never took any.
func TestTheRenewalNamesOnlyTheHostsAtWorkWithTheirClaimTokens(t *testing.T) {
	targets := []Target{
		working("t1", 3),
		{ID: "t2", State: TargetSucceeded, ClaimToken: 3},
		{ID: "t3", State: TargetAwaitingBudget, ClaimToken: 3},
		{ID: "t4", State: TargetQueuedOffline, ClaimToken: 3},
		{ID: "t5", State: TargetRebooting, ClaimToken: 9},
	}
	renewer := &renewerStub{}
	if err := renewCapacity(context.Background(), renewer, targets); err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []budgets.Fenced{{Owner: "t1", Token: 3}, {Owner: "t5", Token: 9}}
	if len(renewer.leases) != len(want) {
		t.Fatalf("renewed %v, expected %v", renewer.leases, want)
	}
	for i, lease := range want {
		if renewer.leases[i] != lease {
			t.Errorf("renewed[%d] = %v, expected %v", i, renewer.leases[i], lease)
		}
	}
}

// A campaign whose hosts have all settled asks the budgets nothing and is free
// to start the next wave.
func TestACampaignWithNoHostAtWorkRenewsNothingAndMayStart(t *testing.T) {
	renewer := &renewerStub{}
	mayLaunch, err := capacityHolds(context.Background(), renewer, Campaign{ID: "c1"},
		[]Target{{ID: "t1", State: TargetSucceeded}}, silentLog())
	if err != nil || !mayLaunch {
		t.Fatalf("mayLaunch = %v, err = %v", mayLaunch, err)
	}
	if renewer.calls != 0 {
		t.Errorf("the budgets were asked %d times about nothing", renewer.calls)
	}
}

// An expired grant must not read as a takeover: the campaign stays with this
// runner, so tick may not forget it.
func TestAnExpiredGrantIsNotReadAsAnotherRunnersClaim(t *testing.T) {
	renewer := &renewerStub{err: budgets.ErrLeaseLost}
	err := renewCapacity(context.Background(), renewer, []Target{working("t1", 1)})
	if !errors.Is(err, errCapacityUnproven) {
		t.Fatalf("err = %v, expected the capacity to be reported unproven", err)
	}
	if errors.Is(err, ErrLeaseLost) {
		t.Error("a grant that ran out was read as the runner lease being lost")
	}
}
