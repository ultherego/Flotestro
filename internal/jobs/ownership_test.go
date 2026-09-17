package jobs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A refused fence is a typed reason with the code the guide documents,
// and it survives wrapping: the gateway and the scheduler tell it apart
// from a closed session row and from a settled job by errors.Is alone.
func TestAStaleFenceIsTypedAndCarriesItsCode(t *testing.T) {
	wrapped := errors.Join(ErrStaleFence, errors.New("recording the result"))
	if !errors.Is(wrapped, ErrStaleFence) {
		t.Fatal("the stale-fence error does not survive wrapping")
	}
	if errors.Is(wrapped, ErrSessionStale) {
		t.Fatal("a stale fence reads as a stale session; the two are different refusals")
	}
	if !strings.HasPrefix(ErrStaleFence.Error(), ErrorSessionFenceStale+":") {
		t.Fatalf("the stale-fence error does not carry its code: %q", ErrStaleFence)
	}
}

// A fence that names no session is refused before the database is asked:
// a write nobody owns is not a write to make, and the check must fail
// closed without a transaction to fail in.
func TestAnEmptyFenceIsRefusedWithoutAskingTheDatabase(t *testing.T) {
	err := fenceHolds(context.Background(), nil, "job", Fence{Token: 7})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("an empty fence was not refused: %v", err)
	}
}

// A host is delivered to only while its row names a session whose lease
// has not run out. A row that was released keeps its token and owns
// nothing; a lease that ran out is a host nobody owns, whatever the
// session says.
func TestAnOwnerIsLiveOnlyWithASessionAndAnUnexpiredLease(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		owner Owner
		live  bool
	}{
		{name: "no row", owner: Owner{}},
		{name: "released", owner: Owner{Token: 3}},
		{name: "lease ran out", owner: Owner{SessionID: "s", Token: 3, LeaseUntil: now.Add(-time.Millisecond)}},
		{name: "owned", owner: Owner{SessionID: "s", Token: 3, LeaseUntil: now.Add(OwnerLeaseTTL)}, live: true},
	}
	for _, c := range cases {
		if got := c.owner.Live(now); got != c.live {
			t.Errorf("%s: live = %v, expected %v", c.name, got, c.live)
		}
	}
}

// The renewal cadence leaves room for a renewal to fail: a session that
// misses one renewal keeps its host, and one that stops renewing loses it
// within the lease.
func TestTheLeaseOutlastsAMissedRenewal(t *testing.T) {
	if OwnerRenewEvery*2 >= OwnerLeaseTTL {
		t.Fatalf("one missed renewal loses the host: renew every %s, lease %s", OwnerRenewEvery, OwnerLeaseTTL)
	}
	if OwnerLeaseTTL > time.Minute {
		t.Fatalf("a dead instance keeps its hosts for %s; the scheduler holds their tasks that long", OwnerLeaseTTL)
	}
}

// The identifier of the process is drawn once: two sessions of one
// instance claim under one name, and a restart is a new name. Nothing
// else about ownership lives in memory.
func TestTheInstanceIdentifierIsOnePerProcess(t *testing.T) {
	if InstanceID() == "" || InstanceID() != InstanceID() {
		t.Fatalf("the instance identifier is not stable: %q", InstanceID())
	}
}

// A session's fence is its identifier and its token, nothing else: the
// registry builds it from the session, and the store compares exactly
// these two with the host's row.
func TestAFenceNamesTheSessionAndItsToken(t *testing.T) {
	fence := Fence{SessionID: "session", Token: 42}
	if fence.SessionID != "session" || fence.Token != 42 {
		t.Fatalf("the fence changed its shape: %+v", fence)
	}
}
