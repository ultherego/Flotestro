package database

import (
	"strings"
	"testing"
	"time"
)

// The claim of a gateway identifier, row by row: what a start does with the
// record it finds under its own identifier.
func TestJudgingTheClaimOfAGatewayIdentifier(t *testing.T) {
	const ours = "11111111-1111-1111-1111-111111111111"
	const theirs = "22222222-2222-2222-2222-222222222222"
	beat := time.Now().Add(-5 * time.Second)

	live := func(heartbeat time.Time, since time.Duration) *Instance {
		return &Instance{
			GatewayID: "panel-1", InstanceID: theirs,
			LastHeartbeatAt: heartbeat, SinceHeartbeat: since,
		}
	}

	cases := []struct {
		name      string
		holder    *Instance
		firstSeen time.Time
		want      instanceDecision
	}{
		{name: "the identifier has never been claimed", holder: nil, want: takeInstance},
		{
			name:   "this very process claims again after an interrupted start",
			holder: &Instance{InstanceID: ours, LastHeartbeatAt: beat, SinceHeartbeat: 5 * time.Second},
			want:   takeInstance,
		},
		{
			name:   "the record of a dead instance: the ordinary restart",
			holder: live(beat, InstanceStaleAfter+time.Second),
			want:   takeInstance,
		},
		{
			name:   "a record that looks fresh, seen once: it is watched, not refused",
			holder: live(beat, 5*time.Second),
			want:   waitInstance,
		},
		{
			name:      "the heartbeat has not moved since the first look",
			holder:    live(beat, 20*time.Second),
			firstSeen: beat,
			want:      waitInstance,
		},
		{
			name:      "the heartbeat moved: another replica is alive under the identifier",
			holder:    live(beat.Add(15*time.Second), 2*time.Second),
			firstSeen: beat,
			want:      refuseInstance,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := judgeInstanceClaim(ours, c.holder, c.firstSeen); got != c.want {
				t.Fatalf("decision = %d, want %d", got, c.want)
			}
		})
	}
}

// A record whose heartbeat stopped exactly at the stale window is a dead
// instance: the window is what "nobody renews this" means, and an ordinary
// restart must not hang on the boundary.
func TestTheStaleWindowDecidesWhoIsLive(t *testing.T) {
	fresh := Instance{SinceHeartbeat: InstanceStaleAfter - time.Millisecond}
	dead := Instance{SinceHeartbeat: InstanceStaleAfter}
	if !fresh.Live() {
		t.Error("a record younger than the stale window is not live")
	}
	if dead.Live() {
		t.Error("a record as old as the stale window is still live")
	}
	if InstanceStaleAfter < 3*InstanceHeartbeatEvery {
		t.Errorf("the stale window %s holds fewer than three heartbeats of %s; one slow query would "+
			"make a running replica look dead", InstanceStaleAfter, InstanceHeartbeatEvery)
	}
}

// The identifier is what everything downstream reads as "the instance", so
// a claim that cannot identify a replica is refused before it reaches the
// database.
func TestAClaimNamesTheReplica(t *testing.T) {
	good := Claim{GatewayID: "panel-1", InstanceID: "11111111-1111-1111-1111-111111111111"}
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed claim was refused: %v", err)
	}
	for _, c := range []struct {
		name  string
		claim Claim
	}{
		{"no identifier", Claim{InstanceID: good.InstanceID}},
		{"whitespace only", Claim{GatewayID: "  ", InstanceID: good.InstanceID}},
		{"padded", Claim{GatewayID: "panel-1 ", InstanceID: good.InstanceID}},
		{"too long", Claim{GatewayID: strings.Repeat("p", 129), InstanceID: good.InstanceID}},
		{"no process", Claim{GatewayID: "panel-1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := c.claim.Validate(); err == nil {
				t.Fatal("the claim was accepted")
			}
		})
	}
}

// The refusal says which process holds the identifier and where, because
// that is what an operator needs in order to decide whether to give the new
// replica an identifier of its own or to stop the old one.
func TestTheRefusalNamesTheHolder(t *testing.T) {
	holder := Instance{
		GatewayID: "panel-1", InstanceID: "22222222-2222-2222-2222-222222222222",
		Hostname: "cp-b", SinceHeartbeat: 3 * time.Second,
	}
	err := &InstanceInUseError{GatewayID: "panel-1", Holder: holder}
	if err.Code() != CodeGatewayIDInUse {
		t.Fatalf("code = %s, want %s", err.Code(), CodeGatewayIDInUse)
	}
	for _, want := range []string{CodeGatewayIDInUse, "panel-1", "cp-b", "22222222"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %s", want, err.Error())
		}
	}
}

// The budget of chapter 21: N replicas times the maximum of the pool against
// what the server answers.
func TestTheConnectionBudgetIsComputedPerInstallation(t *testing.T) {
	replicas := func(pools ...int32) []Instance {
		instances := make([]Instance, 0, len(pools))
		for i, pool := range pools {
			instances = append(instances, Instance{
				GatewayID: string(rune('a'+i)) + "-panel", PoolMaxConns: pool,
			})
		}
		return instances
	}

	t.Run("another replica fits", func(t *testing.T) {
		budget := budgetOf(replicas(16, 16), 16, 100, 3, 40)
		if budget.Replicas != 2 || budget.Claimed != 32 || budget.Available != 97 {
			t.Fatalf("budget = %+v", budget)
		}
		if !budget.NextReplicaFits || budget.Shortfall != 0 || budget.Overcommitted() {
			t.Fatalf("a third replica of 16 does not fit in 97: %+v", budget)
		}
		if budget.Headroom != 65 {
			t.Fatalf("headroom = %d, want 65", budget.Headroom)
		}
	})

	t.Run("the next replica would not fit", func(t *testing.T) {
		budget := budgetOf(replicas(40, 40), 40, 100, 3, 80)
		if budget.NextReplicaFits {
			t.Fatal("a third replica of 40 was said to fit in 97 with 80 already claimed")
		}
		if budget.Shortfall != 23 {
			t.Fatalf("shortfall = %d, want 23", budget.Shortfall)
		}
		if budget.Overcommitted() {
			t.Fatal("two replicas of 40 in 97 were called overcommitted")
		}
		if !strings.Contains(budget.Summary(), "would be 23 over") {
			t.Errorf("summary = %q", budget.Summary())
		}
	})

	t.Run("the replicas already exceed the server", func(t *testing.T) {
		budget := budgetOf(replicas(60, 60), 60, 100, 3, 50)
		if !budget.Overcommitted() || budget.Headroom != -23 {
			t.Fatalf("budget = %+v", budget)
		}
		if !strings.Contains(budget.Summary(), "23 over") {
			t.Errorf("summary = %q", budget.Summary())
		}
	})

	t.Run("a replica that does not say how large its pool is", func(t *testing.T) {
		budget := budgetOf(replicas(16, 0), 16, 100, 3, 20)
		if budget.Unreported != 1 {
			t.Fatalf("unreported = %d, want 1", budget.Unreported)
		}
		// Unknown is not zero: it is counted out of the sum and said out
		// loud, so nobody reads the headroom as a promise.
		if budget.Claimed != 16 {
			t.Fatalf("claimed = %d, want 16", budget.Claimed)
		}
	})

	t.Run("a server that reserves more than it allows", func(t *testing.T) {
		budget := budgetOf(replicas(16), 16, 2, 5, 1)
		if budget.Available != 0 || budget.NextReplicaFits {
			t.Fatalf("budget = %+v", budget)
		}
	})
}

// The identifiers of the live replicas are what the screen lists; they come
// back sorted so that two refreshes do not reorder the list.
func TestTheLiveGatewayIdentifiersAreListedInOrder(t *testing.T) {
	budget := Budget{Instances: []Instance{{GatewayID: "panel-b"}, {GatewayID: "panel-a"}}}
	ids := budget.GatewayIDs()
	if len(ids) != 2 || ids[0] != "panel-a" || ids[1] != "panel-b" {
		t.Fatalf("gateway ids = %v", ids)
	}
}
