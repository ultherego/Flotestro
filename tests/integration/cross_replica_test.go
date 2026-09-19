//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A lifecycle order that lands on a control-plane instance which does not hold
// the host's session.

// ownership is the owner row of a host as host_session_owners holds it.
type ownership struct {
	SessionID  string
	InstanceID string
	Token      int64
}

// ownerOf reads which instance holds the host's session and under which
// token. It is the address every command is written to.
func ownerOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, hostID string) ownership {
	t.Helper()
	var owner ownership
	err := pool.QueryRow(ctx, `
		select session_id::text, owner_instance_id::text, fencing_token
		  from host_session_owners
		 where host_id = $1::uuid and session_id is not null and lease_until > now()`,
		hostID).Scan(&owner.SessionID, &owner.InstanceID, &owner.Token)
	if err != nil {
		t.Skipf("the host %s has no live session owner: %v", hostID, err)
	}
	return owner
}

// writeCommand puts an order in the queue the way another instance of the
// panel would: in the database, addressed to a session and its token.
func writeCommand(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	hostID, sessionID string, token int64, kind, payload string, ttl time.Duration) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `
		insert into gateway_commands
			(host_id, session_id, fencing_token, kind, payload, created_by, expires_at)
		values ($1::uuid, $2::uuid, $3, $4, $5::jsonb, 'integration-test',
		        now() + make_interval(secs => $6))
		returning id::text`,
		hostID, sessionID, token, kind, payload, ttl.Seconds()).Scan(&id); err != nil {
		t.Fatalf("the order was not written: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`delete from gateway_commands where id = $1::uuid`, id)
	})
	return id
}

// commandRow is what became of an order.
type commandRow struct {
	Claimed bool
	Outcome string
	Detail  map[string]any
}

func readCommand(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) commandRow {
	t.Helper()
	var row commandRow
	var outcome *string
	var detail []byte
	if err := pool.QueryRow(ctx, `
		select claimed_at is not null, outcome, outcome_detail
		  from gateway_commands where id = $1::uuid`, id).Scan(&row.Claimed, &outcome, &detail); err != nil {
		t.Fatalf("the order %s was not read: %v", id, err)
	}
	if outcome != nil {
		row.Outcome = *outcome
	}
	if len(detail) > 0 {
		_ = json.Unmarshal(detail, &row.Detail)
	}
	return row
}

// awaitCommand waits for the panel to settle an order.
func awaitCommand(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string,
	limit time.Duration) commandRow {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		row := readCommand(t, ctx, pool, id)
		if row.Outcome != "" {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("the order %s was not settled within %s (claimed=%v)", id, limit, row.Claimed)
		}
		time.Sleep(time.Second)
	}
}

// connectedHost returns any host with a live session on the panel.
func connectedHost(t *testing.T, h *harness) hostView {
	t.Helper()
	for _, host := range h.hosts() {
		if host.ConnectionState == "online" {
			return host
		}
	}
	t.Skip("no connected host in the fleet")
	return hostView{}
}

// TestAnOrderForTheOwningInstanceIsCarriedOut is the scene of the gap: the
// request landed elsewhere, the order was written for the instance holding the
// host, and that instance carries it out on the host's real session.
func TestAnOrderForTheOwningInstanceIsCarriedOut(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := connectedHost(t, h)
	owner := ownerOf(t, ctx, pool, host.ID)

	id := writeCommand(t, ctx, pool, host.ID, owner.SessionID, owner.Token, "session_close",
		`{"reason":"cross_replica_test","actor":"integration-test"}`, 2*time.Minute)
	row := awaitCommand(t, ctx, pool, id, 90*time.Second)
	if row.Outcome != "done" {
		t.Fatalf("the order ended as %q: %+v", row.Outcome, row.Detail)
	}
	if closed, _ := row.Detail["session_closed"].(bool); !closed {
		t.Fatalf("the instance holding the host reported no session ended: %+v", row.Detail)
	}
	// The host comes back by itself: the panel ended a session, not the
	// host's membership.
	h.awaitConnection(host.ID, 3*time.Minute)
}

// TestAnOrderWithAStaleFencingTokenIsNeverCarriedOut guards the fence.
func TestAnOrderWithAStaleFencingTokenIsNeverCarriedOut(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := connectedHost(t, h)
	owner := ownerOf(t, ctx, pool, host.ID)

	// A token one past the host's own is a token no claim ever had; a session
	// identifier nobody holds is the other half of the same mistake.
	stale := writeCommand(t, ctx, pool, host.ID, owner.SessionID, owner.Token+1, "session_close",
		`{"reason":"cross_replica_test stale token","actor":"integration-test"}`, 2*time.Minute)
	foreign := writeCommand(t, ctx, pool, host.ID, uuid.NewString(), owner.Token, "session_close",
		`{"reason":"cross_replica_test foreign session","actor":"integration-test"}`, 2*time.Minute)

	time.Sleep(30 * time.Second)
	for name, id := range map[string]string{"a newer token": stale, "another session": foreign} {
		row := readCommand(t, ctx, pool, id)
		if row.Claimed || row.Outcome != "" {
			t.Fatalf("an order carrying %s was taken up: claimed=%v outcome=%q",
				name, row.Claimed, row.Outcome)
		}
	}
	// And the host was left alone.
	for _, current := range h.hosts() {
		if current.ID == host.ID && current.ConnectionState != "online" {
			t.Fatalf("the host was cut off by an order nobody should have carried out: %s",
				current.ConnectionState)
		}
	}
}

// TestAnOrderForASessionThatIsGoneEndsAsNoSession guards the second check.
func TestAnOrderForASessionThatIsGoneEndsAsNoSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	// The instance identifier of the running panel is read off a host it really
	// holds; the synthetic host is then given an ownership row naming that
	// instance and a session that exists nowhere.
	live := connectedHost(t, h)
	instance := ownerOf(t, ctx, pool, live.ID).InstanceID
	host := h.enrollSyntheticHost(t)
	session := uuid.NewString()
	token := claimFor(t, ctx, pool, host.ID, session, instance)

	id := writeCommand(t, ctx, pool, host.ID, session, token, "decommission_final",
		`{"reason":"cross_replica_test","actor":"integration-test","local_identity_wipe":true}`,
		2*time.Minute)
	row := awaitCommand(t, ctx, pool, id, 90*time.Second)
	if row.Outcome != "no_session" {
		t.Fatalf("an order for a session nobody holds ended as %q: %+v", row.Outcome, row.Detail)
	}
	var view struct {
		LifecycleState string `json:"lifecycle_state"`
	}
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState == "retired" {
		t.Fatal("the host was retired by an order that was never carried out")
	}
}

// TestADecommissionIsHandedToTheInstanceHoldingTheHost guards what the gap is
// about from the operator's side: a host connected to another instance is no
// longer retired as if it were offline.
func TestADecommissionIsHandedToTheInstanceHoldingTheHost(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.enrollSyntheticHost(t)
	sessionID := uuid.NewString()
	token := claimFor(t, ctx, pool, host.ID, sessionID, uuid.NewString())

	var handed struct {
		LifecycleState           string `json:"lifecycle_state"`
		Phase                    string `json:"phase"`
		HandedOver               bool   `json:"handed_over"`
		CommandID                string `json:"command_id"`
		OwnerInstanceID          string `json:"owner_instance_id"`
		RemoteCleanupUnconfirmed bool   `json:"remote_cleanup_unconfirmed"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "the request landed on another instance",
			"typed_confirmation": host.Hostname}, &handed, http.StatusOK)
	if !handed.HandedOver || handed.CommandID == "" {
		t.Fatalf("the order was not handed to the instance holding the host: %+v", handed)
	}
	if handed.Phase != "handover_pending" || handed.LifecycleState != "retiring" {
		t.Fatalf("a host held by another instance was not left with its owner: %+v", handed)
	}
	if handed.RemoteCleanupUnconfirmed {
		t.Fatalf("a host nobody has finished with yet was reported as retired unconfirmed: %+v", handed)
	}
	// The order is addressed to the session the ownership row named, under
	// its token: that is what keeps another instance from carrying it out.
	var wrote struct {
		Kind      string
		SessionID string
		Token     int64
	}
	if err := pool.QueryRow(ctx, `
		select kind, session_id::text, fencing_token from gateway_commands where id = $1::uuid`,
		handed.CommandID).Scan(&wrote.Kind, &wrote.SessionID, &wrote.Token); err != nil {
		t.Fatalf("the order was not written: %v", err)
	}
	if wrote.Kind != "decommission_final" || wrote.SessionID != sessionID || wrote.Token != token {
		t.Fatalf("the order is addressed elsewhere: %+v", wrote)
	}

	// The owner disappears - the instance is gone for good - and the order is
	// repeated.
	if _, err := pool.Exec(ctx, `delete from host_session_owners where host_id = $1::uuid`,
		host.ID); err != nil {
		t.Fatalf("the ownership row was not removed: %v", err)
	}
	var offline struct {
		LifecycleState           string `json:"lifecycle_state"`
		Phase                    string `json:"phase"`
		HandedOver               bool   `json:"handed_over"`
		RemoteCleanupUnconfirmed bool   `json:"remote_cleanup_unconfirmed"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "the owner is gone; retiring without the confirmation",
			"typed_confirmation": host.Hostname}, &offline, http.StatusOK)
	if offline.LifecycleState != "retired" || offline.Phase != "no_session" ||
		!offline.RemoteCleanupUnconfirmed || offline.HandedOver {
		t.Fatalf("a host nobody holds was not retired as before: %+v", offline)
	}
}

// claimFor gives a host an ownership row naming a session and an instance, the
// way a gateway's claim does, and returns the fencing token.
func claimFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	hostID, sessionID, instanceID string) int64 {
	t.Helper()
	var token int64
	if err := pool.QueryRow(ctx, `
		insert into host_session_owners
			(host_id, fencing_token, session_id, owner_instance_id, lease_until, connected_at, revision)
		values ($1::uuid, 1, $2::uuid, $3::uuid, now() + interval '5 minutes', now(), 1)
		on conflict (host_id) do update set
			fencing_token     = host_session_owners.fencing_token + 1,
			session_id        = excluded.session_id,
			owner_instance_id = excluded.owner_instance_id,
			lease_until       = excluded.lease_until,
			updated_at        = now()
		returning fencing_token`, hostID, sessionID, instanceID).Scan(&token); err != nil {
		t.Fatalf("the ownership row was not written: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`delete from host_session_owners where host_id = $1::uuid`, hostID)
	})
	return token
}
