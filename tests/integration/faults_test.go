//go:build integration

package integration

// Fault injection from chapter 23 of the architecture document: the panel
// goes away while a job runs, the link to a host is cut while a job runs,
// and a lease runs out on an attempt nobody will ever finish.
//
// These tests need more than the API. Besides the variables of the harness
// (FLOTESTRO_TEST_TOKEN, FLOTESTRO_TEST_API, FLOTESTRO_TEST_DATABASE_URL,
// FLOTESTRO_TEST_GATEWAY) they read:
//
//   - FLOTESTRO_TEST_CONTROL_PLANE_UNIT - the systemd unit of the control
//     plane on the machine the tests run on. Set, it says the tests run as
//     root on the panel itself and may restart the unit and add nft rules.
//     Empty, the tests that need it skip.
//
// What the product promises here, as read from the code:
//
//   - A task runs under the context of the session that delivered it
//     (internal/agent/session.go: executeTask(sessionCtx, ...)). A session
//     that breaks ends the task; the end of a journal preview is a success
//     ("the preview ended"). The result is written to the idempotency
//     journal before it is sent, and a failed send is only logged.
//   - Nothing on the panel closes an attempt when its session dies. The
//     lease is the only signal (internal/jobs/store.go ReclaimExpiredLeases:
//     "time is the only certain signal that an attempt failed"); it lasts
//     five minutes (cmd/control-plane/main.go) and the scheduler reclaims it
//     in a housekeeping pass every 30 s. The reclaimed attempt is marked
//     lease_expired and the job goes back to the queue; the next delivery is
//     answered from the journal with replayed = true.
//   - A job stays "dispatched" while the agent works: no code path moves it
//     to "running". The tests wait for either.

import (
	"context"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// leaseRecoveryBound is how long a lost result may take to reach the panel:
// the five-minute lease, the housekeeping pass that reclaims it, the
// dispatch pass that redelivers it and a margin for the agent.
const leaseRecoveryBound = 7 * time.Minute

// linkCutDuration is how long the link stays black-holed. It must exceed
// the only liveness check on the link: the agent's HTTP/2 client pings
// after 30 s without a frame and gives up 15 s later (newHTTP2Client in
// internal/agent/session.go); the gateway itself has no keepalive and the
// heartbeat is 60 s with a 30 s jitter. Anything shorter is a hiccup TCP
// retransmission papers over, and the session would never be reopened.
const linkCutDuration = 60 * time.Second

// nftTable is the throwaway table the link cut lives in. A table of its own
// can be deleted whole, whatever the state of the test.
const nftTable = "flotestro_test"

// controlPlaneUnit returns the systemd unit of the control plane or skips:
// restarting the panel and filtering its traffic need root on the panel,
// and only the lab script knows whether that is where the tests run.
func controlPlaneUnit(t *testing.T) string {
	t.Helper()
	unit := os.Getenv("FLOTESTRO_TEST_CONTROL_PLANE_UNIT")
	if unit == "" {
		t.Skip("FLOTESTRO_TEST_CONTROL_PLANE_UNIT is not set; the fault tests run only as root on the panel")
	}
	if os.Geteuid() != 0 {
		t.Skipf("not running as root (uid %d); the unit %s cannot be restarted", os.Geteuid(), unit)
	}
	if output, err := exec.Command("systemctl", "is-active", unit).CombinedOutput(); err != nil {
		t.Skipf("the unit %s is not active here: %s", unit, strings.TrimSpace(string(output)))
	}
	return unit
}

// journalFollow orders a live preview that keeps the agent busy for the
// given number of seconds. A long read is the honest way to have a job in
// flight when the fault strikes: it changes nothing on the host, so the
// test may be repeated freely, and its end is a success either way.
func journalFollow(seconds int) map[string]any {
	return map[string]any{
		"action": "journal.follow",
		"payload": map[string]any{"journal": map[string]any{
			"lines": 3, "follow_seconds": seconds,
		}},
	}
}

// openSession returns the live session of a host as the panel records it,
// together with the address it came from.
func openSession(ctx context.Context, pool *pgxpool.Pool, hostID string) (id, remoteAddr string, found bool) {
	err := pool.QueryRow(ctx, `
		select id, coalesce(remote_addr, '') from agent_sessions
		where host_id = $1::uuid and ended_at is null
		order by started_at desc limit 1`, hostID).Scan(&id, &remoteAddr)
	return id, remoteAddr, err == nil
}

// awaitNewSession waits until the host has a live session other than the
// one it had before the fault. The API alone would not do: after a restart
// the panel keeps saying "online" until the host either comes back or goes
// stale, so only a new row proves the agent reconnected.
func awaitNewSession(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	hostID, previous string, limit time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		if id, _, found := openSession(ctx, pool, hostID); found && id != previous {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatalf("host %s did not open a new session within %s (still %s)", hostID, limit, previous)
		}
		time.Sleep(2 * time.Second)
	}
}

// sessionEnd returns how the panel recorded the end of a session; empty
// means the row is still open.
func sessionEnd(ctx context.Context, pool *pgxpool.Pool, sessionID string) string {
	var reason string
	_ = pool.QueryRow(ctx, `
		select coalesce(end_reason, '') from agent_sessions
		where id = $1::uuid and ended_at is not null`, sessionID).Scan(&reason)
	return reason
}

// assertReplayedFromTheJournal checks the shape of a job whose first
// attempt lost its session: the first attempt was reclaimed by the lease,
// the last one carries the stored result and says so.
func assertReplayedFromTheJournal(t *testing.T, attempts []attemptView) {
	t.Helper()
	if len(attempts) < 2 {
		t.Fatalf("expected the lease to be reclaimed and the job redelivered, there is %d attempt", len(attempts))
	}
	if first := attempts[0]; first.Status != "lease_expired" {
		t.Errorf("the first attempt ended as %q, expected lease_expired", first.Status)
	}
	last := attempts[len(attempts)-1]
	if !last.Replayed {
		t.Error("the last attempt was not answered from the idempotency journal (replayed = false)")
	}
	if last.Status != "succeeded" {
		t.Errorf("the last attempt ended as %q (%s: %s)", last.Status, last.ErrorCode, last.Message)
	}
}

// TestThePanelRestartsWhileAJobRuns restarts the control plane with a
// preview in flight on one host.
//
// The promise: the fleet comes back on its own, the host takes new work
// straight away, and the job in flight is not lost - the agent kept its
// result in the journal and the panel, after the lease ran out, asked for
// it again and got the stored answer rather than a second execution.
func TestThePanelRestartsWhileAJobRuns(t *testing.T) {
	unit := controlPlaneUnit(t)
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	// The sessions from before the restart: each of them has to be replaced,
	// because the old ones die together with the process.
	before := map[string]string{}
	for _, item := range h.hosts() {
		if item.ConnectionState != "online" {
			continue
		}
		if id, _, found := openSession(ctx, pool, item.ID); found {
			before[item.ID] = id
		}
	}
	if len(before) == 0 {
		t.Skip("no host has a live session")
	}

	job := h.createOperation(host.ID, journalFollow(40))
	t.Cleanup(func() { h.cancelJob(job.ID) })
	if job.RequiresApproval {
		h.approve(job.ID, job.PayloadHash)
	}
	h.awaitJobState(job.ID, 60*time.Second, "dispatched", "running")

	if output, err := exec.Command("systemctl", "restart", unit).CombinedOutput(); err != nil {
		t.Fatalf("restarting %s: %v: %s", unit, err, strings.TrimSpace(string(output)))
	}
	h.awaitHealthy(90 * time.Second)

	// The agents reconnect with a backoff that doubles from 2 s with full
	// jitter (internal/endpoints), so a few refused dials while the panel was
	// away add up to about a minute.
	for hostID, previous := range before {
		awaitNewSession(ctx, t, pool, hostID, previous, 3*time.Minute)
		h.awaitConnection(hostID, 30*time.Second)
	}

	// New work on the same host goes through while the old attempt is still
	// waiting for its lease to run out: the two are different jobs and the
	// agent does not hold one behind the other.
	status, _ := h.runOperation(host.ID, map[string]any{
		"action":  "unit.status",
		"payload": map[string]any{"unit_status": map[string]any{"units": []string{"systemd-journald.service"}}},
	}, 90*time.Second)
	if status.State != "succeeded" {
		t.Fatalf("the follow-up read after the restart ended as %s (%s)", status.State, status.ResultErrorCode)
	}

	final := h.awaitTerminal(job.ID, leaseRecoveryBound)
	if final.State != "succeeded" {
		t.Fatalf("the job in flight ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	if !strings.Contains(final.ResultMessage, "the preview ended") {
		t.Errorf("the result is not the stored preview summary: %q", final.ResultMessage)
	}
	assertReplayedFromTheJournal(t, h.attempts(job.ID))
}

// linkCut black-holes the traffic of one host to the gateway on the panel.
//
// A drop, not a reject: a WAN that goes away answers nothing, and the point
// is to see what the product does when nobody tells it the link is gone.
type linkCut struct {
	t *testing.T
}

func cutLink(t *testing.T, hostIP, port string) *linkCut {
	t.Helper()
	// A table left by an interrupted run would make "add table" fail, so it
	// goes first, and its absence is not an error.
	_ = exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	commands := [][]string{
		{"add", "table", "inet", nftTable},
		{"add", "chain", "inet", nftTable, "input", "{ type filter hook input priority 0; policy accept; }"},
		{"add", "rule", "inet", nftTable, "input", "ip", "saddr", hostIP, "tcp", "dport", port, "drop"},
	}
	cut := &linkCut{t: t}
	// The cleanup is registered before the first command: whichever of them
	// fails, the table must not outlive the test.
	t.Cleanup(cut.restore)
	for _, args := range commands {
		if output, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return cut
}

// restore removes the table. It is safe to call twice: the second call
// finds nothing and that is the wanted state.
func (c *linkCut) restore() {
	output, err := exec.Command("nft", "delete", "table", "inet", nftTable).CombinedOutput()
	if err != nil && !strings.Contains(string(output), "No such file or directory") {
		c.t.Errorf("the nft table %s was not removed: %v: %s", nftTable, err, strings.TrimSpace(string(output)))
	}
}

// TestAResultSurvivesALinkCut cuts the link between agent-debian and the
// gateway while a preview runs on it, long enough for the agent to notice.
//
// What was found in the code and is asserted here: the agent, not the
// gateway, notices the dead link (HTTP/2 ping, about 45 s), ends the preview
// with a success, stores the result in its journal and fails to send it.
// It then reconnects, and the new session supersedes the old row. The
// panel learns nothing from the cut itself: the attempt stays open until
// the lease runs out, is reclaimed, and the redelivery is answered from
// the journal with replayed = true.
//
// One race is left to the kernel and accepted: the agent closes its socket
// with the result still in the send queue, and Linux keeps retransmitting
// an orphaned socket. If that retransmission lands before the new session
// supersedes the old one, the result reaches the first attempt directly and
// there is nothing to redeliver. Both endings keep the result; the test
// accepts both and says which one it saw.
func TestAResultSurvivesALinkCut(t *testing.T) {
	controlPlaneUnit(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not available on this machine")
	}
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByName("agent-debian")

	sessionID, remoteAddr, found := openSession(ctx, pool, host.ID)
	if !found {
		t.Skipf("host %s has no live session", host.Hostname)
	}
	hostIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		t.Skipf("the session of %s comes from %q, which is not an address the cut can name", host.Hostname, remoteAddr)
	}
	// A shared address means a relay in front of the host: cutting it would
	// take other hosts down with it, and this test is about one link.
	var sharing int
	if err := pool.QueryRow(ctx, `
		select count(distinct host_id) from agent_sessions
		where ended_at is null and remote_addr like $1`, hostIP+":%").Scan(&sharing); err != nil {
		t.Fatalf("counting the sessions from %s: %v", hostIP, err)
	}
	if sharing > 1 {
		t.Skipf("%d hosts connect from %s; the cut would not be one link", sharing, hostIP)
	}
	port := "8443"
	if gateway, err := url.Parse(envOr("FLOTESTRO_TEST_GATEWAY", defaultGateway)); err == nil && gateway.Port() != "" {
		port = gateway.Port()
	}

	job := h.createOperation(host.ID, journalFollow(30))
	t.Cleanup(func() { h.cancelJob(job.ID) })
	if job.RequiresApproval {
		h.approve(job.ID, job.PayloadHash)
	}
	h.awaitJobState(job.ID, 60*time.Second, "dispatched", "running")

	cut := cutLink(t, hostIP, port)
	time.Sleep(linkCutDuration)
	cut.restore()

	// The dial the agent has in flight when the cut lifts is a SYN on an
	// exponential retry, so the reconnect can take a further minute.
	newSession := awaitNewSession(ctx, t, pool, host.ID, sessionID, 3*time.Minute)
	endReason := ""
	for i := 0; i < 15 && endReason == ""; i++ {
		if endReason = sessionEnd(ctx, pool, sessionID); endReason == "" {
			time.Sleep(time.Second)
		}
	}
	if endReason == "" {
		t.Errorf("the old session %s is still open although %s replaced it", sessionID, newSession)
	}
	t.Logf("session %s ended (%s), replaced by %s", sessionID, endReason, newSession)
	h.awaitConnection(host.ID, 30*time.Second)

	final := h.awaitTerminal(job.ID, leaseRecoveryBound)
	if final.State != "succeeded" {
		t.Fatalf("the job ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	if !strings.Contains(final.ResultMessage, "the preview ended") {
		t.Errorf("the result is not the preview summary: %q", final.ResultMessage)
	}
	attempts := h.attempts(job.ID)
	if len(attempts) == 0 {
		t.Fatal("no recorded attempt")
	}
	if len(attempts) == 1 {
		// The retransmitted result won the race; the single attempt has to
		// carry it, and it was not a replay - nothing was redelivered.
		t.Log("the result arrived on the first attempt over the retransmitted socket")
		if attempts[0].Status != "succeeded" || attempts[0].Replayed {
			t.Errorf("the single attempt is %q, replayed = %v", attempts[0].Status, attempts[0].Replayed)
		}
		return
	}
	t.Log("the result arrived on a redelivery after the lease ran out")
	assertReplayedFromTheJournal(t, attempts)
}

// TestAnExpiredLeaseIsReclaimedByTheScheduler leaves the reclaim to the
// scheduler's housekeeping instead of putting the job back in the queue by
// hand, which is what TestRedeliveryDoesNotRepeatTheMutation does.
//
// The mutation is real and finished on the host; what is simulated is the
// panel's picture after a gateway crashed holding the lease: the attempt
// still open, its lease in the past, the job still handed over. A live link
// cannot produce that picture - the result arrives within a second of the
// mutation, and a redelivery that reaches the agent while it is still
// working is refused as resource_busy rather than replayed - so the rows
// are set to it directly, and from there the product is on its own.
//
// The promise: ReclaimExpiredLeases marks the attempt lease_expired and
// returns the job to the queue, the scheduler redelivers it, and the agent
// answers from its journal with replayed = true, so the service is not
// restarted a second time.
func TestAnExpiredLeaseIsReclaimedByTheScheduler(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	}, 90*time.Second)
	if job.State != "succeeded" {
		t.Fatalf("the first execution ended as %s (%s)", job.State, job.ResultErrorCode)
	}
	if len(attempts) != 1 || attempts[0].UnitStateAfter == nil {
		t.Fatalf("expected one attempt with the state after the restart, got %d", len(attempts))
	}
	pidAfterFirst := attempts[0].UnitStateAfter.MainPID

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		update job_attempts
		   set finished_at = null, status = null,
		       lease_expires_at = now() - interval '1 minute'
		 where job_id = $1 and attempt_number = 1`, job.ID); err != nil {
		t.Fatalf("the attempt was not reopened: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		update jobs
		   set state = 'dispatched', finished_at = null, result_status = null,
		       result_error_code = null, result_message = null, updated_at = now()
		 where id = $1`, job.ID); err != nil {
		t.Fatalf("the job was not returned to the dispatched state: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.cancelJob(job.ID) })

	// The housekeeping pass runs every 30 s; the dispatch that follows the
	// reclaim, every 2 s.
	final := h.awaitTerminal(job.ID, 2*time.Minute)
	if final.State != "succeeded" {
		t.Fatalf("the redelivered job ended as %s (%s: %s)", final.State, final.ResultErrorCode, final.ResultMessage)
	}
	repeated := h.attempts(job.ID)
	assertReplayedFromTheJournal(t, repeated)

	// The crux: the stored answer describes the first restart, and the
	// service kept the PID it got then.
	last := repeated[len(repeated)-1]
	if last.UnitStateAfter == nil {
		t.Fatal("the replayed attempt carries no state after the change")
	}
	if last.UnitStateAfter.MainPID != pidAfterFirst {
		t.Fatalf("the mutation was repeated: PID %d -> %d", pidAfterFirst, last.UnitStateAfter.MainPID)
	}
}
