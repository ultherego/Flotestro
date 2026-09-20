package gateway

import (
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/jobs"
)

// TestASignOfLifeRenewsTheLeaseOncePerInterval guards the pacing of the
// renewal: the first report writes, the ones within the interval do not.
func TestASignOfLifeRenewsTheLeaseOncePerInterval(t *testing.T) {
	service := &AgentService{attempts: map[string]attemptContextEntry{
		"attempt-1": {jobID: "job-1", hostID: "host-1"},
	}}
	start := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	if !service.leaseRenewalDue("attempt-1", "host-1", start) {
		t.Fatal("the first report of an attempt does not renew the lease")
	}
	for _, later := range []time.Duration{time.Second, 10 * time.Second, leaseRenewalInterval - time.Millisecond} {
		if service.leaseRenewalDue("attempt-1", "host-1", start.Add(later)) {
			t.Errorf("a report %s after the renewal wrote again", later)
		}
	}
	if !service.leaseRenewalDue("attempt-1", "host-1", start.Add(leaseRenewalInterval)) {
		t.Error("a report after the interval did not renew the lease")
	}
	if service.leaseRenewalDue("attempt-1", "host-1", start.Add(leaseRenewalInterval+time.Second)) {
		t.Error("the second renewal did not restart the interval")
	}

	if service.leaseRenewalDue("attempt-2", "host-1", start) {
		t.Error("an attempt the gateway has not translated renewed a lease")
	}
	if service.leaseRenewalDue("attempt-1", "host-2", start.Add(time.Hour)) {
		t.Error("another host renewed the lease of an attempt it does not own")
	}
}

// TestTheRenewalOutpacesTheReclaim guards the relation between the three
// durations the mechanism rests on: a renewal buys more time than the pause
// between renewals plus the housekeeping pass that reclaims expired leases
func TestTheRenewalOutpacesTheReclaim(t *testing.T) {
	const housekeeping = 30 * time.Second
	if progressLeaseExtension <= leaseRenewalInterval+housekeeping {
		t.Fatalf("an extension of %s does not outlast a renewal pause of %s and a housekeeping pass of %s",
			progressLeaseExtension, leaseRenewalInterval, housekeeping)
	}
}

// TestTheDispatchLeaseSitsBetweenTheReclaimAndTheExecutionLease: the hand-over
// lease outlasts a housekeeping pass and stays under the execution lease.
func TestTheDispatchLeaseSitsBetweenTheReclaimAndTheExecutionLease(t *testing.T) {
	const housekeeping = 30 * time.Second
	if jobs.DispatchLease <= housekeeping {
		t.Fatalf("a dispatch lease of %s does not outlast a housekeeping pass of %s",
			jobs.DispatchLease, housekeeping)
	}
	if jobs.DispatchLease >= progressLeaseExtension {
		t.Fatalf("a dispatch lease of %s is not shorter than the execution lease of %s",
			jobs.DispatchLease, progressLeaseExtension)
	}
}

// TestTheStagesMatchTheProtocol pins the stage names the gateway reads to the
// ones agent.
func TestTheStagesMatchTheProtocol(t *testing.T) {
	for name, want := range map[string]string{
		stageAccepted: "accepted", stageAwaitingLock: "awaiting_lock",
		stageStarted: "started", stageInProgress: "in_progress",
	} {
		if name != want {
			t.Errorf("stage %q, expected %q", name, want)
		}
	}
}
