package gateway

import (
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
)

// The outcome the agent answers with is stored under the protocol's own name
// in lower case, and every name the protocol has is one the store knows: an
// answer must never be refused for a spelling the panel chose.
func TestTheCancelOutcomeIsStoredUnderTheProtocolsName(t *testing.T) {
	cases := map[agentv1.CancelAck_Outcome]string{
		agentv1.CancelAck_NOT_STARTED:       jobs.CancelOutcomeNotStarted,
		agentv1.CancelAck_INTERRUPTED:       jobs.CancelOutcomeInterrupted,
		agentv1.CancelAck_NOT_INTERRUPTIBLE: jobs.CancelOutcomeNotInterruptible,
		agentv1.CancelAck_ALREADY_DONE:      jobs.CancelOutcomeAlreadyDone,
	}
	for outcome, stored := range cases {
		if got := cancelOutcomeName(outcome); got != stored {
			t.Errorf("%s is stored as %q, expected %q", outcome, got, stored)
		}
		if !jobs.KnownCancelOutcome(cancelOutcomeName(outcome)) {
			t.Errorf("the store does not know the outcome %s", outcome)
		}
	}
}

// The request the host gets names the attempt it holds the task by, the
// revision the answer is read against and the deadline after which the panel
// stops waiting - and a reason, even when the operator gave none, so the
func TestTheCancelRequestCarriesTheAttemptTheRevisionAndTheDeadline(t *testing.T) {
	deadline := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	message := cancelTaskOf(jobs.CancelRequest{
		JobID: "job-1", HostID: "host-1", AttemptID: "attempt-3", Revision: 3,
		Reason: "the window closes", Deadline: deadline,
	})
	if message.GetTaskId() != "attempt-3" || message.GetRequestRevision() != 3 {
		t.Errorf("the request names %q at revision %d", message.GetTaskId(), message.GetRequestRevision())
	}
	if message.GetDeadlineUnix() != deadline.Unix() {
		t.Errorf("the deadline is %d, expected %d", message.GetDeadlineUnix(), deadline.Unix())
	}
	if message.GetReason() != "the window closes" {
		t.Errorf("the reason is %q", message.GetReason())
	}
	if bare := cancelTaskOf(jobs.CancelRequest{AttemptID: "attempt-1"}); bare.GetReason() == "" {
		t.Error("a request without a reason went out without one")
	}
}

// A request is sent once per interval and not on every tick: the answer comes
// within a round trip, and a host that has not answered in half a minute is
// asked again rather than every five seconds.
func TestARequestIsNotRepeatedWithinTheInterval(t *testing.T) {
	var sends cancelSends
	now := time.Now()
	if !sends.due("attempt-1", now) {
		t.Fatal("the first send is not due")
	}
	if sends.due("attempt-1", now.Add(cancelRelayInterval)) {
		t.Fatal("the request was repeated on the next tick")
	}
	if !sends.due("attempt-1", now.Add(cancelResendInterval)) {
		t.Fatal("the request was not repeated after the interval")
	}
	if !sends.due("attempt-2", now) {
		t.Fatal("another attempt's request waited on the first")
	}
	sends.forget("attempt-2")
	if !sends.due("attempt-2", now) {
		t.Fatal("a send that failed was not tried again")
	}
}
