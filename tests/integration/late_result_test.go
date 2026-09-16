//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A result that arrives after the job was settled - here: canceled from
// the panel while the host was still on it - does not take the decision
// back and does not rewrite what the attempt says. The store closes the
// attempt with the bare facts of the result and refuses its output and
// detail; the gateway puts the result on the trail as not applied and
// changes nothing on the host's record. The preview of the journal is the
// operation: the host answers an interrupted preview with a summary of
// its own, which is exactly what must not land on a settled job.
func TestALateResultDoesNotRewriteASettledJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := h.hostByFamily("debian")
	pool := h.database(ctx)

	// A preview kept busy for long enough to be canceled under way.
	job := followingJournal(t, h, host.ID, "", 60)
	h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
		map[string]any{"reason": "canceled while the host was on it"}, nil, http.StatusOK)
	canceled := h.awaitJobState(job.ID, 30*time.Second, "canceled")
	if canceled.State != "canceled" {
		t.Fatalf("the job is %s after the cancel, expected canceled", canceled.State)
	}

	// The interrupted host answers with a result of its own; the trail is
	// where it shows up, as not applied.
	var applied *bool
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var value *bool
		err := pool.QueryRow(ctx, `
			select (detail->>'applied')::boolean
			  from audit_events
			 where action = 'job.result' and target_id = $1
			 order by occurred_at desc limit 1`, job.ID).Scan(&value)
		if err == nil && value != nil {
			applied = value
			break
		}
		time.Sleep(2 * time.Second)
	}
	if applied == nil {
		t.Fatal("the host did not report the interrupted preview within the wait")
	}
	if *applied {
		t.Fatal("the result of a canceled job was applied")
	}

	// The job keeps its settlement, and the attempt carries the bare facts
	// only: the host's own summary, its output and its detail stayed out.
	after := h.awaitJobState(job.ID, 5*time.Second, "canceled")
	if after.State != "canceled" {
		t.Fatalf("the late result moved the job to %s", after.State)
	}
	var status, message, stdout string
	var detail []byte
	var finished *time.Time
	if err := pool.QueryRow(ctx, `
		select coalesce(status, ''), coalesce(message, ''), coalesce(stdout, ''), result_detail, finished_at
		  from job_attempts where job_id = $1 order by attempt_number desc limit 1`, job.ID).
		Scan(&status, &message, &stdout, &detail, &finished); err != nil {
		t.Fatalf("reading the attempt: %v", err)
	}
	if finished == nil {
		t.Error("the attempt of the canceled job stayed open after the late result")
	}
	if status == "" {
		t.Error("the attempt does not say how the host ended the operation")
	}
	if message != "the result arrived after the job was settled" || stdout != "" || len(detail) > 0 {
		t.Errorf("the late result rewrote the attempt: status %q, message %q, stdout %d bytes, detail %d bytes",
			status, message, len(stdout), len(detail))
	}
}
