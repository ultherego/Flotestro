//go:build integration

package integration

import (
	"context"
	"testing"
	"time"
)

// hostVulnerabilityStatus is the part of the fleet screen this test reads.
type hostVulnerabilityStatus struct {
	Items []struct {
		HostID                 string `json:"host_id"`
		Hostname               string `json:"hostname"`
		Status                 string `json:"status"`
		EvaluatedAt            string `json:"evaluated_at"`
		EvaluationFailedReason string `json:"evaluation_failed_reason"`
		EvaluationFailedSource string `json:"evaluation_failed_source"`
		LastSuccessfulAt       string `json:"last_successful_at"`
	} `json:"items"`
}

// TestAHostWhoseAssessmentCouldNotRunSaysSo guards chapter 11.2: a read that
// failed leaves the previous verdict standing, and until this change nothing
// said that it had - a host nobody could assess for days was indistinguishable
// from one judged a minute ago.
func TestAHostWhoseAssessmentCouldNotRunSaysSo(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)

	var before hostVulnerabilityStatus
	h.get("/api/v1/vulnerabilities?limit=100", &before)

	subject := ""
	for _, item := range before.Items {
		if item.EvaluatedAt != "" && item.EvaluationFailedReason == "" {
			subject = item.HostID
			break
		}
	}
	if subject == "" {
		t.Skip("no host in this fleet carries an assessment to spoil")
	}

	// The scheduler writes exactly this when a read stops a pass; the rest of
	// the row - the verdict itself - is deliberately left alone.
	failedAt := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
		update vuln_host_state
		set evaluation_failed_reason = 'evaluation_failed',
		    evaluation_failed_source = 'feed_advisories',
		    evaluation_failed_at = $2
		where host_id = $1`, subject, failedAt); err != nil {
		t.Fatalf("the failed pass was not recorded: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			update vuln_host_state
			set evaluation_failed_reason = '', evaluation_failed_source = '',
			    evaluation_failed_at = null
			where host_id = $1`, subject)
	})

	var after hostVulnerabilityStatus
	h.get("/api/v1/vulnerabilities?limit=100", &after)
	for _, item := range after.Items {
		if item.HostID != subject {
			continue
		}
		if item.EvaluationFailedReason != "evaluation_failed" {
			t.Fatalf("%s reports the reason %q, expected evaluation_failed",
				item.Hostname, item.EvaluationFailedReason)
		}
		if item.EvaluationFailedSource != "feed_advisories" {
			t.Fatalf("%s does not say which read failed: %q",
				item.Hostname, item.EvaluationFailedSource)
		}
		// The whole point: the numbers are still there, and the word beside them
		// says they are not the answer of the last pass.
		if item.Status != "stale" {
			t.Fatalf("%s is reported as %q although its last pass could not run",
				item.Hostname, item.Status)
		}
		if item.LastSuccessfulAt == "" {
			t.Fatalf("%s does not say when its verdict was last computed in full",
				item.Hostname)
		}
		return
	}
	t.Fatalf("the host %s left the fleet answer", subject)
}
