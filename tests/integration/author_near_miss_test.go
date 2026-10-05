//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"
)

// A person whose account begins with the name of one of the panel's own
// authors orders a change, and it goes out.
//
// This is the test that was missing. A guard added on 05.10 refused a task
// whose author "names the panel's own work" and matched that by prefix, so
// "system" caught systemadmin, systemadmin@ipa.example.test and
// system-operator: every such operator was refused everything, while every
// test written beside the guard passed, because each of them used a name the
// guard's author had thought of.
//
// Nothing reads an author's name to decide what it is any more. This holds
// that open from the outside, through the API, with the names that broke it.
func TestAnOperatorNamedLikeThePanelsOwnWorkMayStillOrder(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	for _, prefix := range []string{"systemadmin", "system-operator", "campaign-owner", "flotestro-admin"} {
		t.Run(prefix, func(t *testing.T) {
			operator := h.withToken(h.createPrincipal(uniqueSubject(prefix), []map[string]string{
				{"role": "operator", "site": host.Site, "environment": host.Environment},
				{"role": "approver", "site": host.Site, "environment": host.Environment},
			}))

			job := operator.createOperation(host.ID, map[string]any{
				"action":  "unit.restart",
				"payload": unitPayload("cron.service"),
			})
			t.Cleanup(func() {
				operator.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
					map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
			})
			if job.CreatedByKind != "person" {
				t.Fatalf("the task says %q ordered it", job.CreatedByKind)
			}
			operator.approve(job.ID, job.PayloadHash)

			// Dispatch is where the refusal landed: the capability is minted
			// from the creator's rights, and an author nobody can answer for
			// stops the task with creator_rights_gone.
			final := h.awaitTerminal(job.ID, 90*time.Second)
			if final.State != "succeeded" {
				t.Fatalf("state = %s, error code = %s", final.State, final.ResultErrorCode)
			}
		})
	}
}
