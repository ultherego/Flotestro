//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// uniqueSubject gives a name unique to the run, so that the tests do not
// collide with identities from previous runs.
func uniqueSubject(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// TestMissingTokenBlocksAccess checks that the API is not open.
func TestMissingTokenBlocksAccess(t *testing.T) {
	h := newHarness(t)
	anonymous := h.withToken("")

	for _, path := range []string{
		"/api/v1/hosts", "/api/v1/jobs", "/api/v1/audit",
		"/api/v1/actions", "/api/v1/enrollment-requests",
	} {
		anonymous.do(http.MethodGet, path, nil, nil, http.StatusUnauthorized)
	}
}

// TestInvalidTokenIsRejected checks that a made-up token does not work.
func TestInvalidTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	h.withToken("flta_non-existent-token").
		do(http.MethodGet, "/api/v1/hosts", nil, nil, http.StatusUnauthorized)
}

// TestOperatorDoesNotApproveOwnChanges is a separation of duties test.
func TestOperatorDoesNotApproveOwnChanges(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	operatorToken := h.createPrincipal(uniqueSubject("operator"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	})
	operator := h.withToken(operatorToken)

	job := operator.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		operator.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
	})

	// The operator may order a change, but has no permission to approve.
	operator.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": job.PayloadHash}, nil, http.StatusForbidden)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("the rejected approval changed the state to %s", state)
	}
}

// TestApproverDoesNotOrderChanges checks the other side of the separation
// of duties.
func TestApproverDoesNotOrderChanges(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	approverToken := h.createPrincipal(uniqueSubject("approver"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	})

	h.withToken(approverToken).do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.restart", "payload": unitPayload("cron.service")},
		nil, http.StatusForbidden)
}

// TestOperatorAndApproverCarryOutAChangeTogether checks the full path with
// the roles split: one orders, the other approves.
func TestOperatorAndApproverCarryOutAChangeTogether(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	scope := []map[string]string{
		{"role": "operator", "site": host.Site, "environment": host.Environment},
	}
	operator := h.withToken(h.createPrincipal(uniqueSubject("operator"), scope))
	approver := h.withToken(h.createPrincipal(uniqueSubject("approver"), []map[string]string{
		{"role": "approver", "site": host.Site, "environment": host.Environment},
	}))

	job := operator.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	approver.approve(job.ID, job.PayloadHash)

	final := h.awaitTerminal(job.ID, 90*time.Second)
	if final.State != "succeeded" {
		t.Fatalf("state = %s, error code = %s", final.State, final.ResultErrorCode)
	}
	if final.ApprovedBy == final.CreatedBy {
		t.Error("the requester and the approver are the same identity")
	}
}

// TestScopeLimitsFleetVisibility checks that an operator of one environment
// does not see hosts outside their scope.
func TestScopeLimitsFleetVisibility(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	outsider := h.withToken(h.createPrincipal(uniqueSubject("foreign-scope"), []map[string]string{
		{"role": "operator", "site": "other-site", "environment": "other-environment"},
	}))

	var listing struct {
		Items []hostView `json:"items"`
		Count int        `json:"count"`
	}
	outsider.get("/api/v1/hosts", &listing)
	if listing.Count != 0 {
		t.Errorf("an identity outside the scope sees %d hosts", listing.Count)
	}

	// Direct access to the host must be denied too.
	outsider.do(http.MethodGet, "/api/v1/hosts/"+host.ID, nil, nil, http.StatusForbidden)
	outsider.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "unit.restart", "payload": unitPayload("cron.service")},
		nil, http.StatusForbidden)
}

// TestViewerChangesNothing checks that the read role is really read-only.
func TestViewerChangesNothing(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	viewer := h.withToken(h.createPrincipal(uniqueSubject("viewer"), []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))

	// Reading works.
	viewer.do(http.MethodGet, "/api/v1/hosts/"+host.ID, nil, nil, http.StatusOK)

	// Changes and the audit log do not.
	viewer.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusForbidden)
	viewer.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)
	viewer.do(http.MethodPost, "/api/v1/enrollment-requests",
		map[string]any{"description": "attempt"}, nil, http.StatusForbidden)
	viewer.do(http.MethodGet, "/api/v1/principals", nil, nil, http.StatusForbidden)
}

// TestPermissionIsPerOperation checks that the right to one operation gives
// no right to another. A role without unit permissions may read the
// journal.
func TestPermissionIsPerOperation(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	// The auditor has read rights but no job.create, so cannot order even a
	// non-mutating operation.
	auditor := h.withToken(h.createPrincipal(uniqueSubject("auditor"), []map[string]string{
		{"role": "auditor", "site": host.Site, "environment": host.Environment},
	}))

	// The host audit log within their scope is readable.
	auditor.do(http.MethodGet, "/api/v1/hosts/"+host.ID+"/audit", nil, nil, http.StatusOK)

	// But the global log covers the whole fleet, so it requires the
	// permission in the global scope, which an auditor of one environment
	// does not have.
	auditor.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)

	auditor.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusForbidden)
}

// TestGlobalAuditorReadsTheWholeLog confirms that the global permission
// gives access to the log of the whole fleet.
func TestGlobalAuditorReadsTheWholeLog(t *testing.T) {
	h := newHarness(t)
	auditor := h.withToken(h.createPrincipal(uniqueSubject("global-auditor"), []map[string]string{
		{"role": "auditor", "site": "*", "environment": "*"},
	}))
	auditor.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusOK)
}

// TestProductionRequiresASecondPerson checks the four-eyes rule. The host
// is moved to the production environment for the duration of the test.
func TestProductionRequiresASecondPerson(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pool := h.database(ctx)
	host := h.hostByFamily("debian")

	if _, err := pool.Exec(ctx,
		`update hosts set environment = 'prod' where id = $1`, host.ID); err != nil {
		t.Fatalf("the host was not moved to production: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`update hosts set environment = $2 where id = $1`, host.ID, host.Environment)
	})

	// An identity with both roles: role separation alone is not enough,
	// because one person may hold both.
	both := h.withToken(h.createPrincipal(uniqueSubject("operator-approver"), []map[string]string{
		{"role": "operator", "site": host.Site, "environment": "prod"},
		{"role": "approver", "site": host.Site, "environment": "prod"},
	}))

	job := both.createOperation(host.ID, map[string]any{
		"action":  "unit.restart",
		"payload": unitPayload("cron.service"),
	})
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel",
			map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
	})

	// Has the permission to approve, but not their own change.
	both.do(http.MethodPost, "/api/v1/jobs/"+job.ID+"/approve",
		map[string]any{"payload_hash": job.PayloadHash}, nil, http.StatusForbidden)

	if state := h.job(job.ID).State; state != "awaiting_approval" {
		t.Fatalf("the self-approval changed the state to %s", state)
	}
}

// TestDenialLeavesAnAuditTrail checks that an attempt without permissions
// is recorded. An audit log showing only successes is useless in an
// incident.
func TestDenialLeavesAnAuditTrail(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	subject := uniqueSubject("viewer-audit")

	viewer := h.withToken(h.createPrincipal(subject, []map[string]string{
		{"role": "viewer", "site": host.Site, "environment": host.Environment},
	}))
	viewer.do(http.MethodGet, "/api/v1/audit", nil, nil, http.StatusForbidden)

	var events struct {
		Items []struct {
			ActorID string `json:"actor_id"`
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?limit=100", &events)

	found := false
	for _, event := range events.Items {
		if event.ActorID == subject && event.Outcome == "denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit event about the denial for %s", subject)
	}
}
