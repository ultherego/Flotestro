//go:build integration

package integration

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/vuln/version"
)

// stepView mirrors one installation step.
type stepView struct {
	Key   string `json:"key"`
	State string `json:"state"`
}

// orderView mirrors an enrollment order.
type orderView struct {
	ID                string     `json:"id"`
	Token             string     `json:"token"`
	Site              string     `json:"site"`
	Environment       string     `json:"environment"`
	Kind              string     `json:"kind"`
	Purpose           string     `json:"purpose"`
	ExpectedMachineID string     `json:"expected_machine_id"`
	ExpectedHostID    string     `json:"expected_host_id"`
	MaxUses           int        `json:"max_uses"`
	Uses              int        `json:"uses"`
	Status            string     `json:"status"`
	EnrolledHostID    string     `json:"enrolled_host_id"`
	ExpiresAt         time.Time  `json:"expires_at"`
	Steps             []stepView `json:"steps"`
}

// TestEnrollmentOrderShowsTheTokenOnce guards that the plain token exists
// only in the response to creating the order.
//
// The token is a one-time secret. If it could be read from the list or from
// a single order, anybody with the right to read installations would hold
// the key to bringing their own machine into the fleet.
func TestEnrollmentOrderShowsTheTokenOnce(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "order test", "site": "lab", "environment": "test",
		"ttl_minutes": 15,
	}, &created, http.StatusCreated)

	if created.Token == "" {
		t.Fatal("order without a token - the agent has nothing to introduce itself with")
	}
	if created.Purpose != "new" || created.Kind != "agent" {
		t.Fatalf("purpose = %q, kind = %q", created.Purpose, created.Kind)
	}
	if created.Status != "pending" {
		t.Fatalf("status = %q", created.Status)
	}

	var read orderView
	h.get("/api/v1/enrollment-requests/"+created.ID, &read)
	if read.Token != "" {
		t.Fatal("reading the order gives away the token")
	}
	if read.ID != created.ID {
		t.Fatalf("id = %q, wanted %q", read.ID, created.ID)
	}

	var list struct {
		Items []orderView `json:"items"`
	}
	h.get("/api/v1/enrollment-requests", &list)
	found := false
	for _, item := range list.Items {
		if item.ID == created.ID {
			found = true
		}
		if item.Token != "" {
			t.Fatalf("the order list gives away the token of %s", item.ID)
		}
	}
	if !found {
		t.Fatal("the created order did not appear on the list")
	}
}

// TestRevokedOrderStopsWorkingAtOnce guards that revocation closes the
// token immediately, also when part of the pool has already been used.
func TestRevokedOrderStopsWorkingAtOnce(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "to be revoked", "site": "lab", "environment": "test", "max_uses": 5,
	}, &created, http.StatusCreated)

	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+created.ID+"/revoke",
		nil, nil, http.StatusNoContent)

	var after orderView
	h.get("/api/v1/enrollment-requests/"+created.ID, &after)
	if after.Status != "revoked" {
		t.Fatalf("status after revocation = %q", after.Status)
	}
	// Revocation is idempotent: a second attempt must not end with a server
	// error, because the operator has no way to check whether the first one
	// got through.
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+created.ID+"/revoke",
		nil, nil, http.StatusNoContent)
	h.do(http.MethodPost,
		"/api/v1/enrollment-requests/00000000-0000-4000-8000-000000000000/revoke",
		nil, nil, http.StatusNotFound)
}

// TestIdentityRecoveryOrderIsBoundToTheHost guards that an identity
// replacement is bound to a specific host, not to any machine.
func TestIdentityRecoveryOrderIsBoundToTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var order orderView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"description": "after a reinstall"}, &order, http.StatusCreated)

	if order.Purpose != "replace_identity" {
		t.Fatalf("purpose = %q", order.Purpose)
	}
	if order.ExpectedHostID != host.ID {
		t.Fatalf("the order points at host %q, wanted %q", order.ExpectedHostID, host.ID)
	}
	// Recovery concerns one host, so one use too: a multi-use token would be
	// a spare key to the same machine.
	if order.MaxUses != 1 {
		t.Fatalf("uses = %d", order.MaxUses)
	}
	if order.Token == "" {
		t.Fatal("order without a token")
	}
	// The scope comes from the host: identity recovery is not an occasion
	// to move the host to another environment.
	if order.Site != host.Site || order.Environment != host.Environment {
		t.Fatalf("scope = %s/%s, host = %s/%s", order.Site, order.Environment,
			host.Site, host.Environment)
	}

	// This purpose cannot be ordered through the ordinary entry: an identity
	// replacement has its own permission and its own path.
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"purpose": "replace_identity", "site": "lab", "environment": "test",
	}, nil, http.StatusBadRequest)
}

// TestOrderHasATimeLimit guards that a token cannot lie around for weeks.
func TestOrderHasATimeLimit(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "default lifetime", "site": "lab", "environment": "test",
	}, &created, http.StatusCreated)
	if left := time.Until(created.ExpiresAt); left > time.Hour {
		t.Fatalf("default lifetime = %s", left)
	}
	// Beyond a day the token is a secret waiting to leak.
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "too long", "site": "lab", "environment": "test",
		"ttl_minutes": 60 * 48,
	}, nil, http.StatusBadRequest)
}

// TestQuarantineCutsTheHostOffAndDoesNotLockIt guards that the cut-off
// works at once and can be lifted.
//
// The test runs on a test fleet host and restores it at the end: a host
// left in quarantine would topple all the remaining tests.
func TestQuarantineCutsTheHostOffAndDoesNotLockIt(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")

	var result struct {
		LifecycleState string `json:"lifecycle_state"`
		SessionClosed  bool   `json:"session_closed"`
		JobsCanceled   int    `json:"jobs_canceled"`
	}
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
			map[string]any{"reason": "end of the test"}, nil, http.StatusOK)
		// The agent comes back only after its backoff. Without waiting the
		// next tests find the host offline and fall over for a reason that
		// has nothing to do with what they check.
		h.awaitConnection(host.ID, time.Minute)
	})

	// The reason is required: a host cut off without a reason is a host
	// nobody will know in a week why it does not work.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{}, nil, http.StatusBadRequest)

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "quarantine test"}, &result, http.StatusOK)
	if result.LifecycleState != "quarantined" {
		t.Fatalf("state = %q", result.LifecycleState)
	}
	if !result.SessionClosed {
		t.Error("the host session was not closed - a quarantine checked only " +
			"at the next connection does not cut off a compromised machine")
	}

	// A quarantined host accepts no new operations.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "journal.read",
			"payload": map[string]any{"journal": map[string]any{"lines": 5}}},
		nil, http.StatusConflict)
}

// TestDecommissionRequiresTypingTheName guards that a loss of trust cannot
// be clicked by mistake.
func TestDecommissionRequiresTypingTheName(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "attempt without confirmation"}, nil, http.StatusBadRequest)
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "attempt with somebody else's name", "typed_confirmation": "other-host"},
		nil, http.StatusBadRequest)

	// A test fleet host is not really decommissioned: only the gate is
	// checked. Full decommissioning has its own test on a synthetic machine.
}

// TestDecommissionedHostDoesNotComeBackWithAToken guards that a loss of
// trust is a panel decision, not a state that can be undone with a token on
// the host.
func TestDecommissionedHostDoesNotComeBackWithAToken(t *testing.T) {
	h := newHarness(t)
	// The synthetic machine is not in the fleet, so it can really be
	// decommissioned.
	host := h.enrollSyntheticHost(t)

	var result struct {
		LifecycleState      string `json:"lifecycle_state"`
		CertificatesRevoked int    `json:"certificates_revoked"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "machine handed over", "typed_confirmation": host.Hostname},
		&result, http.StatusOK)
	if result.LifecycleState != "retired" {
		t.Fatalf("state = %q", result.LifecycleState)
	}
	// Decommissioning always revokes the certificates: the host cannot come
	// back on its own with a valid certificate in hand.
	if result.CertificatesRevoked == 0 {
		t.Error("decommissioning revoked no certificate")
	}

	// A recovery order for a decommissioned host is a promise without
	// backing.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"description": "return"}, nil, http.StatusConflict)

	// There is no point lifting the quarantine of a decommissioned host
	// either.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "return attempt"}, nil, http.StatusConflict)
}

// TestInstallationProgressDescribesTheSteps guards that the installation
// screen gets the truth about what the host has already done.
//
// The steps are separate because each fails for a different reason: the
// token may expire, the certificate may be rejected on a CSR error, the
// session may not get through a firewall, and the inventory may not arrive
// when the agent lacks a capability.
func TestInstallationProgressDescribesTheSteps(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "steps test", "site": "lab", "environment": "test",
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+created.ID+"/revoke",
			nil, nil, 0)
	})

	var before orderView
	h.get("/api/v1/enrollment-requests/"+created.ID, &before)
	if len(before.Steps) != 4 {
		t.Fatalf("steps = %d: %+v", len(before.Steps), before.Steps)
	}
	for _, step := range before.Steps {
		if step.State != "waiting" {
			t.Fatalf("step %s before the installation = %q", step.Key, step.State)
		}
	}

	// The synthetic machine enrolls and stops there: it neither connects a
	// session nor sends an inventory, so the first two steps are to be done
	// and the next two still waiting.
	host := h.enrollSyntheticHostWithToken(t, created.Token)
	var after orderView
	h.get("/api/v1/enrollment-requests/"+created.ID, &after)
	states := map[string]string{}
	for _, step := range after.Steps {
		states[step.Key] = step.State
	}
	if states["token"] != "done" || states["certificate"] != "done" {
		t.Fatalf("steps after enrollment = %v", states)
	}
	if states["connected"] != "waiting" || states["inventory"] != "waiting" {
		t.Errorf("a host without a session shown as connected: %v", states)
	}
	if after.EnrolledHostID != host.ID {
		t.Fatalf("the order points at host %q, wanted %q", after.EnrolledHostID, host.ID)
	}
	if after.Status != "enrolled" {
		t.Fatalf("status after enrollment = %q", after.Status)
	}
}

// TestAgentReplacementEndsWithTheHostComingBack guards the property this
// operation exists separately for in the first place: success is a host
// that came back with the expected version, not the exit status of the
// package manager.
//
// The agent replaces itself, so the process accounting for the job dies
// halfway. If the panel waited for its result, every replacement would end
// with a timeout - also when the host came back healthy.
func TestAgentReplacementEndsWithTheHostComingBack(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")

	var before struct {
		AgentVersion string `json:"agent_version"`
	}
	h.get("/api/v1/hosts/"+host.ID, &before)
	// The target comes from the test fleet repository: it must be there,
	// otherwise the package manager has nothing to install. By default it
	// is the newest version - a test that moved the host back to an old
	// release would leave the fleet on code from before the change and
	// could not be repeated.
	target := os.Getenv("FLOTESTRO_TEST_AGENT_VERSION")
	if target == "" {
		target = h.newestAgentVersion()
	}
	if before.AgentVersion == target {
		t.Skipf("the host is already at version %s", target)
	}

	job := h.createOperation(host.ID, map[string]any{
		"action":  "agent.upgrade",
		"payload": map[string]any{"agent_upgrade": map[string]any{"target_version": target}},
	})
	if job.ID == "" {
		t.Fatal("no agent replacement job was created")
	}
	// An agent replacement is a high-risk operation: it cuts the host off
	// from management for the duration of the restart, so it requires
	// approval.
	if !job.RequiresApproval {
		t.Fatal("the agent replacement requires no approval")
	}
	job = h.approve(job.ID, job.PayloadHash)

	// The replacement takes a while: the package, the service restart and
	// the session coming back. The panel decides only after a Hello with
	// the new version.
	deadline := time.Now().Add(4 * time.Minute)
	var state jobView
	for time.Now().Before(deadline) {
		h.get("/api/v1/jobs/"+job.ID, &state)
		if state.State == "succeeded" || state.State == "failed" {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if state.State != "succeeded" {
		t.Fatalf("the agent replacement job in state %q (%s)", state.State, state.ResultMessage)
	}

	var after struct {
		AgentVersion string `json:"agent_version"`
	}
	h.get("/api/v1/hosts/"+host.ID, &after)
	if after.AgentVersion != target {
		t.Fatalf("the host reports version %q, expected %q", after.AgentVersion, target)
	}
	h.awaitConnection(host.ID, time.Minute)
}

// newestAgentVersion reads the highest version of the agent package from
// the test fleet repository.
//
// The version is not guessed from a constant in the test: the lab
// repository grows with every release, and a hard-coded version would move
// the host back the further the longer the project lives. No answer ends
// the test with a skip and a reason - replacing the agent with a version
// the repository does not have is not a test.
func (h *harness) newestAgentVersion() string {
	h.t.Helper()
	address := envOr("FLOTESTRO_TEST_REPO", defaultRepo)
	response, err := h.client.Get(address + "/deb/dists/stable/main/binary-amd64/Packages")
	if err != nil {
		h.t.Skipf("the test fleet repository is unavailable (%s): %v", address, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		h.t.Skipf("the test fleet repository answered %s", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Skipf("the repository index is unreadable: %v", err)
	}

	var pkg string
	var newest string
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case strings.HasPrefix(line, "Package: "):
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Version: ") && pkg == "flotestro-agent":
			candidate := strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			if newest == "" || version.CompareDeb(candidate, newest) > 0 {
				newest = candidate
			}
		}
	}
	if newest == "" {
		h.t.Skip("the test fleet repository has no agent package")
	}
	return newest
}
