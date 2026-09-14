//go:build integration

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/vuln/version"
)

// stepView mirrors one installation step.
type stepView struct {
	Key       string `json:"key"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code"`
	Detail    string `json:"detail"`
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
	ConfigURL         string     `json:"config_url"`
	Steps             []stepView `json:"steps"`
}

// profileView mirrors the installation profile.
type profileView struct {
	Site       string         `json:"site"`
	Connection connectionView `json:"connection"`
	Config     configFileView `json:"config"`
	CA         trustView      `json:"ca"`
	Families   []familyView   `json:"families"`
}

type connectionView struct {
	EnrollmentURL string   `json:"enrollment_url"`
	GatewayURLs   []string `json:"gateway_urls"`
}

type configFileView struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type trustView struct {
	PEM               string `json:"pem"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type familyView struct {
	Key   string        `json:"key"`
	Steps []commandView `json:"steps"`
}

type commandView struct {
	Key     string `json:"key"`
	Command string `json:"command"`
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
	// The order puts the lab host into recovery; revoking it lets the host
	// back at once, so the fleet is as it was for the next test.
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+order.ID+"/revoke", nil, nil, 0)
		var view struct {
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+host.ID, &view)
		if view.LifecycleState != "active" {
			t.Errorf("the host did not come back from recovery after the order was revoked: %q", view.LifecycleState)
		}
	})

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

	var identity struct {
		MachineID string `json:"machine_id"`
	}
	h.get("/api/v1/hosts/"+host.ID, &identity)

	var result struct {
		LifecycleState           string   `json:"lifecycle_state"`
		CertificatesRevoked      int      `json:"certificates_revoked"`
		RemoteCleanupUnconfirmed bool     `json:"remote_cleanup_unconfirmed"`
		Phase                    string   `json:"phase"`
		RunningTasks             []string `json:"running_tasks"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "machine handed over", "typed_confirmation": host.Hostname},
		&result, http.StatusOK)
	if result.LifecycleState != "retired" {
		t.Fatalf("state = %q", result.LifecycleState)
	}
	// Decommissioning revokes the certificates: the host cannot come back
	// on its own with a valid certificate in hand.
	if result.CertificatesRevoked == 0 {
		t.Error("decommissioning revoked no certificate")
	}
	// The synthetic host has no session, so nobody on the machine confirmed
	// the wipe. The answer says so rather than reporting a clean handshake.
	if !result.RemoteCleanupUnconfirmed || result.Phase != "no_session" {
		t.Errorf("a host without a session reported as cleaned up: %+v", result)
	}
	if result.RunningTasks == nil {
		t.Error("running_tasks is missing from the answer")
	}

	var view struct {
		LifecycleState  string `json:"lifecycle_state"`
		LifecycleReason string `json:"lifecycle_reason"`
	}
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState != "retired" || view.LifecycleReason != "machine handed over" {
		t.Errorf("host after the decommission = %+v", view)
	}

	// A recovery order for a decommissioned host is a promise without
	// backing.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"description": "return"}, nil, http.StatusConflict)

	// There is no point lifting the quarantine of a decommissioned host
	// either.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "return attempt"}, nil, http.StatusConflict)

	// Nor does an operation reach a retired host.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "inventory.refresh", "reason": "return attempt"}, nil, http.StatusConflict)

	// The machine itself is held back: a "new host" token does not fit it
	// for the retention period. The refusal reaches the order, with the
	// reason that names the retired host rather than a duplicate.
	var order orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "retired machine comes back", "site": "lab", "environment": "test",
	}, &order, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+order.ID+"/revoke", nil, nil, 0)
	})
	status, body := h.enrollAttempt(t, order.Token, identity.MachineID, testCSR(t, identity.MachineID))
	if status != http.StatusForbidden {
		t.Fatalf("a retired machine was answered with %d: %s", status, body)
	}
	var trail struct {
		Items []struct {
			Detail struct {
				Reason string `json:"reason"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?actor="+identity.MachineID+"&outcome=denied", &trail)
	found := false
	for _, item := range trail.Items {
		if item.Detail.Reason == "machine_id_retired" {
			found = true
		}
	}
	if !found {
		t.Errorf("the trail does not name the retired machine: %+v", trail.Items)
	}
}

// TestIdentityRecoveryPutsTheHostIntoRecovery guards the state between the
// recovery order and the first session of the new certificate: the host
// takes no operation, like a quarantined one, and the panel says which "no"
// this is.
func TestIdentityRecoveryPutsTheHostIntoRecovery(t *testing.T) {
	h := newHarness(t)
	host := h.enrollSyntheticHost(t)

	var order orderView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "planned key replacement", "ttl_seconds": 600,
	}, &order, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+order.ID+"/revoke", nil, nil, 0)
	})

	var view struct {
		LifecycleState  string `json:"lifecycle_state"`
		LifecycleReason string `json:"lifecycle_reason"`
	}
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState != "recovery" {
		t.Fatalf("state after the recovery order = %q", view.LifecycleState)
	}
	if view.LifecycleReason != "planned key replacement" {
		t.Errorf("reason = %q", view.LifecycleReason)
	}

	var denial struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations",
		map[string]any{"action": "inventory.refresh", "reason": "read during recovery"},
		&denial, http.StatusConflict)
	if denial.Code != "host_recovery" {
		t.Errorf("code = %q, expected host_recovery", denial.Code)
	}

	// A second order while the first is pending changes nothing about the
	// state; revoking both leaves the host nothing to wait for, and it
	// comes back to active with the old key still its identity.
	var second orderView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "planned key replacement, second try", "ttl_seconds": 600,
	}, &second, http.StatusCreated)
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+order.ID+"/revoke", nil, nil, http.StatusNoContent)
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState != "recovery" {
		t.Errorf("the host left recovery while an order was still pending: %q", view.LifecycleState)
	}
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+second.ID+"/revoke", nil, nil, http.StatusNoContent)
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState != "active" {
		t.Errorf("the host did not come back once its orders were revoked: %q", view.LifecycleState)
	}

	// Back in recovery, the host can still be decommissioned: the operator
	// who ordered a new key may decide the host leaves instead.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "planned key replacement, third try", "ttl_seconds": 600,
	}, &order, http.StatusCreated)
	h.get("/api/v1/hosts/"+host.ID, &view)
	if view.LifecycleState != "recovery" {
		t.Fatalf("state after the third order = %q", view.LifecycleState)
	}
	var result struct {
		LifecycleState string `json:"lifecycle_state"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/decommission",
		map[string]any{"reason": "left during recovery", "typed_confirmation": host.Hostname},
		&result, http.StatusOK)
	if result.LifecycleState != "retired" {
		t.Errorf("state = %q", result.LifecycleState)
	}
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

// TestRevokedHostIsNotReleasedWithoutRecovery guards that lifting a
// quarantine imposed with a revocation does not pretend to bring the host
// back: without a live certificate the host cannot connect, and its return
// is identity recovery.
func TestRevokedHostIsNotReleasedWithoutRecovery(t *testing.T) {
	h := newHarness(t)
	host := h.enrollSyntheticHost(t)

	var result struct {
		LifecycleState      string `json:"lifecycle_state"`
		CertificatesRevoked int    `json:"certificates_revoked"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine",
		map[string]any{"reason": "suspected key theft", "revoke_certificates": true},
		&result, http.StatusOK)
	if result.LifecycleState != "quarantined" || result.CertificatesRevoked == 0 {
		t.Fatalf("quarantine = %+v", result)
	}

	// The release is refused with the reason, not accepted in name only.
	var denial struct {
		Code string `json:"code"`
	}
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/quarantine/release",
		map[string]any{"reason": "incident assessed"}, &denial, http.StatusConflict)
	if denial.Code != "identity_revoked" {
		t.Errorf("code = %q, expected identity_revoked", denial.Code)
	}

	// The recovery order names its reason and may revoke what is left at
	// once; the token is bound to this host.
	var order orderView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery", map[string]any{
		"reason": "key replaced after the incident", "revoke_old_immediately": true, "ttl_seconds": 600,
	}, &order, http.StatusCreated)
	if order.ExpectedHostID != host.ID {
		t.Errorf("the order points at host %q, wanted %q", order.ExpectedHostID, host.ID)
	}
	// A reason too short to mean anything is refused, like everywhere the
	// authentication is refreshed.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/identity-recovery",
		map[string]any{"reason": "again"}, nil, http.StatusBadRequest)
}

// TestEnrollmentOrderIsIdempotent guards the contract an automation relies
// on: the same order under the same key returns the order already placed,
// without a second token - and without repeating the token, which was
// shown once.
func TestEnrollmentOrderIsIdempotent(t *testing.T) {
	h := newHarness(t)
	key := uuid.NewString()
	body := map[string]any{
		"description": "idempotent order test", "site": "lab", "environment": "test",
		"kind": "agent", "purpose": "new", "ttl_minutes": 5,
	}
	first := h.postWithKey("/api/v1/enrollment-requests", body, key, http.StatusCreated)
	if first["token"] == nil || first["token"] == "" {
		t.Fatal("the first order shows no token")
	}
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+first["id"].(string)+"/revoke",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})

	second := h.postWithKey("/api/v1/enrollment-requests", body, key, http.StatusOK)
	if second["id"] != first["id"] {
		t.Fatalf("the repeat created another order: %v, first %v", second["id"], first["id"])
	}
	if token, _ := second["token"].(string); token != "" {
		t.Error("the repeat showed the token again")
	}
	// Another key is another order.
	third := h.postWithKey("/api/v1/enrollment-requests", body, uuid.NewString(), http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+third["id"].(string)+"/revoke",
			map[string]any{"reason": "end of the test"}, nil, 0)
	})
	if third["id"] == first["id"] {
		t.Error("a different key returned the same order")
	}
}

// TestInstallationProfileNamesTheTrust guards that the profile gives a host
// everything it needs before it holds a token: the addresses to connect
// to, in a configuration the agent reads as it is, and the CA with a
// fingerprint the operator can compare on the host.
func TestInstallationProfileNamesTheTrust(t *testing.T) {
	h := newHarness(t)
	var profile profileView
	h.get("/api/v1/installation-profiles?site=lab&environment=test", &profile)

	if profile.Connection.EnrollmentURL == "" || !strings.HasPrefix(profile.Connection.EnrollmentURL, "https://") {
		t.Fatalf("enrollment_url = %q", profile.Connection.EnrollmentURL)
	}
	if len(profile.Connection.GatewayURLs) == 0 {
		t.Fatal("the profile names no gateway")
	}
	if !strings.Contains(profile.Config.Content, "enrollment_url: \""+profile.Connection.EnrollmentURL+"\"") {
		t.Fatalf("the configuration does not name the enrollment URL:\n%s", profile.Config.Content)
	}
	if !strings.Contains(profile.Config.Content, "schema_version: 1") {
		t.Fatalf("the configuration has no schema version:\n%s", profile.Config.Content)
	}
	if profile.Config.Path != "/etc/flotestro/agent.yaml" {
		t.Errorf("config path = %q", profile.Config.Path)
	}
	if !strings.Contains(profile.CA.PEM, "BEGIN CERTIFICATE") {
		t.Fatal("the profile carries no CA in PEM")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(profile.CA.FingerprintSHA256) {
		t.Fatalf("the CA fingerprint is not a SHA-256 hex digest: %q", profile.CA.FingerprintSHA256)
	}
	// The commands exist for every family the release packages, and none
	// of them carries a token: the token is pasted into a hidden prompt.
	families := map[string]bool{}
	for _, family := range profile.Families {
		families[family.Key] = true
		if len(family.Steps) == 0 {
			t.Errorf("family %s has no commands", family.Key)
		}
		for _, step := range family.Steps {
			if strings.Contains(step.Command, "flt_") {
				t.Errorf("a command of %s carries a token", family.Key)
			}
		}
	}
	for _, key := range []string{"debian", "ubuntu", "rhel", "arch"} {
		if !families[key] {
			t.Errorf("the profile has no commands for %s", key)
		}
	}
	// A relay of another site is not a route for this placement.
	h.do(http.MethodGet, "/api/v1/installation-profiles?site=lab&environment=test&relay_id="+
		uuid.NewString(), nil, nil, http.StatusNotFound)
}

// TestOrderCarriesItsConfiguration guards that an order points at its
// ready configuration, and that the configuration repeats no token: it can
// be fetched as often as the installation needs, the token cannot.
func TestOrderCarriesItsConfiguration(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "configuration test", "site": "lab", "environment": "test",
	}, &created, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+created.ID+"/revoke", nil, nil, 0)
	})
	if created.ConfigURL != "/api/v1/enrollment-requests/"+created.ID+"/config" {
		t.Fatalf("config_url = %q", created.ConfigURL)
	}

	content := h.text(created.ConfigURL)
	if strings.Contains(content, created.Token) || strings.Contains(content, "flt_") {
		t.Fatal("the configuration repeats the token")
	}
	var profile profileView
	h.get("/api/v1/installation-profiles?site=lab&environment=test", &profile)
	if content != profile.Config.Content {
		t.Fatalf("the configuration of the order differs from the profile:\n%s\n---\n%s",
			content, profile.Config.Content)
	}
	if !strings.Contains(content, "enrollment_url: \""+profile.Connection.EnrollmentURL+"\"") {
		t.Fatalf("the configuration does not name the enrollment URL:\n%s", content)
	}
}

// TestRevokedOrderNamesTheRefusal guards that the installation screen
// learns why a host did not get in. The agent gets a uniform answer, so
// that tokens cannot be probed; the operator who placed the order sees the
// reason on the order.
func TestRevokedOrderNamesTheRefusal(t *testing.T) {
	h := newHarness(t)
	var created orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "refusal test", "site": "lab", "environment": "test",
	}, &created, http.StatusCreated)
	h.do(http.MethodPost, "/api/v1/enrollment-requests/"+created.ID+"/revoke",
		nil, nil, http.StatusNoContent)

	// A revoked token is refused like any other invalid one: the answer
	// says nothing about the reason.
	if status := enrollmentAttemptStatus(t, created.Token); status == http.StatusOK {
		t.Fatal("a revoked token registered a host")
	}

	var after orderView
	h.get("/api/v1/enrollment-requests/"+created.ID, &after)
	var token *stepView
	for i := range after.Steps {
		if after.Steps[i].Key == "token" {
			token = &after.Steps[i]
		}
	}
	if token == nil {
		t.Fatalf("no token step: %+v", after.Steps)
	}
	if token.State != "failed" {
		t.Errorf("token step state = %q", token.State)
	}
	if token.ErrorCode != "token_revoked" {
		t.Fatalf("token step error_code = %q, detail %q; wanted token_revoked",
			token.ErrorCode, token.Detail)
	}
	if token.Detail == "" {
		t.Error("the refusal carries no sentence for the operator")
	}
}

// enrollmentAttemptStatus makes one enrollment attempt with a token and
// returns the HTTP status alone. The lifecycle helper fails the test on a
// refusal; here the refusal is the point.
func enrollmentAttemptStatus(t *testing.T, token string) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine := uniqueSubject("refused-machine")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: machine}}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"enrollmentToken": token,
		"machineId":       machine,
		"hostname":        machine,
		"csrPem":          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		"clientRequestId": uuid.NewString(),
		"build":           map[string]any{"agentVersion": "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if bundle, err := os.ReadFile(envOr("FLOTESTRO_TEST_CA", "/var/lib/flotestro/ca.pem")); err == nil {
		pool.AppendCertsFromPEM(bundle)
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS12,
		}},
	}
	address := envOr("FLOTESTRO_TEST_ENROLLMENT", defaultEnrollment) +
		"/flotestro.agent.v1.EnrollmentService/Enroll"
	request, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("the enrollment attempt: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
