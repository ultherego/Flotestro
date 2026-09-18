//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The verification of a change on a live fleet: only a state the host
// showed after the change may end a job succeeded.
//
// Three gaps of chapter 1 of the functional review are reproduced here
// negatively - each of them used to end in a green job that nobody had
// confirmed:
//
//   - a change the host applies and does not keep ends applied_unverified
//     rather than succeeded, with the verifier's own observation on the
//     attempt;
//   - a restart stays open until the host comes back on another boot
//     identifier, instead of succeeding on the exit code of the
//     scheduling;
//   - a copy bound to a plan that no longer holds is refused with
//     stale_plan and nothing runs.

const verifyReason = "integration test of the verification of a change"

// verifiedAttemptView is an attempt with the reading the host made of
// itself after the change. The harness's own attempt view predates the
// verifications, so this test carries its own.
type verifiedAttemptView struct {
	Number       int    `json:"attempt_number"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code"`
	Message      string `json:"message"`
	Verification *struct {
		Verifier string `json:"verifier"`
		Verified bool   `json:"verified"`
		Expected string `json:"expected"`
		Observed string `json:"observed"`
		Reason   string `json:"reason"`
	} `json:"verification"`
}

// verifiedAttempts reads the attempts of a job with their verifications.
func verifiedAttempts(h *harness, jobID string) []verifiedAttemptView {
	h.t.Helper()
	var result struct {
		Items []verifiedAttemptView `json:"items"`
	}
	h.get("/api/v1/jobs/"+jobID+"/attempts", &result)
	return result.Items
}

// lastVerifiedAttempt returns the attempt that settled the job.
func lastVerifiedAttempt(t *testing.T, h *harness, jobID string) verifiedAttemptView {
	t.Helper()
	attempts := verifiedAttempts(h, jobID)
	if len(attempts) == 0 {
		t.Fatalf("job %s has no attempt at all", jobID)
	}
	return attempts[len(attempts)-1]
}

// TestAChangeTheHostDoesNotShowEndsUnverified drives the case chapter 1
// calls false success: the tool reports that it did the work, the host
// does not hold the state that was ordered, and the job used to say
// succeeded.
//
// The change is a kernel setting the kernel itself will not keep. Asking
// for a million huge pages on a machine with three gigabytes of memory is
// accepted by sysctl - the write returns zero - and /proc/sys then reads
// back the number of pages the kernel really managed to reserve, which is
// a different number. That is exactly "applied, not observed", it is
// harmless, and the host can produce it on demand; a unit that a restart
// leaves down cannot be built through the API at all, because a unit file
// is outside the write scope of the files module and nothing in the panel
// reloads systemd's definitions. The unit side of the same rule is
// guarded below, on a masked unit.
//
// The contract puts a rollback on this operation, so the host also puts
// the previous value back and says so in the reason.
func TestAChangeTheHostDoesNotShowEndsUnverified(t *testing.T) {
	h := newHarness(t)
	host := h.hostByName("agent-debian")

	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "sysctl.ensure", "reason": verifyReason,
			"payload": map[string]any{"kernel": map[string]any{
				"settings": map[string]string{"vm.nr_hugepages": "0"}}},
		}, 2*time.Minute)
	})

	job, _ := h.runOperation(host.ID, map[string]any{
		"action": "sysctl.ensure", "reason": verifyReason,
		"payload": map[string]any{"kernel": map[string]any{
			"settings": map[string]string{"vm.nr_hugepages": "1048576"}}},
	}, 5*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("the host does not hold the setting and the job says succeeded: %+v", job)
	}
	if job.ResultErrorCode != "applied_unverified" {
		t.Fatalf("error code = %q, expected applied_unverified (%s)", job.ResultErrorCode, job.ResultMessage)
	}

	// The observation is on the attempt, in full: an operator must be able
	// to read which verifier looked, what it wanted and what it found
	// without opening the host.
	attempt := lastVerifiedAttempt(t, h, job.ID)
	if attempt.Verification == nil {
		t.Fatal("the attempt carries no verification at all")
	}
	if attempt.Verification.Verified {
		t.Errorf("the verification says the state was observed: %+v", *attempt.Verification)
	}
	if attempt.Verification.Verifier != "sysctl" {
		t.Errorf("verifier = %q, expected sysctl", attempt.Verification.Verifier)
	}
	if !strings.Contains(attempt.Verification.Expected, "vm.nr_hugepages") ||
		attempt.Verification.Observed == "" {
		t.Errorf("the observation names neither the setting nor a value: %+v", *attempt.Verification)
	}
	// The contract rolls this operation back, and the reason has to say so:
	// the operator must know whether the host still carries the change.
	if !strings.Contains(attempt.Verification.Reason, "back") {
		t.Errorf("the reason does not say what happened to the change: %q", attempt.Verification.Reason)
	}
}

// TestARestartOfAMaskedUnitIsNeverASuccess is the unit half of the same
// rule, in the one shape the lab can produce honestly: a masked unit
// cannot be started, and the job says so instead of reporting a restart
// nobody performed.
func TestARestartOfAMaskedUnitIsNeverASuccess(t *testing.T) {
	h := newHarness(t)
	host := h.hostByName("agent-debian")
	const unit = "cron.service"

	mask, _ := h.runOperation(host.ID, map[string]any{
		"action": "unit.mask.set", "reason": verifyReason,
		"payload": map[string]any{"unit_toggle": map[string]any{"unit": unit, "enabled": true}},
	}, 2*time.Minute)
	if mask.State != "succeeded" {
		t.Fatalf("masking %s ended %s: %s", unit, mask.State, mask.ResultMessage)
	}
	t.Cleanup(func() {
		h.runOperation(host.ID, map[string]any{
			"action": "unit.mask.set", "reason": verifyReason,
			"payload": map[string]any{"unit_toggle": map[string]any{"unit": unit, "enabled": false}},
		}, 2*time.Minute)
		h.runOperation(host.ID, map[string]any{
			"action": "unit.start", "reason": verifyReason,
			"payload": unitPayload(unit),
		}, 2*time.Minute)
	})

	restart, _ := h.runOperation(host.ID, map[string]any{
		"action": "unit.restart", "reason": verifyReason, "payload": unitPayload(unit),
	}, 2*time.Minute)
	if restart.State == "succeeded" {
		t.Fatalf("a masked unit was restarted according to the panel: %+v", restart)
	}
	if restart.ResultErrorCode == "" {
		t.Error("the failure of the restart carries no code")
	}
}

// TestARestartSettlesOnTheReturnOfTheHost drives the second gap: the job
// of a restart used to end succeeded on the exit code of the scheduling,
// which is the same exit code a host that never comes back produces.
//
// The restart is ordered on the Debian host of the fleet and on no other:
// the Ubuntu and Fedora machines of the lab hang on a restart under
// VirtualBox, and a test that leaves the fleet in pieces is worse than no
// test. The job has to stay open while the host is down and settle
// succeeded only once a session with another boot identifier is there,
// with that identifier in the result.
func TestARestartSettlesOnTheReturnOfTheHost(t *testing.T) {
	h := newHarness(t)
	host := h.hostByName("agent-debian")
	if host.BootID == "" {
		t.Skip("the host reports no boot identifier; there would be nothing to compare")
	}
	bootBefore := host.BootID

	job := h.createOperation(host.ID, map[string]any{
		"action": "system.reboot", "reason": verifyReason,
		"payload": map[string]any{"reboot": map[string]any{
			"delay_seconds": 5, "reason": "Flotestro: " + verifyReason,
		}},
	})
	if job.RequiresApproval {
		job = h.approve(job.ID, job.PayloadHash)
	}

	// The whole point of the operation: while the host is away the job is
	// open. A settlement before a session with another boot identifier is
	// the false success this test exists for.
	deadline := time.Now().Add(6 * time.Minute)
	var settled jobView
	for settled.ID == "" && time.Now().Before(deadline) {
		current := h.job(job.ID)
		switch current.State {
		case "succeeded":
			if bootIDOf(h, host.ID) == bootBefore {
				t.Fatalf("the restart was settled succeeded while the host was still on boot %s", bootBefore)
			}
			settled = current
		case "failed", "timed_out", "canceled", "expired":
			t.Fatalf("the restart ended %s/%s: %s", current.State,
				current.ResultErrorCode, current.ResultMessage)
		default:
			time.Sleep(3 * time.Second)
		}
	}
	if settled.ID == "" {
		t.Fatalf("the restart of %s did not settle; the host is on boot %s",
			host.Hostname, bootIDOf(h, host.ID))
	}

	bootAfter := bootIDOf(h, host.ID)
	if bootAfter == "" || bootAfter == bootBefore {
		t.Fatalf("boot identifier after the restart = %q, before = %q", bootAfter, bootBefore)
	}
	if !strings.Contains(settled.ResultMessage, bootAfter) {
		t.Errorf("the result does not name the boot the host came back on: %q", settled.ResultMessage)
	}

	attempt := lastVerifiedAttempt(t, h, job.ID)
	if attempt.Verification == nil {
		t.Fatal("the settled restart carries no verification")
	}
	if attempt.Verification.Verifier != "reboot" || !attempt.Verification.Verified {
		t.Errorf("verification of the restart = %+v", *attempt.Verification)
	}
	if attempt.Verification.Observed != bootAfter ||
		!strings.Contains(attempt.Verification.Expected, bootBefore) {
		t.Errorf("the observation does not name both boots: %+v", *attempt.Verification)
	}

	// The host is back for the rest of the suite before this test ends.
	h.awaitConnection(host.ID, 5*time.Minute)
}

// bootIDOf reads the boot identifier the panel has for a host now.
func bootIDOf(h *harness, hostID string) string {
	h.t.Helper()
	for _, host := range h.hosts() {
		if host.ID == hostID {
			return host.BootID
		}
	}
	return ""
}

// TestACopyBoundToAForeignPlanIsRefused drives the third gap: the plan of
// a copy binds the copy. The helper computes the plan again under the
// lock of the backup family right before anything is written, and a
// digest that no longer describes this host and this repository is
// refused with stale_plan - nothing runs, and no repository is created.
func TestACopyBoundToAForeignPlanIsRefused(t *testing.T) {
	h := newHarness(t)
	host := hostWithRestic(t, h)
	stamp := time.Now().UnixNano()
	name := fmt.Sprintf("integration-stale-%d", stamp%100000)
	repository := fmt.Sprintf("/srv/flotestro-stale-%d", stamp%100000)
	secret := newSecret(t, h, fmt.Sprintf("repository-password-%d", stamp))

	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/backups", map[string]any{
		"name": name, "tool": "restic", "repository": repository,
		"paths": []string{"/etc/flotestro"}, "keep_last": 2,
		"initialize": true, "password_secret": secret.Name,
	}, nil, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete, "/api/v1/hosts/"+host.ID+"/backups?name="+name, nil, nil, 0)
	})

	// A digest of a plan this host never computed: the shape is right and
	// the content describes nothing that is here.
	foreign := strings.Repeat("a1", 32)
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "backup.run", "reason": verifyReason,
		"payload": map[string]any{"backup": map[string]any{
			"id": name, "tool": "restic", "repository": repository,
			"paths": []string{"/etc/flotestro"}, "keep_last": 2, "initialize": true,
			"password_secret": map[string]any{"name": secret.Name},
			"plan_hash":       foreign,
		}},
	}, 10*time.Minute)

	if job.State == "succeeded" {
		t.Fatalf("a copy ran on a plan this host never computed: %+v", job)
	}
	if job.ResultErrorCode != "stale_plan" {
		t.Fatalf("error code = %q, expected stale_plan: %s", job.ResultErrorCode, lastMessage(attempts))
	}
	// The refusal happens before anything is written: the repository the
	// order names is not created by a refused copy.
	report := hostBackups(h, host.ID)
	for _, definition := range report.Definitions {
		if definition.Name == name && definition.Snapshots != nil && *definition.Snapshots > 0 {
			t.Errorf("the refused copy left %d snapshot(s) behind", *definition.Snapshots)
		}
	}
}
