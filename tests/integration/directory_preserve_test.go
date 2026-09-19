//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const directoryPreserveReason = "integration test of the preserve order of operations"

// preserveChangeView is the change as this test reads it: the plan has to name
// the entry it would move, and the phases have to say what happened where and
// in which order.
type preserveChangeView struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	PayloadHash string `json:"payload_hash"`
	Plan        struct {
		Summary       string   `json:"summary"`
		Steps         []string `json:"steps"`
		Conflicts     []string `json:"conflicts"`
		PreserveEntry *struct {
			DN              string `json:"dn"`
			EntryUUID       string `json:"entry_uuid"`
			ModifyTimestamp string `json:"modify_timestamp"`
		} `json:"preserve_entry"`
	} `json:"plan"`
	Phases        json.RawMessage `json:"phases"`
	ResultMessage string          `json:"result_message"`
}

type preservePhaseView struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// phases decodes the phases of a finished change.
func (c preserveChangeView) phases(t *testing.T) []preservePhaseView {
	t.Helper()
	if len(c.Phases) == 0 {
		return nil
	}
	var phases []preservePhaseView
	if err := json.Unmarshal(c.Phases, &phases); err != nil {
		t.Fatalf("the phases of the change do not read: %v", err)
	}
	return phases
}

// indexOfPhase finds the phase whose name starts with the given words.
func indexOfPhase(phases []preservePhaseView, prefix string) int {
	for index, phase := range phases {
		if strings.HasPrefix(phase.Name, prefix) {
			return index
		}
	}
	return -1
}

// planPreserve orders a preserve and returns the planned change without
// approving it.
func planPreserve(t *testing.T, h *harness, uid string) preserveChangeView {
	t.Helper()
	var change preserveChangeView
	h.do(http.MethodPost, "/api/v1/identity/changes", map[string]any{
		"action": "identity.user.preserve", "reason": directoryPreserveReason,
		"payload": map[string]any{"reference": map[string]any{"uid": uid}},
	}, &change, http.StatusCreated)
	return change
}

// runPreserve approves a planned preserve and waits for the executor.
func runPreserve(t *testing.T, h, approver *harness, change preserveChangeView) preserveChangeView {
	t.Helper()
	approver.do(http.MethodPost, "/api/v1/identity/changes/"+change.ID+"/approve",
		map[string]any{"payload_hash": change.PayloadHash, "reason": directoryPreserveReason},
		nil, http.StatusOK)
	deadline := time.Now().Add(90 * time.Second)
	var last preserveChangeView
	for time.Now().Before(deadline) {
		h.get("/api/v1/identity/changes/"+change.ID, &last)
		switch last.State {
		case "succeeded", "failed", "partially_applied", "canceled":
			return last
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the change %s did not finish (state %s)", change.ID, last.State)
	return last
}

// deniedLocally reads the local denial marker of a panel identity straight
// from the fleet database: whether the host half of a preserve happened is not
// something the change view is allowed to guess at.
func deniedLocally(t *testing.T, h *harness, subject string) bool {
	t.Helper()
	ctx := context.Background()
	var denied *time.Time
	err := h.database(ctx).QueryRow(ctx,
		`select denied_at from principals where subject = $1`, subject).Scan(&denied)
	if err != nil {
		t.Fatalf("the local denial marker of %s was not read: %v", subject, err)
	}
	return denied != nil
}

// TestThePreserveAsksTheDirectoryFirstAndBindsItsPlanToTheEntry is the
// negative side of chapter 14.
func TestThePreserveAsksTheDirectoryFirstAndBindsItsPlanToTheEntry(t *testing.T) {
	h := newHarness(t)
	if !directoryAvailable(t, h) {
		t.Skip("this installation has no directory connection")
	}
	approver := secondPerson(t, h)
	uid := fmt.Sprintf("ftest-preserve-%d", time.Now().UnixNano()%1000000)

	orderAndRun(t, h, approver, "identity.user.create", map[string]any{
		"user": map[string]any{"uid": uid, "first_name": "Integration", "last_name": "Preserve"},
	})
	t.Cleanup(func() {
		if directoryUser(t, h, uid, false) == nil {
			return
		}
		runPreserve(t, h, approver, planPreserve(t, h, uid))
	})

	// A panel identity of the same name, so the local half of the operation
	// has something to leave alone.
	h.createPrincipal(uid, []map[string]string{{"role": "viewer", "scope": "*"}})
	if deniedLocally(t, h, uid) {
		t.Fatalf("the identity %s is denied before anything happened", uid)
	}

	// The plan names the entry it would move: where it is, which entry it is and
	// when it last changed.
	planned := planPreserve(t, h, uid)
	if len(planned.Plan.Conflicts) > 0 {
		t.Fatalf("the plan of the preserve has conflicts: %v", planned.Plan.Conflicts)
	}
	if planned.Plan.PreserveEntry == nil || planned.Plan.PreserveEntry.DN == "" {
		t.Fatalf("the plan does not name the entry it would move: %+v", planned.Plan)
	}
	if !strings.Contains(strings.ToLower(planned.Plan.PreserveEntry.DN), "uid="+uid) {
		t.Errorf("the plan names the entry %q, expected the entry of %s",
			planned.Plan.PreserveEntry.DN, uid)
	}

	// An entry somebody changed between the plan and the approval is refused
	// where the directory reports when an entry last changed.
	if planned.Plan.PreserveEntry.ModifyTimestamp != "" {
		orderAndRun(t, h, approver, "identity.user.posix", map[string]any{
			"posix": map[string]any{"uid": uid, "shell": "/usr/sbin/nologin"},
		})
		touched := runPreserve(t, h, approver, planned)
		if touched.State == "succeeded" {
			t.Fatalf("a plan the entry changed under was carried out: %s", touched.ResultMessage)
		}
		if !phasesCarry(touched.phases(t), "stale_plan") {
			t.Fatalf("the refusal does not carry stale_plan: %+v", touched.phases(t))
		}
		// The whole point of the reordering: a refusal changes nothing
		// locally. The panel identity of the same name is still allowed in.
		if deniedLocally(t, h, uid) {
			t.Fatal("the local denial marker was set although the preserve was refused")
		}
		if directoryUser(t, h, uid, false) == nil {
			t.Fatal("the directory no longer lists the account although the preserve was refused")
		}
		planned = planPreserve(t, h, uid)
	} else {
		t.Log("the directory does not report when an entry last changed; " +
			"the plan binds to the DN and the identifier")
	}

	// A plan made before the account moved.
	kept := planPreserve(t, h, uid)

	final := runPreserve(t, h, approver, planned)
	if final.State != "succeeded" {
		t.Fatalf("the preserve finished as %s: %s", final.State, final.ResultMessage)
	}
	phases := final.phases(t)
	preflight := indexOfPhase(phases, "asking the directory what it can do")
	directory := indexOfPhase(phases, "preserving the account in the directory")
	local := indexOfPhase(phases, "the local denial marker")
	if preflight < 0 || directory < 0 || local < 0 {
		t.Fatalf("the phases of the preserve are %+v", phases)
	}
	if !(preflight < directory && directory < local) {
		t.Fatalf("the phases ran in the order %+v; the directory has to confirm "+
			"before the local account is touched", phases)
	}
	// The preflight reports what it verified, including what it could not: a
	// directory that does not report the rights on an entry has not granted them.
	if phases[preflight].Status == "failed" || phases[preflight].Message == "" {
		t.Errorf("the preflight phase is %s (%q) and says nothing about the directory",
			phases[preflight].Status, phases[preflight].Message)
	}
	if directoryUser(t, h, uid, true) == nil {
		t.Errorf("the directory does not list %s among the preserved accounts", uid)
	}
	if !deniedLocally(t, h, uid) {
		t.Errorf("the local denial marker was not set after the directory confirmed")
	}

	// The second operator arrives with the plan made before the move.
	second := runPreserve(t, h, approver, kept)
	if second.State == "succeeded" {
		t.Fatalf("the same account was preserved twice: %s", second.ResultMessage)
	}
	stalePhases := second.phases(t)
	if !phasesCarry(stalePhases, "stale_plan") {
		t.Fatalf("the second preserve was refused as %q, expected stale_plan: %+v",
			second.ResultMessage, stalePhases)
	}
	if indexOfPhase(stalePhases, "preserving the account in the directory") >= 0 ||
		indexOfPhase(stalePhases, "the local denial marker") >= 0 {
		t.Fatalf("a refused plan still reached the directory or the local account: %+v",
			stalePhases)
	}
}

// phasesCarry says whether any phase message carries the code.
func phasesCarry(phases []preservePhaseView, code string) bool {
	for _, phase := range phases {
		if strings.HasPrefix(phase.Message, code+":") {
			return true
		}
	}
	return false
}
