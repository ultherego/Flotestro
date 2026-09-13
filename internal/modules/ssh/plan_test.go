package ssh

import (
	"strings"
	"testing"
)

func testState() Snapshot {
	return Snapshot{
		Ports: []string{"22"}, PermitRootLogin: "prohibit-password",
		PasswordAuthentication: "yes", PubkeyAuthentication: "yes",
		KbdInteractive: "no", MaxAuthTries: 6,
	}
}

func TestSSHPlanDistinguishesChangeFromTargetState(t *testing.T) {
	change := Compute(testState(), Settings{PasswordAuthentication: "no"}, false)
	if change.Action != PlanUpdate || change.Refusal != "" {
		t.Fatalf("change plan: %+v", change)
	}
	if len(change.Changes) != 2 || !strings.Contains(change.Changes[0], "PasswordAuthentication from yes to no") ||
		change.Changes[1] != "the panel's file will be created" {
		t.Errorf("changes: %v", change.Changes)
	}
	if change.Current["PasswordAuthentication"] != "yes" {
		t.Errorf("state found: %v", change.Current)
	}

	state := testState()
	state.PasswordAuthentication = "no"
	state.ManagedPresent = true
	state.Managed, _ = ComposeDropIn(Settings{PasswordAuthentication: "no"})
	none := Compute(state, Settings{PasswordAuthentication: "no"}, false)
	if none.Action != PlanNoChange || len(none.Changes) != 0 {
		t.Errorf("target state counted as a change: %+v", none)
	}
	if none.PlanHash == change.PlanHash || none.ManagedHash == "" {
		t.Error("plan fingerprints do not differ or the file fingerprint is missing")
	}

	// The server already applies the requested value, but from a different
	// file: the panel's file gets overwritten anyway, so this is a change.
	state.Managed = "# another file\nMaxAuthTries 3\n"
	other := Compute(state, Settings{PasswordAuthentication: "no"}, false)
	if other.Action != PlanUpdate || other.Changes[0] != "the panel's file will be overwritten" {
		t.Errorf("overwrite of the panel's file without a change: %+v", other)
	}
}

func TestSSHPlanRefusesLockoutAndBadValue(t *testing.T) {
	lockout := Compute(testState(), Settings{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, false)
	if !strings.Contains(lockout.Refusal, "authentication method") {
		t.Errorf("lockout without a refusal: %+v", lockout)
	}
	consent := Compute(testState(), Settings{
		PasswordAuthentication: "no", PubkeyAuthentication: "no"}, true)
	if consent.Refusal != "" {
		t.Errorf("explicit consent did not lift the refusal: %+v", consent)
	}
	bad := Compute(testState(), Settings{PermitRootLogin: "maybe"}, false)
	if bad.Refusal == "" {
		t.Error("a bad value passed without a refusal")
	}
	empty := Compute(testState(), Settings{}, false)
	if empty.Refusal == "" {
		t.Error("a change without settings passed without a refusal")
	}
	noServer := Compute(Snapshot{UnavailableReason: "this host has no sshd server"},
		Settings{Port: "22"}, false)
	if noServer.Refusal == "" || noServer.PlanHash == "" {
		t.Errorf("host without sshd: %+v", noServer)
	}
}
