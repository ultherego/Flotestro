package files

import (
	"strings"
	"testing"
)

// TestPlanDistinguishesMissingFileFromDifferentContent guards the essence
// of the per-host plan: two hosts with the same desired state have two
// different answers.
func TestPlanDistinguishesMissingFileFromDifferentContent(t *testing.T) {
	desired := []byte("new content\n")

	missing := Compute(File{Path: "/etc/x.conf"}, desired, "0644", "root", "root", false, false)
	if missing.Action != PlanCreate {
		t.Errorf("a non-existent file has the plan %q", missing.Action)
	}
	if missing.Exists {
		t.Error("the plan says the file exists although it does not")
	}

	other := Compute(File{
		Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644",
		Owner: "root", Group: "root",
	}, desired, "0644", "root", "root", false, false)
	if other.Action != PlanUpdate {
		t.Errorf("a file with different content has the plan %q", other.Action)
	}
	if !containsChange(other.Changes, "content") {
		t.Errorf("the plan does not name the content change: %+v", other.Changes)
	}

	// Two different found states must give two different fingerprints -
	// otherwise approval of one plan would cover the other.
	if missing.PlanHash == other.PlanHash {
		t.Error("the plan of a non-existent file and the change plan have the same fingerprint")
	}
}

// TestPlanNoChangeIsAnAnswer guards that a host already matching the
// desired state says so directly. Without that the operator does not know
// how many hosts the campaign will really touch.
func TestPlanNoChangeIsAnAnswer(t *testing.T) {
	desired := []byte("the same content\n")
	fingerprint := Fingerprint(desired)

	plan := Compute(File{
		Path: "/etc/x.conf", Exists: true, SHA256: fingerprint, Mode: "0644",
		Owner: "root", Group: "root",
	}, desired, "0644", "root", "root", false, false)

	if plan.Action != PlanNoChange {
		t.Fatalf("the plan of an identical file is %q (%+v)", plan.Action, plan.Changes)
	}
	if len(plan.Changes) != 0 {
		t.Errorf("a no-change plan lists changes: %+v", plan.Changes)
	}
}

// TestPlanSeesPermissionsAlone guards a change the content fingerprint does
// not show: the same content with different permissions is still a change.
func TestPlanSeesPermissionsAlone(t *testing.T) {
	desired := []byte("content\n")
	plan := Compute(File{
		Path: "/etc/x.conf", Exists: true, SHA256: Fingerprint(desired), Mode: "0644",
		Owner: "root", Group: "root",
	}, desired, "0600", "root", "root", false, false)

	if plan.Action != PlanUpdate {
		t.Fatalf("a permissions change gave the plan %q", plan.Action)
	}
	if !containsChange(plan.Changes, "permissions from 0644 to 0600") {
		t.Errorf("the plan does not name the permissions change: %+v", plan.Changes)
	}
}

// TestPlanOfSecretFileCarriesNoContent guards the boundary the plan must
// not cross: a value from the store has no right to appear in the change
// description or in its fingerprint.
func TestPlanOfSecretFileCarriesNoContent(t *testing.T) {
	plan := Compute(File{
		Path: "/etc/secret.conf", Exists: true, SHA256: "aaa", Mode: "0600",
	}, []byte("password-from-store"), "0600", "root", "root", true, false)

	if plan.DesiredSHA256 != "" {
		t.Error("the plan of a secret file carries the desired content fingerprint")
	}
	if !containsChange(plan.Changes, "secret store") {
		t.Errorf("the plan does not say the content cannot be compared: %+v", plan.Changes)
	}
}

// TestRemovalPlanDistinguishesExistingFile guards that removing a file that
// does not exist is visible before approval, not after.
func TestRemovalPlanDistinguishesExistingFile(t *testing.T) {
	present := Compute(File{Path: "/etc/x.conf", Exists: true, SHA256: "aaa"},
		nil, "", "", "", false, true)
	if present.Action != PlanRemove {
		t.Errorf("removing an existing file has the plan %q", present.Action)
	}

	absent := Compute(File{Path: "/etc/x.conf"}, nil, "", "", "", false, true)
	if absent.Action != PlanRemoveAbsent {
		t.Errorf("removing a non-existent file has the plan %q", absent.Action)
	}
}

// TestPlanFingerprintDoesNotDependOnValidatorOutput guards repeatability:
// the same diff must give the same fingerprint, even when the validator
// prints something else.
func TestPlanFingerprintDoesNotDependOnValidatorOutput(t *testing.T) {
	desired := []byte("content\n")
	current := File{Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644"}

	plan := Compute(current, desired, "0644", "", "", false, false)

	// The fingerprint is computed directly on two plans differing only in
	// the validator output. Setting the field after Compute would check
	// nothing: the fingerprint is made inside, before the validator even
	// runs.
	withOutput := plan
	withOutput.ValidatorOutput = "nginx: configuration file test is successful"
	withoutOutput := plan
	withoutOutput.ValidatorOutput = ""

	if planFingerprint(withOutput) != planFingerprint(withoutOutput) {
		t.Error("the plan fingerprint changes with the validator output")
	}
	// The difference itself must change the fingerprint though - otherwise
	// it would bind the approval to nothing.
	otherContent := plan
	otherContent.DesiredSHA256 = "other"
	if planFingerprint(otherContent) == planFingerprint(withoutOutput) {
		t.Error("the plan fingerprint did not change despite different desired content")
	}
}

func containsChange(changes []string, fragment string) bool {
	for _, change := range changes {
		if strings.Contains(change, fragment) {
			return true
		}
	}
	return false
}
