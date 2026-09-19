package files

import (
	"strings"
	"testing"
)

// TestPlanDistinguishesMissingFileFromDifferentContent guards the essence of
// the per-host plan: two hosts with the same desired state have two different
// answers.
func TestPlanDistinguishesMissingFileFromDifferentContent(t *testing.T) {
	desired := []byte("new content\n")

	missing := Compute(File{Path: "/etc/x.conf"}, Desired{
		Content: desired, Mode: "0644", Owner: "root", Group: "root"})
	if missing.Action != PlanCreate {
		t.Errorf("a non-existent file has the plan %q", missing.Action)
	}
	if missing.Exists {
		t.Error("the plan says the file exists although it does not")
	}

	other := Compute(File{
		Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644",
		Owner: "root", Group: "root",
	}, Desired{Content: desired, Mode: "0644", Owner: "root", Group: "root"})
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

// TestPlanNoChangeIsAnAnswer guards that a host already matching the desired
// state says so directly.
func TestPlanNoChangeIsAnAnswer(t *testing.T) {
	desired := []byte("the same content\n")
	fingerprint := Fingerprint(desired)

	plan := Compute(File{
		Path: "/etc/x.conf", Exists: true, SHA256: fingerprint, Mode: "0644",
		Owner: "root", Group: "root",
	}, Desired{Content: desired, Mode: "0644", Owner: "root", Group: "root"})

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
	}, Desired{Content: desired, Mode: "0600", Owner: "root", Group: "root"})

	if plan.Action != PlanUpdate {
		t.Fatalf("a permissions change gave the plan %q", plan.Action)
	}
	if !containsChange(plan.Changes, "permissions from 0644 to 0600") {
		t.Errorf("the plan does not name the permissions change: %+v", plan.Changes)
	}
}

// TestPlanOfSecretFileCarriesNoContent guards the boundary the plan must not
// cross: a value from the store has no right to appear in the change
// description or in its fingerprint.
func TestPlanOfSecretFileCarriesNoContent(t *testing.T) {
	plan := Compute(File{
		Path: "/etc/secret.conf", Exists: true, SHA256: "aaa", Mode: "0600",
	}, Desired{Content: []byte("password-from-store"), Mode: "0600", Owner: "root",
		Group: "root", FromSecret: true})

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
		Desired{Removal: true})
	if present.Action != PlanRemove {
		t.Errorf("removing an existing file has the plan %q", present.Action)
	}

	absent := Compute(File{Path: "/etc/x.conf"}, Desired{Removal: true})
	if absent.Action != PlanRemoveAbsent {
		t.Errorf("removing a non-existent file has the plan %q", absent.Action)
	}
}

// TestPlanFingerprintDoesNotDependOnValidatorOutput guards repeatability: the
// same diff must give the same fingerprint, even when the validator prints
// something else.
func TestPlanFingerprintDoesNotDependOnValidatorOutput(t *testing.T) {
	desired := []byte("content\n")
	current := File{Path: "/etc/x.conf", Exists: true, SHA256: "aaa", Mode: "0644"}

	plan := Compute(current, Desired{Content: desired, Mode: "0644"})

	// The fingerprint is computed directly on two plans differing only in the
	// validator output.
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

// TestPlanCarriesTheWholeIntendedState guards what an approval is meant to
// cover: not a digest, but the inode, the rule the path was resolved under,
// who would check the content and what would have to be reloaded afterwards.
func TestPlanCarriesTheWholeIntendedState(t *testing.T) {
	desired := []byte("server {}\n")
	identity := ValidatorIdentity{Known: true, Name: "nginx", Command: "/usr/sbin/nginx",
		Available: true, Version: "nginx version: nginx/1.22.1"}

	plan := Compute(File{
		Path: "/etc/nginx/conf.d/app.conf", Exists: true, SHA256: "aaa",
		Mode: "0644", Owner: "root", Group: "root",
	}, Desired{Content: desired, Mode: "0600", Owner: "www-data", Group: "root",
		Validator: identity, KeptVersions: 3})

	if !plan.ContentChanges || !plan.ModeChanges || !plan.OwnerChanges {
		t.Errorf("the plan does not mark what changes: %+v", plan)
	}
	if plan.GroupChanges {
		t.Error("the plan marks a group change although the group stays")
	}
	if plan.SymlinkPolicy != SymlinkPolicyNoFollow {
		t.Errorf("symlink policy = %q", plan.SymlinkPolicy)
	}
	if plan.Validator.Name != "nginx" || plan.Validator.Version == "" || !plan.Validator.Known {
		t.Errorf("the plan does not say who would check the content: %+v", plan.Validator)
	}
	if plan.KeptVersions != 3 {
		t.Errorf("kept versions = %d", plan.KeptVersions)
	}
	// The file has a consumer: a written file is not an applied change
	// until the service reads it again.
	if len(plan.Consumers) == 0 || plan.Consumers[0].Unit != "nginx.service" ||
		plan.Consumers[0].Action != ConsumerReload {
		t.Errorf("the plan does not name what has to be reloaded: %+v", plan.Consumers)
	}
	if plan.ConsumersReason != "" {
		t.Errorf("a plan with consumers also explains their absence: %q", plan.ConsumersReason)
	}
}

// TestAPlanWithoutConsumersSaysWhy guards the doctrine on an empty list:
// "nothing to reload" and "the panel knows of nothing" are different answers,
// and only one of them is silence.
func TestAPlanWithoutConsumersSaysWhy(t *testing.T) {
	plan := Compute(File{Path: "/etc/motd", Exists: true, SHA256: "aaa", Mode: "0644"},
		Desired{Content: []byte("hello\n"), Mode: "0644"})
	if len(plan.Consumers) != 0 {
		t.Fatalf("a file read at every use has consumers: %+v", plan.Consumers)
	}
	if plan.ConsumersReason == "" {
		t.Error("an empty list of consumers is not explained")
	}

	unknown := Compute(File{Path: "/etc/something-nobody-knows.conf", Exists: true, SHA256: "a"},
		Desired{Content: []byte("x\n"), Mode: "0644"})
	if !strings.Contains(unknown.ConsumersReason, "knows of no service") {
		t.Errorf("a path with no entry in the table claims knowledge: %q", unknown.ConsumersReason)
	}
}

// TestAMissingValidatorIsNotAPassedCheck guards the plan of a host without the
// tool: the identity says the tool is not there, which is not the same as a
// check that found nothing wrong.
func TestAMissingValidatorIsNotAPassedCheck(t *testing.T) {
	plan := Compute(File{Path: "/etc/nginx/conf.d/app.conf", Exists: false},
		Desired{Content: []byte("server {}\n"), Mode: "0644",
			Validator: ValidatorIdentity{Known: true, Name: "nginx", Command: "/usr/sbin/nginx",
				VersionUnavailableReason: "the tool is not installed on this host"}})
	if plan.Validator.Available {
		t.Error("the plan claims a tool the host does not have")
	}
	if plan.Validator.VersionUnavailableReason == "" {
		t.Error("the plan does not say why there is no version")
	}
}

// TestThePlanFingerprintIgnoresTheSurroundings guards that an approval binds
// the change and not the environment: the version of the tool, the units
// installed and the number of copies kept may differ between the plan and the
func TestThePlanFingerprintIgnoresTheSurroundings(t *testing.T) {
	current := File{Path: "/etc/nginx/conf.d/app.conf", Exists: true, SHA256: "aaa", Mode: "0644"}
	desired := Desired{Content: []byte("server {}\n"), Mode: "0644",
		Validator: ValidatorIdentity{Known: true, Name: "nginx", Available: true,
			Version: "nginx version: nginx/1.22.1"}}

	before := Compute(current, desired)
	desired.Validator.Version = "nginx version: nginx/1.24.0"
	desired.KeptVersions = 7
	after := Compute(current, desired)

	if before.PlanHash != after.PlanHash {
		t.Error("an upgrade of the tool turned an approved change into a different one")
	}
	// The identity of the checker still differs where it describes the check
	// itself: a validator that is suddenly unavailable is a different plan.
	desired.Validator.Available = false
	if Compute(current, desired).PlanHash == before.PlanHash {
		t.Error("a plan whose validator disappeared has the same fingerprint")
	}
}
