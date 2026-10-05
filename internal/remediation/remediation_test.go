package remediation

import (
	"encoding/json"
	"testing"

	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/hosts"
)

func finding(id, action string, reboot bool) compliance.Finding {
	result := compliance.Finding{
		CheckID: id, CheckVersion: 1, Applicable: true, Severity: compliance.SeverityMedium,
	}
	if action != "" {
		result.Remediation = &compliance.Remediation{
			Action: action, Payload: json.RawMessage(`{}`), RequiresReboot: reboot,
		}
	}
	return result
}

// A reboot ends the plan: whatever comes after it has to be assessed anew,
// because steps planned earlier refer to facts from before the reboot.
func TestARebootIsTheLastStep(t *testing.T) {
	arranged, err := Arrange([]compliance.Finding{
		finding("reboot.pending", "system.reboot", true),
		finding("kernel.rp-filter", "sysctl.ensure", false),
		finding("ssh.root-login", "ssh.config.apply", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(arranged.Steps) != 3 {
		t.Fatalf("steps = %d", len(arranged.Steps))
	}
	if !arranged.Steps[2].RequiresReboot {
		t.Errorf("the reboot is not last: %+v", arranged.Steps)
	}
	// The positions are a dependency: a step starts only after the previous one.
	for i, step := range arranged.Steps {
		if step.Position != i+1 {
			t.Errorf("the step %s has position %d", step.CheckID, step.Position)
		}
		if step.State != StepPending {
			t.Errorf("the step %s starts in the state %q", step.CheckID, step.State)
		}
	}
	// The resource lock class comes from the operation's contract rather than from the plan.
	for _, step := range arranged.Steps {
		if step.ActionType == "ssh.config.apply" && step.LockClass == "" {
			t.Error("a step changing sshd carries no lock class")
		}
	}
}

// Two reboots are two plans: after the first one the host's state has to be
// assessed anew.
func TestTwoRebootsDoNotMakeOnePlan(t *testing.T) {
	_, err := Arrange([]compliance.Finding{
		finding("reboot.pending", "system.reboot", true),
		finding("kernel.blacklist", "system.reboot", true),
	})
	if err == nil {
		t.Fatal("a plan with two reboots was arranged")
	}
}

// A finding without a remediating operation creates no step - and says why.
func TestAFindingWithoutAnOperationIsSkipped(t *testing.T) {
	withoutOperation := finding("exposure.listening", "", false)
	withoutOperation.Remediation = &compliance.Remediation{Note: "every socket is closed differently"}
	passed := finding("mac.enforcing", "selinux.mode.set", false)
	passed.Passed = true

	arranged, err := Arrange([]compliance.Finding{
		withoutOperation, passed, finding("kernel.rp-filter", "sysctl.ensure", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(arranged.Steps) != 1 || arranged.Steps[0].CheckID != "kernel.rp-filter" {
		t.Fatalf("steps = %+v", arranged.Steps)
	}
	if arranged.Skipped["exposure.listening"] != "every socket is closed differently" {
		t.Errorf("skipped = %v", arranged.Skipped)
	}
	if arranged.Skipped["mac.enforcing"] == "" {
		t.Error("a passed finding was skipped without a reason")
	}
}

// A plan without a single workable step is not a plan.
func TestAPlanWithoutStepsIsAnError(t *testing.T) {
	withoutOperation := finding("exposure.listening", "", false)
	if _, err := Arrange([]compliance.Finding{withoutOperation}); err == nil {
		t.Fatal("a plan without steps was arranged")
	}
}

// An unknown operation must not enter a plan: the runner would reject it only
// after the operator had approved it.
func TestAnUnknownOperationDoesNotEnterAPlan(t *testing.T) {
	if _, err := Arrange([]compliance.Finding{
		finding("invented", "no.such.operation", false),
	}); err == nil {
		t.Fatal("the plan accepted an unknown operation")
	}
}

// The same set of findings gives the same plan: the order does not depend on
// the order the findings arrived in.
func TestTheOrderOfStepsIsRepeatable(t *testing.T) {
	first, err := Arrange([]compliance.Finding{
		finding("ssh.root-login", "ssh.config.apply", false),
		finding("kernel.rp-filter", "sysctl.ensure", false),
		finding("audit.rules-loaded", "unit.restart", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Arrange([]compliance.Finding{
		finding("audit.rules-loaded", "unit.restart", false),
		finding("kernel.rp-filter", "sysctl.ensure", false),
		finding("ssh.root-login", "ssh.config.apply", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range first.Steps {
		if first.Steps[i].CheckID != second.Steps[i].CheckID {
			t.Fatalf("different order: %s vs %s", first.Steps[i].CheckID, second.Steps[i].CheckID)
		}
	}
}

// The current step is the first unsettled one - that is where the plan waits.
func TestTheCurrentStepAndTheProgress(t *testing.T) {
	plan := Plan{Steps: []Step{
		{CheckID: "a", State: StepSucceeded},
		{CheckID: "b", State: StepRunning},
		{CheckID: "c", State: StepPending},
	}}
	if current := plan.Current(); current == nil || current.CheckID != "b" {
		t.Fatalf("current = %+v", plan.Current())
	}
	if progress := plan.Progress(); progress[StepSucceeded] != 1 || progress[StepPending] != 1 {
		t.Errorf("progress = %v", progress)
	}

	settled := Plan{Steps: []Step{{State: StepSucceeded}, {State: StepSkipped}}}
	if settled.Current() != nil {
		t.Error("a plan without open steps has a current step")
	}
}

// What the remediation runner declares a restart on. The host answering is not
// a restart by itself: before this, a plan with no identifier from before the
// change, or a host that reports none, finished the reboot step as done -
// the unknown read as the safe answer (audit of 6c38561, D8).
func TestTheRebootStepNeedsAnIdentifierOnBothSides(t *testing.T) {
	cases := []struct {
		name         string
		host         hosts.Host
		bootIDBefore string
		back         bool
	}{
		{name: "online with a new identifier", back: true, bootIDBefore: "boot-a",
			host: hosts.Host{ConnectionState: "online", BootID: "boot-b"}},
		{name: "online with the same identifier", bootIDBefore: "boot-a",
			host: hosts.Host{ConnectionState: "online", BootID: "boot-a"}},
		{name: "online reporting no identifier", bootIDBefore: "boot-a",
			host: hosts.Host{ConnectionState: "online"}},
		{name: "online with nothing held from before",
			host: hosts.Host{ConnectionState: "online", BootID: "boot-b"}},
		{name: "not answering at all", bootIDBefore: "boot-a",
			host: hosts.Host{ConnectionState: "offline", BootID: "boot-b"}},
	}
	for _, c := range cases {
		host := c.host
		back, reason := hostIsBack(&host, c.bootIDBefore)
		if back != c.back {
			t.Errorf("%s: the host reads as back=%v (%s), expected %v", c.name, back, reason, c.back)
		}
		if !back && reason == "" {
			t.Errorf("%s: the step is held back without saying why", c.name)
		}
	}
}
