package agent

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

func sysctlEnvelope(id, key, value string) *agentv1.TaskEnvelope {
	return &agentv1.TaskEnvelope{
		TaskId: id, IdempotencyKey: id,
		Action: &agentv1.TaskEnvelope_Kernel{Kernel: &agentv1.KernelAction{
			Operation: agentv1.KernelAction_OPERATION_SYSCTL_ENSURE,
			Settings:  map[string]string{key: value},
		}},
	}
}

// TestSimulatedHostCarriesOutDifferentChanges drives the real executor over a
// simulated host: two hosts take different keys and neither sees the other's.
func TestSimulatedHostCarriesOutDifferentChanges(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	facts := func() Facts {
		return Facts{Capabilities: Capabilities{{Name: CapKernel, Version: 1, Available: true}}}
	}
	run := func(host *SimulatedHost, task *agentv1.TaskEnvelope) *agentv1.TaskResult {
		executor, err := NewSimulatedExecutor(host, t.TempDir(), facts, log)
		if err != nil {
			t.Fatal(err)
		}
		return executor.Execute(context.Background(), task)
	}

	first, second := &SimulatedHost{}, &SimulatedHost{}
	if result := run(first, sysctlEnvelope("t1", "user.sim_h0001", "7")); result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("the change was not carried out: %v %s", result.GetStatus(), result.GetMessage())
	}
	if result := run(second, sysctlEnvelope("t2", "user.sim_h0002", "9")); result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("the change was not carried out: %v %s", result.GetStatus(), result.GetMessage())
	}
	if value, _ := first.Sysctl("user.sim_h0001"); value != "7" {
		t.Fatalf("the first host holds %q", value)
	}
	if _, found := first.Sysctl("user.sim_h0002"); found {
		t.Fatal("a key ordered for another host appeared on the first")
	}
}

func simulatedExecutor(t *testing.T, host *SimulatedHost, facts Facts) *TaskExecutor {
	t.Helper()
	executor, err := NewSimulatedExecutor(host, t.TempDir(), func() Facts { return facts },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func kernelFacts() Facts {
	return Facts{Capabilities: Capabilities{{Name: CapKernel, Version: 1, Available: true}}}
}

// A delivery repeated under the same idempotency key is answered from the
// journal: the host is not changed a second time.
func TestSimulatedHostDoesNotRepeatAChange(t *testing.T) {
	host := &SimulatedHost{}
	executor := simulatedExecutor(t, host, kernelFacts())
	first := sysctlEnvelope("t1", "user.sim_h0001", "7")
	if result := executor.Execute(context.Background(), first); result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("first delivery: %v %s", result.GetStatus(), result.GetMessage())
	}
	again := sysctlEnvelope("t2", "user.sim_h0001", "9")
	again.IdempotencyKey = first.IdempotencyKey
	result := executor.Execute(context.Background(), again)
	if !result.GetReplayed() {
		t.Fatalf("the repeated delivery was carried out again: %v", result.GetStatus())
	}
	if value, _ := host.Sysctl("user.sim_h0001"); value != "7" {
		t.Fatalf("the host holds %q after a repeated delivery", value)
	}
}

// A host without the kernel capability refuses the change before it touches
// anything, as a real one does.
func TestSimulatedHostWithoutTheCapabilityRefuses(t *testing.T) {
	host := &SimulatedHost{}
	executor := simulatedExecutor(t, host, Facts{})
	result := executor.Execute(context.Background(), sysctlEnvelope("t1", "user.sim_h0001", "7"))
	if result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatal("a host without the capability carried out the change")
	}
	if _, found := host.Sysctl("user.sim_h0001"); found {
		t.Fatal("the refused change reached the host")
	}
}

// Changes of different keys on one host do not wait for each other and none is lost.
func TestSimulatedHostTakesDifferentChangesTogether(t *testing.T) {
	host := &SimulatedHost{}
	executor := simulatedExecutor(t, host, kernelFacts())
	var group sync.WaitGroup
	statuses := make([]agentv1.TaskResult_Status, 8)
	for i := range statuses {
		group.Add(1)
		go func() {
			defer group.Done()
			id := "t" + strconv.Itoa(i)
			statuses[i] = executor.Execute(context.Background(),
				sysctlEnvelope(id, "user.sim_h"+strconv.Itoa(i), strconv.Itoa(i+1))).GetStatus()
		}()
	}
	group.Wait()
	for i, status := range statuses {
		if status != agentv1.TaskResult_STATUS_SUCCEEDED {
			t.Fatalf("change %d ended as %v", i, status)
		}
		if value, _ := host.Sysctl("user.sim_h" + strconv.Itoa(i)); value != strconv.Itoa(i+1) {
			t.Fatalf("key %d holds %q", i, value)
		}
	}
}

func TestSimulatedFactsOfAWorkingHostCarryTheKernelCapability(t *testing.T) {
	if !SimulatedFacts("h", "m", true).Capabilities.Satisfies(CapKernel) {
		t.Fatal("a working host cannot take kernel changes")
	}
	if SimulatedFacts("h", "m", false).Capabilities.Satisfies(CapKernel) {
		t.Fatal("an idle host claims the kernel capability")
	}
}

// A refresh of some modules on an agent with substituted facts reads the
// substitute, never the machine the process happens to run on.
func TestSubstitutedFactsAreNotRefreshedFromTheMachine(t *testing.T) {
	whole := func(context.Context) (Facts, error) { return Facts{Hostname: "simulated"}, nil }
	partial := func(context.Context, []string) (Facts, error) { return Facts{Hostname: "the-machine"}, nil }

	facts, err := scopedCollection(true, whole, partial)(context.Background(), []string{"kernel"})
	if err != nil || facts.Hostname != "simulated" {
		t.Fatalf("substituted facts: hostname %q, err %v", facts.Hostname, err)
	}
	facts, err = scopedCollection(false, whole, partial)(context.Background(), []string{"kernel"})
	if err != nil || facts.Hostname != "the-machine" {
		t.Fatalf("a real agent lost its partial refresh: hostname %q, err %v", facts.Hostname, err)
	}
}

func restartByName(id, name string) *agentv1.TaskEnvelope {
	return &agentv1.TaskEnvelope{
		TaskId: id, IdempotencyKey: id,
		Action: &agentv1.TaskEnvelope_DockerAction{DockerAction: &agentv1.DockerAction{
			Operation: agentv1.DockerAction_OPERATION_RESTART, ContainerName: name,
		}},
	}
}

// One order names a container; the host that has it restarts it, the host that has an
// engine but not the container refuses with container_not_found, and a host without an
// engine does not accept the order at all.
func TestSimulatedHostsAnswerAnOrderByNameEachForItself(t *testing.T) {
	facts := WithDocker(SimulatedFacts("h", "m", true), false)
	holder := &SimulatedHost{Containers: []SimulatedContainer{{ID: "a1b2c3d4e5f6", Name: "web", Image: "nginx", Running: true}}}
	if result := simulatedExecutor(t, holder, facts).Execute(context.Background(), restartByName("t1", "web")); result.GetStatus() != agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatalf("the holder did not restart it: %v %s %s", result.GetStatus(), result.GetErrorCode(), result.GetMessage())
	}
	if container, _ := holder.Container("web"); !container.Running {
		t.Fatal("the container is not running after the restart")
	}

	empty := &SimulatedHost{}
	result := simulatedExecutor(t, empty, facts).Execute(context.Background(), restartByName("t2", "web"))
	if result.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED || result.GetErrorCode() != "container_not_found" {
		t.Fatalf("a host without the container: %v %q", result.GetStatus(), result.GetErrorCode())
	}

	none := simulatedExecutor(t, &SimulatedHost{}, SimulatedFacts("h", "m", true)).Execute(context.Background(), restartByName("t3", "web"))
	if none.GetStatus() == agentv1.TaskResult_STATUS_SUCCEEDED {
		t.Fatal("a host without an engine carried out a container order")
	}
}

func TestSimulatedFactsWithDockerCarryTheCapabilityAndTheOriginalDoesNot(t *testing.T) {
	plain := SimulatedFacts("h", "m", true)
	withDocker := WithDocker(plain, false)
	if !withDocker.Capabilities.Satisfies(CapDocker) || plain.Capabilities.Satisfies(CapDocker) {
		t.Fatal("the docker capability is not exactly on the host that has an engine")
	}
}

func TestAnOldSimulatedAgentReportsDockerWithoutNamingContainers(t *testing.T) {
	facts := SimulatedFacts("h", "m", true)
	if !WithDocker(facts, false).Capabilities.Feature(CapDocker, "name_addressing") {
		t.Fatal("a current agent does not report that it resolves names")
	}
	old := WithDocker(facts, true).Capabilities
	if old.Feature(CapDocker, "name_addressing") || !old.Satisfies(CapDocker) {
		t.Fatal("an old agent has docker and does not resolve names")
	}
}
