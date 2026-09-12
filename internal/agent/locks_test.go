package agent

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/opspec"
)

func unitEnvelope(id, unit string) *agentv1.TaskEnvelope {
	return &agentv1.TaskEnvelope{
		TaskId: id,
		Action: &agentv1.TaskEnvelope_UnitAction{
			UnitAction: &agentv1.UnitAction{
				Operation: agentv1.UnitAction_OPERATION_RESTART, Unit: unit,
			},
		},
	}
}

// TestCollidingMutationsAreSerialized guards the property these locks exist
// for: two changes of the same resource must not run side by side, even when
// both fit within the task limit of the host.
func TestCollidingMutationsAreSerialized(t *testing.T) {
	l := newLocks()
	ctx := context.Background()

	first, reason := l.acquire(ctx, "task-1", "unit.restart", []string{"units"})
	if first == nil {
		t.Fatalf("the first task did not get the resource: %s", reason)
	}

	second := make(chan struct{})
	go func() {
		release, _ := l.acquire(ctx, "task-2", "unit.stop", []string{"units"})
		if release != nil {
			release()
		}
		close(second)
	}()

	select {
	case <-second:
		t.Fatal("the second task entered a busy resource")
	case <-time.After(50 * time.Millisecond):
	}

	first()
	select {
	case <-second:
	case <-time.After(2 * time.Second):
		t.Fatal("the second task did not start after the resource was released")
	}
}

// TestDifferentResourcesRunSideBySide guards the other half of the same rule: a
// lock is to serialize collisions and not the whole host.
func TestDifferentResourcesRunSideBySide(t *testing.T) {
	l := newLocks()
	ctx := context.Background()

	network, _ := l.acquire(ctx, "task-1", "network.profile.apply", []string{"network"})
	if network == nil {
		t.Fatal("the network task did not get the resource")
	}
	defer network()

	packages, reason := l.acquire(ctx, "task-2", "packages.upgrade", []string{"packages"})
	if packages == nil {
		t.Fatalf("the package operation waited for the network: %s", reason)
	}
	packages()
}

// TestARestartTakesTheWholeHost guards a boundary that is not visible in the
// resource classes: a change that started right before a restart has no way of
// finishing.
func TestARestartTakesTheWholeHost(t *testing.T) {
	l := newLocks()
	ctx := context.Background()

	restart, _ := l.acquire(ctx, "task-1", "system.reboot", []string{HostClaim})
	if restart == nil {
		t.Fatal("the restart did not get the host")
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	other, reason := l.acquire(short, "task-2", "unit.restart", []string{"units"})
	if other != nil {
		t.Fatal("an operation entered next to a restart of the host in progress")
	}
	if !strings.Contains(reason, "system.reboot") {
		t.Errorf("the refusal does not name the blocking operation: %q", reason)
	}
	restart()
}

// TestTheHostWaitsForMutationsInFlight guards the same boundary from the other
// side.
func TestTheHostWaitsForMutationsInFlight(t *testing.T) {
	l := newLocks()
	ctx := context.Background()

	packages, _ := l.acquire(ctx, "task-1", "packages.upgrade", []string{"packages"})
	if packages == nil {
		t.Fatal("the package operation did not get the resource")
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	restart, reason := l.acquire(short, "task-2", "system.reboot", []string{HostClaim})
	if restart != nil {
		t.Fatal("the restart entered during a package transaction")
	}
	if !strings.Contains(reason, "packages") {
		t.Errorf("the refusal does not name the busy resource: %q", reason)
	}
	packages()
}

// TestAReadTakesNoResource guards that the locks concern mutations. Two state
// reads can run side by side, and their cost is limited by the task budget.
func TestAReadTakesNoResource(t *testing.T) {
	read := &agentv1.TaskEnvelope{
		TaskId: "read",
		Action: &agentv1.TaskEnvelope_ReadUnitStatus{
			ReadUnitStatus: &agentv1.ReadUnitStatus{Units: []string{"cron.service"}},
		},
	}
	if claims := taskClaims(read); len(claims) != 0 {
		t.Fatalf("the read takes the resources %v", claims)
	}
}

// TestAUnitMutationTakesTheResourceClass guards that the claims come from the
// operation registry and not from a separate list inside the agent.
func TestAUnitMutationTakesTheResourceClass(t *testing.T) {
	claims := taskClaims(unitEnvelope("task", "cron.service"))
	if len(claims) != 1 || claims[0] != "units" {
		t.Fatalf("claims = %v", claims)
	}
}

// TestAKernelChangeAlsoTakesTheNetwork guards a dependency that is not visible
// in the resource class: sysctl reconfigures the network stack, so it must not
// run in parallel with an address change.
func TestAKernelChangeAlsoTakesTheNetwork(t *testing.T) {
	sysctl := &agentv1.TaskEnvelope{
		TaskId: "sysctl",
		Action: &agentv1.TaskEnvelope_Kernel{
			Kernel: &agentv1.KernelAction{
				Operation: agentv1.KernelAction_OPERATION_SYSCTL_ENSURE,
				Settings:  map[string]string{"net.ipv4.ip_forward": "1"},
			},
		},
	}
	claims := taskClaims(sysctl)
	if len(claims) != 2 || claims[0] != "kernel" || claims[1] != "network" {
		t.Fatalf("claims = %v", claims)
	}
}

// TestFilesAreSeparateResources guards that two changes of different files have
// no reason to wait for each other, while two changes of the same file do.
func TestFilesAreSeparateResources(t *testing.T) {
	file := func(path string) *agentv1.TaskEnvelope {
		return &agentv1.TaskEnvelope{
			TaskId: "file-" + path,
			Action: &agentv1.TaskEnvelope_File{
				File: &agentv1.FileAction{
					Operation: agentv1.FileAction_OPERATION_ENSURE,
					Path:      path, Content: []byte("x"), Mode: "0644",
				},
			},
		}
	}
	first := taskClaims(file("/etc/a.conf"))
	second := taskClaims(file("/etc/b.conf"))
	if len(first) != 1 || first[0] != "file:/etc/a.conf" {
		t.Fatalf("the claims of the first file = %v", first)
	}
	if len(second) != 1 || second[0] != "file:/etc/b.conf" {
		t.Fatalf("the claims of the second file = %v", second)
	}
}

// TestTheRepairPayloadHashesTheSameAsInThePanel guards the property that joins
// the panel with the agent: the envelope has to reproduce exactly the payload
// the panel computed the plan hash from. An empty list is written differently in
// JSON than a missing one, so a repair without answers used to end in a
// payload_hash_mismatch refusal.
func TestTheRepairPayloadHashesTheSameAsInThePanel(t *testing.T) {
	inThePanel := opspec.Payload{PackageRepair: &opspec.PackageRepairPayload{}}
	expected, err := opspec.PayloadHash(opspec.ActionPackageRepair, opspec.ActionVersion, inThePanel)
	if err != nil {
		t.Fatal(err)
	}

	envelope := &agentv1.TaskEnvelope{
		TaskId: "repair",
		Action: &agentv1.TaskEnvelope_PackagesRepair{
			PackagesRepair: &agentv1.PackagesRepair{},
		},
	}
	action, payload, err := decodeAction(envelope)
	if err != nil {
		t.Fatalf("decoding the envelope: %v", err)
	}
	atTheAgent, err := opspec.PayloadHash(action, opspec.ActionVersion, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, atTheAgent) {
		t.Fatalf("the plan hash diverges: panel %x, agent %x", expected, atTheAgent)
	}
}
