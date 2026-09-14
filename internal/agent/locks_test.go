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

// exclusiveOn and sharedOn build claims the way the contract declares
// them, so the tests read as the operations they stand for.
func exclusiveOn(class string) []opspec.ResourceClaim {
	return []opspec.ResourceClaim{{Class: class, Mode: opspec.ClaimExclusive, Weight: 1}}
}

func sharedOn(class string, weight int) []opspec.ResourceClaim {
	return []opspec.ResourceClaim{{Class: class, Mode: opspec.ClaimShared, Weight: weight}}
}

// classesOf lists the classes of the claims, in their order.
func classesOf(claims []opspec.ResourceClaim) []string {
	return claimNames(claims)
}

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

	first, reason := l.acquire(ctx, "task-1", "unit.restart", exclusiveOn("units"))
	if first == nil {
		t.Fatalf("the first task did not get the resource: %s", reason)
	}

	second := make(chan struct{})
	go func() {
		release, _ := l.acquire(ctx, "task-2", "unit.stop", exclusiveOn("units"))
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

	network, _ := l.acquire(ctx, "task-1", "network.profile.apply", exclusiveOn("network"))
	if network == nil {
		t.Fatal("the network task did not get the resource")
	}
	defer network()

	packages, reason := l.acquire(ctx, "task-2", "packages.upgrade", exclusiveOn("packages"))
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

	restart, _ := l.acquire(ctx, "task-1", "system.reboot", exclusiveOn(HostClaim))
	if restart == nil {
		t.Fatal("the restart did not get the host")
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	other, reason := l.acquire(short, "task-2", "unit.restart", exclusiveOn("units"))
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

	packages, _ := l.acquire(ctx, "task-1", "packages.upgrade", exclusiveOn("packages"))
	if packages == nil {
		t.Fatal("the package operation did not get the resource")
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	restart, reason := l.acquire(short, "task-2", "system.reboot", exclusiveOn(HostClaim))
	if restart != nil {
		t.Fatal("the restart entered during a package transaction")
	}
	if !strings.Contains(reason, "packages") {
		t.Errorf("the refusal does not name the busy resource: %q", reason)
	}
	packages()
}

// TestAReadWithoutAContractClaimTakesNoResource guards that a read whose
// contract lists nothing takes nothing: a unit status read has no lock
// class and costs the host nothing worth rationing, so its cost is
// limited by the task budget alone.
func TestAReadWithoutAContractClaimTakesNoResource(t *testing.T) {
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

// TestAReadTakesTheSharedClaimsOfItsContract guards the other kind of
// read: the journal read takes the logs class shared with the weight the
// contract gives it, and a package plan takes the package class shared -
// so that it does not run under a package transaction, and a package
// transaction does not start under it.
func TestAReadTakesTheSharedClaimsOfItsContract(t *testing.T) {
	journal := &agentv1.TaskEnvelope{
		TaskId: "journal",
		Action: &agentv1.TaskEnvelope_ReadJournal{
			ReadJournal: &agentv1.ReadJournal{Unit: "cron.service", Lines: 10},
		},
	}
	claims := taskClaims(journal)
	if len(claims) != 1 || claims[0].Class != opspec.ClaimLogsRead || claims[0].Mode != opspec.ClaimShared || claims[0].Weight != 1 {
		t.Fatalf("the journal read takes %+v", claims)
	}

	plan := &agentv1.TaskEnvelope{
		TaskId: "plan",
		Action: &agentv1.TaskEnvelope_PackagePlan{PackagePlan: &agentv1.PackagePlan{}},
	}
	claims = taskClaims(plan)
	if len(claims) != 1 || claims[0].Class != opspec.LockPackages || claims[0].Mode != opspec.ClaimShared {
		t.Fatalf("the package plan takes %+v", claims)
	}
}

// TestAUnitMutationTakesTheResourceClass guards that the claims come from the
// operation contract and not from a separate list inside the agent.
func TestAUnitMutationTakesTheResourceClass(t *testing.T) {
	claims := taskClaims(unitEnvelope("task", "cron.service"))
	if len(claims) != 1 || claims[0].Class != "units" || claims[0].Mode != opspec.ClaimExclusive {
		t.Fatalf("claims = %+v", claims)
	}
}

// TestTheClaimsOfEveryOperationAreTheContractsOwn guards the source of
// the claims: for every operation the agent binds the classes the
// contract declares, the file class to the path, and nothing of its own.
func TestTheClaimsOfEveryOperationAreTheContractsOwn(t *testing.T) {
	reboot := &agentv1.TaskEnvelope{
		TaskId: "reboot",
		Action: &agentv1.TaskEnvelope_SystemReboot{SystemReboot: &agentv1.SystemReboot{}},
	}
	if got := classesOf(taskClaims(reboot)); len(got) != 1 || got[0] != HostClaim {
		t.Errorf("a reboot takes %v, expected the host", got)
	}
	upgrade := &agentv1.TaskEnvelope{
		TaskId: "upgrade",
		Action: &agentv1.TaskEnvelope_PackageUpgrade{PackageUpgrade: &agentv1.PackageUpgrade{}},
	}
	claims := taskClaims(upgrade)
	want := opspec.ActionPackageUpgrade.Contract().ResourceClaims
	if len(claims) != 1 || len(want) != 1 || claims[0] != want[0] {
		t.Fatalf("a package upgrade takes %+v, the contract declares %+v", claims, want)
	}
	if claims[0].Weight != 4 || claims[0].Mode != opspec.ClaimExclusive {
		t.Errorf("the package upgrade takes %+v; the contract says exclusive with the weight 4", claims[0])
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
	claims := classesOf(taskClaims(sysctl))
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
	first := classesOf(taskClaims(file("/etc/a.conf")))
	second := classesOf(taskClaims(file("/etc/b.conf")))
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

// TestAWaitingTaskNamesItsBlocker guards what the panel shows under a host
// that has not started: the wait is reported the moment the task finds
// the resource busy, the report names the resource and the task holding
// it, and a task that finds its resources free reports no wait at all.
func TestAWaitingTaskNamesItsBlocker(t *testing.T) {
	l := newLocks()
	ctx := context.Background()

	var free []string
	release, reason := l.acquireReporting(ctx, "task-1", "unit.restart", exclusiveOn("units"),
		func(blocker string) { free = append(free, blocker) })
	if release == nil {
		t.Fatalf("the first task did not get the resource: %s", reason)
	}
	if len(free) != 0 {
		t.Errorf("a task that got its resource at once reported a wait: %v", free)
	}

	reported := make(chan string, 8)
	entered := make(chan struct{})
	go func() {
		release, _ := l.acquireReporting(ctx, "task-2", "unit.stop", exclusiveOn("units"),
			func(blocker string) { reported <- blocker })
		if release != nil {
			release()
		}
		close(entered)
	}()

	select {
	case blocker := <-reported:
		if blocker != "units held by task task-1 (unit.restart)" {
			t.Errorf("the blocker is described as %q", blocker)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the wait was not reported when the resource was found busy")
	}
	select {
	case <-entered:
		t.Fatal("the second task entered a busy resource")
	case <-time.After(50 * time.Millisecond):
	}
	// One report per ten seconds: a release that changes nothing for the
	// waiter does not produce a second one right away.
	if len(reported) != 0 {
		t.Errorf("%d extra reports within the interval", len(reported))
	}

	release()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the second task did not start after the resource was released")
	}
}

// TestAWaitThatEndsIsRefusedWithTheHolder: the bounded wait of a task ends
// with a refusal naming what held it, and the refusal text is the one the
// result carries - distinct from the wait report.
func TestAWaitThatEndsIsRefusedWithTheHolder(t *testing.T) {
	l := newLocks()
	release, _ := l.acquire(context.Background(), "task-1", "unit.restart", exclusiveOn("units"))
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var waits int
	got, reason := l.acquireReporting(ctx, "task-2", "unit.stop", exclusiveOn("units"),
		func(string) { waits++ })
	if got != nil {
		t.Fatal("the second task got a busy resource")
	}
	if waits != 1 {
		t.Errorf("%d wait reports for a wait shorter than the interval, expected one", waits)
	}
	if !strings.Contains(reason, "units") || !strings.Contains(reason, "task-1") || !strings.Contains(reason, "unit.restart") {
		t.Errorf("the refusal does not name the holder: %q", reason)
	}
}

// enters says whether a claim set is taken at once: the wait is given a
// short limit and the answer is whether it ended with a release.
func enters(t *testing.T, l *locks, task, operation string, claims []opspec.ResourceClaim) (func(), string) {
	t.Helper()
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	return l.acquire(short, task, operation, claims)
}

// TestSharedClaimsCoexist guards the point of a shared claim: two reads of
// the journal, and two reads of the package database, run side by side
// on the same class, and each gives back only its own place.
func TestSharedClaimsCoexist(t *testing.T) {
	l := newLocks()

	first, reason := enters(t, l, "read-1", "journal.read", sharedOn(opspec.ClaimLogsRead, 1))
	if first == nil {
		t.Fatalf("the first read did not get the class: %s", reason)
	}
	second, reason := enters(t, l, "read-2", "journal.follow", sharedOn(opspec.ClaimLogsRead, 1))
	if second == nil {
		t.Fatalf("the second read waited for the first: %s", reason)
	}
	// A class without a capacity - a lock class read shared - has no
	// count at all.
	plan, reason := enters(t, l, "plan-1", "packages.plan", sharedOn(opspec.LockPackages, 1))
	if plan == nil {
		t.Fatalf("a shared read of the package class waited: %s", reason)
	}
	list, reason := enters(t, l, "plan-2", "packages.list", sharedOn(opspec.LockPackages, 1))
	if list == nil {
		t.Fatalf("two shared reads of the package class did not coexist: %s", reason)
	}

	// Releasing one reader leaves the other in place: an exclusive claim
	// still waits.
	first()
	if got, _ := enters(t, l, "upgrade", "packages.upgrade", exclusiveOn(opspec.LockPackages)); got != nil {
		got()
		t.Fatal("an exclusive claim entered a class still read by another task")
	}
	plan()
	list()
	if got, reason := enters(t, l, "upgrade", "packages.upgrade", exclusiveOn(opspec.LockPackages)); got == nil {
		t.Fatalf("the exclusive claim did not enter once every reader left: %s", reason)
	} else {
		got()
	}
	second()
}

// TestSharedAndExclusiveClaimsExcludeEachOther guards both directions:
// a package upgrade waits for a package plan still reading the database,
// and a package plan waits for an upgrade under way - the read would
// otherwise describe a state that is changing under it.
func TestSharedAndExclusiveClaimsExcludeEachOther(t *testing.T) {
	l := newLocks()

	reading, _ := enters(t, l, "plan", "packages.plan", sharedOn(opspec.LockPackages, 1))
	if reading == nil {
		t.Fatal("the read did not get the class")
	}
	blocked, reason := enters(t, l, "upgrade", "packages.upgrade", exclusiveOn(opspec.LockPackages))
	if blocked != nil {
		blocked()
		t.Fatal("the upgrade entered under a read of the package database")
	}
	if !strings.Contains(reason, "packages") || !strings.Contains(reason, "packages.plan") || !strings.Contains(reason, "plan") {
		t.Errorf("the refusal does not name the reader holding the class: %q", reason)
	}
	reading()

	writing, reason := enters(t, l, "upgrade", "packages.upgrade", exclusiveOn(opspec.LockPackages))
	if writing == nil {
		t.Fatalf("the upgrade did not enter after the read ended: %s", reason)
	}
	entered := make(chan struct{})
	go func() {
		release, _ := l.acquire(context.Background(), "plan-2", "packages.plan", sharedOn(opspec.LockPackages, 1))
		if release != nil {
			release()
		}
		close(entered)
	}()
	select {
	case <-entered:
		t.Fatal("a read entered under an upgrade of the package database")
	case <-time.After(50 * time.Millisecond):
	}
	writing()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the read did not enter after the upgrade released the class")
	}
}

// TestWeightsAddUpAgainstTheCapacity guards the ration of a shared class:
// the logs class carries four at once, so readers enter while their
// weights fit and the one that would exceed the capacity waits for a
// release - and a claim heavier than the whole capacity still gets an
// empty class rather than waiting for ever.
func TestWeightsAddUpAgainstTheCapacity(t *testing.T) {
	if opspec.SharedCapacity(opspec.ClaimLogsRead) != 4 || opspec.SharedCapacity(opspec.ClaimInventoryHeavy) != 2 {
		t.Fatalf("the capacities are logs %d and inventory %d; the test assumes 4 and 2",
			opspec.SharedCapacity(opspec.ClaimLogsRead), opspec.SharedCapacity(opspec.ClaimInventoryHeavy))
	}
	l := newLocks()

	heavy, _ := enters(t, l, "follow", "journal.follow", sharedOn(opspec.ClaimLogsRead, 3))
	if heavy == nil {
		t.Fatal("the first reader did not get the class")
	}
	light, _ := enters(t, l, "read", "journal.read", sharedOn(opspec.ClaimLogsRead, 1))
	if light == nil {
		t.Fatal("a reader that fits the remaining capacity waited")
	}
	over, reason := enters(t, l, "logfile", "logfile.read", sharedOn(opspec.ClaimLogsRead, 1))
	if over != nil {
		over()
		t.Fatal("a reader entered a class already at its capacity")
	}
	if !strings.Contains(reason, opspec.ClaimLogsRead) || !strings.Contains(reason, "follow") {
		t.Errorf("the refusal does not name the class and a holder: %q", reason)
	}
	light()
	fits, reason := enters(t, l, "logfile", "logfile.read", sharedOn(opspec.ClaimLogsRead, 1))
	if fits == nil {
		t.Fatalf("the reader did not enter once a weight was released: %s", reason)
	}
	fits()
	heavy()

	// The weight of a scan is counted on its own class: two scans fill
	// the inventory class, a third waits; the logs class is not touched.
	scan1, _ := enters(t, l, "scan-1", "process.list", sharedOn(opspec.ClaimInventoryHeavy, 1))
	scan2, _ := enters(t, l, "scan-2", "docker.read", sharedOn(opspec.ClaimInventoryHeavy, 1))
	if scan1 == nil || scan2 == nil {
		t.Fatal("two scans did not fill the inventory class together")
	}
	if third, _ := enters(t, l, "scan-3", "storage.plan", sharedOn(opspec.ClaimInventoryHeavy, 1)); third != nil {
		third()
		t.Fatal("a third scan entered a full inventory class")
	}
	if logs, _ := enters(t, l, "read", "journal.read", sharedOn(opspec.ClaimLogsRead, 1)); logs == nil {
		t.Fatal("a full inventory class kept a reader off the logs class")
	} else {
		logs()
	}
	scan1()
	scan2()

	// Heavier than the whole class: it enters an empty class, because
	// waiting for room that can never be there is not an answer.
	oversized, reason := enters(t, l, "big", "journal.follow", sharedOn(opspec.ClaimLogsRead, 9))
	if oversized == nil {
		t.Fatalf("a claim heavier than the capacity never entered an empty class: %s", reason)
	}
	oversized()
}
