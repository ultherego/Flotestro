package storage

import (
	"strings"
	"testing"
)

func snapshotWithDisk(uuid string, mounts ...Mount) Snapshot {
	return Snapshot{
		Devices: []Device{
			{Name: "sdb", Path: "/dev/sdb", Type: "disk", FSType: "ext4", UUID: uuid, SizeBytes: 2 << 30},
		},
		Mounts: mounts,
	}
}

// TestPlanResolvesSourceToHostUUID guards the essence of the per-host plan:
// the same path on two hosts is two different filesystems, and the change
// is meant to carry the one the host really has.
func TestPlanResolvesSourceToHostUUID(t *testing.T) {
	first := ComputeMount(snapshotWithDisk("aaaa-1111"), "/dev/sdb", "/mnt/data", "ext4", "", true)
	second := ComputeMount(snapshotWithDisk("bbbb-2222"), "/dev/sdb", "/mnt/data", "ext4", "", true)

	if first.ResolvedSource != "UUID=aaaa-1111" || second.ResolvedSource != "UUID=bbbb-2222" {
		t.Fatalf("sources resolved to %q and %q", first.ResolvedSource, second.ResolvedSource)
	}
	if first.Action != PlanCreate || second.Action != PlanCreate {
		t.Errorf("plans: %q, %q", first.Action, second.Action)
	}
	if first.PlanHash == second.PlanHash {
		t.Error("two different filesystems gave the same plan fingerprint")
	}
}

// TestPlanRefusesSourceWithoutUUID guards that a change with nothing to
// bind to is a refusal, not a mount by a path that points at a different
// disk after a reboot.
func TestPlanRefusesSourceWithoutUUID(t *testing.T) {
	plan := ComputeMount(snapshotWithDisk(""), "/dev/sdb", "/mnt/data", "ext4", "", true)
	if plan.Refusal == "" || !strings.Contains(plan.Refusal, "UUID") {
		t.Errorf("a filesystem without a UUID gave no refusal: %+v", plan)
	}
	missing := ComputeMount(Snapshot{}, "/dev/sdb", "/mnt/data", "ext4", "", true)
	if missing.Refusal == "" {
		t.Error("a non-existent source gave no refusal")
	}
}

// TestPlanRefusesTargetTakenByOtherFilesystem guards that a campaign does
// not quietly cover somebody else's mount.
func TestPlanRefusesTargetTakenByOtherFilesystem(t *testing.T) {
	state := snapshotWithDisk("aaaa-1111", Mount{
		Target: "/mnt/data", Source: "/dev/sdc", FSType: "xfs", Mounted: true,
	})
	plan := ComputeMount(state, "/dev/sdb", "/mnt/data", "ext4", "", true)
	if plan.Refusal == "" || !strings.Contains(plan.Refusal, "taken") {
		t.Errorf("a taken target gave no refusal: %+v", plan)
	}
}

// TestPlanSeesMissingFstabEntry guards the difference the operator comes
// here for: mounted now and mounted after a reboot are two questions.
func TestPlanSeesMissingFstabEntry(t *testing.T) {
	state := snapshotWithDisk("aaaa-1111", Mount{
		Target: "/mnt/data", Source: "UUID=aaaa-1111", FSType: "ext4", Mounted: true, InFstab: false,
	})
	plan := ComputeMount(state, "/dev/sdb", "/mnt/data", "ext4", "", true)
	if plan.Action != PlanUpdate {
		t.Fatalf("a mount without an entry has the plan %q", plan.Action)
	}
	if !containsChange(plan.Changes, "fstab") {
		t.Errorf("the plan does not name the missing entry: %+v", plan.Changes)
	}

	ready := snapshotWithDisk("aaaa-1111", Mount{
		Target: "/mnt/data", Source: "UUID=aaaa-1111", FSType: "ext4",
		Mounted: true, InFstab: true, FstabOptions: "defaults",
	})
	if plan := ComputeMount(ready, "/dev/sdb", "/mnt/data", "ext4", "", true); plan.Action != PlanNoChange {
		t.Errorf("a mount in the target state has the plan %q (%+v)", plan.Action, plan.Changes)
	}
}

// TestUnmountPlanDistinguishesExistingMount guards that removing something
// that does not exist is visible before approval.
func TestUnmountPlanDistinguishesExistingMount(t *testing.T) {
	present := ComputeUnmount(snapshotWithDisk("a", Mount{Target: "/mnt/data", Mounted: true, InFstab: true}), "/mnt/data")
	if present.Action != PlanRemove || len(present.Changes) != 2 {
		t.Errorf("the unmount has the plan %q (%+v)", present.Action, present.Changes)
	}
	absent := ComputeUnmount(snapshotWithDisk("a"), "/mnt/data")
	if absent.Action != PlanRemoveAbsent {
		t.Errorf("unmounting a non-existent mount has the plan %q", absent.Action)
	}
}

func containsChange(items []string, fragment string) bool {
	for _, item := range items {
		if strings.Contains(item, fragment) {
			return true
		}
	}
	return false
}

func TestRefusalChangesPlanFingerprint(t *testing.T) {
	state := Snapshot{Devices: []Device{{Path: "/dev/sdb", FSType: "ext4", UUID: "abc"}}}
	plan := ComputeMount(state, "/dev/sdb", "/mnt/data", "ext4", "", true)
	before := plan.PlanHash
	plan.Refuse("the filesystem is in use by: PID 1")
	if plan.Refusal == "" || plan.PlanHash == before || plan.PlanHash == "" {
		t.Errorf("the refusal did not change the fingerprint: before=%s after=%s", before, plan.PlanHash)
	}
}
