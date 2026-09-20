import { describe, expect, it } from "vitest";
import {
  byIdName, carriesData, destructiveRefusal, deviceInUse, hasStableIdentity, identity, isSnapshot,
  memberRefusal, mountOrder, mountPlanBinding, mountRows, mountpointWords,
} from "./Storage";

/* The table folds a filesystem mounted twice at one point into one row,
   a disk whose partitions are in use is not offered for formatting, and a
   disk without a stable identity is shown as refused with the reason. */

const mount = (target: string, source: string, fs_type = "ext4") => ({
  target, source, fs_type, in_fstab: true, mounted: true, managed: false,
});

describe("mountRows", () => {
  it("folds identical mounts at one point and counts them", () => {
    const rows = mountRows([mount("/srv", "srv", "vboxsf"), mount("/srv", "srv", "vboxsf"), mount("/", "/dev/sda2")]);
    expect(rows.map((row) => [row.mount.target, row.times])).toEqual([["/srv", 2], ["/", 1]]);
  });

  it("keeps two different sources at one point apart", () => {
    const rows = mountRows([mount("/mnt", "/dev/sdb1"), mount("/mnt", "/dev/sdc1")]);
    expect(rows).toHaveLength(2);
  });
});

describe("deviceInUse", () => {
  const disk = { name: "sda", path: "/dev/sda", type: "disk", size_bytes: 10, read_only: false };
  const part = { name: "sda2", path: "/dev/sda2", type: "part", size_bytes: 9, read_only: false, parent: "sda", mountpoints: ["/"] };
  const spare = { name: "sdb", path: "/dev/sdb", type: "disk", size_bytes: 10, read_only: false };

  it("counts a disk as in use when a partition under it is mounted", () => {
    expect(deviceInUse(disk, [disk, part, spare])).toBe(true);
    expect(deviceInUse(part, [disk, part, spare])).toBe(true);
  });

  it("leaves a disk with nothing on it free", () => {
    expect(deviceInUse(spare, [disk, part, spare])).toBe(false);
  });
});

describe("mountpointWords", () => {
  it("names swap and passes a path through", () => {
    expect(mountpointWords("[SWAP]")).toBe("swap");
    expect(mountpointWords("/var")).toBe("/var");
  });
});

describe("destructiveRefusal", () => {
  const spare = {
    name: "sdb", path: "/dev/sdb", type: "disk", size_bytes: 10, read_only: false,
    by_id: "/dev/disk/by-id/ata-VBOX_HARDDISK_VB1", serial: "VB1",
  };
  const nameless = { name: "sdc", path: "/dev/sdc", type: "disk", size_bytes: 10, read_only: false, identity_unavailable_reason: "no link" };
  const held = { ...spare, name: "sdd", path: "/dev/sdd", holders: ["dm-0"], has_open_holders: true };
  const system = { ...spare, name: "sda", path: "/dev/sda", root_device: true, has_mounted_children: true };
  const volume = { name: "vg-data", path: "/dev/mapper/vg-data", type: "lvm", size_bytes: 5, read_only: false, by_id: "/dev/disk/by-id/dm-uuid-LVM-abc" };
  const namedOnly = { ...volume, path: "/dev/mapper/vg-x", by_id: "/dev/disk/by-id/dm-name-vg-x" };

  it("offers a disk with a by-id link and a serial", () => {
    expect(destructiveRefusal(spare, [spare])).toBeNull();
    expect(hasStableIdentity(volume)).toBe(true);
    expect(byIdName(spare)).toBe("ata-VBOX_HARDDISK_VB1");
  });

  it("refuses a disk without a stable identity and says why", () => {
    expect(destructiveRefusal(nameless, [nameless])).toEqual({ code: "stable_identity_required", reason: "no link" });
    expect(destructiveRefusal(namedOnly, [namedOnly])?.code).toBe("stable_identity_required");
  });

  it("refuses the root disk and a disk held by a volume group", () => {
    expect(destructiveRefusal(system, [system])?.code).toBe("disk_in_use");
    expect(destructiveRefusal(held, [held])).toEqual({ code: "disk_in_use", reason: "held by dm-0" });
  });

  it("sends the identity without the size", () => {
    const payload = identity(spare);
    expect(payload).toEqual({
      device: "/dev/sdb", expected_by_id: "/dev/disk/by-id/ata-VBOX_HARDDISK_VB1", expected_wwn: "", expected_serial: "VB1", expected_uuid: "",
    });
    expect(payload).not.toHaveProperty("expected_size_bytes");
  });
});

/* The array rows: what the panel offers on a member and what it refuses
   before the host is asked. The rule is the host's own - an array without
   a UUID binds nothing, a member without a by-id link binds nothing, and a
   member that still carries data is not taken out of an array that has
   nothing left to lose. */

const healthy = {
  name: "md0", path: "/dev/md0", uuid: "aaaa:bbbb:cccc:dddd", level: "raid1", state: "clean",
  raid_devices: 2, active_devices: 2, working_devices: 2, failed_devices: 0, spare_devices: 0,
  degraded: false, redundant: true,
};
const member = { path: "/dev/sdb1", role: "active", by_id: "/dev/disk/by-id/ata-VB1", slot: 0 };

describe("memberRefusal", () => {
  it("offers a member of a healthy redundant array", () => {
    expect(memberRefusal(healthy, member, true)).toBeNull();
  });

  it("refuses an array the host gave no UUID", () => {
    const nameless = { ...healthy, uuid: undefined, detail_unavailable_reason: "this host has no mdadm" };
    expect(memberRefusal(nameless, member, true)).toEqual({
      code: "array_unknown", reason: "this host has no mdadm",
    });
  });

  it("refuses a member without a stable identity", () => {
    const nameless = { ...member, by_id: undefined, identity_unavailable_reason: "no link" };
    expect(memberRefusal(healthy, nameless, true)).toEqual({
      code: "stable_identity_required", reason: "no link",
    });
  });

  it("refuses to spend the last copy of the data", () => {
    expect(memberRefusal({ ...healthy, level: "raid0", redundant: false }, member, true)?.code)
      .toBe("array_redundancy_lost");
    expect(memberRefusal({ ...healthy, degraded: true, active_devices: 1 }, member, true)?.code)
      .toBe("array_redundancy_lost");
    expect(memberRefusal({ ...healthy, sync_action: "recovery" }, member, true)?.code)
      .toBe("array_rebuilding");
  });

  it("lets a spare go from an array that has nothing to lose by it", () => {
    const spare = { ...member, role: "spare" };
    expect(carriesData(spare)).toBe(false);
    expect(memberRefusal({ ...healthy, degraded: true }, spare, carriesData(spare))).toBeNull();
  });
});

describe("carriesData", () => {
  it("counts the roles that hold a copy and no others", () => {
    expect(carriesData({ path: "/dev/sdb1", role: "active" })).toBe(true);
    expect(carriesData({ path: "/dev/sdb1", role: "rebuilding" })).toBe(true);
    expect(carriesData({ path: "/dev/sdb1", role: "faulty" })).toBe(false);
    expect(carriesData({ path: "", role: "removed" })).toBe(false);
  });
});

describe("isSnapshot", () => {
  it("reads the origin and the first letter of lv_attr", () => {
    expect(isSnapshot({ name: "snap", group: "vg0", path: "/dev/vg0/snap", size_bytes: 1, origin: "data" })).toBe(true);
    expect(isSnapshot({ name: "snap", group: "vg0", path: "/dev/vg0/snap", size_bytes: 1, attributes: "swi-a-s---" })).toBe(true);
    expect(isSnapshot({ name: "data", group: "vg0", path: "/dev/vg0/data", size_bytes: 1, attributes: "-wi-ao----" })).toBe(false);
    expect(isSnapshot({ name: "data", group: "vg0", path: "/dev/vg0/data", size_bytes: 1 })).toBe(false);
  });
});

describe("mountPlanBinding", () => {
  const values = { source: "UUID=abc", target: "/srv/data", fs_type: "ext4", options: "defaults", persist: true };

  it("reads the digest of a mount plan and nothing else", () => {
    expect(mountPlanBinding({ kind: "mount_plan", plan_hash: "abc123", plan: { action: "create" } }))
      .toEqual({ hash: "abc123", plan: { action: "create" } });
    expect(mountPlanBinding({ kind: "device_plan", plan_hash: "abc123" })).toBeNull();
    expect(mountPlanBinding({ kind: "mount_plan" })).toBeNull();
    expect(mountPlanBinding(undefined)).toBeNull();
  });

  it("keeps a refusal, which the wizard reads before it offers the change", () => {
    const binding = mountPlanBinding({ kind: "mount_plan", plan_hash: "abc123", plan: { refusal: "the target /srv/data is taken by /dev/sdc1" } });
    expect(binding?.plan.refusal).toContain("/dev/sdc1");
  });

  it("ties the plan to the values it was computed for", () => {
    expect(mountOrder(values)).toBe(mountOrder({ ...values }));
    expect(mountOrder({ ...values, source: "UUID=def" })).not.toBe(mountOrder(values));
    expect(mountOrder({ ...values, persist: false })).not.toBe(mountOrder(values));
    expect(mountOrder({ ...values, options: "defaults,ro" })).not.toBe(mountOrder(values));
  });
});
