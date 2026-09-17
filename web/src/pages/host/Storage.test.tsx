import { describe, expect, it } from "vitest";
import { byIdName, destructiveRefusal, deviceInUse, hasStableIdentity, identity, mountRows, mountpointWords } from "./Storage";

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
