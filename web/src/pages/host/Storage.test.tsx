import { describe, expect, it } from "vitest";
import { deviceInUse, mountRows, mountpointWords } from "./Storage";

/* The table folds a filesystem mounted twice at one point into one row,
   and a disk whose partitions are in use is not offered for formatting. */

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
