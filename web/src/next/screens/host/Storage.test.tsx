import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Storage, byIdName, carriesData, destructiveRefusal, deviceInUse, hasStableIdentity, identity,
  isSnapshot, memberRefusal, mountOrder, mountPlanBinding, mountRows, mountpointWords,
  storageSuggestions, usageTone,
} from "./Storage";

/**
 * Storage is where the panel can destroy something, so the tests are
 * about what binds an order to a disk. /dev/sdX points at another disk
 * after a reboot, so nothing destructive is offered without a by-id link
 * and a WWN or a serial - and a mount is changed only against a plan the
 * host itself answered with.
 */

const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/jobs` must not answer
        // `/api/v1/jobs/job-1/attempts`.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1234abcd", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
} as unknown as Parameters<typeof Storage>[0]["host"];

const EVERYTHING = [
  "mount.ensure", "mount.remove", "filesystem.check", "filesystem.resize", "filesystem.create",
  "disk.wipe", "lvm.extend", "raid.member.fail", "raid.member.remove", "raid.member.add",
  "lvm.volume.create", "lvm.volume.remove", "lvm.group.extend", "lvm.snapshot.create",
  "lvm.snapshot.remove", "storage.plan", "storage.smart.read",
];

const allowed = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "destructive", allowed: true,
  })),
});

const disk = (over: Record<string, unknown>) => ({
  name: "sdb", path: "/dev/sdb", type: "disk", size_bytes: 500_000_000_000,
  by_id: "/dev/disk/by-id/ata-SAMSUNG_S1234", serial: "S1234", read_only: false,
  mountpoints: [], holders: [],
  ...over,
});

function base(payload: unknown, actions = allowed(...EVERYTHING)) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/inventory/storage": {
      host_id: "h1", module: "storage", revision: "abcdef123456", source: "agent",
      observed_at: "2026-10-16T08:00:00Z", payload,
    },
    "/api/v1/hosts/h1/actions": actions,
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Storage host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the storage of a host", () => {
  it("folds a filesystem mounted twice at one point into one row that says twice", async () => {
    base({
      devices: [],
      mounts: [
        { target: "/vagrant", source: "vagrant", fs_type: "vboxsf", mounted: true, in_fstab: false, managed: false },
        { target: "/vagrant", source: "vagrant", fs_type: "vboxsf", mounted: true, in_fstab: false, managed: false },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("mount-/vagrant")).toBeInTheDocument());
    expect(screen.getAllByTestId("mount-/vagrant")).toHaveLength(1);
    expect(screen.getByTestId("mount-/vagrant")).toHaveTextContent("×2");
  });

  it("says an unreported usage is unknown, never nought per cent", async () => {
    base({
      devices: [],
      mounts: [
        { target: "/srv/nfs", source: "nas:/srv", fs_type: "nfs4", mounted: true, in_fstab: true, managed: false },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("mount-/srv/nfs")).toBeInTheDocument());
    const row = screen.getByTestId("mount-/srv/nfs");
    // A network filesystem may report no inode count at all, and a disk
    // at nought per cent is a disk with room.
    expect(within(row).getAllByText("unknown").length).toBeGreaterThan(0);
    expect(within(row).queryByText("0%")).toBeNull();
  });

  it("will not offer to format a disk nothing can identify after a reboot", async () => {
    base({
      mounts: [],
      devices: [disk({ by_id: undefined, serial: undefined, identity_unavailable_reason: "udev names no link" })],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("device-/dev/sdb")).toBeInTheDocument());
    const row = screen.getByTestId("device-/dev/sdb");
    expect(within(row).getByText(/format refused/)).toBeInTheDocument();
    expect(screen.queryByTestId("format-/dev/sdb")).toBeNull();
    expect(within(row).getByText("no stable identity")).toBeInTheDocument();
  });

  it("carries the disk's identity into a format, never only its path", async () => {
    base({ mounts: [], devices: [disk({ wwn: "0x5002538e40a1b2c3" })] });
    draw();
    await waitFor(() => expect(screen.getByTestId("format-/dev/sdb")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("format-/dev/sdb"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "rebuilding the data disk" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "filesystem.create",
      reason: "rebuilding the data disk",
      payload: {
        storage: {
          device: "/dev/sdb",
          expected_by_id: "/dev/disk/by-id/ata-SAMSUNG_S1234",
          expected_wwn: "0x5002538e40a1b2c3",
          expected_serial: "S1234",
          fs_type: "ext4",
        },
      },
    });
  });

  it("asks the host to plan an unmount before it offers to confirm one", async () => {
    base({
      devices: [],
      mounts: [
        { target: "/srv/data", source: "UUID=1", fs_type: "ext4", mounted: true, in_fstab: true, managed: true },
      ],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("unmount-/srv/data")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("unmount-/srv/data"));
    await waitFor(() => expect(posted).toHaveLength(1));
    // The change binds to the digest of a plan the host answered with;
    // the confirmation is not even offered until that digest is here.
    expect(posted[0].body).toMatchObject({
      action: "storage.plan", payload: { storage: { target: "/srv/data" } },
    });
    expect(screen.queryByTestId("confirm-order")).toBeNull();
  });

  it("says what a host without LVM and without arrays is, rather than drawing nothing", async () => {
    base({
      devices: [], mounts: [],
      lvm_unavailable_reason: "lvm2 is not installed",
      raid_unavailable_reason: "mdadm is not installed",
    });
    draw();
    await waitFor(() => expect(screen.getByText(/No LVM here/)).toBeInTheDocument());
    expect(screen.getAllByText(/No software RAID here/).length).toBeGreaterThan(0);
    // Building and tearing down an array is not an operation on a running
    // fleet, and the module says so rather than leaving a missing button.
    expect(screen.getByText(/manages the members of an array that exists/)).toBeInTheDocument();
  });

  it("refuses to fail the last member that still carries the data", async () => {
    base({
      devices: [], mounts: [],
      arrays: [{
        name: "md0", path: "/dev/md0", uuid: "u-1", level: "raid1", raid_devices: 2,
        active_devices: 1, working_devices: 1, failed_devices: 1, spare_devices: 0,
        degraded: true, redundant: true,
        members: [
          { path: "/dev/sdc", role: "active", by_id: "/dev/disk/by-id/ata-A" },
        ],
      }],
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("members-md0")).toBeInTheDocument());
    // The array is already degraded, so spending the last copy is refused
    // here rather than on the host.
    expect(within(screen.getByTestId("members-md0")).getByText(/refused: array_redundancy_lost/)).toBeInTheDocument();
    expect(screen.queryByTestId("fail-/dev/sdc")).toBeNull();
  });

  it("says a host that has never reported its storage has not reported it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not reported its storage/)).toBeInTheDocument());
  });

  it("reads the whole picture back from the host on request", async () => {
    base({ devices: [], mounts: [] });
    draw();
    await waitFor(() => expect(screen.getByTestId("storage-read")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("storage-read"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({ action: "storage.plan", payload: { storage: {} } });
  });
});

describe("what the storage module works out on its own", () => {
  it("folds mounts by point, source and type", () => {
    const rows = mountRows([
      { target: "/a", source: "s", fs_type: "ext4", mounted: true, in_fstab: true, managed: false },
      { target: "/a", source: "s", fs_type: "ext4", mounted: true, in_fstab: true, managed: false },
      { target: "/b", source: "s", fs_type: "ext4", mounted: true, in_fstab: true, managed: false },
    ]);
    expect(rows).toHaveLength(2);
    expect(rows[0].times).toBe(2);
  });

  it("knows a disk is in use when something under it is mounted", () => {
    const parent = disk({ mountpoints: [] });
    const child = disk({ name: "sdb1", path: "/dev/sdb1", parent: "sdb", mountpoints: ["/srv"] });
    expect(deviceInUse(parent, [parent, child])).toBe(true);
    expect(deviceInUse(disk({}), [disk({})])).toBe(false);
  });

  it("refuses a destructive order on a disk with nothing durable to bind to", () => {
    expect(hasStableIdentity(disk({ by_id: undefined }))).toBe(false);
    // A by-id link that is only a path is not an identity either.
    expect(hasStableIdentity(disk({ by_id: "/dev/disk/by-id/wwn-x", serial: undefined, wwn: undefined }))).toBe(false);
    expect(hasStableIdentity(disk({}))).toBe(true);
    expect(destructiveRefusal(disk({ root_device: true }), [])?.code).toBe("disk_in_use");
    expect(destructiveRefusal(disk({ holders: ["dm-0"] }), [])?.code).toBe("disk_in_use");
    expect(destructiveRefusal(disk({}), [])).toBeNull();
  });

  it("names the reason an array member may not be touched", () => {
    const array = {
      name: "md0", path: "/dev/md0", uuid: "u", level: "raid1", raid_devices: 2, active_devices: 2,
      working_devices: 2, failed_devices: 0, spare_devices: 0, degraded: false, redundant: true,
    };
    const member = { path: "/dev/sdc", role: "active", by_id: "/dev/disk/by-id/ata-A" };
    expect(memberRefusal(array, member, true)).toBeNull();
    expect(memberRefusal({ ...array, uuid: undefined }, member, true)?.code).toBe("array_unknown");
    expect(memberRefusal({ ...array, redundant: false }, member, true)?.code).toBe("array_redundancy_lost");
    expect(memberRefusal({ ...array, sync_action: "recovery" }, member, true)?.code).toBe("array_rebuilding");
    expect(memberRefusal(array, { ...member, by_id: undefined }, true)?.code).toBe("stable_identity_required");
    // A spare carries no copy, so taking it out costs nothing.
    expect(carriesData({ path: "/dev/sdd", role: "spare" })).toBe(false);
    expect(carriesData(member)).toBe(true);
  });

  it("tells a snapshot from a volume by its origin or its attributes", () => {
    expect(isSnapshot({ name: "s", group: "vg", path: "/dev/vg/s", size_bytes: 1, origin: "root" })).toBe(true);
    expect(isSnapshot({ name: "s", group: "vg", path: "/dev/vg/s", size_bytes: 1, attributes: "swi-a-s---" })).toBe(true);
    expect(isSnapshot({ name: "r", group: "vg", path: "/dev/vg/r", size_bytes: 1, attributes: "-wi-ao----" })).toBe(false);
  });

  it("has no tone for a share nobody reported", () => {
    expect(usageTone(undefined, 100)).toBeUndefined();
    expect(usageTone(50, 0)).toBeUndefined();
    expect(usageTone(95, 100)).toBe("error");
    expect(usageTone(85, 100)).toBe("warn");
    expect(usageTone(10, 100)).toBe("ok");
  });

  it("binds a mount plan to the values it was computed for", () => {
    const values = { source: "UUID=1", target: "/srv", fs_type: "ext4", options: "defaults", persist: true };
    expect(mountOrder(values)).not.toBe(mountOrder({ ...values, target: "/srv2" }));
    expect(mountPlanBinding({ kind: "mount_plan", plan_hash: "abc", plan: {} })).toEqual({ hash: "abc", plan: {} });
    // Anything that is not a mount plan binds to nothing.
    expect(mountPlanBinding({ kind: "smart", plan_hash: "abc" })).toBeNull();
    expect(mountPlanBinding({ kind: "mount_plan" })).toBeNull();
  });

  it("offers the host's own paths to the fields of an order", () => {
    const suggestions = storageSuggestions({
      devices: [disk({})],
      volumes: [{ name: "root", group: "vg", path: "/dev/vg/root", size_bytes: 1 }],
      groups: [{ name: "vg", size_bytes: 1, free_bytes: 0, lv_count: 1 }],
      arrays: [],
    });
    expect(suggestions.device).toEqual(["/dev/sdb", "/dev/vg/root"]);
    expect(suggestions.group).toEqual(["vg"]);
  });

  it("reads a mount point the way an operator says it", () => {
    expect(mountpointWords("[SWAP]")).toBe("swap");
    expect(mountpointWords("/srv")).toBe("/srv");
    expect(byIdName(disk({}))).toBe("ata-SAMSUNG_S1234");
    expect(byIdName(disk({ by_id: undefined }))).toBe("");
  });

  it("sends an empty string rather than nothing for an identity the host did not give", () => {
    expect(identity(disk({ wwn: undefined, uuid: undefined }))).toEqual({
      device: "/dev/sdb",
      expected_by_id: "/dev/disk/by-id/ata-SAMSUNG_S1234",
      expected_wwn: "",
      expected_serial: "S1234",
      expected_uuid: "",
    });
  });
});
