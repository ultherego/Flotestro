import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { awaitJob } from "../../../lib/jobs";
import { bytes } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import {
  emptyForm, operationForm, type FieldSuggestions, type FormValue,
} from "../../../lib/operations";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import { PlanBody } from "../Job";
import type { HostPlan, PackagePlanFacts } from "../../../components/plan";
import {
  Band, Banner, Bars, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Meter, Note,
  Pill, Readout, Table, Tag, Tags, TwoLine, type Segment, type Tone,
} from "../../kit";
import {
  Confirm, freshnessOf, Guard, JobLine, OperationFields, ReadOnlyNotice, useOrder, type Intent,
} from "./Power";

/**
 * The host's storage.
 *
 * Devices from the kernel, mounts from mountinfo, persistence from fstab
 * - kept apart on purpose: the file says what should be mounted after a
 * reboot, not what is mounted now. Everything destructive binds to an
 * identity that still means the same disk after a reboot, because
 * /dev/sdX does not.
 */

export type Device = {
  name: string;
  kernel_name?: string;
  path: string;
  type: string;
  size_bytes: number;
  fs_type?: string;
  label?: string;
  uuid?: string;
  model?: string;
  serial?: string;
  wwn?: string;
  /** The /dev/disk/by-id link: the identity a destructive operation binds to. */
  by_id?: string;
  identity_unavailable_reason?: string;
  parent?: string;
  children?: string[];
  /** Devices stacked on this one: a volume group, an array, an encrypted container. */
  holders?: string[];
  root_device?: boolean;
  has_mounted_children?: boolean;
  has_open_holders?: boolean;
  rotational?: boolean;
  read_only: boolean;
  mountpoints?: string[];
  fs_size_bytes?: number;
  fs_used_bytes?: number;
};

type Mount = {
  target: string;
  source: string;
  fs_type: string;
  options?: string;
  fstab_options?: string;
  in_fstab: boolean;
  mounted: boolean;
  managed: boolean;
  used_percent?: number;
  inodes_used_percent?: number;
  size_bytes?: number;
  avail_bytes?: number;
};

/** One volume group, with the identity an order inside it binds to. */
type VolumeGroup = {
  name: string;
  uuid?: string;
  size_bytes: number;
  free_bytes: number;
  extent_size_bytes?: number;
  lv_count: number;
};

type LogicalVolume = {
  name: string;
  group: string;
  path: string;
  uuid?: string;
  size_bytes: number;
  attributes?: string;
  origin?: string;
  data_percent?: number;
};

/** One disk or partition a group is built out of. */
type PhysicalVolume = {
  path: string;
  group?: string;
  uuid?: string;
  size_bytes: number;
  free_bytes: number;
};

type RAIDMember = {
  path: string;
  kernel_name?: string;
  slot?: number;
  number?: number;
  role: string;
  state?: string;
  by_id?: string;
  wwn?: string;
  serial?: string;
  identity_unavailable_reason?: string;
  size_bytes?: number;
};

type RAIDArray = {
  name: string;
  path: string;
  uuid?: string;
  level?: string;
  state?: string;
  metadata?: string;
  size_bytes?: number;
  raid_devices: number;
  active_devices: number;
  working_devices: number;
  failed_devices: number;
  spare_devices: number;
  degraded: boolean;
  redundant: boolean;
  sync_action?: string;
  sync_percent?: number;
  sync_finish?: string;
  sync_speed?: string;
  members?: RAIDMember[];
  detail_unavailable_reason?: string;
};

type Snapshot = {
  devices?: Device[];
  mounts?: Mount[];
  groups?: VolumeGroup[];
  volumes?: LogicalVolume[];
  physical_volumes?: PhysicalVolume[];
  arrays?: RAIDArray[];
  lvm_unavailable_reason?: string;
  raid_unavailable_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/** One row of the ATA attribute table, as smartctl reports it. */
type SmartAttribute = {
  id: number;
  name: string;
  value: number;
  worst: number;
  threshold: number;
  raw: number;
  raw_string?: string;
  failing?: boolean;
};

/**
 * The SMART report of one device. Every number is optional: a device that
 * does not report its temperature has none here, not a nought.
 */
type SmartResult = {
  kind?: string;
  device?: string;
  model?: string;
  serial?: string;
  health?: string;
  health_reason?: string;
  temperature_c?: number;
  power_on_hours?: number;
  reallocated_sectors?: number;
  pending_sectors?: number;
  wear_percent?: number;
  attributes?: SmartAttribute[];
  unsupported?: boolean;
  unsupported_reason?: string;
  output?: string;
};

/** One row of the mount table: a mount, and how many times it is mounted there. */
type MountRow = { mount: Mount; times: number };

/**
 * The mounts folded by mount point and source: a shared folder mounted
 * twice at the same path - what a provisioning tool does when it runs
 * again - is one row that says "twice", not two rows that read as two
 * different filesystems.
 */
export function mountRows(mounts: Mount[]): MountRow[] {
  const rows: MountRow[] = [];
  const seen = new Map<string, MountRow>();
  for (const mount of mounts) {
    const key = `${mount.target}\u0000${mount.source}\u0000${mount.fs_type}`;
    const known = seen.get(key);
    if (known) {
      known.times += 1;
      continue;
    }
    const row = { mount, times: 1 };
    seen.set(key, row);
    rows.push(row);
  }
  return rows;
}

/**
 * Whether anything sits on the device: its own mount points, or a
 * partition or volume under it that is mounted or used as swap.
 */
export function deviceInUse(device: Device, devices: Device[]): boolean {
  if ((device.mountpoints ?? []).length > 0) return true;
  return devices.some((other) =>
    other !== device && (other.parent === device.name || other.parent === device.path) && deviceInUse(other, devices));
}

/**
 * How deep a device sits in the disk -> partition -> volume topology.
 *
 * A flat list of block devices says nothing about what sits on what, and
 * the parent printed as a second line makes the reader rebuild the tree
 * in their head. The depth is what the table sets the row in by. A
 * parent is named either way round by lsblk, so both are followed, and
 * the walk is bounded in case a holder chain points back at itself.
 */
export function deviceDepth(device: Device, devices: Device[]): number {
  let depth = 0;
  let at: Device | undefined = device;
  const seen = new Set<string>();
  while (at?.parent && depth < 8 && !seen.has(at.path)) {
    seen.add(at.path);
    const parent: string = at.parent;
    at = devices.find((one) => one.name === parent || one.path === parent);
    if (!at) break;
    depth += 1;
  }
  return depth;
}

/** A mount point as lsblk prints it: "[SWAP]" is swap, the rest a path. */
export function mountpointWords(mountpoint: string): string {
  return mountpoint === "[SWAP]" ? "swap" : mountpoint;
}

/** The by-id link without its directory: what the operator recognises the disk by. */
export function byIdName(device: Device): string {
  return device.by_id ? device.by_id.replace(/^\/dev\/disk\/by-id\//, "") : "";
}

/** Whether the device has an identity a destructive operation can bind to. */
export function hasStableIdentity(device: Device): boolean {
  const link = byIdName(device);
  if (!link) return false;
  if (device.wwn || device.serial) return true;
  return /^(dm-uuid-|md-uuid-|lvm-pv-uuid-)/.test(link);
}

/**
 * Why the host would refuse to format or wipe the device, in the host's
 * own codes, or nothing when the operation may be ordered.
 */
export function destructiveRefusal(device: Device, devices: Device[]): { code: string; reason: string } | null {
  if (!hasStableIdentity(device)) {
    return {
      code: "stable_identity_required",
      reason: device.identity_unavailable_reason
        || (byIdName(device) ? "the by-id link carries neither a WWN nor a serial" : "no /dev/disk/by-id link names this device"),
    };
  }
  if (device.root_device) return { code: "disk_in_use", reason: "carries the root filesystem" };
  if ((device.mountpoints ?? []).length > 0) return { code: "disk_in_use", reason: `mounted at ${device.mountpoints![0]}` };
  if (device.has_mounted_children || deviceInUse(device, devices)) {
    return { code: "disk_in_use", reason: "a partition or volume on it is mounted or used as swap" };
  }
  if (device.has_open_holders || (device.holders ?? []).length > 0) {
    return { code: "disk_in_use", reason: `held by ${(device.holders ?? []).join(", ") || "another device"}` };
  }
  return null;
}

/**
 * Why the panel will not fail or remove this member, in the host's own
 * codes, or nothing when the order may be given.
 */
export function memberRefusal(array: RAIDArray, member: RAIDMember, losingData: boolean):
  { code: string; reason: string } | null {
  if (!array.uuid) {
    return {
      code: "array_unknown",
      reason: array.detail_unavailable_reason || "the array reports no UUID to bind the change to",
    };
  }
  if (!member.by_id) {
    return {
      code: "stable_identity_required",
      reason: member.identity_unavailable_reason || `no /dev/disk/by-id link names ${member.path}`,
    };
  }
  if (!losingData) return null;
  if (!array.redundant) {
    return { code: "array_redundancy_lost", reason: `${array.level || "this level"} keeps no copy of the data` };
  }
  if (array.sync_action) {
    return { code: "array_rebuilding", reason: `the array is ${array.sync_action}` };
  }
  if (array.degraded) {
    return { code: "array_redundancy_lost", reason: "the array is already degraded" };
  }
  return null;
}

/** Whether losing this member now costs the array a copy of the data. */
export function carriesData(member: RAIDMember): boolean {
  return member.role === "active" || member.role === "write_mostly" || member.role === "rebuilding";
}

/** Whether the volume is a snapshot of another one. */
export function isSnapshot(volume: LogicalVolume): boolean {
  if (volume.origin) return true;
  const first = (volume.attributes ?? "").charAt(0);
  return first === "s" || first === "S";
}

/** The device identity sent together with the operation. */
export function identity(device: Device): Record<string, unknown> {
  return {
    device: device.path,
    expected_by_id: device.by_id ?? "",
    expected_wwn: device.wwn ?? "",
    expected_serial: device.serial ?? "",
    expected_uuid: device.uuid ?? "",
  };
}

/** The values a mount plan was computed for. */
export type MountValues = { source: string; target: string; fs_type: string; options: string; persist: boolean };

/**
 * The order a plan belongs to. A field edited after the planning leaves
 * the digest bound to values nobody looked at, so the two are compared as
 * text.
 */
export function mountOrder(values: MountValues): string {
  return [values.source, values.target, values.fs_type, values.options, values.persist ? "fstab" : "boot"].join("\u0000");
}

type MountPlanDetail = { kind?: string; plan_hash?: string; plan?: HostPlan };

/** The mount plan of a planning job: the digest the change binds to, and what the host would do. */
export function mountPlanBinding(detail?: MountPlanDetail): { hash: string; plan: HostPlan } | null {
  if (detail?.kind !== "mount_plan" || !detail.plan_hash) return null;
  return { hash: detail.plan_hash, plan: detail.plan ?? {} };
}

/** What this host really has, for the fields of a storage order. */
export function storageSuggestions(snapshot?: Snapshot): FieldSuggestions {
  if (!snapshot) return {};
  const paths = (values: (string | undefined)[]) =>
    Array.from(new Set(values.filter((value): value is string => Boolean(value)))).sort();
  return {
    device: paths([
      ...(snapshot.devices ?? []).map((device) => device.path),
      ...(snapshot.volumes ?? []).map((volume) => volume.path),
    ]),
    array: paths((snapshot.arrays ?? []).map((array) => array.path)),
    group: paths((snapshot.groups ?? []).map((group) => group.name)),
    member: paths((snapshot.devices ?? []).map((device) => device.path)),
  };
}

/**
 * The tone of a share of a whole: a filesystem at four fifths is a
 * warning, at nine tenths an error. A share nobody reported has no tone.
 */
export function usageTone(used?: number, total?: number): Tone | undefined {
  if (used === undefined || total === undefined || total <= 0) return undefined;
  const share = used / total;
  if (share >= 0.9) return "error";
  if (share >= 0.8) return "warn";
  return "ok";
}

/**
 * The sentence the panel gives when somebody looks for a button that
 * builds or tears down an array.
 */
const ARRAY_LIFECYCLE_REFUSAL =
  "The panel manages the members of an array that exists. Creating an array and destroying one are decisions about a machine's whole disk layout, taken on the machine when it is built, not operations run over a running fleet.";

/** The same for the volume manager, so a missing button is read rather than guessed at. */
const GROUP_LIFECYCLE_REFUSAL =
  "The panel manages what a group that exists holds: its volumes, its snapshots and the disks it is built out of. Creating a volume group and taking one apart belong to a machine's disk layout, settled when the machine is built, not run over a running fleet.";

/** The changes this module offers; when every one is refused, it says so once. */
const STORAGE_CHANGES = [
  "mount.ensure", "mount.remove", "filesystem.check", "filesystem.resize", "filesystem.create", "disk.wipe", "lvm.extend",
  "raid.member.fail", "raid.member.remove", "raid.member.add",
  "lvm.volume.create", "lvm.volume.remove", "lvm.group.extend",
  "lvm.snapshot.create", "lvm.snapshot.remove",
];

/** One attempt of a job as a read of the host reads it. */
type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/**
 * A read ordered through a job: the order goes out, the attempts are
 * polled until the host answers, and the last attempt is the result.
 */
function useRead<T>(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<T>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items && items.length > 0 && items[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  return {
    order: order.mutate,
    ordered: job !== "",
    busy: order.isPending || (job !== "" && !last?.status),
    message,
    attempt: last?.status ? last : undefined,
    reset: () => { setJob(""); setMessage(""); },
  };
}

export function Storage({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [unmounting, setUnmounting] = useState("");
  const [smartOf, setSmartOf] = useState<Device | null>(null);
  const [wizard, setWizard] = useState(false);
  // The order being composed in a form of the operation registry: the
  // volume and group operations need values typed in, and they come from
  // the same registry the Bulk wizard draws from.
  const [layer, setLayer] = useState<{ action: string; seed: FormValue } | null>(null);

  const module = useQuery({
    queryKey: ["inventory", host.id, "storage"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/storage`),
    retry: false,
  });

  // The image of the storage lands in the inventory when a read or a
  // change is over: every operation sends it back after itself.
  const refresh = (job: Job) => {
    void awaitJob(api, job.id).then(() => {
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["inventory", host.id, "storage"] });
    }, () => undefined);
  };

  const order = useOrder(host, (job) => {
    setIntent(null);
    setUnmounting("");
    setWizard(false);
    setLayer(null);
    refresh(job);
  });

  // An unmount binds to a plan too: the host is asked what it would take
  // away, and the change carries the digest of that answer.
  const unmountPlan = useRead<MountPlanDetail>(host);
  const unmountBinding = unmounting ? mountPlanBinding(unmountPlan.attempt?.detail) : null;
  // The confirmation appears once the host has answered with a digest; a
  // refusal is shown where the button is instead.
  const plannedUnmount: Intent | null = unmountBinding && !unmountBinding.plan.refusal
    ? {
      action: "mount.remove",
      label: t("Unmount"),
      danger: true,
      description: t("{target} will be unmounted and its fstab entry removed. Processes holding it are checked first.", { target: unmounting }),
      payload: { storage: { target: unmounting, plan_hash: unmountBinding.hash } },
    }
    : null;
  const confirming = intent ?? plannedUnmount;

  const snapshot = module.data?.payload;
  const mounts = snapshot?.mounts ?? [];
  const devices = snapshot?.devices ?? [];
  const rows = mountRows(mounts);
  // An unread snapshot has no mounts to count; an empty one has nought.
  // A reading still on its way is unread too, or the tiles stand at a
  // nought that reads as "nothing is full here".
  const known = module.data && !snapshot?.unavailable_reason ? mounts : undefined;
  const countWhere = (test: (mount: Mount) => boolean) =>
    known === undefined ? undefined : known.filter(test).length;
  const full = countWhere((one) => one.mounted && (one.used_percent ?? 0) >= 80);
  const volatile_ = countWhere((one) => one.mounted && !one.in_fstab);

  const states: Segment[] = [
    { label: t("persistent"), value: countWhere((one) => one.mounted && one.in_fstab), tone: "ok" },
    { label: t("gone after reboot"), value: volatile_, tone: "warn" },
    { label: t("not mounted"), value: countWhere((one) => !one.mounted && one.in_fstab), tone: "unknown" },
    { label: t("over 80 % full"), value: full, tone: "error" },
  ];

  const deviceTypes = Object.entries(devices.reduce<Record<string, number>>((into, device) => {
    into[device.type] = (into[device.type] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]);

  if (!module.data && !module.isLoading) {
    return <Empty>{t("This host has not reported its storage yet.")}</Empty>;
  }

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={STORAGE_CHANGES} />
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">
          {t("Storage state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
        </Banner>
      )}
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {/* The host refused to plan the unmount: nothing is offered to confirm. */}
      {unmounting && unmountPlan.attempt && !plannedUnmount && (
        <Banner tone="error">
          {unmountBinding?.plan.refusal || unmountPlan.attempt.message
            || t("The host refused to plan the unmount of {target}.", { target: unmounting })}
        </Banner>
      )}
      {order.job && <JobLine job={order.job} hostID={host.id} />}

      <Board screen={STORAGE_SCREEN} catalogue={HOST_STORAGE} drawn={{
        mounts: (
          <Kpi
            icon="storage"
            label={t("Mounts")}
            value={known === undefined ? null : rows.length}
            note={t("folded by mount point and source")}
          />
        ),
        full: (
          <Kpi
            icon="storage"
            label={t("Over 80 % full")}
            value={full ?? null}
            tone={full ? "error" : "ok"}
          />
        ),
        volatile: (
          <Kpi
            icon="storage"
            label={t("Gone after reboot")}
            value={volatile_ ?? null}
            tone={volatile_ ? "warn" : "ok"}
            note={t("mounted now, not written in fstab")}
          />
        ),
        states: (
          <Card
            title={t("Mounts")}
            note={t("Mounted now against written in fstab, and the filesystems that are filling up.")}
            foot={freshnessOf(t, module.data)}
            tools={(
              <Guard action="storage.plan" host={host.id} explain>
                <Button
                  kind="quiet"
                  testId="storage-read"
                  disabled={order.request.isPending || host.connection_state !== "online"}
                  onClick={() => order.request.mutate({ action: "storage.plan", payload: { storage: {} } })}
                >
                  {t("Read from host")}
                </Button>
              </Guard>
            )}
          >
            <Band segments={states} testId="mount-states" />
          </Card>
        ),
        devices_by_kind: (
          <Card title={t("Devices")} note={t("What the kernel sees, by kind.")}>
            {deviceTypes.length > 0
              ? <Bars items={deviceTypes.map(([type, count]) => ({ label: type, value: count }))} />
              : <Empty>{t("This host reports no block device.")}</Empty>}
            <Note>{t("Volume groups")}</Note>
            {snapshot?.lvm_unavailable_reason
              ? <Note>{t("No LVM here: {reason}", { reason: snapshot.lvm_unavailable_reason })}</Note>
              : !snapshot?.groups?.length
                ? <Note>{t("This host has LVM but no volume groups.")}</Note>
                : (
                  <Bars items={(snapshot.groups ?? []).map((group) => ({
                    label: group.name,
                    value: group.lv_count,
                    tone: usageTone(group.size_bytes - group.free_bytes, group.size_bytes),
                  }))} />
                )}
            {/* The arrays have a container of their own below, with the
                members and the rebuild; this card says how many there are. */}
            <Note>{t("Software RAID")}</Note>
            {snapshot?.raid_unavailable_reason
              ? <Note>{t("No software RAID here: {reason}", { reason: snapshot.raid_unavailable_reason })}</Note>
              : !snapshot?.arrays?.length
                ? <Note>{t("This kernel has software RAID and no array assembled.")}</Note>
                : (
                  // The bar is the slots the array has filled against the
                  // slots it has: a shorter bar has lost a member.
                  <Bars items={snapshot.arrays.map((array) => ({
                    label: `${array.name} ${array.level || ""}${array.degraded ? ` · ${t("degraded")}` : ""}`,
                    value: array.active_devices,
                    tone: array.degraded ? "error" : "ok",
                  }))} />
                )}
          </Card>
        ),
        wizard: wizard ? (
          <Guard action="mount.ensure" host={host.id} explain>
            <MountWizard host={host} devices={devices} onIntent={setIntent} onClose={() => setWizard(false)} />
          </Guard>
        ) : undefined,
        mount_list: (
          <Card
            title={t("Mounts")}
            tools={(
              <Guard action="mount.ensure" host={host.id}>
                <Button kind="quiet" testId="mount-open" onClick={() => setWizard((open) => !open)}>
                  {wizard ? t("Cancel") : t("Mount a filesystem")}
                </Button>
              </Guard>
            )}
            flush
          >
            <Table
              rows={rows}
              keyOf={({ mount }) => `${mount.target}|${mount.source}|${mount.fs_type}`}
              loading={module.isLoading}
              testId="mounts"
              rowTestId={({ mount }) => `mount-${mount.target}`}
              empty={t("This host reports no mounted filesystem.")}
              columns={[
                { key: "target", head: t("Mount point"), tight: true, cell: ({ mount, times }) => (
                  <>
                    {mount.target}
                    {times > 1 && (
                      <Pill title={t("The host has this filesystem mounted {n} times at this point, one over the other.", { n: times })}>
                        ×{times}
                      </Pill>
                    )}
                  </>
                ) },
                { key: "source", head: t("Source"), tight: true, cell: ({ mount }) => mount.source },
                { key: "type", head: t("Type"), minor: true, cell: ({ mount }) => mount.fs_type },
                // The four "mounted / in fstab" combinations mean four
                // different things, and all of them matter to the operator.
                { key: "state", head: t("State"), cell: ({ mount }) => (
                  mount.mounted && mount.in_fstab ? <Pill tone="ok">{t("mounted, persistent")}</Pill>
                    : mount.mounted ? <Pill tone="warn">{t("mounted, gone after reboot")}</Pill>
                    : mount.in_fstab ? <Pill tone="unknown">{t("in fstab, not mounted")}</Pill>
                    : null
                ) },
                // Unknown usage stays unknown: a network filesystem may not
                // report an inode count at all.
                { key: "space", head: t("Space used"), cell: ({ mount }) => (
                  mount.used_percent === undefined
                    ? <Pill tone="unknown">{t("unknown")}</Pill>
                    : (
                      <Meter
                        share={mount.used_percent / 100}
                        tone={usageTone(mount.used_percent, 100)}
                        text={mount.size_bytes !== undefined
                          ? `${mount.used_percent}% ${t("of {size}", { size: bytes(mount.size_bytes) })}`
                          : `${mount.used_percent}%`}
                      />
                    )
                ) },
                { key: "inodes", head: t("Inodes used"), minor: true, cell: ({ mount }) => (
                  mount.inodes_used_percent === undefined
                    ? <Pill tone="unknown">{t("unknown")}</Pill>
                    : (
                      <Meter
                        share={mount.inodes_used_percent / 100}
                        tone={usageTone(mount.inodes_used_percent, 100)}
                        text={`${mount.inodes_used_percent}%`}
                      />
                    )
                ) },
                { key: "owner", head: t("Owner"), minor: true, cell: ({ mount }) => (
                  mount.managed ? <Pill tone="ok">{t("panel")}</Pill> : <Pill tone="unknown">{t("host admin")}</Pill>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: ({ mount }) => (
                  mount.managed && mount.mounted ? (
                    <Guard action="mount.remove" host={host.id}>
                      <Button
                        kind="danger"
                        testId={`unmount-${mount.target}`}
                        disabled={unmountPlan.busy}
                        onClick={() => {
                          unmountPlan.reset();
                          setUnmounting(mount.target);
                          unmountPlan.order({ action: "storage.plan", payload: { storage: { target: mount.target } } });
                        }}
                      >
                        {unmountPlan.busy && unmounting === mount.target ? t("Planning…") : t("Unmount")}
                      </Button>
                    </Guard>
                  ) : null
                ) },
              ]}
            />
          </Card>
        ),
        devices: (
          <Card title={t("Devices")} flush>
            <Table
              rows={devices}
              keyOf={(one) => one.path}
              loading={module.isLoading}
              testId="devices"
              rowTestId={(one) => `device-${one.path}`}
              empty={t("This host reports no block device.")}
              columns={[
                // The row is set in by the disk -> partition -> volume
                // topology, which is how the panel being replaced drew it:
                // the eye reads what sits on what without reading a word.
                {
                  key: "path", head: t("Device"), tight: true,
                  indent: (one) => deviceDepth(one, devices),
                  cell: (one) => (
                    <>
                      {one.path}
                      {one.read_only && <Pill>{t("read-only")}</Pill>}
                    </>
                  ),
                },
                { key: "type", head: t("Type"), minor: true, cell: (one) => one.type },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                { key: "fs", head: t("Filesystem"), cell: (one) => (
                  <>
                    {one.fs_type || "—"}
                    {one.fs_size_bytes !== undefined && one.fs_size_bytes < one.size_bytes
                      && <Pill tone="unknown">{t("filesystem {size}", { size: bytes(one.fs_size_bytes) })}</Pill>}
                  </>
                ) },
                { key: "at", head: t("Mounted at"), tight: true, cell: (one) => (
                  (one.mountpoints ?? []).map((point) => t(mountpointWords(point))).join(", ") || "—"
                ) },
                // Identification goes by the by-id link, the WWN and the
                // serial: /dev/sdX depends on the detection order and points
                // at another disk after a reboot.
                { key: "identity", head: t("Identity"), minor: true, cell: (one) => (
                  <Tags>
                    {byIdName(one) && <Tag title={one.by_id}>{byIdName(one)}</Tag>}
                    {one.wwn && <Tag>{`WWN ${one.wwn}`}</Tag>}
                    {one.serial && <Tag>{`${t("serial")} ${one.serial}`}</Tag>}
                    {one.uuid && <Tag title={one.uuid}>{`UUID=${one.uuid.slice(0, 13)}…`}</Tag>}
                    {(one.holders ?? []).length > 0 && (
                      <Pill tone="warn">{t("held by {holders}", { holders: one.holders!.join(", ") })}</Pill>
                    )}
                    {!one.by_id && (
                      <Pill tone="unknown" title={one.identity_unavailable_reason}>{t("no stable identity")}</Pill>
                    )}
                  </Tags>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <DeviceActions
                    device={one}
                    devices={devices}
                    hostID={host.id}
                    smartOpen={smartOf?.path === one.path}
                    onSmart={() => setSmartOf(smartOf?.path === one.path ? null : one)}
                    onIntent={setIntent}
                  />
                ) },
              ]}
            />
          </Card>
        ),
        smart: smartOf ? (
          <SmartReport key={smartOf.path} host={host} device={smartOf} onClose={() => setSmartOf(null)} />
        ) : undefined,
        raid: (
          <Card
            title={t("Software RAID")}
            note={t("The arrays of the host: the level, the members, and what each array is left with.")}
            foot={t(ARRAY_LIFECYCLE_REFUSAL)}
          >
            {snapshot?.raid_unavailable_reason ? (
              <Empty>{t("No software RAID here: {reason}", { reason: snapshot.raid_unavailable_reason })}</Empty>
            ) : !snapshot?.arrays?.length ? (
              <Empty>{t("This kernel has software RAID and no array assembled.")}</Empty>
            ) : (
              snapshot.arrays.map((array) => (
                <ArrayCard
                  key={array.path}
                  array={array}
                  hostID={host.id}
                  onIntent={setIntent}
                  onAdd={(seed) => setLayer({ action: "raid.member.add", seed })}
                />
              ))
            )}
          </Card>
        ),
        groups: snapshot?.lvm_unavailable_reason ? undefined : (
          <Card title={t("Volume groups")} foot={t(GROUP_LIFECYCLE_REFUSAL)} flush>
            <Table
              rows={snapshot?.groups ?? []}
              keyOf={(one) => one.name}
              testId="volume-groups"
              empty={t("This host has LVM but no volume groups.")}
              columns={[
                { key: "name", head: t("Group"), tight: true, cell: (one) => (
                  <TwoLine sub={one.uuid ? undefined : t("no UUID")}>{one.name}</TwoLine>
                ) },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                { key: "allocated", head: t("Allocated"), cell: (one) => (
                  <Meter
                    share={one.size_bytes > 0 ? (one.size_bytes - one.free_bytes) / one.size_bytes : 0}
                    tone={usageTone(one.size_bytes - one.free_bytes, one.size_bytes)}
                    text={one.size_bytes > 0
                      ? `${Math.round((one.size_bytes - one.free_bytes) / one.size_bytes * 100)}%`
                      : "—"}
                  />
                ) },
                // Nought free space decides whether anything can be extended
                // - and it is a number, not an absence.
                { key: "free", head: t("Free"), num: true, cell: (one) => bytes(one.free_bytes) },
                { key: "volumes", head: t("Volumes"), num: true, cell: (one) => one.lv_count },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  // A group without a UUID is a group no order binds to, so
                  // the row says so rather than offering a refused button.
                  one.uuid ? (
                    <>
                      <Guard action="lvm.volume.create" host={host.id}>
                        <Button
                          kind="quiet"
                          testId={`new-volume-${one.name}`}
                          onClick={() => setLayer({
                            action: "lvm.volume.create",
                            seed: { group: one.name, expected_group_uuid: one.uuid ?? "" },
                          })}
                        >
                          {t("New volume")}
                        </Button>
                      </Guard>
                      <Guard action="lvm.group.extend" host={host.id}>
                        <Button
                          kind="danger"
                          testId={`extend-group-${one.name}`}
                          onClick={() => setLayer({
                            action: "lvm.group.extend",
                            seed: { group: one.name, expected_group_uuid: one.uuid ?? "" },
                          })}
                        >
                          {t("Add a disk")}
                        </Button>
                      </Guard>
                    </>
                  ) : <Pill tone="unknown">{t("no UUID")}</Pill>
                ) },
              ]}
            />
          </Card>
        ),
        physical: snapshot?.physical_volumes?.length ? (
          <Card
            title={t("Physical volumes")}
            note={t("A physical volume in no group is a disk prepared for LVM and unused — a fact of its own, not a broken one.")}
            flush
          >
            <Table
              rows={snapshot.physical_volumes}
              keyOf={(one) => one.path}
              testId="physical-volumes"
              columns={[
                { key: "path", head: t("Device"), tight: true, cell: (one) => one.path },
                { key: "group", head: t("Group"), tight: true, cell: (one) => (
                  one.group || <Pill tone="unknown">{t("in no group")}</Pill>
                ) },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                { key: "free", head: t("Free"), num: true, cell: (one) => bytes(one.free_bytes) },
              ]}
            />
          </Card>
        ) : undefined,
        volumes: snapshot?.volumes?.length ? (
          <Card title={t("Volumes")} flush>
            <Table
              rows={snapshot.volumes}
              keyOf={(one) => one.path}
              testId="volumes"
              rowTestId={(one) => `volume-${one.path}`}
              columns={[
                { key: "path", head: t("Logical volume"), tight: true, cell: (one) => (
                  <TwoLine sub={one.uuid ? undefined : t("no UUID")}>{one.path}</TwoLine>
                ) },
                { key: "group", head: t("Group"), minor: true, cell: (one) => one.group },
                { key: "size", head: t("Size"), num: true, cell: (one) => bytes(one.size_bytes) },
                // A snapshot that fills its copy-on-write space is dropped
                // by the kernel, so the fill is the number that decides
                // whether it is still usable. An ordinary volume has no such
                // space at all - that is not a snapshot at nought.
                { key: "kind", head: t("Kind"), cell: (one) => (
                  isSnapshot(one) ? (
                    <>
                      <Pill>{t("snapshot of {origin}", { origin: one.origin || "—" })}</Pill>
                      {one.data_percent !== undefined && (
                        <Meter
                          share={one.data_percent / 100}
                          tone={usageTone(one.data_percent, 100)}
                          text={`${one.data_percent.toFixed(1)}%`}
                        />
                      )}
                    </>
                  ) : t("volume")
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <VolumeActions
                    volume={one}
                    devices={devices}
                    hostID={host.id}
                    onIntent={setIntent}
                    onLayer={setLayer}
                  />
                ) },
              ]}
            />
          </Card>
        ) : undefined,
        layer: layer ? (
          <LayerWizard
            action={layer.action}
            seed={layer.seed}
            suggestions={storageSuggestions(snapshot)}
            onIntent={setIntent}
            onClose={() => setLayer(null)}
          />
        ) : undefined,
      }} />

      {confirming && (
        <Confirm
          key={`${confirming.action}-${confirming.label}`}
          host={host}
          intent={confirming}
          busy={order.request.isPending}
          onConfirm={(reason, confirmation) => order.request.mutate({
            action: confirming.action,
            reason,
            // A destructive operation requires the target name typed out.
            target_confirmation: confirmation,
            payload: confirming.payload,
          })}
          onCancel={() => { setIntent(null); setUnmounting(""); unmountPlan.reset(); }}
        />
      )}
    </>
  );
}

/**
 * What may be done to one device. The health log belongs to a whole disk
 * rather than to a partition, and reading it changes nothing, so a
 * mounted disk is asked as well; everything else makes sense only when
 * nothing sits on the device or under it.
 */
function DeviceActions({ device, devices, hostID, smartOpen, onSmart, onIntent }: {
  device: Device;
  devices: Device[];
  hostID: string;
  smartOpen: boolean;
  onSmart: () => void;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const refusal = destructiveRefusal(device, devices);
  return (
    <>
      {!device.parent && (
        <Button kind="quiet" testId={`smart-${device.path}`} onClick={onSmart}>
          {smartOpen ? t("Close SMART") : t("SMART")}
        </Button>
      )}
      {!deviceInUse(device, devices) && (
        <>
          {device.fs_type && (
            <Guard action="filesystem.check" host={hostID}>
              <Button
                testId={`check-${device.path}`}
                onClick={() => onIntent({
                  action: "filesystem.check",
                  label: t("Check filesystem"),
                  description: t("{device} will be checked read-only. The check refuses to run if the filesystem is mounted.", { device: device.path }),
                  payload: { storage: { device: device.path } },
                })}
              >
                {t("Check")}
              </Button>
            </Guard>
          )}
          {device.fs_type && (
            <Guard action="filesystem.resize" host={hostID}>
              <Button
                testId={`grow-${device.path}`}
                onClick={() => onIntent({
                  action: "filesystem.resize",
                  label: t("Grow filesystem"),
                  description: t("The filesystem on {device} will grow to fill the device ({size}).", {
                    device: device.path, size: bytes(device.size_bytes),
                  }),
                  payload: { storage: identity(device) },
                })}
              >
                {t("Grow")}
              </Button>
            </Guard>
          )}
          {/* Formatting and wiping carry the device identity from this row -
              the by-id link, the WWN, the serial - and the host refuses if
              it hits something else. The size is in the description for the
              operator, never an identity. A device without a stable
              identity is not offered: the host would refuse, and the row
              says why. */}
          {refusal ? (
            <Pill tone="error" title={refusal.reason}>
              {t("format refused: {code}", { code: refusal.code })}
            </Pill>
          ) : (
            <>
              <Guard action="filesystem.create" host={hostID}>
                <Button
                  kind="danger"
                  testId={`format-${device.path}`}
                  onClick={() => onIntent({
                    action: "filesystem.create",
                    label: t("Format device"),
                    danger: true,
                    description: t("Everything on {device} ({details}) will be destroyed and a new ext4 filesystem created. This needs two approvals.", {
                      device: device.path,
                      details: `${bytes(device.size_bytes)}, ${byIdName(device)}${device.serial ? `, ${t("serial")} ${device.serial}` : ""}`,
                    }),
                    payload: { storage: { ...identity(device), fs_type: "ext4" } },
                  })}
                >
                  {t("Format")}
                </Button>
              </Guard>
              <Guard action="disk.wipe" host={hostID}>
                <Button
                  kind="danger"
                  testId={`wipe-${device.path}`}
                  onClick={() => onIntent({
                    action: "disk.wipe",
                    label: t("Wipe signatures"),
                    danger: true,
                    description: t("Filesystem signatures on {device} will be removed, so the host stops recognising what is on it. The contents are not overwritten. This needs two approvals.", { device: device.path }),
                    payload: { storage: identity(device) },
                  })}
                >
                  {t("Wipe")}
                </Button>
              </Guard>
            </>
          )}
        </>
      )}
    </>
  );
}

/** What may be done to one logical volume. */
function VolumeActions({ volume, devices, hostID, onIntent, onLayer }: {
  volume: LogicalVolume;
  devices: Device[];
  hostID: string;
  onIntent: (intent: Intent) => void;
  onLayer: (layer: { action: string; seed: FormValue }) => void;
}) {
  const t = useT();
  // Deleting a volume is the same loss as a format, so it carries the
  // volume's UUID and the by-id link of the device the kernel publishes
  // for it. A volume the host gave neither is not offered.
  const device = devices.find((one) => one.path === volume.path
    || one.path === `/dev/mapper/${volume.group.replace(/-/g, "--")}-${volume.name.replace(/-/g, "--")}`);
  return (
    <>
      {/* We extend upwards only and together with the filesystem: a volume
          bigger than its filesystem gives not a single byte. */}
      <Guard action="lvm.extend" host={hostID}>
        <Button
          kind="quiet"
          testId={`extend-${volume.path}`}
          onClick={() => onIntent({
            action: "lvm.extend",
            label: t("Extend volume"),
            description: t("{volume} will grow by 512M together with its filesystem, if the group has room.", { volume: volume.path }),
            payload: { storage: { device: volume.path, size: "+512M" } },
          })}
        >
          {t("Extend by 512M")}
        </Button>
      </Guard>
      {volume.uuid && !isSnapshot(volume) && (
        <Guard action="lvm.snapshot.create" host={hostID}>
          <Button
            kind="quiet"
            testId={`snapshot-${volume.path}`}
            onClick={() => onLayer({
              action: "lvm.snapshot.create",
              seed: { device: volume.path, expected_volume_uuid: volume.uuid ?? "" },
            })}
          >
            {t("Snapshot")}
          </Button>
        </Guard>
      )}
      {volume.uuid && isSnapshot(volume) && (
        <Guard action="lvm.snapshot.remove" host={hostID}>
          <Button
            kind="danger"
            testId={`drop-${volume.path}`}
            onClick={() => onIntent({
              action: "lvm.snapshot.remove",
              label: t("Drop snapshot"),
              danger: true,
              description: t("The snapshot {volume} will be dropped and its {size} go back to {group}.", {
                volume: volume.path, size: bytes(volume.size_bytes), group: volume.group,
              }),
              payload: { storage: { device: volume.path, expected_volume_uuid: volume.uuid } },
            })}
          >
            {t("Drop")}
          </Button>
        </Guard>
      )}
      {volume.uuid && !isSnapshot(volume) && (
        device?.by_id ? (
          <Guard action="lvm.volume.remove" host={hostID}>
            <Button
              kind="danger"
              testId={`delete-${volume.path}`}
              onClick={() => onIntent({
                action: "lvm.volume.remove",
                label: t("Delete volume"),
                danger: true,
                description: t("Everything on {volume} ({size}) will be destroyed and its extents go back to {group}. This needs two approvals.", {
                  volume: volume.path, size: bytes(volume.size_bytes), group: volume.group,
                }),
                payload: {
                  storage: {
                    device: volume.path,
                    expected_volume_uuid: volume.uuid,
                    expected_by_id: device.by_id,
                    expected_wwn: device.wwn ?? "",
                    expected_serial: device.serial ?? "",
                  },
                },
              })}
            >
              {t("Delete")}
            </Button>
          </Guard>
        ) : (
          <Pill tone="unknown" title={device?.identity_unavailable_reason}>
            {t("delete refused: {code}", { code: "stable_identity_required" })}
          </Pill>
        )
      )}
    </>
  );
}

/**
 * One software array: what it is, what it is left with, and what may be
 * done to its members.
 */
function ArrayCard({ array, hostID, onIntent, onAdd }: {
  array: RAIDArray;
  hostID: string;
  onIntent: (intent: Intent) => void;
  onAdd: (seed: FormValue) => void;
}) {
  const t = useT();
  const members = array.members ?? [];
  // The order a member operation carries: the array by the UUID out of its
  // superblock, the member by the link that still means the same disk
  // after a reboot.
  const memberOrder = (member: RAIDMember) => ({
    array: array.path,
    device: member.path,
    expected_array_uuid: array.uuid ?? "",
    expected_by_id: member.by_id ?? "",
    expected_wwn: member.wwn ?? "",
    expected_serial: member.serial ?? "",
  });

  return (
    <>
      <Facts>
        <Fact label={t("Array")}>{array.path}</Fact>
        <Fact label={t("Level")}>
          {array.level || <Pill tone="unknown">{t("unknown")}</Pill>}
          {array.level && !array.redundant && <Pill tone="warn">{t("keeps no copy")}</Pill>}
        </Fact>
        <Fact label={t("State")}>
          {array.degraded
            ? <Pill tone="error">{t("degraded")}</Pill>
            : <Pill tone="ok">{array.state || t("assembled")}</Pill>}
        </Fact>
        <Fact label={t("Slots filled")}>
          {array.raid_devices > 0
            ? `${array.active_devices} / ${array.raid_devices}`
            : <Pill tone="unknown">{t("unknown")}</Pill>}
        </Fact>
        <Fact label={t("Spares")}>{array.spare_devices}</Fact>
        <Fact label={t("Failed")}>
          {array.failed_devices > 0
            ? <Pill tone="error">{array.failed_devices}</Pill>
            : <Pill tone="ok">0</Pill>}
        </Fact>
        <Fact label={t("Size")}>
          {array.size_bytes ? bytes(array.size_bytes) : <Pill tone="unknown">{t("unknown")}</Pill>}
        </Fact>
        {/* No percentage means no rebuild is running - not a rebuild
            standing at nought. */}
        <Fact label={t("Rebuild")}>
          {array.sync_action === undefined || array.sync_percent === undefined ? t("none running") : (
            <Meter
              share={array.sync_percent / 100}
              tone="warn"
              text={`${array.sync_action} ${array.sync_percent.toFixed(1)}%${array.sync_finish ? ` · ${array.sync_finish}` : ""}`}
            />
          )}
        </Fact>
        <Fact label={t("Identity")}>
          {array.uuid
            ? array.uuid
            : <Pill tone="unknown" title={array.detail_unavailable_reason}>{t("no UUID")}</Pill>}
        </Fact>
      </Facts>

      {array.detail_unavailable_reason && (
        <Banner tone="warn">
          {t("This array carries no superblock detail: {reason}. No member operation binds to it.", {
            reason: array.detail_unavailable_reason,
          })}
        </Banner>
      )}

      <Table
        rows={members}
        keyOf={(member, index) => member.path || `slot-${member.slot ?? index}`}
        testId={`members-${array.name}`}
        empty={t("This array reports no members.")}
        columns={[
          { key: "path", head: t("Member"), tight: true, cell: (one) => one.path || t("empty slot") },
          { key: "slot", head: t("Slot"), num: true, cell: (one) => (one.slot === undefined ? "—" : one.slot) },
          { key: "role", head: t("Role"), cell: (one) => (
            <TwoLine sub={one.state || undefined}><MemberRole role={one.role} /></TwoLine>
          ) },
          { key: "identity", head: t("Identity"), minor: true, tight: true, cell: (one) => (
            one.by_id
              ? one.by_id.replace(/^\/dev\/disk\/by-id\//, "")
              : <Pill tone="unknown" title={one.identity_unavailable_reason}>{t("no stable identity")}</Pill>
          ) },
          { key: "act", head: t("Actions"), actions: true, cell: (one) => {
            if (!one.path) return null;
            const refusal = memberRefusal(array, one, carriesData(one));
            if (refusal) {
              return <Pill tone="error" title={refusal.reason}>{t("refused: {code}", { code: refusal.code })}</Pill>;
            }
            return (
              <>
                {one.role !== "faulty" && (
                  <Guard action="raid.member.fail" host={hostID}>
                    <Button
                      kind="danger"
                      testId={`fail-${one.path}`}
                      onClick={() => onIntent({
                        action: "raid.member.fail",
                        label: t("Fail member"),
                        danger: true,
                        description: t("{member} will be marked failed and {array} will stop reading from it. This spends the redundancy of the array and needs two approvals.", {
                          member: one.path, array: array.path,
                        }),
                        payload: { storage: memberOrder(one) },
                      })}
                    >
                      {t("Fail")}
                    </Button>
                  </Guard>
                )}
                {!carriesData(one) && (
                  <Guard action="raid.member.remove" host={hostID}>
                    <Button
                      kind="danger"
                      testId={`remove-member-${one.path}`}
                      onClick={() => onIntent({
                        action: "raid.member.remove",
                        label: t("Remove member"),
                        danger: true,
                        description: t("{member} will be taken out of {array}.", { member: one.path, array: array.path }),
                        payload: { storage: memberOrder(one) },
                      })}
                    >
                      {t("Remove")}
                    </Button>
                  </Guard>
                )}
              </>
            );
          } },
        ]}
      />

      {array.uuid && (
        <Guard action="raid.member.add" host={hostID}>
          <Button
            kind="quiet"
            testId={`add-member-${array.name}`}
            onClick={() => onAdd({ array: array.path, expected_array_uuid: array.uuid ?? "" })}
          >
            {t("Add a member")}
          </Button>
        </Guard>
      )}
    </>
  );
}

/** What one member of an array is doing, in the array's own words. */
function MemberRole({ role }: { role: string }) {
  const t = useT();
  if (role === "faulty") return <Pill tone="error">{t("failed")}</Pill>;
  if (role === "removed") return <Pill tone="unknown">{t("empty slot")}</Pill>;
  if (role === "spare") return <Pill>{t("spare")}</Pill>;
  if (role === "rebuilding") return <Pill tone="warn">{t("rebuilding")}</Pill>;
  if (role === "active") return <Pill tone="ok">{t("active")}</Pill>;
  if (role === "write_mostly") return <Pill tone="ok">{t("write-mostly")}</Pill>;
  if (role === "journal") return <Pill>{t("journal")}</Pill>;
  return <Pill tone="unknown">{t("unknown")}</Pill>;
}

/** The form of one volume or array operation, drawn from the operation registry. */
function LayerWizard({ action, seed, suggestions, onIntent, onClose }: {
  action: string;
  seed: FormValue;
  /** What this host really carries, by field name; see storageSuggestions. */
  suggestions?: FieldSuggestions;
  onIntent: (intent: Intent) => void;
  onClose: () => void;
}) {
  const t = useT();
  const entry = operationForm(action);
  const [value, setValue] = useState<FormValue>(() => (entry ? { ...emptyForm(entry), ...seed } : seed));
  const [json, setJson] = useState("");
  if (!entry) return null;
  const ready = entry.validate(value).length === 0 && json === "";

  return (
    <Card
      title={t(entry.title)}
      note={entry.note ? t(entry.note) : undefined}
      tools={<Button kind="quiet" onClick={onClose} testId="layer-cancel">{t("Cancel")}</Button>}
    >
      <OperationFields
        entry={entry}
        value={value}
        onChange={setValue}
        json={json}
        onJson={setJson}
        suggestions={suggestions}
      />
      <Button
        testId="layer-order"
        disabled={!ready}
        onClick={() => onIntent({
          action,
          label: t(entry.title),
          danger: true,
          description: t("{operation} on {target}.", {
            operation: entry.title, target: entry.summary(entry.toPayload(value)),
          }),
          payload: entry.toPayload(value),
        })}
      >
        {t("Order")}
      </Button>
    </Card>
  );
}

/**
 * The SMART state of one disk. The read goes through a job like every
 * other read: the tool needs root to talk to the device.
 */
function SmartReport({ host, device, onClose }: { host: Host; device: Device; onClose: () => void }) {
  const t = useT();
  const read = useRead<SmartResult>(host);
  const report = read.attempt?.detail;
  const refused = read.attempt && read.attempt.status !== "succeeded";
  const attributes = report?.attributes ?? [];

  return (
    <Card
      title={t("SMART of {device}", { device: device.path })}
      note={device.model || device.serial ? `${device.model ?? ""} ${device.serial ?? ""}`.trim() : undefined}
      tools={(
        <>
          <Guard action="storage.smart.read" host={host.id} explain>
            <Button
              testId="smart-read"
              disabled={read.busy || host.connection_state !== "online"}
              onClick={() => read.order({ action: "storage.smart.read", payload: { storage: { device: device.path } } })}
            >
              {read.busy ? t("Reading…") : read.ordered ? t("Read again") : t("Read SMART")}
            </Button>
          </Guard>
          <Button kind="quiet" onClick={onClose} testId="smart-close">{t("Close")}</Button>
        </>
      )}
    >
      {read.message && <Banner tone="error">{read.message}</Banner>}
      {refused && (
        <Banner tone="error">
          {read.attempt?.message || read.attempt?.error_code || t("The host refused the read.")}
        </Banner>
      )}
      {!read.ordered ? (
        <Empty>{t("The health log is read on request; the tool asks the device for it.")}</Empty>
      ) : !report ? null : report.unsupported ? (
        <Empty>{t("SMART is not available for this device: {reason}", { reason: report.unsupported_reason || "" })}</Empty>
      ) : (
        <>
          <Facts>
            <Fact label={t("Health")}><SmartHealth report={report} /></Fact>
            <Fact label={t("Model")}>{report.model || "—"}</Fact>
            <Fact label={t("Serial")}>{report.serial || "—"}</Fact>
            <Fact label={t("Temperature")}>
              {report.temperature_c !== undefined
                ? `${report.temperature_c} °C`
                : <Pill tone="unknown">{t("unknown")}</Pill>}
            </Fact>
            <Fact label={t("Power-on hours")}>
              {report.power_on_hours !== undefined
                ? report.power_on_hours.toLocaleString()
                : <Pill tone="unknown">{t("unknown")}</Pill>}
            </Fact>
            {/* A reallocated or a pending sector is the number that matters
                most: a disk that has started moving data is a disk to
                replace. Unknown stays unknown, never nought. */}
            <Fact label={t("Reallocated sectors")}>
              {report.reallocated_sectors === undefined
                ? <Pill tone="unknown">{t("unknown")}</Pill>
                : <SectorCount count={report.reallocated_sectors} />}
            </Fact>
            <Fact label={t("Pending sectors")}>
              {report.pending_sectors === undefined
                ? <Pill tone="unknown">{t("unknown")}</Pill>
                : <SectorCount count={report.pending_sectors} />}
            </Fact>
            <Fact label={t("Wear")}>
              {report.wear_percent !== undefined
                ? `${report.wear_percent}%`
                : <Pill tone="unknown">{t("unknown")}</Pill>}
            </Fact>
          </Facts>
          {attributes.length > 0 && (
            <Table
              rows={attributes}
              keyOf={(one) => String(one.id)}
              testId="smart-attributes"
              columns={[
                { key: "id", head: "ID", num: true, cell: (one) => one.id },
                { key: "name", head: t("Attribute"), tight: true, cell: (one) => (
                  <>
                    {one.name}
                    {one.failing && <Pill tone="error">{t("failing")}</Pill>}
                  </>
                ) },
                { key: "value", head: t("Value"), num: true, cell: (one) => one.value },
                { key: "worst", head: t("Worst"), num: true, cell: (one) => one.worst },
                { key: "threshold", head: t("Threshold"), num: true, minor: true, cell: (one) => one.threshold },
                { key: "raw", head: t("Raw"), num: true, tight: true, cell: (one) => one.raw_string || one.raw },
              ]}
            />
          )}
          {report.output && <Readout label={t("What the tool printed")} value={report.output} lines={16} testId="smart-output" />}
        </>
      )}
    </Card>
  );
}

/** The verdict of the tool: passed, failed, or unknown with the reason. */
function SmartHealth({ report }: { report: SmartResult }) {
  const t = useT();
  if (report.health === "passed") return <Pill tone="ok">{t("passed")}</Pill>;
  if (report.health === "failed") {
    return <Pill tone="error">{t("failed")}{report.health_reason ? ` · ${report.health_reason}` : ""}</Pill>;
  }
  return <Pill tone="unknown">{t("unknown")}{report.health_reason ? ` · ${report.health_reason}` : ""}</Pill>;
}

/** A sector count: nought is the good answer here, and anything else a warning. */
function SectorCount({ count }: { count: number }) {
  return count === 0 ? <Pill tone="ok">0</Pill> : <Pill tone="error">{count}</Pill>;
}

/**
 * The mount wizard. The host plans the mount first and the change carries
 * the digest of that plan: an fstab entry already naming the mount point
 * is then refused instead of deciding what gets mounted.
 */
function MountWizard({ host, devices, onIntent, onClose }: {
  host: Host;
  devices: Device[];
  onIntent: (intent: Intent) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [type, setType] = useState("ext4");
  const [options, setOptions] = useState("defaults,nofail");
  const [persist, setPersist] = useState(true);
  const plan = useRead<MountPlanDetail>(host);
  // The order the plan was asked for, kept next to the plan itself.
  const [planned, setPlanned] = useState("");
  const order = mountOrder({ source, target, fs_type: type, options, persist });
  const binding = planned === order ? mountPlanBinding(plan.attempt?.detail) : null;
  const refused = planned === order && plan.attempt && plan.attempt.status !== "succeeded";
  const hash = binding && !binding.plan.refusal ? binding.hash : "";
  // A filesystem the host reported and named by a UUID: that is what can
  // be mounted and what survives a reboot under the same name.
  const named = devices.filter((device) => device.uuid && device.fs_type);

  /* Choosing one of the host's own filesystems fills the type in as well:
     the host has already said what is on that device, and a type typed
     over it is a mount that fails for no reason the operator can see. */
  const chooseSource = (value: string) => {
    setSource(value);
    const found = named.find((device) => `UUID=${device.uuid}` === value || device.path === value);
    if (found?.fs_type) setType(found.fs_type);
  };

  return (
    <Card
      title={t("Mount a filesystem")}
      tools={<Button kind="quiet" onClick={onClose} testId="mount-cancel">{t("Cancel")}</Button>}
    >
      <Fields>
        <Field
          label={t("Source")}
          hint={named.length
            ? t("The filesystems this host reported are on the list; anything else is typed in as UUID=… or a path in /dev.")
            : t("The host has reported no filesystem with a durable identifier; write it as UUID=… or a path in /dev.")}
          wide
        >
          <input
            value={source}
            onChange={(event) => chooseSource(event.target.value)}
            list="mount-source"
            placeholder="UUID=… or /dev/mapper/…"
            data-testid="mount-source"
          />
          <datalist id="mount-source">
            {named.map((device) => (
              <option key={device.path} value={`UUID=${device.uuid}`}>
                {`${device.path} · ${device.fs_type}${device.label ? ` · ${device.label}` : ""} · ${bytes(device.size_bytes)}`}
              </option>
            ))}
          </datalist>
        </Field>
        <Field label={t("Mount point")}>
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={t("An absolute path on the host")}
            data-testid="mount-target"
          />
        </Field>
        <Field label={t("Filesystem type")}>
          <input value={type} onChange={(event) => setType(event.target.value)} placeholder={t("Filesystem type")} data-testid="mount-type" />
        </Field>
        <Field label={t("Options")}>
          <input value={options} onChange={(event) => setOptions(event.target.value)} placeholder={t("Options")} data-testid="mount-options" />
        </Field>
      </Fields>
      {/* Without an fstab entry the mount disappears after a reboot; the
          operator is to know that before, not after the failure. */}
      <Check checked={persist} onChange={setPersist}>
        {t("Keep it after reboot (write an fstab entry)")}
      </Check>
      {plan.message && <Banner tone="error">{plan.message}</Banner>}
      {refused && (
        <Banner tone="error">
          {plan.attempt?.message || plan.attempt?.error_code || t("The host refused the planning.")}
        </Banner>
      )}
      {/* What the host says it would do, and the digest the change is bound
          to; without it the order is refused on the host. */}
      {binding
        ? <PlanBody plan={binding.plan as HostPlan & PackagePlanFacts} />
        : plan.busy
          ? <Note>{t("The host is planning this mount…")}</Note>
          : <Note>{t("Plan the mount on the host first: the change is carried out only against the plan it answers with.")}</Note>}
      <Guard action="storage.plan" host={host.id} explain>
        <Button
          kind="quiet"
          testId="mount-plan"
          disabled={!source || !target || !type || plan.busy || host.connection_state !== "online"}
          onClick={() => {
            setPlanned(order);
            plan.order({ action: "storage.plan", payload: { storage: { source, target, fs_type: type, options, persist } } });
          }}
        >
          {plan.busy ? t("Planning…") : t("Plan on the host")}
        </Button>
      </Guard>
      <Button
        testId="mount-order"
        disabled={!hash}
        onClick={() => onIntent({
          action: "mount.ensure",
          label: t("Mount filesystem"),
          description: persist
            ? t("{source} will be mounted at {target} as {type} and written to fstab.", { source, target, type })
            : t("{source} will be mounted at {target} as {type} for this boot only.", { source, target, type }),
          payload: { storage: { source, target, fs_type: type, options, persist, plan_hash: hash } },
        })}
      >
        {t("Mount")}
      </Button>
    </Card>
  );
}

/** The name this module's arrangement is stored under. */
export const STORAGE_SCREEN = "next_host_storage";

/** The containers this module can draw, and the shape each ships with. */
export const HOST_STORAGE: BoardEntry[] = [
  { key: "mounts", title: "Mounts", width: 4, height: 1 },
  { key: "full", title: "Over 80 % full", width: 4, height: 1 },
  { key: "volatile", title: "Gone after reboot", width: 4, height: 1 },
  { key: "states", title: "Mounts", width: 7, height: 2 },
  { key: "devices_by_kind", title: "Devices", width: 5, height: 3 },
  { key: "wizard", title: "Mount a filesystem", width: 12, height: 4 },
  { key: "mount_list", title: "Mounts", width: 12, height: 4 },
  { key: "devices", title: "Devices", width: 12, height: 4 },
  { key: "smart", title: "SMART", width: 12, height: 4 },
  { key: "raid", title: "Software RAID", width: 12, height: 4 },
  { key: "groups", title: "Volume groups", width: 6, height: 3 },
  { key: "volumes", title: "Volumes", width: 6, height: 3 },
  { key: "physical", title: "Physical volumes", width: 12, height: 3 },
  { key: "layer", title: "An order on the volumes", width: 12, height: 4 },
];
