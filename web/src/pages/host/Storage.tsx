import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown, Meter } from "../../components/widgets";
import {
  Check, Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, usageTone, useHost, useModule, useModuleRefresh, useReadOperation,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import { OperationForm } from "../../components/OperationForm";
import { emptyForm, operationForm, type FieldSuggestions, type FormValue } from "../../lib/operations";
import { useT } from "../../i18n";

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

/**
 * One logical volume. `attributes` is lv_attr as LVM prints it and
 * `data_percent` is how full a snapshot's copy-on-write space is - absent
 * on an ordinary volume, which has none, rather than zero.
 */
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

/**
 * One member of a software array. The role is what the array thinks the
 * device is now; the by-id link is what an order binds to, and a member
 * without one says why instead of showing an empty cell.
 */
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

/**
 * One software array. `sync_percent` is absent when nothing is being
 * rebuilt - not a rebuild standing at zero - and
 * `detail_unavailable_reason` says why an array carries no UUID, which is
 * the same as saying no order can bind to it.
 */
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

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

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
 * does not report its temperature has none here, not a zero.
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

/** One row of the mount table: a mount, and how many times the host has it mounted at that point. */
type MountRow = { mount: Mount; times: number };

/**
 * The mounts folded by mount point and source: a shared folder mounted
 * twice at the same path (what a provisioning tool does when it runs
 * again) is one row that says "twice", not two rows that read as two
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
 * partition or volume under it that is mounted or used as swap. A disk
 * whose partitions are in use is not a blank disk to format, whatever
 * its own row says.
 */
export function deviceInUse(device: Device, devices: Device[]): boolean {
  if ((device.mountpoints ?? []).length > 0) return true;
  return devices.some((other) =>
    other !== device && (other.parent === device.name || other.parent === device.path) && deviceInUse(other, devices),
  );
}

/** A mount point as lsblk prints it, in the operator's words: "[SWAP]" is swap, the rest a path. */
export function mountpointWords(mountpoint: string): string {
  return mountpoint === "[SWAP]" ? "swap" : mountpoint;
}

/** The by-id link without its directory: what the operator recognises the disk by. */
export function byIdName(device: Device): string {
  return device.by_id ? device.by_id.replace(/^\/dev\/disk\/by-id\//, "") : "";
}

/**
 * Whether the device has an identity a destructive operation can bind to.
 * The host applies the same rule: a by-id link, and behind it a WWN or a
 * serial - or the UUID of a device-mapper or RAID volume, which is the
 * identity such a device has. A dm-name link is a name, not an identity.
 */
export function hasStableIdentity(device: Device): boolean {
  const link = byIdName(device);
  if (!link) return false;
  if (device.wwn || device.serial) return true;
  return /^(dm-uuid-|md-uuid-|lvm-pv-uuid-)/.test(link);
}

/**
 * Why the host would refuse to format or wipe the device, in the host's
 * own codes, or nothing when the operation may be ordered. The host checks
 * again right before the change; this is the same answer given before the
 * operator clicks, so a refused plan is shown as refused and not offered.
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
 * The host's storage.
 *
 * The panel shows the kernel state and the fstab content separately: the
 * file says what is to be mounted after a reboot, not what is mounted now.
 * The difference between the two is usually the reason somebody opens this
 * tab.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const STORAGE_CHANGES = [
  "mount.ensure", "mount.remove", "filesystem.check", "filesystem.resize", "filesystem.create", "disk.wipe", "lvm.extend",
  "raid.member.fail", "raid.member.remove", "raid.member.add",
  "lvm.volume.create", "lvm.volume.remove", "lvm.group.extend",
  "lvm.snapshot.create", "lvm.snapshot.remove",
];

/**
 * Why the panel will not fail or remove this member, in the host's own
 * codes, or nothing when the order may be given. The host checks again
 * before the change; this is the same answer, given before the operator
 * clicks.
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

/**
 * The sentence the panel gives when somebody looks for a button that
 * builds or tears down an array. The boundary is drawn on purpose, and a
 * boundary that says nothing reads as a missing feature.
 */
const ARRAY_LIFECYCLE_REFUSAL =
  "The panel manages the members of an array that exists. Creating an array and destroying one are decisions about a machine's whole disk layout, taken on the machine when it is built, not operations run over a running fleet.";

export function Storage() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "storage");
  // The image of the storage lands in the inventory when a read or a
  // change is over: every operation sends it back after itself.
  const refresh = useModuleRefresh(host.id, ["storage"]);
  const [intent, setIntent] = useState<Intent | null>(null);
  const [smartOf, setSmartOf] = useState<Device | null>(null);
  const [message, setMessage] = useState("");
  const [wizard, setWizard] = useState(false);
  // The order being composed in a form of the operation registry: the
  // volume and group operations need values typed in, and they are drawn
  // from the same registry the Bulk wizard draws from.
  const [layer, setLayer] = useState<{ action: string; seed: FormValue } | null>(null);
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      setWizard(false);
      setLayer(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      refresh(job);
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its storage yet.")}</Empty>;

  const mounts = snapshot?.mounts ?? [];
  const devices = snapshot?.devices ?? [];
  // An unread snapshot has no mounts to count; an empty one has zero.
  const known = snapshot?.unavailable_reason ? undefined : mounts;
  const deviceTypes = Object.entries(devices.reduce<Record<string, number>>((acc, device) => {
    acc[device.type] = (acc[device.type] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Storage")}
        description={t("Devices from the kernel, mounts from mountinfo, persistence from fstab — kept apart on purpose: the file says what should be mounted after a reboot, not what is mounted now.")}
        actions={
          <>
            <ActionGuard action="mount.ensure" host={host.id}>
              <button className="secondary" onClick={() => setWizard((open) => !open)}>
                {wizard ? t("Cancel") : t("Mount a filesystem")}
              </button>
            </ActionGuard>
            <ActionGuard action="storage.plan" host={host.id} explain>
              <button
                onClick={() => request.mutate({ action: "storage.plan", payload: { storage: {} } })}
                disabled={request.isPending || host.connection_state !== "online"}
              >
                {t("Read from host")}
              </button>
            </ActionGuard>
          </>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <ReadOnlyModuleNotice host={host.id} actions={STORAGE_CHANGES} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Storage state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      {wizard && (
        <ActionGuard action="mount.ensure" host={host.id}>
          <MountWizard devices={devices} onIntent={setIntent} />
        </ActionGuard>
      )}

      <Widgets>
      {/* The mounts by what they will look like after a reboot, and the ones
          that are running out of room: the two reasons to open this page. */}
      <Summary
        title={t("Mounts")}
        description={t("Mounted now against written in fstab, and the filesystems that are filling up.")}
        span={8}
        segments={[
          { label: t("persistent"), value: countWhere(known, (m) => m.mounted && m.in_fstab), tone: "ok" },
          { label: t("gone after reboot"), value: countWhere(known, (m) => m.mounted && !m.in_fstab), tone: "warn" },
          { label: t("not mounted"), value: countWhere(known, (m) => !m.mounted && m.in_fstab), tone: "unknown" },
          { label: t("over 80 % full"), value: countWhere(known, (m) => m.mounted && (m.used_percent ?? 0) >= 80), tone: "error" },
        ]}
      />
      <Section title={t("Devices")} span={4} description={t("What the kernel sees, by kind.")}>
        {deviceTypes.length ? (
          <Breakdown items={deviceTypes.map(([type, count]) => ({ label: type, value: count }))} />
        ) : (
          <p className="source" style={{ margin: 0 }}>{t("This host reports no block device.")}</p>
        )}
        <p className="widget-subhead">{t("Volume groups")}</p>
        {snapshot?.lvm_unavailable_reason ? (
          <p className="source" style={{ margin: 0 }}>{t("No LVM here: {reason}", { reason: snapshot.lvm_unavailable_reason })}</p>
        ) : !snapshot?.groups?.length ? (
          <p className="source" style={{ margin: 0 }}>{t("This host has LVM but no volume groups.")}</p>
        ) : (
          <Breakdown
            items={(snapshot?.groups ?? []).map((group) => ({
              label: <span className="hm-mono">{group.name}</span>,
              value: group.lv_count,
              tone: usageTone(group.size_bytes - group.free_bytes, group.size_bytes),
            }))}
          />
        )}
        {/* The arrays have a section of their own below, with the members
            and the rebuild; this card says only how many there are. */}
        <p className="widget-subhead">{t("Software RAID")}</p>
        {snapshot?.raid_unavailable_reason ? (
          <p className="source" style={{ margin: 0 }}>{t("No software RAID here: {reason}", { reason: snapshot.raid_unavailable_reason })}</p>
        ) : !snapshot?.arrays?.length ? (
          <p className="source" style={{ margin: 0 }}>{t("This kernel has software RAID and no array assembled.")}</p>
        ) : (
          <Breakdown
            items={snapshot.arrays.map((array) => ({
              // The bar is the slots the array has filled against the slots
              // it has: a shorter bar is an array that has lost a member.
              label: (
                <span className="hm-mono">
                  {array.name} {array.level || ""}
                  {array.degraded && <span className="badge error"> {t("degraded")}</span>}
                </span>
              ),
              value: array.active_devices,
              tone: array.degraded ? "error" : "ok",
            }))}
          />
        )}
      </Section>

      <Section title={t("Mounts")} count={mountRows(mounts).length} span={12} flush>
        <Table>
          <thead>
            <tr>
              <th>{t("Mount point")}</th><th>{t("Source")}</th><th>{t("Type")}</th><th>{t("State")}</th>
              <th>{t("Space used")}</th><th>{t("Inodes used")}</th><th>{t("Owner")}</th><th>{t("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {mountRows(mounts).map(({ mount, times }) => (
              <tr key={`${mount.target}|${mount.source}|${mount.fs_type}`}>
                <td className="hm-mono hm-primary">
                  {mount.target}
                  {times > 1 && (
                    <span className="badge" title={t("The host has this filesystem mounted {n} times at this point, one over the other.", { n: times })}> ×{times}</span>
                  )}
                </td>
                <td className="hm-mono" title={mount.source}>{mount.source.slice(0, 40)}</td>
                <td>{mount.fs_type}</td>
                {/* The four "mounted / in fstab" combinations mean four
                    different things, and all of them matter to the operator. */}
                <td>
                  {mount.mounted && mount.in_fstab && <span className="badge ok">{t("mounted, persistent")}</span>}
                  {mount.mounted && !mount.in_fstab && (
                    <span className="badge warn">{t("mounted, gone after reboot")}</span>
                  )}
                  {!mount.mounted && mount.in_fstab && (
                    <span className="badge unknown">{t("in fstab, not mounted")}</span>
                  )}
                </td>
                {/* Unknown usage stays unknown: a network filesystem may not
                    report an inode count at all. */}
                <td>
                  {mount.used_percent === undefined ? (
                    unknown
                  ) : (
                    <Meter
                      value={mount.used_percent}
                      max={100}
                      tone={usageTone(mount.used_percent, 100)}
                      text={mount.size_bytes !== undefined
                        ? `${mount.used_percent}% ${t("of {size}", { size: bytes(mount.size_bytes) })}`
                        : `${mount.used_percent}%`}
                    />
                  )}
                </td>
                <td>
                  {mount.inodes_used_percent === undefined ? (
                    unknown
                  ) : (
                    <Meter
                      value={mount.inodes_used_percent}
                      max={100}
                      tone={usageTone(mount.inodes_used_percent, 100)}
                      text={`${mount.inodes_used_percent}%`}
                    />
                  )}
                </td>
                <td>{mount.managed ? "Flotestro" : <span className="badge unknown">{t("host admin")}</span>}</td>
                <td>
                  {mount.managed && mount.mounted && (
                    <ActionGuard action="mount.remove" host={host.id}>
                      <button
                        className="hm-danger"
                        onClick={() =>
                          setIntent({
                            action: "mount.remove",
                            label: t("Unmount"),
                            description: t("{target} will be unmounted and its fstab entry removed. Processes holding it are checked first.", { target: mount.target }),
                            payload: { storage: { target: mount.target } },
                          })
                        }
                      >
                        {t("Unmount")}
                      </button>
                    </ActionGuard>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      <Section title={t("Devices")} count={devices.length} span={12} flush>
        <Table>
          <thead>
            <tr><th>{t("Device")}</th><th>{t("Type")}</th><th className="hm-num">{t("Size")}</th><th>{t("Filesystem")}</th><th>{t("Mounted at")}</th><th>{t("Identity")}</th><th>{t("Actions")}</th></tr>
          </thead>
          <tbody>
            {devices.map((device) => (
              <tr key={device.path}>
                {/* The indentation reflects the disk -> partition -> volume topology. */}
                <td className={device.parent ? "hm-mono hm-indent" : "hm-mono hm-primary"}>
                  {device.path}
                  {device.read_only && <span className="badge"> {t("read-only")}</span>}
                </td>
                <td>{device.type}</td>
                <td className="hm-num">{bytes(device.size_bytes)}</td>
                <td>
                  {device.fs_type || "—"}
                  {device.fs_size_bytes !== undefined && device.fs_size_bytes < device.size_bytes && (
                    <span className="source"> · fs {bytes(device.fs_size_bytes)}</span>
                  )}
                </td>
                <td className="hm-mono">{(device.mountpoints ?? []).map((point) => t(mountpointWords(point))).join(", ") || "—"}</td>
                {/* Identification goes by the by-id link, the WWN and the
                    serial: /dev/sdX depends on the detection order and points
                    at another disk after a reboot. A device without a link
                    has no identity to bind a destructive operation to, and
                    the row says so instead of showing an empty cell. */}
                <td
                  className="source hm-mono"
                  title={[
                    device.by_id ?? "",
                    device.wwn ? `WWN ${device.wwn}` : "",
                    device.serial ? `${t("serial")} ${device.serial}` : "",
                    device.uuid ? `UUID=${device.uuid}` : "",
                    device.label ? `LABEL=${device.label}` : "",
                    device.model ?? "",
                    (device.holders ?? []).length ? `${t("held by")} ${device.holders!.join(", ")}` : "",
                    device.identity_unavailable_reason ?? "",
                  ].filter(Boolean).join(" · ") || undefined}
                >
                  {byIdName(device) ? <div>{byIdName(device)}</div> : null}
                  {device.wwn ? <div>WWN {device.wwn}</div> : null}
                  {device.serial ? <div>{t("serial")} {device.serial}</div> : null}
                  {device.uuid ? <div>UUID={device.uuid.slice(0, 13)}…</div> : null}
                  {(device.holders ?? []).length > 0 && (
                    <div><span className="badge warn">{t("held by {holders}", { holders: device.holders!.join(", ") })}</span></div>
                  )}
                  {!device.by_id && (
                    <div>
                      <span className="badge unknown" title={device.identity_unavailable_reason}>{t("no stable identity")}</span>
                    </div>
                  )}
                </td>
                <td>
                  {/* The health log belongs to a whole disk, not to a
                      partition; reading it changes nothing, so a mounted
                      disk is asked as well. */}
                  {!device.parent && (
                    <div className="operations">
                      <button
                        className="secondary"
                        onClick={() => setSmartOf(smartOf?.path === device.path ? null : device)}
                      >
                        SMART
                      </button>
                    </div>
                  )}
                  {/* Operations on a device make sense only when nothing sits
                      on it or under it - and the host checks that once more
                      anyway. */}
                  {!deviceInUse(device, devices) && (
                    <div className="operations">
                      {device.fs_type && (
                        <ActionGuard action="filesystem.check" host={host.id}>
                          <button
                            onClick={() =>
                              setIntent({
                                action: "filesystem.check",
                                label: t("Check filesystem"),
                                description: t("{device} will be checked read-only. The check refuses to run if the filesystem is mounted.", { device: device.path }),
                                payload: { storage: { device: device.path } },
                              })
                            }
                          >
                            {t("Check")}
                          </button>
                        </ActionGuard>
                      )}
                      {device.fs_type && (
                        <ActionGuard action="filesystem.resize" host={host.id}>
                          <button
                            onClick={() =>
                              setIntent({
                                action: "filesystem.resize",
                                label: t("Grow filesystem"),
                                description: t("The filesystem on {device} will grow to fill the device ({size}).", { device: device.path, size: bytes(device.size_bytes) }),
                                payload: { storage: identity(device) },
                              })
                            }
                          >
                            {t("Grow")}
                          </button>
                        </ActionGuard>
                      )}
                      {/* Formatting and wiping carry the device identity from
                          this row - the by-id link, the WWN, the serial - and
                          the host refuses if it hits something else. The size
                          is in the description for the operator, never an
                          identity. A device without a stable identity is not
                          offered: the host would refuse, and the row says why. */}
                      {destructiveRefusal(device, devices) ? (
                        <span
                          className="badge error"
                          title={destructiveRefusal(device, devices)!.reason}
                        >
                          {t("format refused: {code}", { code: destructiveRefusal(device, devices)!.code })}
                        </span>
                      ) : (
                        <>
                          <ActionGuard action="filesystem.create" host={host.id}>
                            <button
                              className="hm-danger"
                              onClick={() =>
                                setIntent({
                                  action: "filesystem.create",
                                  label: t("Format device"),
                                  description: t("Everything on {device} ({details}) will be destroyed and a new ext4 filesystem created. This needs two approvals.", {
                                    device: device.path,
                                    details: `${bytes(device.size_bytes)}, ${byIdName(device)}${device.serial ? `, ${t("serial")} ${device.serial}` : ""}`,
                                  }),
                                  payload: {
                                    storage: { ...identity(device), fs_type: "ext4" },
                                  },
                                })
                              }
                            >
                              {t("Format")}
                            </button>
                          </ActionGuard>
                          <ActionGuard action="disk.wipe" host={host.id}>
                            <button
                              className="hm-danger"
                              onClick={() =>
                                setIntent({
                                  action: "disk.wipe",
                                  label: t("Wipe signatures"),
                                  description: t("Filesystem signatures on {device} will be removed, so the host stops recognising what is on it. The contents are not overwritten. This needs two approvals.", { device: device.path }),
                                  payload: { storage: identity(device) },
                                })
                              }
                            >
                              {t("Wipe")}
                            </button>
                          </ActionGuard>
                        </>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      {smartOf && <SmartReport key={smartOf.path} device={smartOf} onClose={() => setSmartOf(null)} />}

      {/* Software RAID. An array the host cannot be asked about is not a
          host without arrays, and a degraded array is a fact this page
          exists to show. */}
      <Section
        title={t("Software RAID")}
        count={snapshot?.raid_unavailable_reason ? undefined : snapshot?.arrays?.length}
        span={12}
        description={t("The arrays of the host: the level, the members, and what each array is left with.")}
        flush
      >
        <p className="source hm-section-body">{t(ARRAY_LIFECYCLE_REFUSAL)}</p>
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
      </Section>

      {/* The two LVM tables are narrow; side by side they fill the row. A
          host without LVM tools has no table to show: the devices card
          above says so, and an empty section would say it twice. */}
      {!snapshot?.lvm_unavailable_reason && (
      <Section title={t("Volume groups")} count={snapshot?.groups?.length} span={snapshot?.volumes?.length ? 6 : 12} flush>
        {!snapshot?.groups?.length ? (
          <Empty>{t("This host has LVM but no volume groups.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Group")}</th><th className="hm-num">{t("Size")}</th><th>{t("Allocated")}</th><th className="hm-num">{t("Free")}</th><th className="hm-num">{t("Volumes")}</th><th>{t("Actions")}</th></tr></thead>
            <tbody>
              {snapshot.groups.map((group) => (
                <tr key={group.name}>
                  <td className="hm-mono hm-primary">
                    {group.name}
                    {/* A group without a UUID is a group no order binds to,
                        and the row says so rather than offering a button the
                        host would refuse. */}
                    {!group.uuid && <div><span className="badge unknown">{t("no UUID")}</span></div>}
                  </td>
                  <td className="hm-num">{bytes(group.size_bytes)}</td>
                  <td>
                    <Meter
                      value={group.size_bytes - group.free_bytes}
                      max={group.size_bytes}
                      tone={usageTone(group.size_bytes - group.free_bytes, group.size_bytes)}
                      text={group.size_bytes > 0 ? `${Math.round((group.size_bytes - group.free_bytes) / group.size_bytes * 100)}%` : "—"}
                    />
                  </td>
                  {/* Zero free space decides whether anything can be extended
                      - and it is a number, not an absence. */}
                  <td className="hm-num">{bytes(group.free_bytes)}</td>
                  <td className="hm-num">{group.lv_count}</td>
                  <td>
                    {group.uuid && (
                      <div className="operations">
                        <ActionGuard action="lvm.volume.create" host={host.id}>
                          <button
                            className="secondary"
                            onClick={() => setLayer({
                              action: "lvm.volume.create",
                              seed: { group: group.name, expected_group_uuid: group.uuid ?? "" },
                            })}
                          >
                            {t("New volume")}
                          </button>
                        </ActionGuard>
                        <ActionGuard action="lvm.group.extend" host={host.id}>
                          <button
                            className="hm-danger"
                            onClick={() => setLayer({
                              action: "lvm.group.extend",
                              seed: { group: group.name, expected_group_uuid: group.uuid ?? "" },
                            })}
                          >
                            {t("Add a disk")}
                          </button>
                        </ActionGuard>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      )}

      {/* The disks the groups are built out of. A physical volume in no
          group is a disk prepared for LVM and unused - a fact of its own,
          not a broken one. */}
      {snapshot?.physical_volumes?.length ? (
        <Section title={t("Physical volumes")} count={snapshot.physical_volumes.length} span={12} flush>
          <Table>
            <thead><tr><th>{t("Device")}</th><th>{t("Group")}</th><th className="hm-num">{t("Size")}</th><th className="hm-num">{t("Free")}</th></tr></thead>
            <tbody>
              {snapshot.physical_volumes.map((physical) => (
                <tr key={physical.path}>
                  <td className="hm-mono hm-primary">{physical.path}</td>
                  <td className="hm-mono">
                    {physical.group || <span className="badge unknown">{t("in no group")}</span>}
                  </td>
                  <td className="hm-num">{bytes(physical.size_bytes)}</td>
                  <td className="hm-num">{bytes(physical.free_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      ) : null}

      {snapshot?.volumes?.length ? (
        <Section title={t("Volumes")} count={snapshot.volumes.length} span={6} flush>
          <Table>
            <thead><tr><th>{t("Logical volume")}</th><th>{t("Group")}</th><th className="hm-num">{t("Size")}</th><th>{t("Kind")}</th><th>{t("Actions")}</th></tr></thead>
            <tbody>
              {snapshot.volumes.map((volume) => (
                <tr key={volume.path}>
                  <td className="hm-mono hm-primary">
                    {volume.path}
                    {!volume.uuid && <div><span className="badge unknown">{t("no UUID")}</span></div>}
                  </td>
                  <td className="hm-mono">{volume.group}</td>
                  <td className="hm-num">{bytes(volume.size_bytes)}</td>
                  {/* A snapshot that fills its copy-on-write space is dropped
                      by the kernel, so the fill is the number that decides
                      whether it is still usable. An ordinary volume has no
                      such space at all - that is not a snapshot at zero. */}
                  <td>
                    {isSnapshot(volume) ? (
                      <>
                        <span className="badge">{t("snapshot of {origin}", { origin: volume.origin || "—" })}</span>
                        {volume.data_percent !== undefined && (
                          <Meter
                            value={volume.data_percent}
                            max={100}
                            tone={usageTone(volume.data_percent, 100)}
                            text={`${volume.data_percent.toFixed(1)}%`}
                          />
                        )}
                      </>
                    ) : (
                      t("volume")
                    )}
                  </td>
                  <td>
                    <div className="operations">
                      {/* We extend upwards only and together with the
                          filesystem: a volume bigger than its filesystem gives
                          not a single byte. */}
                      <ActionGuard action="lvm.extend" host={host.id}>
                        <button
                          className="secondary"
                          onClick={() =>
                            setIntent({
                              action: "lvm.extend",
                              label: t("Extend volume"),
                              description: t("{volume} will grow by 512M together with its filesystem, if the group has room.", { volume: volume.path }),
                              payload: { storage: { device: volume.path, size: "+512M" } },
                            })
                          }
                        >
                          {t("Extend by 512M")}
                        </button>
                      </ActionGuard>
                      {volume.uuid && !isSnapshot(volume) && (
                        <ActionGuard action="lvm.snapshot.create" host={host.id}>
                          <button
                            className="secondary"
                            onClick={() => setLayer({
                              action: "lvm.snapshot.create",
                              seed: { device: volume.path, expected_volume_uuid: volume.uuid ?? "" },
                            })}
                          >
                            {t("Snapshot")}
                          </button>
                        </ActionGuard>
                      )}
                      {volume.uuid && isSnapshot(volume) && (
                        <ActionGuard action="lvm.snapshot.remove" host={host.id}>
                          <button
                            className="hm-danger"
                            onClick={() =>
                              setIntent({
                                action: "lvm.snapshot.remove",
                                label: t("Drop snapshot"),
                                description: t("The snapshot {volume} will be dropped and its {size} go back to {group}.", {
                                  volume: volume.path, size: bytes(volume.size_bytes), group: volume.group,
                                }),
                                payload: { storage: { device: volume.path, expected_volume_uuid: volume.uuid } },
                              })
                            }
                          >
                            {t("Drop")}
                          </button>
                        </ActionGuard>
                      )}
                      {/* Deleting a volume is the same loss as a format, so
                          it carries the volume's UUID and the by-id link of
                          the device the kernel publishes for it. A volume
                          the host gave neither is not offered. */}
                      {volume.uuid && !isSnapshot(volume) && (() => {
                        const device = devices.find((candidate) => candidate.path === volume.path
                          || candidate.path === `/dev/mapper/${volume.group.replace(/-/g, "--")}-${volume.name.replace(/-/g, "--")}`);
                        if (!device?.by_id) {
                          return (
                            <span className="badge unknown" title={device?.identity_unavailable_reason}>
                              {t("delete refused: {code}", { code: "stable_identity_required" })}
                            </span>
                          );
                        }
                        return (
                          <ActionGuard action="lvm.volume.remove" host={host.id}>
                            <button
                              className="hm-danger"
                              onClick={() =>
                                setIntent({
                                  action: "lvm.volume.remove",
                                  label: t("Delete volume"),
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
                                })
                              }
                            >
                              {t("Delete")}
                            </button>
                          </ActionGuard>
                        );
                      })()}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      ) : null}
      </Widgets>

      {layer && (
        <LayerWizard
          action={layer.action}
          seed={layer.seed}
          suggestions={storageSuggestions(snapshot)}
          onIntent={setIntent}
          onClose={() => setLayer(null)}
        />
      )}

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Storage read")} <Time value={snapshot.observed_at} /></span>
        </p>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: intent.action,
              reason,
              // A destructive operation requires the target name typed out.
              // The other operations do not need it, but sending it does no
              // harm.
              target_confirmation: confirmation,
              payload: intent.payload,
            })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}

/**
 * One software array: what it is, what it is left with, and what may be
 * done to its members.
 *
 * The numbers the operator came for are the slot count and the rebuild:
 * "2 of 3 slots filled" is an array that still answers every read and has
 * lost its redundancy, and that is worth knowing before the second disk
 * goes. A level that keeps no copy is said outright, because such an array
 * is never "healthy with a spare to lose".
 */
function ArrayCard({ array, hostID, onIntent, onAdd }: {
  array: RAIDArray;
  hostID: string;
  onIntent: (intent: Intent) => void;
  onAdd: (seed: FormValue) => void;
}) {
  const t = useT();
  const unknown = <span className="badge unknown">{t("unknown")}</span>;
  const members = array.members ?? [];
  // The order a member operation carries: the array by the UUID out of its
  // superblock, the member by the link that still means the same disk
  // after a reboot. The panel has already refused what has neither.
  const memberOrder = (member: RAIDMember) => ({
    array: array.path,
    device: member.path,
    expected_array_uuid: array.uuid ?? "",
    expected_by_id: member.by_id ?? "",
    expected_wwn: member.wwn ?? "",
    expected_serial: member.serial ?? "",
  });

  return (
    <div className="hm-section-body">
      <Facts>
        <Fact label={t("Array")}><span className="hm-mono">{array.path}</span></Fact>
        <Fact label={t("Level")}>
          {array.level || unknown}
          {array.level && !array.redundant && (
            <span className="badge warn"> {t("keeps no copy")}</span>
          )}
        </Fact>
        <Fact label={t("State")}>
          {array.degraded
            ? <span className="badge error">{t("degraded")}</span>
            : <span className="badge ok">{array.state || t("assembled")}</span>}
        </Fact>
        <Fact label={t("Slots filled")}>
          {array.raid_devices > 0 ? `${array.active_devices} / ${array.raid_devices}` : unknown}
        </Fact>
        <Fact label={t("Spares")}>{array.spare_devices}</Fact>
        <Fact label={t("Failed")}>
          {array.failed_devices > 0
            ? <span className="badge error">{array.failed_devices}</span>
            : <span className="badge ok">0</span>}
        </Fact>
        <Fact label={t("Size")}>{array.size_bytes ? bytes(array.size_bytes) : unknown}</Fact>
        {/* No percentage means no rebuild is running - not a rebuild
            standing at zero. */}
        <Fact label={t("Rebuild")}>
          {array.sync_action === undefined || array.sync_percent === undefined ? (
            t("none running")
          ) : (
            <Meter
              value={array.sync_percent}
              max={100}
              tone="warn"
              text={`${array.sync_action} ${array.sync_percent.toFixed(1)}%${array.sync_finish ? ` · ${array.sync_finish}` : ""}`}
            />
          )}
        </Fact>
        <Fact label={t("Identity")}>
          {array.uuid
            ? <span className="hm-mono">{array.uuid}</span>
            : <span className="badge unknown" title={array.detail_unavailable_reason}>{t("no UUID")}</span>}
        </Fact>
      </Facts>

      {array.detail_unavailable_reason && (
        <p className="warning">
          <span>{t("This array carries no superblock detail: {reason}. No member operation binds to it.", { reason: array.detail_unavailable_reason })}</span>
        </p>
      )}

      <Table>
        <thead>
          <tr>
            <th>{t("Member")}</th><th className="hm-num">{t("Slot")}</th><th>{t("Role")}</th>
            <th>{t("Identity")}</th><th>{t("Actions")}</th>
          </tr>
        </thead>
        <tbody>
          {members.map((member, index) => {
            const refusal = memberRefusal(array, member, carriesData(member));
            return (
              <tr key={member.path || `slot-${member.slot ?? index}`}>
                <td className="hm-mono hm-primary">{member.path || t("empty slot")}</td>
                <td className="hm-num">{member.slot === undefined ? "—" : member.slot}</td>
                <td>
                  {member.role === "faulty" && <span className="badge error">{t("failed")}</span>}
                  {member.role === "removed" && <span className="badge unknown">{t("empty slot")}</span>}
                  {member.role === "spare" && <span className="badge">{t("spare")}</span>}
                  {member.role === "rebuilding" && <span className="badge warn">{t("rebuilding")}</span>}
                  {member.role === "active" && <span className="badge ok">{t("active")}</span>}
                  {member.role === "write_mostly" && <span className="badge ok">{t("write-mostly")}</span>}
                  {member.role === "journal" && <span className="badge">{t("journal")}</span>}
                  {member.role === "" && unknown}
                  {member.state ? <div className="source">{member.state}</div> : null}
                </td>
                <td className="source hm-mono" title={member.identity_unavailable_reason}>
                  {member.by_id
                    ? member.by_id.replace(/^\/dev\/disk\/by-id\//, "")
                    : <span className="badge unknown">{t("no stable identity")}</span>}
                </td>
                <td>
                  {!member.path ? null : refusal ? (
                    <span className="badge error" title={refusal.reason}>
                      {t("refused: {code}", { code: refusal.code })}
                    </span>
                  ) : (
                    <div className="operations">
                      {member.role !== "faulty" && (
                        <ActionGuard action="raid.member.fail" host={hostID}>
                          <button
                            className="hm-danger"
                            onClick={() => onIntent({
                              action: "raid.member.fail",
                              label: t("Fail member"),
                              description: t("{member} will be marked failed and {array} will stop reading from it. This spends the redundancy of the array and needs two approvals.", {
                                member: member.path, array: array.path,
                              }),
                              payload: { storage: memberOrder(member) },
                            })}
                          >
                            {t("Fail")}
                          </button>
                        </ActionGuard>
                      )}
                      {!carriesData(member) && (
                        <ActionGuard action="raid.member.remove" host={hostID}>
                          <button
                            className="hm-danger"
                            onClick={() => onIntent({
                              action: "raid.member.remove",
                              label: t("Remove member"),
                              description: t("{member} will be taken out of {array}.", {
                                member: member.path, array: array.path,
                              }),
                              payload: { storage: memberOrder(member) },
                            })}
                          >
                            {t("Remove")}
                          </button>
                        </ActionGuard>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </Table>

      {array.uuid && (
        <FormActions>
          <ActionGuard action="raid.member.add" host={hostID}>
            <button
              className="secondary"
              onClick={() => onAdd({ array: array.path, expected_array_uuid: array.uuid ?? "" })}
            >
              {t("Add a member")}
            </button>
          </ActionGuard>
        </FormActions>
      )}
    </div>
  );
}

/**
 * What this host really has, for the fields of a storage order.
 *
 * The registry names no device, no array and no group, because each of
 * them is called something different on every machine and an order that
 * names the wrong one destroys what is on it. The page has just read the
 * host, so it offers exactly what the host reported - and nothing else.
 */
export function storageSuggestions(snapshot?: Snapshot): FieldSuggestions {
  if (!snapshot) return {};
  const paths = (values: (string | undefined)[]) =>
    Array.from(new Set(values.filter((value): value is string => !!value))).sort();
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
 * The form of one volume or array operation, drawn from the operation
 * registry.
 *
 * The screen does not know the shape of these orders: it hands the
 * registry the identity read off the row - the group's UUID, the volume's
 * UUID, the array's UUID - and the registry draws the fields, refuses what
 * the server would refuse and builds the payload. One description of an
 * operation, used by this page and by the Bulk wizard alike.
 */
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
  const problems = entry.validate(value);
  const ready = problems.length === 0 && json === "";

  return (
    <Section
      title={t(entry.title)}
      description={entry.note ? t(entry.note) : undefined}
      tools={<button className="secondary" onClick={onClose}>{t("Cancel")}</button>}
    >
      <Form>
        <OperationForm entry={entry} value={value} onChange={setValue}
          json={json} onJson={setJson} suggestions={suggestions} />
        <FormActions>
          <button
            disabled={!ready}
            onClick={() => onIntent({
              action,
              label: t(entry.title),
              description: t("{operation} on {target}.", { operation: entry.title, target: entry.summary(entry.toPayload(value)) }),
              payload: entry.toPayload(value),
            })}
          >
            {t("Order")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}

/**
 * The SMART state of one disk.
 *
 * The read goes through a job like every other read: the tool needs root
 * to talk to the device. A virtual disk, a USB bridge without passthrough
 * or a device the tool does not know comes back as unsupported with the
 * tool's own words - the panel shows that reason and invents no healthy
 * disk. Every counter is shown only when the device reported it.
 */
function SmartReport({ device, onClose }: { device: Device; onClose: () => void }) {
  const t = useT();
  const host = useHost();
  const read = useReadOperation<SmartResult>(host);
  const report = read.attempt?.detail;
  const refused = read.attempt && read.attempt.status !== "succeeded";
  const unknown = <span className="badge unknown">{t("unknown")}</span>;
  const attributes = report?.attributes ?? [];

  return (
    <Section
      title={t("SMART of {device}", { device: device.path })}
      description={device.model || device.serial ? `${device.model ?? ""} ${device.serial ?? ""}`.trim() : undefined}
      span={12}
      tools={
        <>
          <ActionGuard action="storage.smart.read" host={host.id} explain>
            <button onClick={() => read.order({ action: "storage.smart.read", payload: { storage: { device: device.path } } })} disabled={read.busy || host.connection_state !== "online"}>
              {read.busy ? t("Reading…") : read.ordered ? t("Read again") : t("Read SMART")}
            </button>
          </ActionGuard>
          <button className="secondary" onClick={onClose}>{t("Close")}</button>
        </>
      }
      flush
    >
      <Message text={read.message} error />
      {refused && (
        <Message text={read.attempt?.message || read.attempt?.error_code || t("The host refused the read.")} error />
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
            <Fact label={t("Serial")}><span className="hm-mono">{report.serial || "—"}</span></Fact>
            <Fact label={t("Temperature")}>{report.temperature_c !== undefined ? `${report.temperature_c} °C` : unknown}</Fact>
            <Fact label={t("Power-on hours")}>{report.power_on_hours !== undefined ? report.power_on_hours.toLocaleString() : unknown}</Fact>
            {/* A reallocated or a pending sector is the number that matters
                most: a disk that has started moving data is a disk to
                replace. Unknown stays unknown, never zero. */}
            <Fact label={t("Reallocated sectors")}>
              {report.reallocated_sectors === undefined ? unknown : <SectorCount count={report.reallocated_sectors} />}
            </Fact>
            <Fact label={t("Pending sectors")}>
              {report.pending_sectors === undefined ? unknown : <SectorCount count={report.pending_sectors} />}
            </Fact>
            <Fact label={t("Wear")}>{report.wear_percent !== undefined ? `${report.wear_percent}%` : unknown}</Fact>
          </Facts>
          {attributes.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <th className="hm-num">ID</th><th>{t("Attribute")}</th><th className="hm-num">{t("Value")}</th>
                  <th className="hm-num">{t("Worst")}</th><th className="hm-num">{t("Threshold")}</th><th className="hm-num">{t("Raw")}</th>
                </tr>
              </thead>
              <tbody>
                {attributes.map((attribute) => (
                  <tr key={attribute.id}>
                    <td className="hm-num">{attribute.id}</td>
                    <td className="hm-mono">
                      {attribute.name}
                      {attribute.failing && <span className="badge error"> {t("failing")}</span>}
                    </td>
                    <td className="hm-num">{attribute.value}</td>
                    <td className="hm-num">{attribute.worst}</td>
                    <td className="hm-num">{attribute.threshold}</td>
                    <td className="hm-num hm-mono">{attribute.raw_string || attribute.raw}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
          {report.output && (
            <div className="hm-section-body">
              <pre className="hm-log">{report.output}</pre>
            </div>
          )}
        </>
      )}
    </Section>
  );
}

/** The verdict of the tool: passed, failed, or unknown with the reason. */
function SmartHealth({ report }: { report: SmartResult }) {
  const t = useT();
  switch (report.health) {
    case "passed":
      return <span className="badge ok">{t("passed")}</span>;
    case "failed":
      return <span className="badge error">{t("failed")}{report.health_reason ? ` · ${report.health_reason}` : ""}</span>;
    default:
      return <span className="badge unknown">{t("unknown")}{report.health_reason ? ` · ${report.health_reason}` : ""}</span>;
  }
}

/** A sector count: zero is the good answer here, and anything else is a warning. */
function SectorCount({ count }: { count: number }) {
  return count === 0 ? <span className="badge ok">0</span> : <span className="badge error">{count}</span>;
}

/**
 * The device identity sent together with the operation. The host compares
 * it with its state and refuses at the first mismatch: /dev/sdX after a
 * reboot may point at a different disk than the one the operator is looking
 * at. The size is not sent as an identity: two disks of the same size prove
 * nothing about each other.
 */
export function identity(device: Device): Record<string, unknown> {
  return {
    device: device.path,
    expected_by_id: device.by_id ?? "",
    expected_wwn: device.wwn ?? "",
    expected_serial: device.serial ?? "",
    expected_uuid: device.uuid ?? "",
  };
}

/**
 * The mount wizard. The source is given by a durable identifier, because
 * the /dev/sdX name depends on the detection order and may point at a
 * different disk after a reboot.
 *
 * The identifiers are the host's own: the filesystems this host reported
 * are offered by their UUID, with the device and the type beside them, so
 * nobody has to copy a string out of another tab - and the panel suggests
 * no device of its own invention. Something the list does not hold, a
 * network filesystem among others, is still typed in by hand, which is
 * why this is a list beside the field rather than a closed choice.
 */
function MountWizard({ devices, onIntent }: { devices: Device[]; onIntent: (intent: Intent) => void }) {
  const t = useT();
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [type, setType] = useState("ext4");
  const [options, setOptions] = useState("defaults,nofail");
  const [persist, setPersist] = useState(true);
  // A filesystem the host reported and named by a UUID: that is what can
  // be mounted and what survives a reboot under the same name.
  const known = devices.filter((device) => device.uuid && device.fs_type);

  /* Choosing one of the host's own filesystems fills the type in as well:
     the host has already said what is on that device, and a type typed
     over it is a mount that fails for no reason the operator can see. */
  function chooseSource(value: string) {
    setSource(value);
    const found = known.find((device) => `UUID=${device.uuid}` === value || device.path === value);
    if (found?.fs_type) setType(found.fs_type);
  }

  return (
    <Section title={t("Mount a filesystem")}>
      <Form>
        <Fields>
          <Field
            label={t("Source")}
            help={known.length
              ? t("The filesystems this host reported are on the list; anything else is typed in as UUID=… or a path in /dev.")
              : t("The host has reported no filesystem with a durable identifier; write it as UUID=… or a path in /dev.")}
          >
            <input
              value={source}
              onChange={(e) => chooseSource(e.target.value)}
              list="mount-source"
              placeholder="UUID=… or /dev/mapper/…"
            />
            <datalist id="mount-source">
              {known.map((device) => (
                <option key={device.path} value={`UUID=${device.uuid}`}>
                  {`${device.path} · ${device.fs_type}${device.label ? ` · ${device.label}` : ""} · ${bytes(device.size_bytes)}`}
                </option>
              ))}
            </datalist>
          </Field>
          <Field label={t("Mount point")}>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={t("An absolute path on the host")} />
          </Field>
          <Field label={t("Filesystem type")} narrow>
            <input value={type} onChange={(e) => setType(e.target.value)} placeholder={t("Filesystem type")} />
          </Field>
          <Field label={t("Options")}>
            <input value={options} onChange={(e) => setOptions(e.target.value)} placeholder={t("Options")} />
          </Field>
        </Fields>
        {/* Without an fstab entry the mount disappears after a reboot; the
            operator is to know that before, not after the failure. */}
        <Check checked={persist} onChange={setPersist}>
          {t("Keep it after reboot (write an fstab entry)")}
        </Check>
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                action: "mount.ensure",
                label: t("Mount filesystem"),
                description: persist
                  ? t("{source} will be mounted at {target} as {type} and written to fstab.", { source, target, type })
                  : t("{source} will be mounted at {target} as {type} for this boot only.", { source, target, type }),
                payload: {
                  storage: { source, target, fs_type: type, options, persist },
                },
              })
            }
            disabled={!source || !target || !type}
          >
            {t("Mount")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
