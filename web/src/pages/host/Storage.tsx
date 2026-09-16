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
import { useT } from "../../i18n";

type Device = {
  name: string;
  path: string;
  type: string;
  size_bytes: number;
  fs_type?: string;
  label?: string;
  uuid?: string;
  model?: string;
  serial?: string;
  parent?: string;
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

type Snapshot = {
  devices?: Device[];
  mounts?: Mount[];
  groups?: { name: string; size_bytes: number; free_bytes: number; lv_count: number }[];
  volumes?: { name: string; group: string; path: string; size_bytes: number }[];
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

/**
 * The host's storage.
 *
 * The panel shows the kernel state and the fstab content separately: the
 * file says what is to be mounted after a reboot, not what is mounted now.
 * The difference between the two is usually the reason somebody opens this
 * tab.
 */
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
            <button className="secondary" onClick={() => setWizard((open) => !open)}>
              {wizard ? t("Cancel") : t("Mount a filesystem")}
            </button>
            <button
              onClick={() => request.mutate({ action: "storage.plan", payload: { storage: {} } })}
              disabled={request.isPending || host.connection_state !== "online"}
            >
              {t("Read from host")}
            </button>
          </>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Storage state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      {wizard && <MountWizard onIntent={setIntent} />}

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
        {snapshot?.raid_unavailable_reason && (
          <>
            <p className="widget-subhead">{t("Software RAID")}</p>
            <p className="source" style={{ margin: 0 }}>{t("No software RAID here: {reason}", { reason: snapshot.raid_unavailable_reason })}</p>
          </>
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
                {/* Identification goes by UUID and serial: /dev/sdX depends on
                    the detection order and points at another disk after a
                    reboot. */}
                <td
                  className="source hm-mono"
                  title={[
                    device.uuid ? `UUID=${device.uuid}` : "",
                    device.label ? `LABEL=${device.label}` : "",
                    device.model ?? "",
                    device.serial ? `${t("serial")} ${device.serial}` : "",
                  ].filter(Boolean).join(" · ") || undefined}
                >
                  {device.uuid ? `UUID=${device.uuid.slice(0, 13)}…` : ""}
                  {device.serial ? ` ${device.model ?? ""} ${device.serial}` : ""}
                  {!device.uuid && !device.serial && "—"}
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
                      )}
                      {device.fs_type && (
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
                      )}
                      {/* Formatting and wiping carry the device identity from
                          this row: the host refuses if it hits something else. */}
                      <button
                        className="hm-danger"
                        onClick={() =>
                          setIntent({
                            action: "filesystem.create",
                            label: t("Format device"),
                            description: t("Everything on {device} ({details}) will be destroyed and a new ext4 filesystem created. This needs two approvals.", {
                              device: device.path,
                              details: `${bytes(device.size_bytes)}${device.serial ? `, ${t("serial")} ${device.serial}` : ""}`,
                            }),
                            payload: {
                              storage: { ...identity(device), fs_type: "ext4" },
                            },
                          })
                        }
                      >
                        {t("Format")}
                      </button>
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
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      {smartOf && <SmartReport key={smartOf.path} device={smartOf} onClose={() => setSmartOf(null)} />}

      {/* The two LVM tables are narrow; side by side they fill the row. A
          host without LVM tools has no table to show: the devices card
          above says so, and an empty section would say it twice. */}
      {!snapshot?.lvm_unavailable_reason && (
      <Section title={t("Volume groups")} count={snapshot?.groups?.length} span={snapshot?.volumes?.length ? 6 : 12} flush>
        {!snapshot?.groups?.length ? (
          <Empty>{t("This host has LVM but no volume groups.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Group")}</th><th className="hm-num">{t("Size")}</th><th>{t("Allocated")}</th><th className="hm-num">{t("Free")}</th><th className="hm-num">{t("Volumes")}</th></tr></thead>
            <tbody>
              {snapshot.groups.map((group) => (
                <tr key={group.name}>
                  <td className="hm-mono hm-primary">{group.name}</td>
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
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      )}

      {snapshot?.volumes?.length ? (
        <Section title={t("Volumes")} count={snapshot.volumes.length} span={6} flush>
          <Table>
            <thead><tr><th>{t("Logical volume")}</th><th>{t("Group")}</th><th className="hm-num">{t("Size")}</th><th>{t("Actions")}</th></tr></thead>
            <tbody>
              {snapshot.volumes.map((volume) => (
                <tr key={volume.path}>
                  <td className="hm-mono hm-primary">{volume.path}</td>
                  <td className="hm-mono">{volume.group}</td>
                  <td className="hm-num">{bytes(volume.size_bytes)}</td>
                  <td>
                    {/* We extend upwards only and together with the
                        filesystem: a volume bigger than its filesystem gives
                        not a single byte. */}
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
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      ) : null}
      </Widgets>

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
          <button onClick={() => read.order({ action: "storage.smart.read", payload: { storage: { device: device.path } } })} disabled={read.busy || host.connection_state !== "online"}>
            {read.busy ? t("Reading…") : read.ordered ? t("Read again") : t("Read SMART")}
          </button>
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
 * at.
 */
function identity(device: Device): Record<string, unknown> {
  return {
    device: device.path,
    expected_serial: device.serial ?? "",
    expected_size_bytes: device.size_bytes,
    expected_uuid: device.uuid ?? "",
  };
}

/**
 * The mount wizard. The source is given by a durable identifier, because
 * the /dev/sdX name depends on the detection order and may point at a
 * different disk after a reboot.
 */
function MountWizard({ onIntent }: { onIntent: (intent: Intent) => void }) {
  const t = useT();
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [type, setType] = useState("ext4");
  const [options, setOptions] = useState("defaults,nofail");
  const [persist, setPersist] = useState(true);

  return (
    <Section title={t("Mount a filesystem")}>
      <Form>
        <Fields>
          <Field label={t("Source")}>
            <input
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="UUID=… or /dev/mapper/…"
            />
          </Field>
          <Field label={t("Mount point")}>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={t("Mount point, e.g. /mnt/data")} />
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
