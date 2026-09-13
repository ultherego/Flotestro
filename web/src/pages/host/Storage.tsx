import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { ModuleFreshness, useHost, useModule } from "./shared";
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
  const [intent, setIntent] = useState<Intent | null>(null);
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
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its storage yet.")}</Empty>;

  return (
    <>
      <p className="subtitle">
        {t("Devices from the kernel, mounts from mountinfo, persistence from fstab — kept apart on purpose: the file says what should be mounted after a reboot, not what is mounted now.")}
      </p>

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Storage state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <div className="filters">
        <button
          onClick={() => request.mutate({ action: "storage.plan", payload: { storage: {} } })}
          disabled={request.isPending || host.connection_state !== "online"}
        >
          {t("Read from host")}
        </button>
        <button className="secondary" onClick={() => setWizard((open) => !open)}>
          {wizard ? t("Cancel") : t("Mount a filesystem")}
        </button>
      </div>

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}
      {wizard && <MountWizard onIntent={setIntent} />}

      <h2>{t("Mounts")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t("Mount point")}</th><th>{t("Source")}</th><th>{t("Type")}</th><th>{t("State")}</th>
            <th>{t("Space used")}</th><th>{t("Inodes used")}</th><th>{t("Owner")}</th><th>{t("Actions")}</th>
          </tr>
        </thead>
        <tbody>
          {(snapshot?.mounts ?? []).map((mount) => (
            <tr key={mount.target}>
              <td>{mount.target}</td>
              <td title={mount.source}>{mount.source.slice(0, 40)}</td>
              <td>{mount.fs_type}</td>
              {/* The four "mounted / in fstab" combinations mean four
                  different things, and all of them matter to the operator. */}
              <td>
                {mount.mounted && mount.in_fstab && t("mounted, persistent")}
                {mount.mounted && !mount.in_fstab && (
                  <span className="badge unknown">{t("mounted, gone after reboot")}</span>
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
                  <>
                    {mount.used_percent}%
                    {mount.size_bytes !== undefined && (
                      <span className="source"> {t("of {size}", { size: bytes(mount.size_bytes) })}</span>
                    )}
                  </>
                )}
              </td>
              <td>
                {mount.inodes_used_percent === undefined ? (
                  unknown
                ) : (
                  `${mount.inodes_used_percent}%`
                )}
              </td>
              <td>{mount.managed ? "Flotestro" : <span className="badge unknown">{t("host admin")}</span>}</td>
              <td>
                {mount.managed && mount.mounted && (
                  <button
                    className="secondary"
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
      </table>

      <h2>{t("Devices")}</h2>
      <table>
        <thead>
          <tr><th>{t("Device")}</th><th>{t("Type")}</th><th>{t("Size")}</th><th>{t("Filesystem")}</th><th>{t("Mounted at")}</th><th>{t("Identity")}</th><th>{t("Actions")}</th></tr>
        </thead>
        <tbody>
          {(snapshot?.devices ?? []).map((device) => (
            <tr key={device.path}>
              {/* The indentation reflects the disk -> partition -> volume topology. */}
              <td style={{ paddingLeft: device.parent ? 24 : undefined }}>
                {device.path}
                {device.read_only && <span className="badge"> {t("read-only")}</span>}
              </td>
              <td>{device.type}</td>
              <td>{bytes(device.size_bytes)}</td>
              <td>
                {device.fs_type || "—"}
                {device.fs_size_bytes !== undefined && device.fs_size_bytes < device.size_bytes && (
                  <span className="source"> · fs {bytes(device.fs_size_bytes)}</span>
                )}
              </td>
              <td>{(device.mountpoints ?? []).join(", ") || "—"}</td>
              {/* Identification goes by UUID and serial: /dev/sdX depends on
                  the detection order and points at another disk after a
                  reboot. */}
              <td className="source">
                {device.uuid ? `UUID=${device.uuid.slice(0, 13)}…` : ""}
                {device.serial ? ` ${device.model ?? ""} ${device.serial}` : ""}
                {!device.uuid && !device.serial && "—"}
              </td>
              <td>
                {/* Operations on a device make sense only when nothing sits
                    on it - and the host checks that once more anyway. */}
                {(device.mountpoints ?? []).length === 0 && (
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
                      className="secondary"
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
                      className="secondary"
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
      </table>

      <h2>{t("Volume groups")}</h2>
      {snapshot?.lvm_unavailable_reason ? (
        <Empty>{snapshot.lvm_unavailable_reason}</Empty>
      ) : !snapshot?.groups?.length ? (
        <Empty>{t("This host has LVM but no volume groups.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Group")}</th><th>{t("Size")}</th><th>{t("Free")}</th><th>{t("Volumes")}</th></tr></thead>
          <tbody>
            {snapshot.groups.map((group) => (
              <tr key={group.name}>
                <td>{group.name}</td>
                <td>{bytes(group.size_bytes)}</td>
                {/* Zero free space decides whether anything can be extended
                    - and it is a number, not an absence. */}
                <td>{bytes(group.free_bytes)}</td>
                <td>{group.lv_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {snapshot?.volumes?.length ? (
        <table>
          <thead><tr><th>{t("Logical volume")}</th><th>{t("Group")}</th><th>{t("Size")}</th><th>{t("Actions")}</th></tr></thead>
          <tbody>
            {snapshot.volumes.map((volume) => (
              <tr key={volume.path}>
                <td>{volume.path}</td>
                <td>{volume.group}</td>
                <td>{bytes(volume.size_bytes)}</td>
                <td>
                  {/* We extend upwards only and together with the
                      filesystem: a volume bigger than its filesystem gives
                      not a single byte. */}
                  <button
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
        </table>
      ) : null}

      {snapshot?.raid_unavailable_reason && (
        <p className="source">{snapshot.raid_unavailable_reason}</p>
      )}

      <ModuleFreshness fragment={module.data} />
      {snapshot?.observed_at && (
        <p className="source">
          {t("Storage read")} <Time value={snapshot.observed_at} />
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
    </>
  );
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
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("Mount a filesystem")}</h2>
      <div className="filters">
        <input
          value={source}
          onChange={(e) => setSource(e.target.value)}
          placeholder="UUID=… or /dev/mapper/…"
          style={{ minWidth: 300 }}
        />
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={t("Mount point, e.g. /mnt/data")} />
        <input value={type} onChange={(e) => setType(e.target.value)} placeholder={t("Filesystem type")} style={{ width: 120 }} />
        <input value={options} onChange={(e) => setOptions(e.target.value)} placeholder={t("Options")} />
      </div>
      {/* Without an fstab entry the mount disappears after a reboot; the
          operator is to know that before, not after the failure. */}
      <label className="toggle">
        <input type="checkbox" checked={persist} onChange={(e) => setPersist(e.target.checked)} />
        {t("Keep it after reboot (write an fstab entry)")}
      </label>
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
    </div>
  );
}
