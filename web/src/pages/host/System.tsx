import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { SystemHistoryEntry, SystemSnapshot } from "../../lib/types";
import { Time as Timestamp, Empty } from "../../components/ui";
import { Meter } from "../../components/widgets";
import { absoluteTime, bytes } from "../../lib/format";
import {
  Fact, Facts, Foot, ModuleFreshness, ModuleHeader, ModulePage, Section, Table, Unknown, Widgets,
  usageTone, useHost, useModule,
} from "./shared";
import { adapterSegment } from "./Overview";
import { useT } from "../../i18n";

/**
 * The reason a fact is missing, or nothing when the fact was read. A fact
 * inherits the reason of its parent: "dmi.serial" is unknown for the same
 * reason "dmi" is when the host has no DMI tables at all.
 */
export function factReason(missing: Record<string, string> | undefined, fact: string): string | undefined {
  if (!missing) return undefined;
  let key = fact;
  for (;;) {
    if (missing[key]) return missing[key];
    const dot = key.lastIndexOf(".");
    if (dot < 0) return undefined;
    key = key.slice(0, dot);
  }
}

/** Days, hours and minutes from a count of seconds: "3 d 4 h 5 min". */
export function uptimeText(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days} d`);
  if (days > 0 || hours > 0) parts.push(`${hours} h`);
  parts.push(`${minutes} min`);
  return parts.join(" ");
}

/**
 * The processor layout in one phrase: "2 sockets × 4 cores, 16 threads".
 * A layout the host did not describe - most virtual machines, every ARM
 * board - is the thread count alone, never "0 sockets".
 */
export function layoutText(cpu: { sockets?: number; cores?: number; threads?: number } | undefined): string {
  if (!cpu) return "";
  const parts: string[] = [];
  if (cpu.sockets !== undefined && cpu.cores !== undefined && cpu.sockets > 0) {
    const perSocket = Math.round(cpu.cores / cpu.sockets);
    parts.push(`${cpu.sockets} ${cpu.sockets === 1 ? "socket" : "sockets"} × ${perSocket} ${perSocket === 1 ? "core" : "cores"}`);
  } else if (cpu.cores !== undefined) {
    parts.push(`${cpu.cores} ${cpu.cores === 1 ? "core" : "cores"}`);
  }
  if (cpu.threads !== undefined) parts.push(`${cpu.threads} ${cpu.threads === 1 ? "thread" : "threads"}`);
  return parts.join(", ");
}

/**
 * The platform of the host: what the machine is, as procfs, sysfs and the
 * DMI tables say. Everything here is static - it changes when somebody
 * changes the machine - so the page says when it was last read and keeps
 * the kernels and releases the panel has seen the host on.
 */
export function System() {
  const t = useT();
  const host = useHost();
  const module = useModule<SystemSnapshot>(host.id, "system");
  const history = useQuery({
    queryKey: ["system-history", host.id],
    queryFn: () => api.get<{ items: SystemHistoryEntry[] }>(`/api/v1/hosts/${host.id}/system/history`),
    retry: false,
  });

  const snapshot = module.data?.payload;
  if (!module.data || !snapshot) return <Empty>{t("This host has not reported its platform yet.")}</Empty>;

  const missing = snapshot.missing;
  /** A value, or the reason it is unknown; an empty string that was read is a dash. */
  const fact = (key: string, value: string | number | undefined | null) => {
    const reason = factReason(missing, key);
    if (reason) return <span className="badge unknown" title={reason}>{t("unknown")}</span>;
    if (value === undefined || value === null || value === "") return "—";
    return value;
  };
  const platformRead = Boolean(snapshot.observed_at);
  const uptime = snapshot.boot?.uptime_seconds;
  const virtualization = snapshot.virtualization?.kind;
  const historyItems = history.data?.items ?? [];

  return (
    <ModulePage>
      <ModuleHeader
        title={t("System")}
        description={t("What the machine is: the processor, the memory, the firmware, the kernel and the release. Static facts, read every six hours and after a boot.")}
      />
      <ModuleFreshness fragment={module.data} />

      {/* An agent from before the platform picture sends the basic facts
          alone; the page says so rather than showing every section as
          unknown for no reason. */}
      {!platformRead && (
        <p className="warning">
          <span>{t("This agent reports the basic facts only; the platform picture needs an agent with the system module.")}</span>
        </p>
      )}

      <Widgets>
      {/* The four facts the operator asks first, read before the sections
          below: which kernel, which release, since when, and on what. */}
      <Section title={t("At a glance")} span={12} flush>
        <Facts>
          <Fact label={t("Kernel")}>
            <span className="hm-mono">{snapshot.kernel?.release || snapshot.os?.kernel || <Unknown />}</span>
            {(snapshot.kernel?.architecture || snapshot.os?.architecture) && (
              <span className="source"> · {snapshot.kernel?.architecture || snapshot.os?.architecture}</span>
            )}
          </Fact>
          <Fact label={t("Release")}>
            {snapshot.distribution?.pretty_name || snapshot.os?.pretty_name || <Unknown />}
          </Fact>
          {/* The uptime is as old as the read; beside it the boot instant
              itself, absolute, so the two never disagree by the age of
              the snapshot. */}
          <Fact label={t("Uptime")}>
            {uptime === undefined ? <Unknown /> : <span title={t("as of the last read")}>{uptimeText(uptime)}</span>}
            {snapshot.boot?.booted_at && <span className="source"> · {t("since")} {absoluteTime(snapshot.boot.booted_at)}</span>}
          </Fact>
          <Fact label={t("Runs on")}>
            {virtualization ? (virtualization === "none" ? t("bare metal") : virtualization) : <Unknown />}
            {snapshot.virtualization?.source && <span className="source"> · {snapshot.virtualization.source}</span>}
          </Fact>
        </Facts>
      </Section>

      <Section title={t("Operating system")} span={6} flush>
        <Facts>
          <Fact label={t("Distribution")}>{fact("distribution", snapshot.distribution?.pretty_name || snapshot.os?.pretty_name)}</Fact>
          <Fact label={t("Identifier")}><span className="hm-mono">{fact("distribution", snapshot.distribution?.id || snapshot.os?.distribution)}</span></Fact>
          <Fact label={t("Version")}>{fact("distribution", snapshot.distribution?.version || snapshot.os?.version)}</Fact>
          <Fact label={t("Codename")}>{fact("distribution", snapshot.distribution?.codename || snapshot.os?.codename)}</Fact>
          <Fact label={t("Family")}>{snapshot.os?.family || "—"}</Fact>
          <Fact label={t("Like")}>{(snapshot.distribution?.like ?? []).join(", ") || "—"}</Fact>
          <Fact label={t("Timezone")}>{fact("timezone", snapshot.timezone)}</Fact>
          <Fact label={t("Hostname")}><span className="hm-mono">{snapshot.hostname || "—"}</span></Fact>
        </Facts>
      </Section>

      <Section title={t("Kernel")} span={6} flush>
        <Facts>
          <Fact label={t("Release")}><span className="hm-mono">{fact("kernel", snapshot.kernel?.release || snapshot.os?.kernel)}</span></Fact>
          <Fact label={t("Architecture")}>{fact("kernel", snapshot.kernel?.architecture || snapshot.os?.architecture)}</Fact>
          <Fact label={t("Build")} wide>{fact("kernel", snapshot.kernel?.version)}</Fact>
          <Fact label={t("Command line")} wide>
            {factReason(missing, "kernel.cmdline")
              ? fact("kernel.cmdline", undefined)
              : <code className="hm-mono">{snapshot.kernel?.cmdline || "—"}</code>}
          </Fact>
        </Facts>
      </Section>

      <Section title={t("Processor")} span={6} flush>
        <Facts>
          <Fact label={t("Model")} wide>{fact("cpu", snapshot.cpu?.model)}</Fact>
          <Fact label={t("Vendor")}>{fact("cpu", snapshot.cpu?.vendor)}</Fact>
          <Fact label={t("Layout")}>{fact("cpu", layoutText(snapshot.cpu))}</Fact>
          <Fact label={t("Frequency")}>{snapshot.cpu?.mhz !== undefined ? `${Math.round(snapshot.cpu.mhz)} MHz` : "—"}</Fact>
          <Fact label={t("Logical processors")}>{snapshot.hardware?.cpu_cores ?? "—"}</Fact>
          {/* The flags an operator asks about - virtualization, crypto,
              vector instructions, mitigations - and the size of the whole
              list, which the page does not show. */}
          <Fact label={t("Flags")} wide>
            {factReason(missing, "cpu")
              ? fact("cpu", undefined)
              : (
                <>
                  {(snapshot.cpu?.flags ?? []).map((flag) => <span key={flag} className="badge">{flag}</span>)}
                  {snapshot.cpu?.flag_count !== undefined && (
                    <span className="source"> {t("{count} flags in total", { count: snapshot.cpu.flag_count })}</span>
                  )}
                </>
              )}
          </Fact>
        </Facts>
      </Section>

      <Section title={t("Memory and root filesystem")} span={6} flush>
        <Facts>
          <Fact label={t("Memory")}>{fact("memory", snapshot.memory?.total_bytes !== undefined ? bytes(snapshot.memory.total_bytes) : undefined)}</Fact>
          <Fact label={t("Swap")}>
            {factReason(missing, "memory")
              ? fact("memory", undefined)
              : snapshot.memory?.swap_total_bytes === undefined ? "—" : snapshot.memory.swap_total_bytes === 0 ? t("none") : bytes(snapshot.memory.swap_total_bytes)}
          </Fact>
          <Fact label={t("Root filesystem")} wide>
            {snapshot.hardware?.root_fs_bytes && snapshot.hardware.root_fs_free_bytes !== undefined ? (
              <Meter
                value={snapshot.hardware.root_fs_bytes - snapshot.hardware.root_fs_free_bytes}
                max={snapshot.hardware.root_fs_bytes}
                tone={usageTone(snapshot.hardware.root_fs_bytes - snapshot.hardware.root_fs_free_bytes, snapshot.hardware.root_fs_bytes)}
                text={t("{free} free of {total}", { free: bytes(snapshot.hardware.root_fs_free_bytes), total: bytes(snapshot.hardware.root_fs_bytes) })}
              />
            ) : snapshot.hardware?.root_fs_bytes ? bytes(snapshot.hardware.root_fs_bytes) : "—"}
          </Fact>
        </Facts>
      </Section>

      <Section
        title={t("Machine")}
        description={t("The identity from the DMI tables. The serial numbers and the UUID are readable by root alone, so they come through the helper.")}
        span={6}
        flush
      >
        <Facts>
          <Fact label={t("Vendor")}>{fact("dmi", snapshot.dmi?.vendor)}</Fact>
          <Fact label={t("Product")}>{fact("dmi", snapshot.dmi?.product)}</Fact>
          <Fact label={t("Version")}>{fact("dmi", snapshot.dmi?.version)}</Fact>
          <Fact label={t("Family")}>{fact("dmi", snapshot.dmi?.family)}</Fact>
          <Fact label={t("Board")}>{fact("dmi", [snapshot.dmi?.board_vendor, snapshot.dmi?.board_name].filter(Boolean).join(" "))}</Fact>
          <Fact label={t("Chassis")}>{fact("dmi", snapshot.dmi?.chassis_type)}</Fact>
          <Fact label={t("Serial number")}><span className="hm-mono">{fact("dmi.serial", snapshot.dmi?.serial)}</span></Fact>
          <Fact label={t("UUID")}><span className="hm-mono">{fact("dmi.uuid", snapshot.dmi?.uuid)}</span></Fact>
          <Fact label={t("Board serial")}><span className="hm-mono">{fact("dmi.serial", snapshot.dmi?.board_serial)}</span></Fact>
          <Fact label={t("Chassis serial")}><span className="hm-mono">{fact("dmi.serial", snapshot.dmi?.chassis_serial)}</span></Fact>
        </Facts>
      </Section>

      <Section title={t("Firmware and boot")} span={6} flush>
        <Facts>
          <Fact label={t("Boot mode")}>
            {factReason(missing, "firmware")
              ? fact("firmware", undefined)
              : snapshot.firmware?.mode === "uefi" ? "UEFI" : snapshot.firmware?.mode === "bios" ? "BIOS" : "—"}
          </Fact>
          <Fact label={t("Firmware vendor")}>{fact("firmware", snapshot.firmware?.vendor)}</Fact>
          <Fact label={t("Firmware version")}>{fact("firmware", snapshot.firmware?.version)}</Fact>
          <Fact label={t("Firmware date")}>{fact("firmware", snapshot.firmware?.date)}</Fact>
          <Fact label={t("Booted")}>{snapshot.boot?.booted_at ? <Timestamp value={snapshot.boot.booted_at} /> : fact("boot", undefined)}</Fact>
          <Fact label={t("Uptime")}>{uptime === undefined ? fact("boot", undefined) : uptimeText(uptime)}</Fact>
          <Fact label={t("Boot id")}><span className="hm-mono">{snapshot.boot_id || "—"}</span></Fact>
          <Fact label={t("Virtualization")}>
            {fact("virtualization", virtualization === "none" ? t("bare metal") : virtualization)}
            {snapshot.virtualization?.source && <span className="source"> · {snapshot.virtualization.source}</span>}
          </Fact>
        </Facts>
      </Section>

      {/* What the agent found on the host: the adapters the other modules
          stand on, with the reason where one is missing. */}
      <Section title={t("Detected capabilities")} count={(host.capabilities ?? []).length} span={6} flush>
        <Table>
          <thead><tr><th>{t("Adapter")}</th><th>{t("State")}</th><th>{t("Reason")}</th></tr></thead>
          <tbody>
            {(host.capabilities ?? []).length === 0 ? (
              <tr><td colSpan={3} className="empty">{t("The host has not reported its adapters.")}</td></tr>
            ) : (host.capabilities ?? []).map((capability) => (
              <tr key={capability.name}>
                <td className="hm-mono hm-primary">
                  {adapterSegment(capability.name)
                    ? <Link to={`/hosts/${host.id}/${adapterSegment(capability.name)}`}>{capability.name}</Link>
                    : capability.name}
                </td>
                {/* The same three states as the overview: a read-only
                    adapter is available, and the reason says what it
                    would take to write. */}
                <td>
                  {!capability.available
                    ? <span className="badge">{t("unavailable")}</span>
                    : capability.read_only
                      ? <span className="badge warn">{t("read only")}</span>
                      : <span className="badge ok">{t("available")}</span>}
                </td>
                <td>{capability.reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      {/* The kernels and releases the panel has seen this host on: a host
          that came up on another kernel is a row here, not a diff the
          operator has to remember. */}
      <Section
        title={t("Kernel and release history")}
        count={historyItems.length}
        description={t("Every kernel and release the panel has seen this host report, newest first; the panel keeps the last twenty.")}
        span={6}
        flush
      >
        <Table>
          <thead><tr><th>{t("Kernel")}</th><th>{t("Release")}</th><th>{t("First seen")}</th><th>{t("Last seen")}</th></tr></thead>
          <tbody>
            {history.error ? (
              <tr><td colSpan={4} className="empty">{t("The history could not be read.")}</td></tr>
            ) : historyItems.length === 0 ? (
              <tr><td colSpan={4} className="empty">{t("No platform has been recorded for this host yet.")}</td></tr>
            ) : historyItems.map((entry) => (
              <tr key={`${entry.kernel}/${entry.distribution}/${entry.distribution_version}`}>
                <td className="hm-mono hm-primary">{entry.kernel || "—"}</td>
                <td>{[entry.distribution, entry.distribution_version].filter(Boolean).join(" ") || "—"}</td>
                <td><Timestamp value={entry.first_seen_at} /></td>
                <td><Timestamp value={entry.last_seen_at} /></td>
              </tr>
            ))}
          </tbody>
        </Table>
        <Foot>{t("The current kernel and release are the top row; a row below it is what the host ran before.")}</Foot>
      </Section>

      {/* The facts that could not be read, each with its reason: a
          container without DMI is not a machine with an empty serial. */}
      {missing && Object.keys(missing).length > 0 && (
        <Section title={t("Not read")} count={Object.keys(missing).length} span={12} flush>
          <Table>
            <thead><tr><th>{t("Fact")}</th><th>{t("Reason")}</th></tr></thead>
            <tbody>
              {Object.entries(missing).map(([key, reason]) => (
                <tr key={key}><td className="hm-mono">{key}</td><td>{reason}</td></tr>
              ))}
            </tbody>
          </Table>
        </Section>
      )}
      </Widgets>

      {snapshot.observed_at && (
        <p className="hm-freshness">
          <span>{t("Platform read")} <Timestamp value={snapshot.observed_at} /></span>
        </p>
      )}
    </ModulePage>
  );
}
