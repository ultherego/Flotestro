import { useQuery } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { absoluteTime, bytes, relativeTime } from "../../../lib/format";
import type { Capability, Host, InventoryFragment, SystemHistoryEntry, SystemSnapshot } from "../../../lib/types";
import { adapterSegment, factReason, layoutText, uptimeText } from "../../../lib/host/system";
import { useT } from "../../../i18n";
import {
  Banner, Bones, C, Card, Empty, Fact, Facts, Grid, Kpi, Kpis, Meter, Pill, Readout, Table, Tabs, Tag,
  Tags, useTab, type Tone,
} from "../../kit";

/**
 * What the machine is: the processor, the memory, the firmware, the kernel
 * and the release.
 *
 * Everything here is read, and the one thing it must never do is turn a
 * fact nobody could read into a fact of none. A container has no DMI
 * tables; that is not a machine with an empty serial number, and the
 * reason the host gave travels with the word "unknown" rather than being
 * swallowed by an em dash.
 */

/** The sub-tabs of this screen, in the order a reader wants them. */
const SYSTEM_TABS = ["state", "hardware", "capabilities", "history"] as const;

/** How full the root filesystem is, and whether that is a condition. */
export function rootPressure(total?: number, free?: number): { share?: number; tone?: Tone } {
  if (total === undefined || free === undefined || total <= 0) return {};
  const share = (total - free) / total;
  return { share, tone: share > 0.9 ? "error" : share > 0.8 ? "warn" : "ok" };
}

/** The state of one adapter, as the three words the panel uses everywhere. */
export function adapterTone(capability: Capability): { tone: Tone; label: string } {
  if (!capability.available) return { tone: "neutral", label: "unavailable" };
  if (capability.read_only) return { tone: "warn", label: "read only" };
  return { tone: "ok", label: "available" };
}

export function System({ host }: { host: Host }) {
  const t = useT();
  const [tab, go] = useTab(SYSTEM_TABS);

  const module = useQuery({
    queryKey: ["inventory", host.id, "system"],
    queryFn: () => api.get<InventoryFragment<SystemSnapshot>>(`/api/v1/hosts/${host.id}/inventory/system`),
    retry: false,
  });
  const history = useQuery({
    queryKey: ["system-history", host.id],
    queryFn: () => api.get<{ items: SystemHistoryEntry[] }>(`/api/v1/hosts/${host.id}/system/history`),
    retry: false,
  });

  const snapshot = module.data?.payload;
  if (module.isLoading) return <Bones rows={6} />;
  if (!module.data || !snapshot) {
    return <Empty icon="server">{t("This host has not reported its platform yet.")}</Empty>;
  }

  const missing = snapshot.missing;
  /**
   * A value, or the reason nobody could read it.
   *
   * Three answers and not two: a fact the host refused to read says so
   * with the reason behind it, a fact read as empty is an em dash, and a
   * fact that was read is itself.
   */
  const fact = (key: string, value: string | number | undefined | null) => {
    const reason = factReason(missing, key);
    if (reason) return <Pill tone="unknown" title={reason}>{t("unknown")}</Pill>;
    if (value === undefined || value === null || value === "") return "—";
    return value;
  };

  const platformRead = Boolean(snapshot.observed_at);
  const uptime = snapshot.boot?.uptime_seconds;
  const virtualization = snapshot.virtualization?.kind;
  const root = rootPressure(snapshot.hardware?.root_fs_bytes, snapshot.hardware?.root_fs_free_bytes);
  const adapters = host.capabilities ?? [];
  const historyItems = history.data?.items ?? [];
  const notRead = Object.entries(missing ?? {});
  const flags = snapshot.cpu?.flags ?? [];

  const freshness = module.data
    ? t("Source: {source}, revision {revision}, observed {when}", {
        source: module.data.source,
        revision: module.data.revision.slice(0, 12),
        when: relativeTime(module.data.observed_at),
      })
    : undefined;

  return (
    <>
      {/* An agent from before the platform picture sends the basic facts
          alone; the screen says so once rather than drawing nine cards of
          unknowns and letting the reader guess why. */}
      {!platformRead && (
        <Banner tone="info">
          {t("This agent reports the basic facts only; the platform picture needs an agent with the system module.")}
        </Banner>
      )}
      {module.data.unavailable_reason && (
        <Banner tone="warn">
          {t("The platform could not be read: {reason}", { reason: module.data.unavailable_reason })}
        </Banner>
      )}

      <Kpis>
        <Kpi
          icon="time"
          label={t("Uptime")}
          value={uptime === undefined ? null : uptimeText(uptime)}
          note={snapshot.boot?.booted_at
            ? t("booted {when}", { when: absoluteTime(snapshot.boot.booted_at) })
            : undefined}
          testId="kpi-uptime"
        />
        <Kpi
          icon="kernel"
          label={t("Kernel")}
          value={snapshot.kernel?.release || snapshot.os?.kernel || null}
          note={snapshot.kernel?.architecture || snapshot.os?.architecture || undefined}
          testId="kpi-kernel"
        />
        <Kpi
          icon="server"
          label={t("Release")}
          value={snapshot.distribution?.pretty_name || snapshot.os?.pretty_name || null}
          note={snapshot.timezone || undefined}
          testId="kpi-release"
        />
        <Kpi
          icon="containers"
          label={t("Runs on")}
          value={virtualization ? (virtualization === "none" ? t("bare metal") : virtualization) : null}
          note={snapshot.virtualization?.source || undefined}
          testId="kpi-runs-on"
        />
      </Kpis>

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "state", label: t("System") },
          { value: "hardware", label: t("Hardware") },
          { value: "capabilities", label: t("Capabilities") },
          { value: "history", label: t("History") },
        ]}
      />

      {tab !== "history" && (
        <Grid>
          {tab === "state" && (
<C span={12}>
            <Card title={t("Operating system")} foot={freshness}>
              <Facts>
                <Fact label={t("Distribution")}>{fact("distribution", snapshot.distribution?.pretty_name || snapshot.os?.pretty_name)}</Fact>
                <Fact label={t("Identifier")}>{fact("distribution", snapshot.distribution?.id || snapshot.os?.distribution)}</Fact>
                <Fact label={t("Version")}>{fact("distribution", snapshot.distribution?.version || snapshot.os?.version)}</Fact>
                <Fact label={t("Codename")}>{fact("distribution", snapshot.distribution?.codename || snapshot.os?.codename)}</Fact>
                <Fact label={t("Family")}>{snapshot.os?.family || "—"}</Fact>
                <Fact label={t("Like")}>{(snapshot.distribution?.like ?? []).join(", ") || "—"}</Fact>
                <Fact label={t("Timezone")}>{fact("timezone", snapshot.timezone)}</Fact>
                <Fact label={t("Hostname")}>{snapshot.hostname || "—"}</Fact>
              </Facts>
            </Card>
          </C>
)}
          {tab === "state" && (
<C span={12}>
            <Card title={t("Kernel")}>
              <Facts>
                <Fact label={t("Release")}>{fact("kernel", snapshot.kernel?.release || snapshot.os?.kernel)}</Fact>
                <Fact label={t("Architecture")}>{fact("kernel", snapshot.kernel?.architecture || snapshot.os?.architecture)}</Fact>
                <Fact label={t("Build")}>{fact("kernel", snapshot.kernel?.version)}</Fact>
              </Facts>
              {/* The command line is read as one line and copied as one line:
                  broken across two it stops being the thing a reader pastes
                  into a bug report. */}
              {factReason(missing, "kernel.cmdline")
                ? <Facts><Fact label={t("Command line")}>{fact("kernel.cmdline", undefined)}</Fact></Facts>
                : snapshot.kernel?.cmdline
                  ? <Readout label={t("Command line")} value={snapshot.kernel.cmdline} lines={3} testId="kernel-cmdline" />
                  : <Facts><Fact label={t("Command line")}>—</Fact></Facts>}
            </Card>
          </C>
)}
          {tab === "hardware" && (
<C span={12}>
            <Card
              title={t("Processor")}
              foot={snapshot.cpu?.flag_count !== undefined
                ? t("{count} flags in total", { count: snapshot.cpu.flag_count })
                : undefined}
            >
              <Facts>
                <Fact label={t("Model")}>{fact("cpu", snapshot.cpu?.model)}</Fact>
                <Fact label={t("Vendor")}>{fact("cpu", snapshot.cpu?.vendor)}</Fact>
                <Fact label={t("Layout")}>{fact("cpu", layoutText(snapshot.cpu))}</Fact>
                <Fact label={t("Frequency")}>
                  {snapshot.cpu?.mhz !== undefined ? t("{n} MHz", { n: Math.round(snapshot.cpu.mhz) }) : "—"}
                </Fact>
                <Fact label={t("Logical processors")}>{snapshot.hardware?.cpu_cores ?? "—"}</Fact>
                <Fact label={t("Flags")}>
                  {factReason(missing, "cpu")
                    ? fact("cpu", undefined)
                    : flags.length === 0
                      ? "—"
                      : <Tags>{flags.map((flag) => <Tag key={flag}>{flag}</Tag>)}</Tags>}
                </Fact>
              </Facts>
            </Card>
          </C>
)}
          {tab === "hardware" && (
<C span={12}>
            <Card title={t("Memory and root filesystem")}>
              <Facts>
                <Fact label={t("Memory")}>
                  {fact("memory", snapshot.memory?.total_bytes !== undefined ? bytes(snapshot.memory.total_bytes) : undefined)}
                </Fact>
                <Fact label={t("Swap")}>
                  {factReason(missing, "memory")
                    ? fact("memory", undefined)
                    : snapshot.memory?.swap_total_bytes === undefined
                      ? "—"
                      : snapshot.memory.swap_total_bytes === 0
                        ? t("none")
                        : bytes(snapshot.memory.swap_total_bytes)}
                </Fact>
                <Fact label={t("Root filesystem")}>
                  {root.share === undefined
                    ? (snapshot.hardware?.root_fs_bytes ? bytes(snapshot.hardware.root_fs_bytes) : "—")
                    : (
                      <Meter
                        share={root.share}
                        tone={root.tone}
                        text={t("{free} free of {total}", {
                          free: bytes(snapshot.hardware?.root_fs_free_bytes ?? 0),
                          total: bytes(snapshot.hardware?.root_fs_bytes ?? 0),
                        })}
                      />
                    )}
                </Fact>
              </Facts>
            </Card>
          </C>
)}
          {tab === "hardware" && (
<C span={12}>
            <Card
              title={t("Machine")}
              note={t("The identity from the DMI tables. The serial numbers and the UUID are readable by root alone, so they come through the helper.")}
            >
              <Facts>
                <Fact label={t("Vendor")}>{fact("dmi", snapshot.dmi?.vendor)}</Fact>
                <Fact label={t("Product")}>{fact("dmi", snapshot.dmi?.product)}</Fact>
                <Fact label={t("Version")}>{fact("dmi", snapshot.dmi?.version)}</Fact>
                <Fact label={t("Family")}>{fact("dmi", snapshot.dmi?.family)}</Fact>
                <Fact label={t("Board")}>
                  {fact("dmi", [snapshot.dmi?.board_vendor, snapshot.dmi?.board_name].filter(Boolean).join(" "))}
                </Fact>
                <Fact label={t("Chassis")}>{fact("dmi", snapshot.dmi?.chassis_type)}</Fact>
                <Fact label={t("Serial number")} mono>{fact("dmi.serial", snapshot.dmi?.serial)}</Fact>
                <Fact label={t("UUID")} mono>{fact("dmi.uuid", snapshot.dmi?.uuid)}</Fact>
                <Fact label={t("Board serial")} mono>{fact("dmi.serial", snapshot.dmi?.board_serial)}</Fact>
                <Fact label={t("Chassis serial")} mono>{fact("dmi.serial", snapshot.dmi?.chassis_serial)}</Fact>
              </Facts>
            </Card>
          </C>
)}
          {tab === "hardware" && (
<C span={12}>
            <Card title={t("Firmware and boot")}>
              <Facts>
                <Fact label={t("Boot mode")}>
                  {factReason(missing, "firmware")
                    ? fact("firmware", undefined)
                    : snapshot.firmware?.mode === "uefi" ? "UEFI"
                      : snapshot.firmware?.mode === "bios" ? "BIOS" : "—"}
                </Fact>
                <Fact label={t("Firmware vendor")}>{fact("firmware", snapshot.firmware?.vendor)}</Fact>
                <Fact label={t("Firmware version")}>{fact("firmware", snapshot.firmware?.version)}</Fact>
                <Fact label={t("Firmware date")}>{fact("firmware", snapshot.firmware?.date)}</Fact>
                <Fact label={t("Booted")}>
                  {snapshot.boot?.booted_at
                    ? <span title={absoluteTime(snapshot.boot.booted_at)}>{relativeTime(snapshot.boot.booted_at)}</span>
                    : fact("boot", undefined)}
                </Fact>
                {/* The uptime is as old as the read, so the read's own instant
                    stands beside it: the two can then never disagree by the
                    age of the snapshot. */}
                <Fact label={t("Uptime")}>
                  {uptime === undefined
                    ? fact("boot", undefined)
                    : <span title={t("as of the last read")}>{uptimeText(uptime)}</span>}
                </Fact>
                <Fact label={t("Boot id")} mono>{snapshot.boot_id || "—"}</Fact>
                <Fact label={t("Virtualization")}>
                  {fact("virtualization", virtualization === "none" ? t("bare metal") : virtualization)}
                </Fact>
              </Facts>
            </Card>
          </C>
)}
          {tab === "capabilities" && (
<C span={12}>
            <Card
              title={t("Detected capabilities")}
              note={t("The adapters the other modules stand on, and the reason where one is missing.")}
              flush
            >
              <Table
                rows={adapters}
                keyOf={(one) => one.name}
                testId="adapters"
                empty={t("The host has not reported its adapters.")}
                columns={[
                  {
                    key: "adapter", head: t("Adapter"), tight: true, cell: (one) => {
                      const segment = adapterSegment(one.name);
                      return segment
                        ? <Tag to={`/hosts/${host.id}/${segment}`}>{one.name}</Tag>
                        : one.name;
                    },
                  },
                  {
                    key: "state", head: t("State"), cell: (one) => {
                      const state = adapterTone(one);
                      return <Pill tone={state.tone}>{t(state.label)}</Pill>;
                    },
                  },
                  { key: "reason", head: t("Reason"), minor: true, cell: (one) => one.reason || "—" },
                ]}
              />
            </Card>
          </C>
)}
          {/* The facts that could not be read, each with its reason. A
              container without DMI is not a machine with an empty serial,
              and this is the card that says which of the two this host is. */}
          {tab === "hardware" && notRead.length > 0 && (
<C span={12}>
              <Card title={t("Not read")} note={t("What the host could not read, and why.")} flush>
                <Table
                  rows={notRead}
                  keyOf={([key]) => key}
                  testId="not-read"
                  columns={[
                    { key: "fact", head: t("Fact"), tight: true, cell: ([key]) => key },
                    { key: "reason", head: t("Reason"), cell: ([, reason]) => reason },
                  ]}
                />
              </Card>
            </C>
          )}
        </Grid>
      )}

      {tab === "history" && (
        <Grid>
          <C span={12}>
            <Card
              title={t("Kernel and release history")}
              note={t("Every kernel and release the panel has seen this host report, newest first; the panel keeps the last twenty.")}
              foot={t("The current kernel and release are the top row; a row below it is what the host ran before.")}
              flush
            >
              {history.error
                ? <Empty icon="help">{t("The history could not be read.")}</Empty>
                : (
                  <Table
                    rows={historyItems}
                    keyOf={(one) => `${one.kernel}/${one.distribution}/${one.distribution_version}`}
                    loading={history.isLoading}
                    empty={t("No platform has been recorded for this host yet.")}
                    testId="system-history"
                    columns={[
                      { key: "kernel", head: t("Kernel"), tight: true, cell: (one) => one.kernel || "—" },
                      {
                        key: "release", head: t("Release"),
                        cell: (one) => [one.distribution, one.distribution_version].filter(Boolean).join(" ") || "—",
                      },
                      {
                        key: "first", head: t("First seen"), minor: true,
                        cell: (one) => <span title={absoluteTime(one.first_seen_at)}>{relativeTime(one.first_seen_at)}</span>,
                      },
                      {
                        key: "last", head: t("Last seen"),
                        cell: (one) => <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>,
                      },
                    ]}
                  />
                )}
            </Card>
          </C>
        </Grid>
      )}
    </>
  );
}
