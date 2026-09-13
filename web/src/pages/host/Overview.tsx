import { Time, OptionalFlag, OptionalNumber, Pair, Pairs, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { useT } from "../../i18n";

type SystemState = {
  os?: Record<string, string>;
  hardware?: {
    cpu_cores?: number;
    memory_bytes?: number;
    root_fs_bytes?: number;
    root_fs_free_bytes?: number;
    virtualization?: string;
  };
};

export function Overview() {
  const t = useT();
  const host = useHost();
  const module = useModule<SystemState>(host.id, "system");
  const hardware = module.data?.payload?.hardware;

  return (
    <>
      <Pairs>
        <Pair label={t("System")}>{host.os_distribution} {host.os_version} ({host.os_family})</Pair>
        <Pair label={t("Architecture")}>{host.architecture || "—"}</Pair>
        <Pair label={t("Management address")}>
          {host.management_address
            ? `${host.management_address} (${host.management_address_source})`
            : <span className="badge unknown">{t("unknown")}</span>}
        </Pair>
        <Pair label={t("Machine ID")}>{host.machine_id}</Pair>
        <Pair label={t("Boot ID")}>{host.boot_id || "—"}</Pair>
        <Pair label={t("Lifecycle state")}>{host.lifecycle_state}</Pair>
        <Pair label={t("Reboot required")}><OptionalFlag value={host.reboot_required} /></Pair>
        <Pair label={t("Failed units")}><OptionalNumber value={host.failed_units} /></Pair>
        <Pair label={t("Package database")}>
          {host.package_database_broken ? <span className="badge error">{t("needs repair")}</span> : t("healthy")}
        </Pair>
        <Pair label={t("Enrolled")}><Time value={host.enrolled_at} /></Pair>
      </Pairs>

      {hardware && (
        <>
          <h2>{t("Hardware")}</h2>
          <Pairs>
            <Pair label={t("CPU cores")}>{hardware.cpu_cores}</Pair>
            <Pair label={t("Memory")}>{bytes(hardware.memory_bytes)}</Pair>
            <Pair label={t("Root filesystem")}>
              {t("{free} free of {total}", { free: bytes(hardware.root_fs_free_bytes), total: bytes(hardware.root_fs_bytes) })}
            </Pair>
            <Pair label={t("Virtualization")}>{hardware.virtualization || "—"}</Pair>
          </Pairs>
        </>
      )}

      <h2>{t("Adapters")}</h2>
      <Adapters host={host} />

      <ModuleFreshness fragment={module.data} />
    </>
  );
}

/**
 * The host's adapter registry. The operator sees not only what is missing
 * but also why - the reason comes from the host, not from browser code.
 */
function Adapters({ host }: { host: ReturnType<typeof useHost> }) {
  const t = useT();
  const adapters = host.capabilities ?? [];
  if (adapters.length === 0) {
    return <Empty>{t("This host has not reported its adapters yet.")}</Empty>;
  }
  return (
    <table>
      <thead><tr><th>{t("Adapter")}</th><th>{t("State")}</th><th>{t("Features")}</th><th>{t("Reason")}</th></tr></thead>
      <tbody>
        {adapters.map((adapter) => (
          <tr key={adapter.name}>
            <td>{adapter.name}</td>
            <td>
              {!adapter.available ? (
                <span className="badge">{t("unavailable")}</span>
              ) : adapter.read_only ? (
                <span className="badge warn">{t("read only")}</span>
              ) : (
                <span className="badge ok">{t("available")}</span>
              )}
            </td>
            <td>
              {Object.entries(adapter.features ?? {}).length === 0
                ? "—"
                : Object.entries(adapter.features ?? {})
                    .map(([name, present]) => `${name}: ${present ? t("yes") : t("no")}`)
                    .join(", ")}
            </td>
            <td className="source">{adapter.reason || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
