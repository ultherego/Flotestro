import { Time, OptionalFlag, OptionalNumber, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Fact, Facts, ModuleFreshness, ModuleHeader, ModulePage, Section, Table, useHost, useModule } from "./shared";
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
    <ModulePage>
      <ModuleHeader
        title={t("Overview")}
        description={t("Identity, hardware and the adapters of this host, as the agent last reported them.")}
      />
      <ModuleFreshness fragment={module.data} />

      <div className="columns">
      <Section title={t("System")} flush>
        <Facts>
          <Fact label={t("System")}>{host.os_distribution} {host.os_version} ({host.os_family})</Fact>
          <Fact label={t("Architecture")}>{host.architecture || "—"}</Fact>
          <Fact label={t("Management address")}>
            {host.management_address
              ? <span className="hm-mono">{host.management_address} ({host.management_address_source})</span>
              : <span className="badge unknown">{t("unknown")}</span>}
          </Fact>
          <Fact label={t("Lifecycle state")}>{host.lifecycle_state}</Fact>
          <Fact label={t("Reboot required")}><OptionalFlag value={host.reboot_required} /></Fact>
          <Fact label={t("Failed units")}><OptionalNumber value={host.failed_units} /></Fact>
          <Fact label={t("Package database")}>
            {host.package_database_broken ? <span className="badge error">{t("needs repair")}</span> : t("healthy")}
          </Fact>
          <Fact label={t("Enrolled")}><Time value={host.enrolled_at} /></Fact>
          <Fact label={t("Machine ID")}><span className="hm-mono">{host.machine_id}</span></Fact>
          <Fact label={t("Boot ID")}><span className="hm-mono">{host.boot_id || "—"}</span></Fact>
        </Facts>
      </Section>

      {hardware && (
        <Section title={t("Hardware")} flush>
          <Facts>
            <Fact label={t("CPU cores")}>{hardware.cpu_cores}</Fact>
            <Fact label={t("Memory")}>{bytes(hardware.memory_bytes)}</Fact>
            <Fact label={t("Root filesystem")}>
              {t("{free} free of {total}", { free: bytes(hardware.root_fs_free_bytes), total: bytes(hardware.root_fs_bytes) })}
            </Fact>
            <Fact label={t("Virtualization")}>{hardware.virtualization || "—"}</Fact>
          </Facts>
        </Section>
      )}
      </div>

      <Section title={t("Adapters")} count={(host.capabilities ?? []).length} flush>
        <Adapters host={host} />
      </Section>
    </ModulePage>
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
    <Table>
      <thead><tr><th>{t("Adapter")}</th><th>{t("State")}</th><th>{t("Features")}</th><th>{t("Reason")}</th></tr></thead>
      <tbody>
        {adapters.map((adapter) => (
          <tr key={adapter.name}>
            <td className="hm-mono">{adapter.name}</td>
            <td>
              {!adapter.available ? (
                <span className="badge">{t("unavailable")}</span>
              ) : adapter.read_only ? (
                <span className="badge warn">{t("read only")}</span>
              ) : (
                <span className="badge ok">{t("available")}</span>
              )}
            </td>
            <td className="source">
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
    </Table>
  );
}
