import { Czas, FlagaOpcjonalna, LiczbaOpcjonalna, Para, Pary, Pusto } from "../../components/ui";
import { bytes } from "../../lib/format";
import { useHost, useInventory } from "./wspolne";

export function Przeglad() {
  const host = useHost();
  const inventory = useInventory(host.id);
  const sprzet = inventory.data?.payload?.hardware;

  return (
    <>
      <Pary>
        <Para etykieta="System">{host.os_distribution} {host.os_version} ({host.os_family})</Para>
        <Para etykieta="Architecture">{host.architecture || "—"}</Para>
        <Para etykieta="Management address">
          {host.management_address
            ? `${host.management_address} (${host.management_address_source})`
            : <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Machine ID">{host.machine_id}</Para>
        <Para etykieta="Boot ID">{host.boot_id || "—"}</Para>
        <Para etykieta="Lifecycle state">{host.lifecycle_state}</Para>
        <Para etykieta="Reboot required"><FlagaOpcjonalna wartosc={host.reboot_required} /></Para>
        <Para etykieta="Failed units"><LiczbaOpcjonalna wartosc={host.failed_units} /></Para>
        <Para etykieta="Package database">
          {host.package_database_broken ? <span className="znacznik blad">needs repair</span> : "healthy"}
        </Para>
        <Para etykieta="Enrolled"><Czas wartosc={host.enrolled_at} /></Para>
      </Pary>

      {sprzet && (
        <>
          <h2>Hardware</h2>
          <Pary>
            <Para etykieta="CPU cores">{sprzet.cpu_cores}</Para>
            <Para etykieta="Memory">{bytes(sprzet.memory_bytes)}</Para>
            <Para etykieta="Root filesystem">
              {bytes(sprzet.root_fs_free_bytes)} free of {bytes(sprzet.root_fs_bytes)}
            </Para>
            <Para etykieta="Virtualization">{sprzet.virtualization || "—"}</Para>
          </Pary>
        </>
      )}

      <h2>Adapters</h2>
      <Adaptery host={host} />

      {inventory.data && (
        <p className="zrodlo" style={{ marginTop: 16 }}>
          Source: inventory, revision {inventory.data.revision.slice(0, 12)}, observed{" "}
          <Czas wartosc={inventory.data.observed_at} />
        </p>
      )}
    </>
  );
}

/**
 * Rejestr adapterow hosta. Operator widzi nie tylko, czego nie ma, ale i
 * dlaczego - powod pochodzi z hosta, a nie z kodu przegladarki.
 */
function Adaptery({ host }: { host: ReturnType<typeof useHost> }) {
  const adaptery = host.capabilities ?? [];
  if (adaptery.length === 0) {
    return <Pusto>This host has not reported its adapters yet.</Pusto>;
  }
  return (
    <table>
      <thead><tr><th>Adapter</th><th>State</th><th>Features</th><th>Reason</th></tr></thead>
      <tbody>
        {adaptery.map((adapter) => (
          <tr key={adapter.name}>
            <td>{adapter.name}</td>
            <td>
              {!adapter.available ? (
                <span className="znacznik">unavailable</span>
              ) : adapter.read_only ? (
                <span className="znacznik uwaga">read only</span>
              ) : (
                <span className="znacznik ok">available</span>
              )}
            </td>
            <td>
              {Object.entries(adapter.features ?? {}).length === 0
                ? "—"
                : Object.entries(adapter.features ?? {})
                    .map(([nazwa, jest]) => `${nazwa}: ${jest ? "yes" : "no"}`)
                    .join(", ")}
            </td>
            <td className="zrodlo">{adapter.reason || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
