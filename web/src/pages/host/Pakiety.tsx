import { LiczbaOpcjonalna, Para, Pary } from "../../components/ui";
import { useHost, useInventory, ZlecOperacje } from "./wspolne";

export function Pakiety() {
  const host = useHost();
  const inventory = useInventory(host.id);
  const pakiety = inventory.data?.payload?.packages;

  return (
    <>
      <Pary>
        <Para etykieta="Manager">{pakiety?.manager || "—"}</Para>
        <Para etykieta="Installed">{pakiety?.installed ?? <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="Upgradable"><LiczbaOpcjonalna wartosc={host.pending_updates} /></Para>
        <Para etykieta="Security updates"><LiczbaOpcjonalna wartosc={host.pending_security_updates} /></Para>
      </Pary>
      {pakiety?.unavailable_reason && (
        <p className="zrodlo" style={{ marginTop: 12 }}>
          The state could not be determined: {pakiety.unavailable_reason}
        </p>
      )}
      <ZlecOperacje
        host={host}
        opis="Count available updates without changing host state."
        akcja="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        etykieta="Plan updates"
      />
    </>
  );
}
