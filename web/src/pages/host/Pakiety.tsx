import { LiczbaOpcjonalna, Para, Pary } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul, ZlecOperacje } from "./wspolne";

type StanPakietow = {
  manager?: string;
  installed?: number;
  upgradable?: number;
  security_upgradable?: number;
  unavailable_reason?: string;
};

export function Pakiety() {
  const host = useHost();
  const modul = useModul<StanPakietow>(host.id, "packages");
  const pakiety = modul.data?.payload;

  return (
    <>
      <Pary>
        <Para etykieta="Manager">{pakiety?.manager || "—"}</Para>
        <Para etykieta="Installed">
          {pakiety?.installed ?? <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Upgradable"><LiczbaOpcjonalna wartosc={host.pending_updates} /></Para>
        <Para etykieta="Security updates">
          <LiczbaOpcjonalna wartosc={host.pending_security_updates} />
        </Para>
      </Pary>
      <ZlecOperacje
        host={host}
        opis="Count available updates without changing host state."
        akcja="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        etykieta="Plan updates"
      />
      <SwiezoscModulu fragment={modul.data} />
    </>
  );
}
