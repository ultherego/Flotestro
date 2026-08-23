import { Czas, FlagaOpcjonalna, Para, Pary } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";

type StanTozsamosci = {
  servers?: string[];
  sssd_running?: boolean;
  cache_age_seconds?: number;
  host_principal?: string;
  keytab_kvno?: number;
  time_synchronized?: boolean;
  unavailable_reason?: string;
};

export function Tozsamosc() {
  const host = useHost();
  const modul = useModul<StanTozsamosci>(host.id, "identity");
  const tozsamosc = modul.data?.payload ?? {};

  return (
    <>
      <Pary>
        <Para etykieta="In domain">
          {host.identity.enrolled ? <span className="znacznik ok">yes</span> : <span className="znacznik">no</span>}
        </Para>
        <Para etykieta="Domain">{host.identity.domain || "—"}</Para>
        <Para etykieta="Realm">{host.identity.realm || "—"}</Para>
        <Para etykieta="Servers">{(tozsamosc.servers ?? []).join(", ") || "—"}</Para>
        <Para etykieta="SSSD running">{tozsamosc.sssd_running ? "yes" : "no"}</Para>
        <Para etykieta="SSSD online"><FlagaOpcjonalna wartosc={host.identity.sssd_online} /></Para>
        <Para etykieta="Cache age">
          {tozsamosc.cache_age_seconds !== undefined
            ? `${tozsamosc.cache_age_seconds} s`
            : <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Host principal">{tozsamosc.host_principal || <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="Keytab KVNO">{tozsamosc.keytab_kvno ?? <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="Clock synchronized">{tozsamosc.time_synchronized ? "yes" : "no"}</Para>
        <Para etykieta="Checked"><Czas wartosc={host.identity.checked_at} /></Para>
      </Pary>
      <SwiezoscModulu fragment={modul.data} />
    </>
  );
}
