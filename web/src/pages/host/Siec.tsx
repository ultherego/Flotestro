import { useState } from "react";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";

type Adres = {
  family: string;
  address: string;
  scope: string;
  source?: string;
  permanent: boolean;
};

type Interfejs = {
  name: string;
  index: number;
  kind?: string;
  mac?: string;
  mtu: number;
  oper_state: string;
  carrier?: boolean;
  speed_mbps?: number;
  driver?: string;
  addresses?: Adres[];
  management: boolean;
};

type Trasa = {
  destination: string;
  gateway?: string;
  interface?: string;
  source?: string;
  protocol?: string;
  scope?: string;
  metric: number;
  family: string;
  table?: string;
};

type Snapshot = {
  interfaces?: Interfejs[];
  routes?: Trasa[];
  management_interface?: string;
  management_address?: string;
  write_adapter?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/**
 * Siec hosta: interfejsy, adresy i trasy czytane z jadra.
 *
 * Panel pokazuje stan faktyczny, a nie tresc plikow konfiguracyjnych: to, co
 * host ma podniesione, i to, co ktos kiedys wpisal do konfiguracji, potrafi
 * sie rozjechac - a operator pyta o pierwsze.
 */
export function Siec() {
  const host = useHost();
  const modul = useModul<Snapshot>(host.id, "network");
  // Host z dockerem ma kilkanascie interfejsow wirtualnych i tylko czesc
  // z nich cokolwiek znaczy. Domyslnie pokazujemy te, ktore znacza.
  const [wszystkie, setWszystkie] = useState(false);

  const snapshot = modul.data?.payload;
  const interfejsy = snapshot?.interfaces ?? [];
  const widoczne = wszystkie ? interfejsy : interfejsy.filter(istotny);
  const trasy = snapshot?.routes ?? [];

  if (!modul.data) return <Pusto>This host has not reported its network state yet.</Pusto>;

  return (
    <>
      <p className="podtytul">
        Read from the kernel, not from configuration files: what the host has up
        and what someone once wrote into a config file can differ.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Network state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      {/* Brak mechanizmu zapisu jest odpowiedzia, a nie awaria: modul dziala,
          tylko w trybie odczytu i mowi dlaczego. */}
      {!snapshot?.write_adapter && (
        <p className="ostrzezenie">
          <span>
            Read-only on this host: no NetworkManager, nmstate or netplan, so the
            panel will not change its network configuration.
          </span>
        </p>
      )}

      <div className="filtry">
        <label className="przelacznik">
          <input
            type="checkbox"
            checked={wszystkie}
            onChange={(e) => setWszystkie(e.target.checked)}
          />
          Show virtual interfaces ({interfejsy.length - widoczne.length} hidden)
        </label>
      </div>

      <h2>Interfaces</h2>
      <table>
        <thead>
          <tr>
            <th>Interface</th><th>Kind</th><th>State</th><th>Addresses</th>
            <th>MTU</th><th>Link</th><th>MAC</th><th>Driver</th>
          </tr>
        </thead>
        <tbody>
          {widoczne.map((interfejs) => (
            <tr key={interfejs.name}>
              <td>
                {interfejs.name}
                {/* Interfejs zarzadzania to ten, przez ktory przyszlo
                    polecenie. Zmiana wlasnie jego jest zmiana galezi,
                    na ktorej siedzimy. */}
                {interfejs.management && <span className="znacznik"> management</span>}
              </td>
              <td>{interfejs.kind || "—"}</td>
              <td>{interfejs.oper_state}</td>
              <td>
                {(interfejs.addresses ?? []).length === 0
                  ? "—"
                  : (interfejs.addresses ?? []).map((adres) => (
                      <div key={adres.address}>
                        {adres.address}
                        {!adres.permanent && <span className="zrodlo"> · temporary</span>}
                        {adres.source && <span className="zrodlo"> · {adres.source}</span>}
                      </div>
                    ))}
              </td>
              <td>{interfejs.mtu}</td>
              {/* Nieznana nosna i nieznana predkosc zostaja nieznane:
                  brak wartosci to nie to samo co brak kabla. */}
              <td>
                {interfejs.carrier === undefined ? (
                  <span className="znacznik nieznany">unknown</span>
                ) : interfejs.carrier ? (
                  interfejs.speed_mbps ? `up, ${interfejs.speed_mbps} Mbps` : "up"
                ) : (
                  "no carrier"
                )}
              </td>
              <td>{interfejs.mac || "—"}</td>
              <td>{interfejs.driver || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Routes</h2>
      {!trasy.length ? (
        <Pusto>No routes reported.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Destination</th><th>Gateway</th><th>Interface</th>
              <th>Source</th><th>Protocol</th><th>Metric</th><th>Family</th>
            </tr>
          </thead>
          <tbody>
            {trasy.map((trasa, i) => (
              <tr key={`${trasa.family}-${trasa.destination}-${trasa.interface}-${i}`}>
                <td>{trasa.destination}</td>
                <td>{trasa.gateway || "—"}</td>
                <td>{trasa.interface || "—"}</td>
                <td>{trasa.source || "—"}</td>
                <td>{trasa.protocol || "—"}</td>
                <td>{trasa.metric}</td>
                <td>{trasa.family === "inet6" ? "IPv6" : "IPv4"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="zrodlo" style={{ marginTop: 12 }}>
        Management channel: {snapshot?.management_interface || "unknown"}
        {snapshot?.management_address && ` · ${snapshot.management_address}`}
        {snapshot?.write_adapter && ` · write adapter ${snapshot.write_adapter}`}
        {snapshot?.observed_at && (
          <>
            {" · read "}
            <Czas wartosc={snapshot.observed_at} />
          </>
        )}
      </p>
      <SwiezoscModulu fragment={modul.data} />
    </>
  );
}

/**
 * Interfejs jest istotny, gdy operator moze o niego zapytac: fizyczny,
 * z adresem albo bedacy kanalem zarzadzania. Reszta to veth i mosty
 * kontenerow, ktore zaslanialyby obraz.
 */
function istotny(interfejs: Interfejs): boolean {
  if (interfejs.management) return true;
  if (interfejs.kind === "veth") return false;
  if (interfejs.name.startsWith("br-") || interfejs.name.startsWith("veth")) return false;
  return (interfejs.addresses ?? []).length > 0 || interfejs.kind === "ethernet";
}
