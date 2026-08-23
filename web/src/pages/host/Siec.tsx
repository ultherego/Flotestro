import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

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
type Zamiar = {
  akcja: string;
  etykieta: string;
  opis: string;
  payload: Record<string, unknown>;
};

export function Siec() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "network");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [edytowany, setEdytowany] = useState<Interfejs | null>(null);

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setZamiar(null);
      setEdytowany(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });
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
            <th>MTU</th><th>Link</th><th>MAC</th><th>Driver</th><th>Actions</th>
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
              <td>
                {/* Bez mechanizmu zapisu nie ma czego edytowac: panel nie
                    zmienia konfiguracji, ktorej host nie utrzyma po restarcie. */}
                <button
                  onClick={() => setEdytowany(interfejs)}
                  disabled={!snapshot?.write_adapter}
                  title={
                    snapshot?.write_adapter
                      ? ""
                      : "This host has no NetworkManager, nmstate or netplan."
                  }
                >
                  Change
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {edytowany && (
        <ZmianaInterfejsu
          interfejs={edytowany}
          zarzadzajacy={edytowany.management}
          onZamiar={setZamiar}
          onAnuluj={() => setEdytowany(null)}
        />
      )}

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

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({ action: zamiar.akcja, reason: powod, payload: zamiar.payload })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}

/**
 * Formularz zmiany interfejsu.
 *
 * Kazda zmiana jest uzbrajana wycofaniem po stronie hosta: jesli po zmianie
 * agent nie potwierdzi lacznosci, host sam wroci do poprzedniej konfiguracji.
 * Dlatego formularz pyta o okno wycofania, a nie ukrywa go jako szczegol.
 */
function ZmianaInterfejsu({
  interfejs, zarzadzajacy, onZamiar, onAnuluj,
}: {
  interfejs: Interfejs;
  zarzadzajacy: boolean;
  onZamiar: (zamiar: Zamiar) => void;
  onAnuluj: () => void;
}) {
  const [mtu, setMtu] = useState(String(interfejs.mtu));
  const [metoda, setMetoda] = useState<"auto" | "manual">("manual");
  const [adresy, setAdresy] = useState(
    (interfejs.addresses ?? [])
      .filter((adres) => adres.family === "inet")
      .map((adres) => adres.address)
      .join(", "),
  );
  const [brama, setBrama] = useState("");
  const [dns, setDns] = useState("");
  const [trasy, setTrasy] = useState("");
  const [okno, setOkno] = useState("120");

  const lista = (wartosc: string) =>
    wartosc.split(",").map((element) => element.trim()).filter(Boolean);
  const sekundy = Number(okno) || 0;

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Change {interfejs.name}</h2>
      {/* Zmiana interfejsu zarzadzania jest zmiana galezi, na ktorej siedzimy:
          operator ma to przeczytac przed, a nie zobaczyc po. */}
      {zarzadzajacy && (
        <p className="ostrzezenie">
          <span>
            This is the interface the panel talks to. If the change breaks it, the
            host will roll back on its own after the rollback window — but until
            then it is unreachable, and no further command will arrive.
          </span>
        </p>
      )}
      <p className="podtytul" style={{ margin: 0 }}>
        The host arms a rollback before it applies anything and cancels it only
        after the agent proves it can still reach the panel.
      </p>
      <label>
        Rollback window (seconds, 30–900)
        <input value={okno} onChange={(e) => setOkno(e.target.value)} />
      </label>

      <div className="filtry" style={{ marginTop: 8 }}>
        <input value={mtu} onChange={(e) => setMtu(e.target.value)} placeholder="MTU or auto" />
        <button
          onClick={() =>
            onZamiar({
              akcja: "network.mtu.set",
              etykieta: `Set MTU on ${interfejs.name}`,
              opis: `${interfejs.name} will use MTU ${mtu}. The host rolls back after ${sekundy}s unless the agent confirms connectivity.`,
              payload: {
                network: { interface: interfejs.name, mtu, rollback_seconds: sekundy },
              },
            })
          }
          disabled={!mtu}
        >
          Set MTU
        </button>
      </div>

      <div className="filtry">
        <input
          value={trasy}
          onChange={(e) => setTrasy(e.target.value)}
          placeholder="Routes, e.g. 10.0.0.0/8 192.168.56.1, 172.16.0.0/12"
          style={{ minWidth: 380 }}
        />
        <button
          onClick={() =>
            onZamiar({
              akcja: "network.route.ensure",
              etykieta: `Replace routes on ${interfejs.name}`,
              opis: `${interfejs.name} will carry exactly these routes: ${
                lista(trasy).join("; ") || "none"
              }. Routes not listed here are removed from the profile.`,
              payload: {
                network: {
                  interface: interfejs.name,
                  routes: lista(trasy),
                  rollback_seconds: sekundy,
                },
              },
            })
          }
        >
          Replace routes
        </button>
      </div>

      <div className="filtry">
        <select value={metoda} onChange={(e) => setMetoda(e.target.value as "auto" | "manual")}>
          <option value="manual">static addresses</option>
          <option value="auto">DHCP</option>
        </select>
        <input
          value={adresy}
          onChange={(e) => setAdresy(e.target.value)}
          placeholder="Addresses with masks, e.g. 192.168.56.30/24"
          style={{ minWidth: 260 }}
          disabled={metoda === "auto"}
        />
        <input value={brama} onChange={(e) => setBrama(e.target.value)} placeholder="Gateway" disabled={metoda === "auto"} />
        <input value={dns} onChange={(e) => setDns(e.target.value)} placeholder="DNS servers" disabled={metoda === "auto"} />
        <button
          onClick={() =>
            onZamiar({
              akcja: "network.profile.apply",
              etykieta: `Apply address profile to ${interfejs.name}`,
              opis:
                metoda === "auto"
                  ? `${interfejs.name} will take its address from DHCP. Its current address is dropped.`
                  : `${interfejs.name} will use ${lista(adresy).join(", ")}${
                      brama ? ` via ${brama}` : ""
                    }. Addresses not listed here are removed.`,
              payload: {
                network: {
                  interface: interfejs.name,
                  method: metoda,
                  addresses: metoda === "auto" ? [] : lista(adresy),
                  gateway: metoda === "auto" ? "" : brama,
                  dns: metoda === "auto" ? [] : lista(dns),
                  rollback_seconds: sekundy,
                },
              },
            })
          }
          disabled={metoda === "manual" && lista(adresy).length === 0}
        >
          Apply profile
        </button>
      </div>

      <button className="wtorny" onClick={onAnuluj}>Cancel</button>
    </div>
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
