import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type KluczHosta = { type: string; bits: number; fingerprint: string; path: string };

type Snapshot = {
  ports?: string[];
  listen_addresses?: string[];
  permit_root_login?: string;
  password_authentication?: string;
  pubkey_authentication?: string;
  kbd_interactive_authentication?: string;
  gssapi_authentication?: string;
  max_auth_tries?: number;
  allow_users?: string[];
  allow_groups?: string[];
  deny_users?: string[];
  deny_groups?: string[];
  host_keys?: KluczHosta[];
  managed_config?: string;
  managed_path?: string;
  managed_present?: boolean;
  unit?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Serwer sshd.
 *
 * Panel zapisuje wylacznie wlasny plik w sshd_config.d: plik glowny nalezy do
 * dystrybucji i administratora hosta. Stan pokazujemy taki, jaki podaje sam
 * serwer - w sshd wygrywa pierwsza wartosc, wiec skladanie go z tresci plikow
 * dawaloby obraz, ktorego host nie potwierdza.
 */
export function SerwerSSH() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "ssh");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [edytor, setEdytor] = useState(false);

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
      setEdytor(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its sshd yet.</Pusto>;

  const metody: [string, string | undefined][] = [
    ["Password", snapshot?.password_authentication],
    ["Public key", snapshot?.pubkey_authentication],
    ["Keyboard interactive", snapshot?.kbd_interactive_authentication],
    ["GSSAPI", snapshot?.gssapi_authentication],
  ];

  return (
    <>
      <p className="podtytul">
        Effective configuration as sshd itself reports it. The panel writes only
        its own file in sshd_config.d — the main config belongs to the
        distribution and to whoever runs this host.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>sshd configuration could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Port</th><td>{(snapshot?.ports ?? []).join(", ") || "—"}</td></tr>
          <tr><th>Listening on</th><td>{(snapshot?.listen_addresses ?? []).join(", ") || "—"}</td></tr>
          {/* "prohibit-password" nie jest ani yes, ani no - pokazujemy to,
              co powiedzial serwer, a nie przetlumaczone na flage. */}
          <tr><th>Root login</th><td>{snapshot?.permit_root_login || "—"}</td></tr>
          <tr><th>Max auth tries</th><td>{snapshot?.max_auth_tries ?? "—"}</td></tr>
          <tr><th>Allow users</th><td>{(snapshot?.allow_users ?? []).join(" ") || "—"}</td></tr>
          <tr><th>Allow groups</th><td>{(snapshot?.allow_groups ?? []).join(" ") || "—"}</td></tr>
          <tr><th>Deny users</th><td>{(snapshot?.deny_users ?? []).join(" ") || "—"}</td></tr>
          <tr><th>Service unit</th><td>{snapshot?.unit || "—"}</td></tr>
        </tbody>
      </table>

      <h2>Authentication methods</h2>
      <table>
        <thead><tr><th>Method</th><th>Enabled</th></tr></thead>
        <tbody>
          {metody.map(([nazwa, wartosc]) => (
            <tr key={nazwa}>
              <td>{nazwa}</td>
              <td>{wartosc || <span className="znacznik nieznany">unknown</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Host keys</h2>
      <p className="podtytul">
        Fingerprints only — the panel has no reason to see a host's private key.
        Rotating one changes this host's identity for every client that has it
        in known_hosts.
      </p>
      <table>
        <thead><tr><th>Type</th><th>Bits</th><th>Fingerprint</th><th>Actions</th></tr></thead>
        <tbody>
          {(snapshot?.host_keys ?? []).map((klucz) => (
            <tr key={klucz.path}>
              <td>{klucz.type}</td>
              <td>{klucz.bits}</td>
              <td className="zrodlo">{klucz.fingerprint}</td>
              <td>
                <button
                  className="wtorny"
                  onClick={() =>
                    setZamiar({
                      akcja: "ssh.hostkey.rotate",
                      etykieta: "Rotate host key",
                      opis: `A new ${klucz.type} host key will be generated on ${host.hostname}. Every client with the old fingerprint in known_hosts will warn, and anything keyed to the old fingerprint stops working. The old key is kept on the host with a timestamp.`,
                      payload: { ssh: { key_type: klucz.type } },
                    })
                  }
                >
                  Rotate
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Managed drop-in</h2>
      <p className="zrodlo">{snapshot?.managed_path}</p>
      {snapshot?.managed_present ? (
        <pre style={{ marginTop: 8 }}>{snapshot.managed_config}</pre>
      ) : (
        <Pusto>The panel has not written anything to this host yet.</Pusto>
      )}

      <div className="filtry">
        <button onClick={() => setEdytor((otwarty) => !otwarty)}>
          {edytor ? "Cancel" : "Change configuration"}
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}
      {edytor && <EdytorSSH stan={snapshot} onZamiar={setZamiar} />}

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Configuration read <Czas wartosc={snapshot.observed_at} />
        </p>
      )}

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
 * Edytor zarzadzanego pliku. Puste pole oznacza "nie zmieniaj": panel nie
 * przepisuje calej konfiguracji serwera, tylko to, o co operator poprosil.
 */
function EdytorSSH({
  stan, onZamiar,
}: {
  stan?: Snapshot;
  onZamiar: (zamiar: Zamiar) => void;
}) {
  const [root, setRoot] = useState("");
  const [haslo, setHaslo] = useState("");
  const [klucz, setKlucz] = useState("");
  const [proby, setProby] = useState("");
  const [grupy, setGrupy] = useState("");
  const [odciecie, setOdciecie] = useState(false);

  const lista = (wartosc: string) => wartosc.split(/[\s,]+/).filter(Boolean);
  const zmiana: Record<string, unknown> = {};
  if (root) zmiana.permit_root_login = root;
  if (haslo) zmiana.password_authentication = haslo;
  if (klucz) zmiana.pubkey_authentication = klucz;
  if (proby) zmiana.max_auth_tries = proby;
  if (grupy) zmiana.allow_groups = lista(grupy);
  if (odciecie) zmiana.allow_lockout = true;

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Change configuration</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        Empty means “leave it alone”. The host validates the file with sshd
        itself before reloading, and reloads instead of restarting so open
        sessions survive.
      </p>
      <div className="filtry">
        <select value={root} onChange={(e) => setRoot(e.target.value)}>
          <option value="">root login: leave</option>
          <option value="no">root login: no</option>
          <option value="prohibit-password">root login: keys only</option>
          <option value="yes">root login: yes</option>
        </select>
        <select value={haslo} onChange={(e) => setHaslo(e.target.value)}>
          <option value="">password auth: leave</option>
          <option value="no">password auth: no</option>
          <option value="yes">password auth: yes</option>
        </select>
        <select value={klucz} onChange={(e) => setKlucz(e.target.value)}>
          <option value="">public key auth: leave</option>
          <option value="yes">public key auth: yes</option>
          <option value="no">public key auth: no</option>
        </select>
        <input value={proby} onChange={(e) => setProby(e.target.value)} placeholder="MaxAuthTries" style={{ width: 130 }} />
        <input value={grupy} onChange={(e) => setGrupy(e.target.value)} placeholder="AllowGroups" />
      </div>
      {/* Serwer, do ktorego nie da sie zalogowac zadna metoda, nie jest
          zabezpieczony - jest niedostepny. */}
      <label className="przelacznik">
        <input type="checkbox" checked={odciecie} onChange={(e) => setOdciecie(e.target.checked)} />
        Allow a configuration that leaves no working authentication method
      </label>
      <button
        onClick={() =>
          onZamiar({
            akcja: "ssh.config.apply",
            etykieta: "Apply sshd configuration",
            opis: `${Object.entries(zmiana)
              .filter(([klucz]) => klucz !== "allow_lockout")
              .map(([klucz, wartosc]) => `${klucz} = ${Array.isArray(wartosc) ? wartosc.join(" ") : wartosc}`)
              .join(", ")} on ${stan?.unit ?? "sshd"}. Existing sessions stay open.`,
            payload: { ssh: zmiana },
          })
        }
        disabled={Object.keys(zmiana).filter((klucz) => klucz !== "allow_lockout").length === 0}
      >
        Apply
      </button>
    </div>
  );
}
