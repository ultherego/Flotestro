import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Regula = {
  family: string;
  table: string;
  chain: string;
  handle: number;
  text: string;
  source: string;
  comment?: string;
  packets?: number;
  bytes?: number;
};

type Strefa = {
  name: string;
  active: boolean;
  default: boolean;
  target?: string;
  interfaces?: string[];
  sources?: string[];
  services?: string[];
  ports?: string[];
};

type Snapshot = {
  adapter?: string;
  hash?: string;
  tables?: { family: string; name: string; source: string; owner?: string }[];
  rules?: Regula[];
  zones?: Strefa[];
  writable?: boolean;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Zapora hosta.
 *
 * Panel zmienia wylacznie wlasna tablice nftables albo strefe firewalld.
 * Cudze lancuchy - dockera, firewalld, iptables-nft - sa przepisywane bez
 * jego udzialu, wiec regula w nich zniknelaby przy pierwszym starcie
 * kontenera albo przeladowaniu uslugi. Operator widzi je, ale ich nie edytuje.
 */
export function Zapora() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "firewall");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [kreator, setKreator] = useState(false);
  const [filtr, setFiltr] = useState("");
  const [tylkoWlasne, setTylkoWlasne] = useState(false);

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
      setKreator(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its firewall yet.</Pusto>;

  const reguly = (snapshot?.rules ?? []).filter((regula) => {
    if (tylkoWlasne && regula.source !== "managed") return false;
    if (!filtr) return true;
    const szukane = filtr.toLowerCase();
    return (
      regula.text.toLowerCase().includes(szukane) ||
      regula.chain.toLowerCase().includes(szukane) ||
      regula.table.toLowerCase().includes(szukane)
    );
  });
  const wlasne = (snapshot?.rules ?? []).filter((regula) => regula.source === "managed");

  return (
    <>
      <p className="podtytul">
        Read from the kernel with nft. Flotestro owns one table of its own —
        docker, firewalld and iptables-nft rewrite theirs without asking, so a
        rule placed in those would vanish at the next container start or reload.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Firewall state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Adapter</th><td>{snapshot?.adapter || <span className="znacznik nieznany">unknown</span>}</td></tr>
          {/* Odcisk wiaze plan ze zbiorem regul: zmiana zlecona wobec innego
              zbioru nie jest ta sama zmiana, ktora operator ogladal. */}
          <tr><th>Ruleset fingerprint</th><td>{snapshot?.hash || "—"}</td></tr>
          <tr><th>Rules owned by Flotestro</th><td>{wlasne.length}</td></tr>
          <tr><th>Read</th><td>{snapshot?.observed_at ? <Czas wartosc={snapshot.observed_at} /> : "—"}</td></tr>
        </tbody>
      </table>

      {snapshot?.zones?.length ? (
        <>
          <h2>Zones</h2>
          <p className="podtytul">
            firewalld describes access by zone, not by rule order: the question
            is what is open on an interface, not which rule matches first.
          </p>
          <table>
            <thead>
              <tr><th>Zone</th><th>State</th><th>Target</th><th>Interfaces</th><th>Services</th><th>Ports</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {snapshot.zones
                .filter((strefa) => strefa.active || strefa.default || (strefa.ports ?? []).length > 0)
                .map((strefa) => (
                  <tr key={strefa.name}>
                    <td>{strefa.name}</td>
                    <td>
                      {strefa.active ? "active" : "inactive"}
                      {strefa.default && <span className="znacznik"> default</span>}
                    </td>
                    <td>{strefa.target || "—"}</td>
                    <td>{(strefa.interfaces ?? []).join(", ") || "—"}</td>
                    <td>{(strefa.services ?? []).join(", ") || "—"}</td>
                    <td>{(strefa.ports ?? []).join(", ") || "—"}</td>
                    <td>
                      <PortStrefy strefa={strefa.name} onZamiar={setZamiar} hostname={host.hostname} />
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </>
      ) : null}

      <h2>Effective rules</h2>
      <div className="filtry">
        <input
          value={filtr}
          onChange={(e) => setFiltr(e.target.value)}
          placeholder="Filter by rule, chain or table"
          style={{ minWidth: 280 }}
        />
        <label className="przelacznik">
          <input type="checkbox" checked={tylkoWlasne} onChange={(e) => setTylkoWlasne(e.target.checked)} />
          Only rules owned by Flotestro
        </label>
        <button onClick={() => setKreator((otwarty) => !otwarty)} disabled={!snapshot?.writable}>
          {kreator ? "Cancel" : "New rule"}
        </button>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {kreator && <KreatorReguly odcisk={snapshot?.hash ?? ""} onZamiar={setZamiar} />}

      {!reguly.length ? (
        <Pusto>No rules match.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Table</th><th>Chain</th><th>Rule</th><th>Owner</th><th>Counters</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {reguly.map((regula) => (
              <tr key={`${regula.family}-${regula.table}-${regula.chain}-${regula.handle}`}>
                <td>{regula.family} {regula.table}</td>
                <td>{regula.chain}</td>
                <td title={regula.text} style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
                  {regula.text.slice(0, 70)}
                </td>
                {/* Regula w cudzej tablicy nie jest ani nasza, ani trwala. */}
                <td>
                  {regula.source === "managed" ? (
                    "Flotestro"
                  ) : (
                    <span className="znacznik nieznany">{regula.source}</span>
                  )}
                </td>
                {/* Regula bez licznika nie moze udawac, ze nic przez nia
                    nie przeszlo. */}
                <td>
                  {regula.packets === undefined ? (
                    <span className="znacznik nieznany">no counter</span>
                  ) : (
                    `${regula.packets} pkt / ${regula.bytes} B`
                  )}
                </td>
                <td>
                  {regula.source === "managed" && (
                    <button
                      className="wtorny"
                      onClick={() =>
                        setZamiar({
                          akcja: "firewall.rule.remove",
                          etykieta: "Remove rule",
                          opis: `${nazwaReguly(regula)} will be removed from ${host.hostname}. The remaining Flotestro rules are rebuilt in order.`,
                          payload: { firewall: { rule_id: nazwaReguly(regula), rollback_seconds: 120 } },
                        })
                      }
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="zrodlo" style={{ marginTop: 12 }}>
        {reguly.length} of {(snapshot?.rules ?? []).length} rules shown
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

/** Nazwa reguly panelu jest zapisana w jej komentarzu. */
function nazwaReguly(regula: Regula): string {
  const bezPrefiksu = (regula.comment ?? "").replace(/^flotestro:\s*/, "");
  return bezPrefiksu.split(" - ")[0] || "";
}

/**
 * Kreator reguly. Panel nie przyjmuje surowego zapisu nft: tekst reguly jest
 * jezykiem, a przyjmowanie jezyka znaczyloby, ze host wykona wszystko, co da
 * sie w nim zapisac.
 */
function KreatorReguly({ odcisk, onZamiar }: { odcisk: string; onZamiar: (zamiar: Zamiar) => void }) {
  const [id, setId] = useState("");
  const [lancuch, setLancuch] = useState("wejscie");
  const [dzialanie, setDzialanie] = useState("accept");
  const [protokol, setProtokol] = useState("tcp");
  const [porty, setPorty] = useState("");
  const [zrodla, setZrodla] = useState("");
  const [komentarz, setKomentarz] = useState("");
  const [przelamanie, setPrzelamanie] = useState(false);

  const lista = (wartosc: string) =>
    wartosc.split(",").map((element) => element.trim()).filter(Boolean);

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>New rule</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        The rule goes into Flotestro's own table. The host arms a rollback
        before applying it and cancels it only after the agent proves it can
        still reach the panel.
      </p>
      <div className="filtry">
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder="Rule name, e.g. block-smtp" />
        <select value={lancuch} onChange={(e) => setLancuch(e.target.value)}>
          <option value="wejscie">incoming</option>
          <option value="wyjscie">outgoing</option>
        </select>
        <select value={dzialanie} onChange={(e) => setDzialanie(e.target.value)}>
          <option value="accept">accept</option>
          <option value="drop">drop</option>
          <option value="reject">reject</option>
        </select>
        <select value={protokol} onChange={(e) => setProtokol(e.target.value)}>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
          <option value="">any protocol</option>
        </select>
      </div>
      <div className="filtry">
        <input value={porty} onChange={(e) => setPorty(e.target.value)} placeholder="Ports, e.g. 25, 1000-2000" />
        <input
          value={zrodla}
          onChange={(e) => setZrodla(e.target.value)}
          placeholder="Sources with masks, e.g. 10.0.0.0/8"
          style={{ minWidth: 220 }}
        />
        <input value={komentarz} onChange={(e) => setKomentarz(e.target.value)} placeholder="Comment (optional)" />
      </div>
      {/* Przelamanie ochrony kanalu zarzadzania jest jawna decyzja: skutkiem
          bywa host, do ktorego trzeba pojechac. */}
      <label className="przelacznik">
        <input type="checkbox" checked={przelamanie} onChange={(e) => setPrzelamanie(e.target.checked)} />
        Allow a rule that can cut this host off from the panel (break glass)
      </label>
      <button
        onClick={() =>
          onZamiar({
            akcja: "firewall.rule.ensure",
            etykieta: "Create rule",
            opis: `${dzialanie} ${protokol || "any protocol"}${
              lista(porty).length ? ` port ${lista(porty).join(", ")}` : ""
            }${lista(zrodla).length ? ` from ${lista(zrodla).join(", ")}` : ""} (${
              lancuch === "wejscie" ? "incoming" : "outgoing"
            })`,
            payload: {
              firewall: {
                rule_id: id,
                chain: lancuch,
                action: dzialanie,
                protocol: protokol,
                ports: lista(porty),
                sources: lista(zrodla),
                comment: komentarz,
                break_glass: przelamanie,
                rollback_seconds: 120,
                expected_hash: odcisk,
              },
            },
          })
        }
        disabled={!id}
      >
        Create rule
      </button>
    </div>
  );
}

/** Otwarcie albo zamkniecie portu w strefie firewalld. */
function PortStrefy({
  strefa, onZamiar, hostname,
}: {
  strefa: string;
  onZamiar: (zamiar: Zamiar) => void;
  hostname: string;
}) {
  const [port, setPort] = useState("");

  return (
    <div className="operacje">
      <input
        value={port}
        onChange={(e) => setPort(e.target.value)}
        placeholder="port/tcp"
        style={{ width: 110 }}
      />
      {["open", "close"].map((operacja) => (
        <button
          key={operacja}
          onClick={() => {
            const [numer, protokol = "tcp"] = port.split("/");
            onZamiar({
              akcja: "firewall.zone.port",
              etykieta: operacja === "open" ? "Open port" : "Close port",
              opis: `${numer}/${protokol} will be ${
                operacja === "open" ? "opened" : "closed"
              } in zone ${strefa} on ${hostname}, permanently and reloaded now.`,
              payload: {
                firewall: {
                  zone: strefa,
                  ports: [numer],
                  protocol: protokol,
                  enable: operacja === "open",
                },
              },
            });
          }}
          disabled={!port}
        >
          {operacja === "open" ? "Open" : "Close"}
        </button>
      ))}
    </div>
  );
}
