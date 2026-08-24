import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Nasluch = {
  protocol: string;
  address: string;
  port: number;
  process?: string;
  exposed: boolean;
};

type Snapshot = {
  mac: {
    system?: string;
    mode?: string;
    configured_mode?: string;
    policy?: string;
    profiles_enforcing?: number | null;
    profiles_complain?: number | null;
    reason?: string;
  };
  audit: { present: boolean; active?: boolean | null; rules?: number | null; reason?: string };
  fips_enabled?: boolean | null;
  secure_boot?: boolean | null;
  secure_boot_reason?: string;
  lockdown?: string;
  listening?: Nasluch[];
  listening_known?: boolean;
  observed_at?: string;
  unavailable_reason?: string;
};

type Naprawa = { action?: string; payload?: unknown; note?: string };

type Ustalenie = {
  check_id: string;
  check_version: number;
  title: string;
  severity: string;
  rationale: string;
  passed: boolean;
  unknown: boolean;
  expected: string;
  observed: string;
  evidence?: string;
  module: string;
  revision?: string;
  observed_at?: string;
  remediation?: Naprawa;
};

type Raport = {
  findings: Ustalenie[];
  plan_hash: string;
  generated_at: string;
  counts: Record<string, number>;
};

type KrokNaprawy = { check_id: string; action?: string; job_id?: string; state?: string; skipped?: string };

const nieznane = <span className="znacznik nieznany">unknown</span>;

function flaga(wartosc?: boolean | null) {
  if (wartosc === undefined || wartosc === null) return nieznane;
  return wartosc ? "yes" : "no";
}

/** Waga mowi, co sie stanie, gdy nikt nic nie zrobi - nie jak trudno naprawic. */
function znacznikWagi(ustalenie: Ustalenie) {
  if (ustalenie.unknown) return <span className="znacznik nieznany">unknown</span>;
  if (ustalenie.passed) return <span className="znacznik ok">passed</span>;
  const klasa = ustalenie.severity === "high" ? "blad" : ustalenie.severity === "info" ? "nieznany" : "uwaga";
  return <span className={`znacznik ${klasa}`}>{ustalenie.severity}</span>;
}

/**
 * Bezpieczenstwo i hardening.
 *
 * Host zglasza fakty, panel je ocenia. Sprawdzenia sa wersjonowane i licza sie
 * z tego, co i tak jest w inwentarzu, wiec wynik da sie powtorzyc, a dwa hosty
 * ocenia to samo sprawdzenie. Naprawa nie jest osobnym mechanizmem: kazda
 * mapuje sie na typowana operacje modulu, ktory za dana rzecz odpowiada.
 */
export function Bezpieczenstwo() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "security");
  const [wybrane, setWybrane] = useState<string[]>([]);
  const [komunikat, setKomunikat] = useState("");
  const [kroki, setKroki] = useState<KrokNaprawy[]>([]);
  const [zamiar, setZamiar] = useState<{ etykieta: string; opis: string } | null>(null);

  const raport = useQuery({
    queryKey: ["security", host.id],
    queryFn: () => api.get<Raport>(`/api/v1/hosts/${host.id}/security`),
  });

  const skanuj = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "security.scan",
        reason: "odswiezenie stanu ochronnego hosta",
        payload: {},
      }),
    onSuccess: (zadanie) => {
      setKomunikat(`Job ${zadanie.id.slice(0, 8)} has been queued; findings refresh once it reports back.`);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const napraw = useMutation({
    mutationFn: (powod: string) =>
      api.post<{ steps: KrokNaprawy[] }>(`/api/v1/hosts/${host.id}/security/remediation`, {
        plan_hash: raport.data?.plan_hash,
        check_ids: wybrane,
        reason: powod,
      }),
    onSuccess: (odpowiedz) => {
      setKroki(odpowiedz.steps);
      setWybrane([]);
      setZamiar(null);
      setKomunikat("");
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setZamiar(null);
      setKomunikat(error instanceof Error ? error.message : String(error));
    },
  });

  const snapshot = modul.data?.payload;
  const ustalenia = raport.data?.findings ?? [];
  const doNaprawy = ustalenia.filter((u) => !u.passed && !u.unknown && u.remediation?.action);

  return (
    <>
      <p className="podtytul">
        The host reports facts; the panel judges them. Checks are versioned and
        run against inventory the host already sends, so a result can be
        repeated and two hosts are judged by the same check. Every fix maps to
        a typed operation of the module that owns the thing being fixed.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Security state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr>
            <th>Mandatory access control</th>
            <td>
              {snapshot?.mac?.system
                ? `${snapshot.mac.system}: ${snapshot.mac.mode || "unknown"}`
                : snapshot?.mac?.reason || nieznane}
              {snapshot?.mac?.policy && <span className="zrodlo"> · {snapshot.mac.policy}</span>}
              {/* Tryb dzialajacy i tryb z konfiguracji bywaja rozne - i to
                  jest cala roznica miedzy ochrona a ochrona do restartu. */}
              {snapshot?.mac?.configured_mode &&
                snapshot.mac.configured_mode !== snapshot.mac.mode && (
                  <span className="znacznik uwaga"> after reboot: {snapshot.mac.configured_mode}</span>
                )}
              {snapshot?.mac?.profiles_enforcing !== undefined &&
                snapshot?.mac?.profiles_enforcing !== null && (
                  <span className="zrodlo">
                    {" "}· {snapshot.mac.profiles_enforcing} enforcing,{" "}
                    {snapshot.mac.profiles_complain ?? 0} complaining
                  </span>
                )}
            </td>
          </tr>
          <tr>
            <th>Audit daemon</th>
            <td>
              {!snapshot?.audit?.present
                ? snapshot?.audit?.reason || "not installed"
                : `${flaga(snapshot.audit.active)}${
                    snapshot.audit.rules !== undefined && snapshot.audit.rules !== null
                      ? ` · ${snapshot.audit.rules} rules`
                      : ""
                  }`}
            </td>
          </tr>
          <tr>
            <th>Secure boot</th>
            <td>
              {snapshot?.secure_boot === undefined || snapshot?.secure_boot === null ? (
                <>
                  {nieznane}
                  {snapshot?.secure_boot_reason && (
                    <span className="zrodlo"> · {snapshot.secure_boot_reason}</span>
                  )}
                </>
              ) : (
                flaga(snapshot.secure_boot)
              )}
            </td>
          </tr>
          <tr><th>FIPS mode</th><td>{flaga(snapshot?.fips_enabled)}</td></tr>
          <tr><th>Kernel lockdown</th><td>{snapshot?.lockdown || nieznane}</td></tr>
        </tbody>
      </table>

      <h2>Exposed services</h2>
      <p className="podtytul">
        Sockets listening beyond the loopback interface. Each one is a way into
        this host for anyone who can see its network.
      </p>
      {!snapshot?.listening_known ? (
        <Pusto>This host did not report its listening sockets.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Proto</th><th>Address</th><th>Port</th><th>Process</th><th>Reach</th></tr></thead>
          <tbody>
            {(snapshot.listening ?? [])
              .slice()
              .sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port)
              .map((gniazdo, i) => (
                <tr key={`${gniazdo.protocol}-${gniazdo.address}-${gniazdo.port}-${i}`}>
                  <td>{gniazdo.protocol}</td>
                  <td>{gniazdo.address}</td>
                  <td>{gniazdo.port}</td>
                  <td>{gniazdo.process || "—"}</td>
                  <td>
                    {gniazdo.exposed ? (
                      <span className="znacznik uwaga">exposed</span>
                    ) : (
                      <span className="zrodlo">loopback</span>
                    )}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      )}

      <h2>Findings</h2>
      <div className="filtry">
        <button onClick={() => skanuj.mutate()} disabled={skanuj.isPending}>
          Scan now
        </button>
        <span className="zrodlo">
          {raport.data
            ? `${raport.data.counts.failed ?? 0} need action · ${raport.data.counts.passed ?? 0} passed · ${
                raport.data.counts.unknown ?? 0
              } unknown`
            : "…"}
        </span>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {!raport.data ? (
        <Pusto>Computing findings…</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th></th><th>Check</th><th>State</th><th>Expected</th><th>Observed</th><th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {ustalenia.map((ustalenie) => (
              <tr key={ustalenie.check_id}>
                <td>
                  {/* Zaznaczyc mozna wylacznie ustalenie, ktore ma operacje
                      naprawcza. Reszta wymaga decyzji, ktorej panel nie
                      podejmie za operatora. */}
                  <input
                    type="checkbox"
                    disabled={!ustalenie.remediation?.action || ustalenie.passed || ustalenie.unknown}
                    checked={wybrane.includes(ustalenie.check_id)}
                    onChange={(e) =>
                      setWybrane((lista) =>
                        e.target.checked
                          ? [...lista, ustalenie.check_id]
                          : lista.filter((id) => id !== ustalenie.check_id),
                      )
                    }
                  />
                </td>
                <td>
                  {ustalenie.title}
                  <div className="zrodlo">
                    {ustalenie.check_id} v{ustalenie.check_version} · {ustalenie.rationale}
                  </div>
                </td>
                <td>{znacznikWagi(ustalenie)}</td>
                <td>{ustalenie.expected}</td>
                <td>
                  {ustalenie.observed}
                  {ustalenie.evidence && <div className="zrodlo">{ustalenie.evidence}</div>}
                  {/* Dowod niesie modul i rewizje, z ktorej wynik powstal. */}
                  {ustalenie.revision && (
                    <div className="zrodlo">
                      {ustalenie.module} @ {ustalenie.revision.slice(0, 8)}
                      {ustalenie.observed_at && (
                        <>
                          {" · "}
                          <Czas wartosc={ustalenie.observed_at} />
                        </>
                      )}
                    </div>
                  )}
                </td>
                <td>
                  {ustalenie.remediation?.action ? (
                    <>
                      <code>{ustalenie.remediation.action}</code>
                      {ustalenie.remediation.note && (
                        <div className="zrodlo">{ustalenie.remediation.note}</div>
                      )}
                    </>
                  ) : (
                    <span className="zrodlo">{ustalenie.remediation?.note || "—"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="filtry">
        <button
          onClick={() =>
            setZamiar({
              etykieta: "Apply remediation",
              opis:
                `${wybrane.length} finding(s) on ${host.hostname} will be fixed by ${wybrane.length} separate ` +
                "jobs, each going through the permissions and approval of the module that owns it. " +
                "The plan is bound to the state you are looking at: if the host changed meanwhile, the request is refused.",
            })
          }
          disabled={!wybrane.length || napraw.isPending}
        >
          Fix selected ({wybrane.length})
        </button>
        <span className="zrodlo">
          {doNaprawy.length} of the findings that need action have an operation behind them
        </span>
      </div>

      {kroki.length > 0 && (
        <table>
          <thead><tr><th>Check</th><th>Operation</th><th>Job</th><th>State</th></tr></thead>
          <tbody>
            {kroki.map((krok) => (
              <tr key={krok.check_id}>
                <td>{krok.check_id}</td>
                <td>{krok.action || <span className="zrodlo">{krok.skipped}</span>}</td>
                <td>{krok.job_id ? krok.job_id.slice(0, 8) : "—"}</td>
                <td>{krok.state || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <SwiezoscModulu fragment={modul.data} />
      {raport.data?.generated_at && (
        <p className="zrodlo">
          Findings computed <Czas wartosc={raport.data.generated_at} /> · plan{" "}
          {raport.data.plan_hash.slice(0, 12)}
        </p>
      )}

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={napraw.isPending}
          onPotwierdz={(powod) => napraw.mutate(powod)}
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}
