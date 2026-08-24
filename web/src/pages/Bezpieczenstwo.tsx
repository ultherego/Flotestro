import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type HostZUstaleniem = { host_id: string; hostname: string; observed: string; action?: string };

type Sprawdzenie = {
  check_id: string;
  title: string;
  severity: string;
  expected: string;
  failed: number;
  passed: number;
  unknown: number;
  not_applicable: number;
  fixable: number;
  hosts?: HostZUstaleniem[];
};

type Widok = { hosts: number; checks: Sprawdzenie[]; generated_at: string };

function znacznikWagi(waga: string, ile: number) {
  if (ile === 0) return <span className="znacznik ok">0</span>;
  const klasa = waga === "high" ? "blad" : waga === "info" ? "nieznany" : "uwaga";
  return <span className={`znacznik ${klasa}`}>{ile}</span>;
}

/**
 * Zgodnosc floty z profilem hardeningu.
 *
 * Jedno zle ustawienie na stu hostach jest jednym problemem, a nie stoma -
 * i widac to dopiero wtedy, gdy ustalenia stoja obok siebie. Naprawa idzie
 * jednak host po hoscie: kazda tworzy zwykle zadanie modulu, ktory za dana
 * rzecz odpowiada.
 */
export function Bezpieczenstwo() {
  const [rozwiniete, setRozwiniete] = useState("");
  const { data, error } = useQuery({
    queryKey: ["security", "fleet"],
    queryFn: () => api.get<Widok>("/api/v1/security"),
  });

  if (error) return <Blad error={error} />;
  if (!data) return <Pusto>Computing findings…</Pusto>;

  return (
    <>
      <h1>Security</h1>
      <p className="podtytul">
        Versioned checks over the facts hosts already report. One bad setting on
        a hundred hosts is one problem, not a hundred — but the fix still goes
        host by host, as a job of the module that owns it.
      </p>

      <table>
        <thead>
          <tr>
            <th>Check</th><th>Need action</th><th>Passed</th><th>Unknown</th><th>N/A</th><th>Expected</th><th>Fixable</th>
          </tr>
        </thead>
        <tbody>
          {data.checks.map((sprawdzenie) => (
            <Fragment key={sprawdzenie.check_id}>
              <tr>
                <td>
                  <button
                    className="wtorny"
                    onClick={() =>
                      setRozwiniete((obecne) =>
                        obecne === sprawdzenie.check_id ? "" : sprawdzenie.check_id,
                      )
                    }
                    disabled={!sprawdzenie.failed}
                  >
                    {rozwiniete === sprawdzenie.check_id ? "▾" : "▸"}
                  </button>{" "}
                  {sprawdzenie.title}
                  <div className="zrodlo">{sprawdzenie.check_id}</div>
                </td>
                <td>{znacznikWagi(sprawdzenie.severity, sprawdzenie.failed)}</td>
                <td>{sprawdzenie.passed}</td>
                {/* Nieustalone nie jest zaliczone: host, ktory nie zglosil
                    faktu, nie jest hostem zgodnym. */}
                <td>{sprawdzenie.unknown ? <span className="znacznik nieznany">{sprawdzenie.unknown}</span> : 0}</td>
                {/* Sprawdzenie, ktore hosta nie dotyczy, nie wchodzi ani do
                    zgodnosci, ani do niezgodnosci. */}
                <td>{sprawdzenie.not_applicable}</td>
                <td>{sprawdzenie.expected}</td>
                <td>
                  {sprawdzenie.fixable}
                  {sprawdzenie.failed > sprawdzenie.fixable && (
                    <div className="zrodlo">
                      {sprawdzenie.failed - sprawdzenie.fixable} need a decision
                    </div>
                  )}
                </td>
              </tr>
              {rozwiniete === sprawdzenie.check_id &&
                (sprawdzenie.hosts ?? []).map((host) => (
                  <tr key={`${sprawdzenie.check_id}-${host.host_id}`}>
                    <td colSpan={2}>
                      <Link to={`/hosts/${host.host_id}/security`}>{host.hostname}</Link>
                    </td>
                    <td colSpan={4}>{host.observed}</td>
                    <td>{host.action ? <code>{host.action}</code> : <span className="zrodlo">—</span>}</td>
                  </tr>
                ))}
            </Fragment>
          ))}
        </tbody>
      </table>

      <p className="zrodlo">
        {data.hosts} hosts · computed <Czas wartosc={data.generated_at} />
      </p>
    </>
  );
}
