import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { AuditEvent } from "../lib/types";
import { Blad, Czas, Pusto, StanZadania } from "../components/ui";

/** Dziennik audytu. Odmowy sa widoczne tak samo jak sukcesy. */
export function Audyt() {
  const [tylkoOdmowy, setTylkoOdmowy] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["audit"],
    queryFn: () => api.get<Collection<AuditEvent>>("/api/v1/audit?limit=200"),
    retry: false,
  });

  if (error instanceof ApiError && error.forbidden) {
    return (
      <>
        <h1>Audit</h1>
        <Pusto>
          You do not have permission to read the fleet-wide audit trail.
          A single host's audit trail is available in its own view.
        </Pusto>
      </>
    );
  }
  if (error) return <Blad error={error} />;

  const zdarzenia = (data?.items ?? []).filter((zdarzenie) => !tylkoOdmowy || zdarzenie.outcome === "denied");

  return (
    <>
      <h1>Audit</h1>
      <p className="podtytul">Every success and failure creates an event; so does every denial.</p>

      <div className="filtry">
        <label>
          <input type="checkbox" checked={tylkoOdmowy} onChange={(e) => setTylkoOdmowy(e.target.checked)} />
          {" "}denials only
        </label>
      </div>

      {!zdarzenia.length ? (
        <Pusto>No events.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Time</th><th>Actor</th><th>Kind</th><th>Operation</th><th>Target</th><th>Result</th><th>Details</th></tr></thead>
          <tbody>
            {zdarzenia.map((zdarzenie) => (
              <tr key={zdarzenie.id}>
                <td><Czas wartosc={zdarzenie.occurred_at} /></td>
                <td>{zdarzenie.actor_id}</td>
                <td>{zdarzenie.actor_type}</td>
                <td>{zdarzenie.action}</td>
                <td>{zdarzenie.target_type ? `${zdarzenie.target_type}/${(zdarzenie.target_id ?? "").slice(0, 8)}` : "—"}</td>
                <td><StanZadania stan={zdarzenie.outcome} /></td>
                <td className="zrodlo">{skrot(zdarzenie.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function skrot(detail: Record<string, unknown>): string {
  const interesujace = ["reason", "action_type", "hostname", "state", "permission", "scope"];
  const czesci = interesujace
    .filter((klucz) => detail?.[klucz] !== undefined)
    .map((klucz) => `${klucz}=${String(detail[klucz])}`);
  return czesci.join(" ").slice(0, 90);
}
