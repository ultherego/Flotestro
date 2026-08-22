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
        <h1>Audyt</h1>
        <Pusto>
          Brak uprawnienia do odczytu dziennika calej floty. Audyt pojedynczego hosta
          jest dostepny w jego widoku.
        </Pusto>
      </>
    );
  }
  if (error) return <Blad error={error} />;

  const zdarzenia = (data?.items ?? []).filter((zdarzenie) => !tylkoOdmowy || zdarzenie.outcome === "denied");

  return (
    <>
      <h1>Audyt</h1>
      <p className="podtytul">Kazda sciezka sukcesu i bledu tworzy zdarzenie; odmowy takze.</p>

      <div className="filtry">
        <label>
          <input type="checkbox" checked={tylkoOdmowy} onChange={(e) => setTylkoOdmowy(e.target.checked)} />
          {" "}tylko odmowy
        </label>
      </div>

      {!zdarzenia.length ? (
        <Pusto>Brak zdarzen.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Czas</th><th>Kto</th><th>Typ</th><th>Operacja</th><th>Cel</th><th>Wynik</th><th>Szczegoly</th></tr></thead>
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
