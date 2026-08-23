import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { AuditEvent } from "../../lib/types";
import { Blad, Czas, Pusto, StanZadania } from "../../components/ui";
import { useHost } from "./wspolne";

export function AudytHosta() {
  const host = useHost();
  const { data, error } = useQuery({
    queryKey: ["audit", host.id],
    queryFn: () => api.get<Collection<AuditEvent>>(`/api/v1/hosts/${host.id}/audit?limit=50`),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Pusto>You do not have permission to read this host's audit trail.</Pusto>;
  }
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No events.</Pusto>;

  return (
    <table>
      <thead><tr><th>Time</th><th>Actor</th><th>Operation</th><th>Result</th></tr></thead>
      <tbody>
        {data.items.map((zdarzenie) => (
          <tr key={zdarzenie.id}>
            <td><Czas wartosc={zdarzenie.occurred_at} /></td>
            <td>{zdarzenie.actor_id}</td>
            <td>{zdarzenie.action}</td>
            <td><StanZadania stan={zdarzenie.outcome} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
