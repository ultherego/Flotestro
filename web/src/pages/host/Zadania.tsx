import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto, StanZadania } from "../../components/ui";
import { useHost } from "./wspolne";

export function ZadaniaHosta() {
  const host = useHost();
  const { data, error } = useQuery({
    queryKey: ["jobs", host.id],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=50`),
  });
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No jobs for this host.</Pusto>;

  return (
    <table>
      <thead><tr><th>Operation</th><th>State</th><th>Requested by</th><th>Approved by</th><th>Result</th><th>Created</th></tr></thead>
      <tbody>
        {data.items.map((zadanie) => (
          <tr key={zadanie.id}>
            <td>{zadanie.action_type}</td>
            <td><StanZadania stan={zadanie.state} /></td>
            <td>{zadanie.created_by}</td>
            <td>{zadanie.approved_by || "—"}</td>
            <td>{zadanie.result_error_code || zadanie.result_status || "—"}</td>
            <td><Czas wartosc={zadanie.created_at} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
