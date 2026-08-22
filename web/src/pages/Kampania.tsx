import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign as CampaignType, CampaignReport, CampaignTarget } from "../lib/types";
import { Blad, Czas, Para, Pary, Pusto, StanZadania } from "../components/ui";

export function Kampania() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();

  const kampania = useQuery({
    queryKey: ["campaign", id],
    queryFn: () => api.get<CampaignType>(`/api/v1/campaigns/${id}`),
  });
  const cele = useQuery({
    queryKey: ["campaign-targets", id],
    queryFn: () => api.get<Collection<CampaignTarget>>(`/api/v1/campaigns/${id}/targets`),
  });
  const raport = useQuery({
    queryKey: ["campaign-report", id],
    queryFn: () => api.get<CampaignReport>(`/api/v1/campaigns/${id}/report`),
  });

  const steruj = useMutation({
    mutationFn: (operacja: string) =>
      api.post(`/api/v1/campaigns/${id}/${operacja}`, { reason: "z panelu" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["campaign", id] });
      queryClient.invalidateQueries({ queryKey: ["campaign-targets", id] });
    },
  });

  if (kampania.error) return <Blad error={kampania.error} />;
  if (!kampania.data) return <Pusto>Loading…</Pusto>;
  const dane = kampania.data;

  return (
    <>
      <h1>{dane.name}</h1>
      <p className="podtytul">
        <StanZadania stan={dane.state} /> · {dane.action_type} · zlecil {dane.created_by}
      </p>

      <div style={{ marginBottom: 20 }}>
        {dane.state === "awaiting_approval" && (
          <button onClick={() => steruj.mutate("approve")}>Approve</button>
        )}{" "}
        {["canary", "running", "planned"].includes(dane.state) && (
          <button className="wtorny" onClick={() => steruj.mutate("pause")}>Pause</button>
        )}{" "}
        {dane.state === "paused" && (
          <button onClick={() => steruj.mutate("resume")}>Resume</button>
        )}{" "}
        {!["completed", "failed", "canceled"].includes(dane.state) && (
          <button className="wtorny" onClick={() => steruj.mutate("cancel")}>Cancel</button>
        )}
      </div>

      <Pary>
        <Para etykieta="Canary / wave">{dane.canary_size} / {dane.wave_size}</Para>
        <Para etykieta="Rownolegle hostow">{dane.max_concurrent}</Para>
        <Para etykieta="Failure threshold">{dane.failure_threshold_percent}% albo {dane.failure_threshold_absolute} szt.</Para>
        <Para etykieta="Reboot policy">{dane.reboot_policy}</Para>
        <Para etykieta="Approved by">{dane.approved_by || "—"}</Para>
        <Para etykieta="Paused by">{dane.paused_by || "—"}</Para>
        <Para etykieta="Pause reason">{dane.pause_reason || "—"}</Para>
        <Para etykieta="Created"><Czas wartosc={dane.created_at} /></Para>
      </Pary>

      {raport.data && (
        <>
          <h2>Waves</h2>
          <table>
            <thead><tr><th>Wave</th><th>Canary</th><th>Closed</th><th>Summary</th></tr></thead>
            <tbody>
              {raport.data.waves.map((fala) => (
                <tr key={fala.wave}>
                  <td>{fala.wave}</td>
                  <td>{fala.is_canary ? "tak" : "nie"}</td>
                  <td>{fala.completed ? "tak" : "nie"}</td>
                  <td>{Object.entries(fala.totals).map(([stan, ile]) => `${stan}: ${ile}`).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>Cele</h2>
      {!cele.data?.items.length ? (
        <Pusto>No targets.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Host</th><th>Wave</th><th>State</th><th>Error code</th><th>Message</th></tr></thead>
          <tbody>
            {cele.data.items.map((cel) => (
              <tr key={cel.host_id}>
                <td>{cel.hostname || cel.host_id.slice(0, 8)}</td>
                <td>{cel.wave}{cel.wave === 0 && " (canary)"}</td>
                <td><StanZadania stan={cel.state} /></td>
                <td>{cel.error_code || "—"}</td>
                <td>{cel.message || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
