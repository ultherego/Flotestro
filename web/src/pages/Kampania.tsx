import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type {
  Campaign as CampaignType, CampaignReport, CampaignTarget, WpisPrzebiegu,
} from "../lib/types";
import { Blad, Czas, Para, Pary, PasekPostepu, Pusto, StanZadania } from "../components/ui";
import { ODSTEP_OPERACJI, usePostep, useStrumienPostepu } from "../lib/strumien";

export function Kampania() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();

  const kampania = useQuery({
    queryKey: ["campaign", id],
    queryFn: () => api.get<CampaignType>(`/api/v1/campaigns/${id}`),
    refetchInterval: ODSTEP_OPERACJI,
  });
  const cele = useQuery({
    queryKey: ["campaign-targets", id],
    queryFn: () => api.get<Collection<CampaignTarget>>(`/api/v1/campaigns/${id}/targets`),
    refetchInterval: ODSTEP_OPERACJI,
  });
  const raport = useQuery({
    queryKey: ["campaign-report", id],
    queryFn: () => api.get<CampaignReport>(`/api/v1/campaigns/${id}/report`),
    refetchInterval: ODSTEP_OPERACJI,
  });
  // Przebieg pochodzi z trwalego sladu, a nie z powiadomien: zdarzenie wyslane
  // w chwili restartu panelu nie istnieje juz nigdzie, a operator wracajacy do
  // kampanii ma zobaczyc, jak szla, a nie tylko czym sie skonczyla.
  const przebieg = useQuery({
    queryKey: ["campaign-timeline", id],
    queryFn: () => api.get<Collection<WpisPrzebiegu>>(`/api/v1/campaigns/${id}/timeline`),
    refetchInterval: ODSTEP_OPERACJI,
  });

  // Kampania jest tym ekranem, na ktorym postep ma znaczenie decyzyjne:
  // operator patrzy na canary i decyduje, czy puszczac dalsze fale.
  useStrumienPostepu(id ? `/api/v1/campaigns/${id}/events` : null, [
    ["campaign", id],
    ["campaign-targets", id],
    ["campaign-report", id],
  ]);
  // Postep trwajacych operacji kampanii, po hostach.
  const postepy = usePostep(id ? `/api/v1/campaigns/${id}/events` : null);

  const steruj = useMutation({
    mutationFn: (operacja: string) =>
      api.post(`/api/v1/campaigns/${id}/${operacja}`, {
        reason: "z panelu",
        // Zatwierdzenie niesie odcisk kampanii, ktora wlasnie widac. Gdy
        // kampania zmienila sie od jej wczytania, serwer odmawia zamiast
        // przenosic zgode na cos innego.
        approval_fingerprint: kampania.data?.approval_fingerprint,
      }),
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
        <Para etykieta="Concurrent hosts">{dane.max_concurrent}</Para>
        <Para etykieta="Failure threshold">{dane.failure_threshold_percent}% or {dane.failure_threshold_absolute} hosts</Para>
        <Para etykieta="Reboot policy">{dane.reboot_policy}</Para>
        <Para etykieta="Approved by">{dane.approved_by || "—"}</Para>
        <Para etykieta="Approval fingerprint">
          <span title={dane.approval_fingerprint}>{dane.approval_fingerprint.slice(0, 16) || "—"}</span>
        </Para>
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
                  <td>{fala.is_canary ? "yes" : "no"}</td>
                  <td>{fala.completed ? "yes" : "no"}</td>
                  <td>{Object.entries(fala.totals).map(([stan, ile]) => `${stan}: ${ile}`).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2>Timeline</h2>
      {!przebieg.data?.items.length ? (
        <Pusto>No recorded events yet.</Pusto>
      ) : (
        <table>
          <thead><tr><th>When</th><th>Event</th><th>Host</th><th>Detail</th></tr></thead>
          <tbody>
            {przebieg.data.items.map((wpis) => (
              <tr key={wpis.id}>
                <td><Czas wartosc={wpis.occurred_at} /></td>
                <td>{wpis.event_type}</td>
                <td>{nazwaHostaZdarzenia(wpis, cele.data?.items ?? [])}</td>
                <td>{opisZdarzenia(wpis)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Targets</h2>
      {!cele.data?.items.length ? (
        <Pusto>No targets.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Host</th><th>Wave</th><th>State</th><th>Progress</th><th>Error code</th><th>Message</th></tr></thead>
          <tbody>
            {cele.data.items.map((cel) => (
              <tr key={cel.host_id}>
                <td>{cel.hostname || cel.host_id.slice(0, 8)}</td>
                <td>{cel.wave}{cel.wave === 0 && " (canary)"}</td>
                <td><StanZadania stan={cel.state} /></td>
                {/* Postep dotyczy operacji, ktora akurat trwa na tym hoscie.
                    Host czekajacy na swoja fale nie ma czego pokazywac. */}
                <td>
                  {postepDlaCelu(postepy, cel) ? (
                    <PasekPostepu
                      procent={postepDlaCelu(postepy, cel)?.percent}
                      krok={postepDlaCelu(postepy, cel)?.step}
                      krokow={postepDlaCelu(postepy, cel)?.total}
                      opis={postepDlaCelu(postepy, cel)?.message}
                    />
                  ) : (
                    "—"
                  )}
                </td>
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

/** nazwaHostaZdarzenia tlumaczy identyfikator hosta na nazwe z listy celow. */
function nazwaHostaZdarzenia(wpis: WpisPrzebiegu, cele: CampaignTarget[]): string {
  const hostID = wpis.payload?.host_id;
  if (!hostID) return "—";
  const cel = cele.find((pozycja) => pozycja.host_id === hostID);
  return cel?.hostname || hostID.slice(0, 8);
}

/**
 * opisZdarzenia pokazuje to, co odroznia jedno zdarzenie od drugiego.
 *
 * Kod bledu i powod wstrzymania sa tu wazniejsze niz sam typ zdarzenia:
 * "host failed" bez powodu nie mowi nic poza tym, ze cos poszlo zle.
 */
function opisZdarzenia(wpis: WpisPrzebiegu): string {
  const czesci = [
    wpis.payload?.error_code,
    wpis.payload?.message,
    wpis.payload?.pause_reason,
  ].filter((czesc) => czesc);
  if (typeof wpis.payload?.wave === "number" && wpis.aggregate_type === "campaign_target") {
    czesci.unshift(`wave ${wpis.payload.wave}`);
  }
  return czesci.join(" · ") || "—";
}

/**
 * Postep celu kampanii szukamy po operacji, ktora do niego nalezy. Kampania
 * zaklada hostowi kolejno kilka operacji - aktualizacje, restart, health check
 * - wiec sam identyfikator hosta nie wystarczy.
 */
function postepDlaCelu(
  postepy: Map<string, { step?: number; total?: number; percent?: number; message?: string }>,
  cel: CampaignTarget,
) {
  for (const jobID of [cel.job_id, cel.reboot_job_id, cel.health_job_id]) {
    if (jobID && postepy.has(jobID)) return postepy.get(jobID);
  }
  return undefined;
}
