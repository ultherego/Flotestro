import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Attempt, Job } from "../lib/types";
import { Blad, Czas, PasekPostepu, Pusto, StanZadania } from "../components/ui";
import { ODSTEP_OPERACJI, usePostep } from "../lib/strumien";

/** Lista zadan z zatwierdzaniem. Zatwierdzenie potwierdza hash planu. */
export function Zadania() {
  const [stan, setStan] = useState("");
  const [rozwiniete, setRozwiniete] = useState<string>("");
  const queryClient = useQueryClient();

  const parametry = new URLSearchParams({ limit: "100" });
  if (stan) parametry.set("state", stan);

  const { data, error } = useQuery({
    queryKey: ["jobs", parametry.toString()],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?${parametry}`),
    // Lista operacji nie ma wlasnego strumienia, bo jej zawartosc zmienia sie
    // takze przez operacje innych operatorow i przez wygasanie zadan.
    refetchInterval: ODSTEP_OPERACJI,
  });

  // Jeden strumien na karte niesie postep wszystkich trwajacych operacji
  // i budzi liste, gdy ktoras zmieni stan.
  const postepy = usePostep("/api/v1/events");

  const zatwierdz = useMutation({
    mutationFn: (zadanie: Job) =>
      api.post(`/api/v1/jobs/${zadanie.id}/approve`, { payload_hash: zadanie.payload_hash }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const anuluj = useMutation({
    mutationFn: (zadanie: Job) =>
      api.post(`/api/v1/jobs/${zadanie.id}/cancel`, { reason: "canceled from the panel" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["jobs"] }),
  });

  if (error) return <Blad error={error} />;

  return (
    <>
      <h1>Jobs</h1>
      <p className="podtytul">Approval confirms the plan hash, so tampering with its content is detectable.</p>

      <div className="filtry">
        <select value={stan} onChange={(e) => setStan(e.target.value)}>
          <option value="">state: any</option>
          {["awaiting_approval", "queued", "dispatched", "running", "succeeded", "failed", "canceled", "expired"].map(
            (wartosc) => <option key={wartosc} value={wartosc}>{wartosc}</option>,
          )}
        </select>
      </div>

      {!data?.items.length ? (
        <Pusto>No jobs.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Operation</th><th>State</th><th>Requested by</th><th>Approved by</th>
              <th>Result</th><th>Created</th><th></th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((zadanie) => (
              <>
                <tr key={zadanie.id}>
                  <td>
                    <a href="#" onClick={(e) => { e.preventDefault(); setRozwiniete(rozwiniete === zadanie.id ? "" : zadanie.id); }}>
                      {zadanie.action_type}
                    </a>
                  </td>
                  <td>
                    <StanZadania stan={zadanie.state} />
                    {/* Pasek towarzyszy stanowi, a nie zastepuje go: operator
                        ma widziec i to, ze operacja trwa, i jak daleko zaszla. */}
                    {postepy.has(zadanie.id) && (
                      <PasekPostepu
                        procent={postepy.get(zadanie.id)?.percent}
                        krok={postepy.get(zadanie.id)?.step}
                        krokow={postepy.get(zadanie.id)?.total}
                        opis={postepy.get(zadanie.id)?.message}
                      />
                    )}
                  </td>
                  <td>{zadanie.created_by}</td>
                  <td>{zadanie.approved_by || "—"}</td>
                  <td>{zadanie.result_error_code || zadanie.result_status || "—"}</td>
                  <td><Czas wartosc={zadanie.created_at} /></td>
                  <td>
                    {zadanie.state === "awaiting_approval" && (
                      <>
                        <button onClick={() => zatwierdz.mutate(zadanie)} disabled={zatwierdz.isPending}>
                          Approve
                        </button>{" "}
                        <button className="wtorny" onClick={() => anuluj.mutate(zadanie)}>Cancel</button>
                      </>
                    )}
                  </td>
                </tr>
                {rozwiniete === zadanie.id && (
                  <tr key={`${zadanie.id}-proby`}>
                    <td colSpan={7}><Proby jobId={zadanie.id} /></td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Proby wykonania zadania wraz z wynikiem typowanym dla danej operacji. */
function Proby({ jobId }: { jobId: string }) {
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No execution attempts.</Pusto>;

  return (
    <div>
      {data.items.map((proba) => (
        <div key={proba.id} style={{ marginBottom: 12 }}>
          <div>
            proba {proba.attempt_number} · <StanZadania stan={proba.status ?? "—"} /> ·
            kod {proba.exit_code ?? "—"}
            {proba.replayed && <> · <span className="znacznik">replayed from journal</span></>}
            {proba.error_code && <> · <span className="znacznik blad">{proba.error_code}</span></>}
          </div>
          {proba.unit_state_before && proba.unit_state_after && (
            <div className="zrodlo">
              jednostka: {proba.unit_state_before.active_state}/{proba.unit_state_before.sub_state}
              {" "}pid {proba.unit_state_before.main_pid} → {proba.unit_state_after.active_state}/
              {proba.unit_state_after.sub_state} pid {proba.unit_state_after.main_pid}
            </div>
          )}
          {proba.message && <div className="zrodlo">{proba.message}</div>}
          {proba.detail && <WynikTypowany detail={proba.detail} />}
          {proba.stdout && <pre style={{ marginTop: 8 }}>{proba.stdout.slice(0, 4000)}</pre>}
          {proba.stderr && <pre style={{ marginTop: 8 }}>{proba.stderr.slice(0, 2000)}</pre>}
        </div>
      ))}
    </div>
  );
}

/** Wynik zalezny od typu operacji: plan pakietow, raport transakcji, preflight. */
function WynikTypowany({ detail }: { detail: Record<string, any> }) {
  switch (detail.kind) {
    case "package_plan":
      return (
        <div className="zrodlo">
          plan {detail.manager}: {detail.changes?.length ?? 0} zmian, pobranie{" "}
          {Math.round((detail.download_bytes ?? 0) / 1048576)} MB
          {detail.reboot_predicted && ", reboot predicted"}
        </div>
      );
    case "package_apply":
      return (
        <div className="zrodlo">
          zastosowano {detail.applied?.length ?? 0} pakietow
          {detail.reboot_required && ", reboot required"}
          {detail.package_database_broken && ", PACKAGE DATABASE NEEDS REPAIR"}
        </div>
      );
    case "domain_enroll":
      return (
        <div className="zrodlo">
          {(detail.checks ?? []).map((sprawdzenie: any) => (
            <div key={sprawdzenie.name}>
              {sprawdzenie.passed === true ? "OK" : sprawdzenie.passed === false ? (sprawdzenie.blocking ? "BLOKUJE" : "uwaga") : "nieznane"}
              {" "}{sprawdzenie.name}: {sprawdzenie.detail}
            </div>
          ))}
        </div>
      );
    case "unit_status":
      return (
        <div className="zrodlo">
          {(detail.units ?? []).map((jednostka: any) => (
            <div key={jednostka.name}>
              {jednostka.name}: {jednostka.active_state}/{jednostka.sub_state}
            </div>
          ))}
        </div>
      );
    default:
      return null;
  }
}
