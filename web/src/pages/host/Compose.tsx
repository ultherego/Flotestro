import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto, StanZadania } from "../../components/ui";
import { useHost } from "./wspolne";

type WersjaProjektu = {
  job_id: string;
  state: string;
  plan_digest?: string;
  manifest: string;
  created_by: string;
  created_at: string;
  applied: boolean;
};

type UslugaPlanu = { name: string; image: string; image_digest?: string; replicas?: number };
type ZmianaPlanu = { kind: string; name: string; action: string };
type PlanProjektu = {
  project: string;
  digest: string;
  services?: UslugaPlanu[];
  changes?: ZmianaPlanu[];
  warnings?: string[];
};

/**
 * Projekty Docker Compose.
 *
 * Manifest opisuje stan docelowy, a nie polecenie. Operator planuje, oglada
 * roznice i dopiero wtedy wdraza - wdrozenie jest zwiazane z tym planem
 * i odmawia, gdy stan podstawy zmienil sie od zatwierdzenia.
 */
export function Compose() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [projekt, setProjekt] = useState("");
  const [manifest, setManifest] = useState("");
  const [plan, setPlan] = useState<PlanProjektu | null>(null);
  const [komunikat, setKomunikat] = useState("");

  const wersje = useQuery({
    queryKey: ["compose-versions", host.id, projekt],
    queryFn: () =>
      api.get<Collection<WersjaProjektu>>(
        `/api/v1/hosts/${host.id}/compose/${encodeURIComponent(projekt)}/versions`,
      ),
    enabled: projekt.length > 0,
  });

  const zaplanuj = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.plan",
        payload: { compose: { project: projekt, manifest } },
      }),
    onSuccess: (zadanie) => {
      setPlan(null);
      setKomunikat(`Planning as job ${zadanie.id.slice(0, 8)}. The result appears below when it finishes.`);
      czekajNaPlan(zadanie.id);
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  // Plan powstaje na hoscie, wiec ekran czeka na wynik operacji. Strumien
  // budzi liste zadan; tutaj wystarczy odpytac o ten jeden wynik.
  async function czekajNaPlan(jobID: string) {
    for (let proba = 0; proba < 30; proba++) {
      await new Promise((gotowe) => setTimeout(gotowe, 2000));
      const proby = await api.get<{ items: { status?: string; detail?: { payload?: PlanProjektu } }[] }>(
        `/api/v1/jobs/${jobID}/attempts`,
      );
      const ostatnia = proby.items[proby.items.length - 1];
      if (!ostatnia?.status) continue;
      if (ostatnia.detail?.payload) {
        setPlan(ostatnia.detail.payload);
        setKomunikat("");
        return;
      }
      setKomunikat(`Planning finished with status ${ostatnia.status} and no plan.`);
      return;
    }
    setKomunikat("The plan did not arrive in time.");
  }

  const wdroz = useMutation({
    mutationFn: (tresc: { manifest: string; digest: string; powod: string }) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "docker.compose.deploy",
        reason: tresc.powod,
        payload: {
          compose: { project: projekt, manifest: tresc.manifest, plan_digest: tresc.digest },
        },
      }),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      queryClient.invalidateQueries({ queryKey: ["compose-versions", host.id, projekt] });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  return (
    <>
      <h2>Project</h2>
      <div className="formularz">
        <label>
          Project name
          <input
            value={projekt}
            onChange={(e) => setProjekt(e.target.value)}
            placeholder="shop"
          />
        </label>
        <label>
          Manifest (docker-compose.yml)
          <textarea
            rows={12}
            value={manifest}
            onChange={(e) => { setManifest(e.target.value); setPlan(null); }}
            placeholder={"services:\n  web:\n    image: nginx@sha256:…"}
          />
        </label>
        <div className="operacje">
          <button
            onClick={() => zaplanuj.mutate()}
            disabled={zaplanuj.isPending || !projekt || !manifest}
          >
            {zaplanuj.isPending ? "Planning…" : "Plan"}
          </button>
        </div>
        {/* Manifest jest przechowywany w panelu razem z historia wersji,
            wiec wpisane w nim haslo przestaje byc sekretem. */}
        <p className="zrodlo" style={{ margin: 0 }}>
          The manifest is stored with the operation and stays in the panel's history.
          Keep credentials out of it.
        </p>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginTop: 12 }}>{komunikat}</p>}

      {plan && (
        <>
          <h2>Plan</h2>
          <p className="podtytul">
            Digest {plan.digest.slice(0, 16)} · deploying uses exactly this plan; if the
            manifest or the images change, the deployment is refused.
          </p>

          {plan.warnings?.map((ostrzezenie) => (
            <p key={ostrzezenie} className="ostrzezenie"><span>{ostrzezenie}</span></p>
          ))}

          <table>
            <thead><tr><th>Object</th><th>Name</th><th>Change</th></tr></thead>
            <tbody>
              {!plan.changes?.length ? (
                <tr><td colSpan={3} className="pusto">Nothing would change on this host.</td></tr>
              ) : (
                plan.changes.map((zmiana) => (
                  <tr key={`${zmiana.kind}/${zmiana.name}`}>
                    <td>{zmiana.kind}</td>
                    <td>{zmiana.name}</td>
                    <td>{zmiana.action}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <h2>Services after deployment</h2>
          <table>
            <thead><tr><th>Service</th><th>Image</th><th>Replicas</th></tr></thead>
            <tbody>
              {(plan.services ?? []).map((usluga) => (
                <tr key={usluga.name}>
                  <td>{usluga.name}</td>
                  <td>{usluga.image}</td>
                  <td>{usluga.replicas ?? 1}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <PotwierdzenieWdrozenia
            pracuje={wdroz.isPending}
            onWdroz={(powod) => wdroz.mutate({ manifest, digest: plan.digest, powod })}
          />
        </>
      )}

      <h2>History</h2>
      {!projekt ? (
        <Pusto>Name a project to see its deployment history.</Pusto>
      ) : !wersje.data?.items.length ? (
        <Pusto>This project has not been deployed from the panel yet.</Pusto>
      ) : (
        <table>
          <thead><tr><th>When</th><th>By</th><th>State</th><th>Plan</th><th></th></tr></thead>
          <tbody>
            {wersje.data.items.map((wersja) => (
              <tr key={wersja.job_id}>
                <td><Czas wartosc={wersja.created_at} /></td>
                <td>{wersja.created_by}</td>
                <td><StanZadania stan={wersja.state} /></td>
                <td>{wersja.plan_digest?.slice(0, 12) || "—"}</td>
                <td>
                  {/* Wycofanie zmiany to wdrozenie wczesniejszej wersji.
                      Wczytujemy ja do edytora, zeby przeszla przez plan -
                      stan hosta mogl sie od tamtej pory zmienic. */}
                  <button
                    className="wtorny"
                    onClick={() => { setManifest(wersja.manifest); setPlan(null); }}
                  >
                    Load into editor
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** Wdrozenie jest operacja krytyczna, wiec wymaga uzasadnienia w audycie. */
function PotwierdzenieWdrozenia({
  onWdroz, pracuje,
}: { onWdroz: (powod: string) => void; pracuje: boolean }) {
  const [powod, setPowod] = useState("");
  return (
    <div className="formularz" style={{ marginTop: 16 }}>
      <label>
        Reason (at least 8 characters, kept in the audit trail)
        <input value={powod} onChange={(e) => setPowod(e.target.value)} />
      </label>
      <div className="operacje">
        <button disabled={pracuje || powod.trim().length < 8} onClick={() => onWdroz(powod)}>
          {pracuje ? "Requesting…" : "Deploy this plan"}
        </button>
      </div>
    </div>
  );
}
