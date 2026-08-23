import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { LiczbaOpcjonalna, Para, Pary, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul, ZlecOperacje } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type StanPakietow = {
  manager?: string;
  installed?: number;
  upgradable?: number;
  security_upgradable?: number;
  unavailable_reason?: string;
};

type PlanUsuniecia = {
  mode?: string;
  removals?: string[];
  protected?: string[];
};

type Proba = { status?: string; message?: string; detail?: PlanUsuniecia };

/**
 * Pakiety hosta.
 *
 * Instalacja i usuniecie sa oddzielone od aktualizacji: to trzy rozne decyzje
 * o tym samym hoscie. Usuniecie przechodzi przez plan, bo jeden pakiet potrafi
 * pociagnac kilkadziesiat zaleznych.
 */
export function Pakiety() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<StanPakietow>(host.id, "packages");
  const pakiety = modul.data?.payload;

  const [nazwy, setNazwy] = useState("");
  const [plan, setPlan] = useState<PlanUsuniecia | null>(null);
  const [doUsuniecia, setDoUsuniecia] = useState<string[] | null>(null);
  const [komunikat, setKomunikat] = useState("");

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setDoUsuniecia(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const lista = () =>
    nazwy.split(/[\s,]+/).map((nazwa) => nazwa.trim()).filter(Boolean);

  // Plan usuniecia liczy sie na hoscie, wiec ekran czeka na jego wynik.
  const zaplanujUsuniecie = useMutation({
    mutationFn: async () => {
      const zadanie = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.plan",
        payload: { package_plan: { mode: "remove", only_packages: lista() } },
      });
      for (let proba = 0; proba < 30; proba++) {
        await new Promise((gotowe) => setTimeout(gotowe, 1500));
        const proby = await api.get<{ items: Proba[] }>(`/api/v1/jobs/${zadanie.id}/attempts`);
        const ostatnia = proby.items[proby.items.length - 1];
        if (!ostatnia?.status) continue;
        if (ostatnia.status !== "succeeded") {
          throw new Error(ostatnia.message || "The host refused to plan the removal.");
        }
        return ostatnia.detail ?? {};
      }
      throw new Error("The plan did not arrive in time.");
    },
    onSuccess: (wynik) => { setPlan(wynik); setKomunikat(""); },
    onError: (error) => {
      setPlan(null);
      setKomunikat(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <>
      <Pary>
        <Para etykieta="Manager">{pakiety?.manager || "—"}</Para>
        <Para etykieta="Installed">
          {pakiety?.installed ?? <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Upgradable"><LiczbaOpcjonalna wartosc={host.pending_updates} /></Para>
        <Para etykieta="Security updates">
          <LiczbaOpcjonalna wartosc={host.pending_security_updates} />
        </Para>
        <Para etykieta="Package database">
          {host.package_database_broken
            ? <span className="znacznik blad">needs repair</span>
            : "healthy"}
        </Para>
      </Pary>
      <SwiezoscModulu fragment={modul.data} />

      <ZlecOperacje
        host={host}
        opis="Count available updates without changing host state."
        akcja="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        etykieta="Plan updates"
      />

      <h2>Install, remove or hold</h2>
      <div className="formularz">
        <label>
          Package names (space or comma separated)
          <input value={nazwy} onChange={(e) => { setNazwy(e.target.value); setPlan(null); }}
                 placeholder="nginx htop" />
        </label>
        <div className="operacje">
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.install",
              payload: { package_change: { packages: lista() } },
            })}
          >
            Install
          </button>
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.hold.set",
              payload: { package_change: { packages: lista(), hold: true } },
            })}
          >
            Hold
          </button>
          <button
            disabled={zlec.isPending || lista().length === 0}
            onClick={() => zlec.mutate({
              action: "packages.hold.set",
              payload: { package_change: { packages: lista(), hold: false } },
            })}
          >
            Unhold
          </button>
          {/* Usuniecie nie idzie wprost: jeden pakiet potrafi pociagnac
              kilkadziesiat zaleznych i operator ma je zobaczyc wczesniej. */}
          <button
            className="wtorny"
            disabled={zaplanujUsuniecie.isPending || lista().length === 0}
            onClick={() => zaplanujUsuniecie.mutate()}
          >
            {zaplanujUsuniecie.isPending ? "Planning…" : "Plan removal"}
          </button>
        </div>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginTop: 12 }}>{komunikat}</p>}

      {plan && (
        <>
          <h2>Removal plan</h2>
          {plan.protected && plan.protected.length > 0 && (
            <p className="ostrzezenie">
              <span>
                These packages are protected and will not be removed:{" "}
                {plan.protected.join(", ")}. Removing them would leave the host
                unmanageable or unbootable.
              </span>
            </p>
          )}
          {!plan.removals?.length ? (
            <Pusto>Nothing would be removed.</Pusto>
          ) : (
            <>
              <table>
                <thead><tr><th>Package</th><th>Reason</th></tr></thead>
                <tbody>
                  {plan.removals.map((pakiet) => (
                    <tr key={pakiet}>
                      <td>{pakiet}</td>
                      <td>{lista().includes(pakiet) ? "requested" : "dependency"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="zrodlo" style={{ marginTop: 8 }}>
                {plan.removals.length} package(s) would be removed. The host recomputes
                this set before removing; a difference cancels the operation.
              </p>
              {(!plan.protected || plan.protected.length === 0) && (
                <div className="operacje" style={{ marginTop: 12 }}>
                  <button onClick={() => setDoUsuniecia(plan.removals ?? [])}>
                    Remove these packages
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}

      {doUsuniecia && (
        <PotwierdzenieCelu
          host={host}
          etykieta="Remove packages"
          opis={`${doUsuniecia.length} package(s) will be removed: ${doUsuniecia.slice(0, 6).join(", ")}${doUsuniecia.length > 6 ? "…" : ""}.`}
          pracuje={zlec.isPending}
          onPotwierdz={(powod, potwierdzenie) =>
            zlec.mutate({
              action: "packages.remove",
              reason: powod,
              target_confirmation: potwierdzenie,
              payload: {
                package_change: { packages: lista(), expected_removals: doUsuniecia },
              },
            })
          }
          onAnuluj={() => setDoUsuniecia(null)}
        />
      )}
    </>
  );
}
