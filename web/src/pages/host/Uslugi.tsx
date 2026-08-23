import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type StanUslug = {
  failed_units: string[] | null;
  failed_units_known: boolean;
};

type Jednostka = {
  name: string;
  load_state: string;
  active_state: string;
  sub_state: string;
  unit_file_state?: string;
  n_restarts?: number;
};

type WykazJednostek = { units?: Jednostka[]; truncated?: boolean };

export function Uslugi() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<StanUslug>(host.id, "services");
  const wykaz = useModul<WykazJednostek>(host.id, "services.full");
  const [filtr, setFiltr] = useState("");
  const [tylkoAktywne, setTylkoAktywne] = useState(false);
  const [doZamaskowania, setDoZamaskowania] = useState<Jednostka | null>(null);
  const [komunikat, setKomunikat] = useState("");

  const wBledzie = modul.data?.payload?.failed_units ?? [];
  const znane = modul.data?.payload?.failed_units_known ?? false;

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setDoZamaskowania(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  function operacja(akcja: string, jednostka: string) {
    zlec.mutate({ action: akcja, payload: { unit: { unit: jednostka } } });
  }

  function przelacz(akcja: string, jednostka: string, wartosc: boolean) {
    zlec.mutate({
      action: akcja,
      ...(akcja === "unit.mask.set" ? { reason: "maskowanie jednostki z panelu" } : {}),
      payload: { unit_toggle: { unit: jednostka, enabled: wartosc } },
    });
  }

  const jednostki = (wykaz.data?.payload?.units ?? []).filter((jednostka) => {
    if (tylkoAktywne && jednostka.active_state !== "active") return false;
    if (!filtr) return true;
    return jednostka.name.toLowerCase().includes(filtr.toLowerCase());
  });

  return (
    <>
      <h2>Failed units</h2>
      {/* Nieodczytany stan nie moze wygladac jak brak jednostek w bledzie. */}
      {!znane ? (
        <Pusto>Unit states could not be determined.</Pusto>
      ) : wBledzie.length === 0 ? (
        <Pusto>No unit is in a failed state.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Unit</th><th>Actions</th></tr></thead>
          <tbody>
            {wBledzie.map((jednostka) => (
              <tr key={jednostka}>
                <td>{jednostka}</td>
                <td>
                  <div className="operacje">
                    <button onClick={() => operacja("unit.restart", jednostka)}>Restart</button>
                    <button onClick={() => operacja("unit.start", jednostka)}>Start</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <SwiezoscModulu fragment={modul.data} />

      <h2>All units</h2>
      <p className="podtytul">
        The full list is read from the host on request, not on every inventory cycle.{" "}
        <button
          className="wtorny"
          onClick={() => zlec.mutate({ action: "unit.status", payload: { unit_status: { all: true } } })}
          disabled={zlec.isPending || host.connection_state !== "online"}
        >
          {zlec.isPending ? "Requesting…" : "Read from host"}
        </button>
      </p>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {!wykaz.data ? (
        <Pusto>This host has not been read yet. Use “Read from host”.</Pusto>
      ) : (
        <>
          <div className="filtry">
            <input
              placeholder="Filter by name"
              value={filtr}
              onChange={(e) => setFiltr(e.target.value)}
            />
            <label className="przelacznik">
              <input
                type="checkbox"
                checked={tylkoAktywne}
                onChange={(e) => setTylkoAktywne(e.target.checked)}
              />
              active only
            </label>
          </div>
          {/* Urwany wykaz jest zaznaczony: lista bez tego znacznika
              wygladalaby na pelna. */}
          {wykaz.data.payload?.truncated && (
            <p className="ostrzezenie">
              <span>The list was truncated by the host limit; narrow the filter on the host.</span>
            </p>
          )}
          <table>
            <thead>
              <tr>
                <th>Unit</th><th>Active</th><th>Sub</th><th>On boot</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {jednostki.map((jednostka) => (
                <tr key={jednostka.name}>
                  <td>{jednostka.name}</td>
                  <td>
                    <span className={jednostka.active_state === "active" ? "znacznik ok" : "znacznik"}>
                      {jednostka.active_state}
                    </span>
                  </td>
                  <td>{jednostka.sub_state}</td>
                  <td>{jednostka.unit_file_state || "—"}</td>
                  <td>
                    <div className="operacje">
                      {jednostka.active_state === "active" ? (
                        <>
                          <button onClick={() => operacja("unit.restart", jednostka.name)}>Restart</button>
                          <button onClick={() => operacja("unit.stop", jednostka.name)}>Stop</button>
                        </>
                      ) : (
                        <button onClick={() => operacja("unit.start", jednostka.name)}>Start</button>
                      )}
                      {/* Wlaczenie zmienia zachowanie hosta po restarcie,
                          wiec jest osobne od uruchomienia teraz. */}
                      {jednostka.unit_file_state === "enabled" ? (
                        <button onClick={() => przelacz("unit.enable.set", jednostka.name, false)}>Disable</button>
                      ) : jednostka.unit_file_state === "disabled" ? (
                        <button onClick={() => przelacz("unit.enable.set", jednostka.name, true)}>Enable</button>
                      ) : null}
                      {jednostka.unit_file_state === "masked" ? (
                        <button onClick={() => przelacz("unit.mask.set", jednostka.name, false)}>Unmask</button>
                      ) : (
                        <button onClick={() => setDoZamaskowania(jednostka)}>Mask</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="zrodlo" style={{ marginTop: 12 }}>
            {jednostki.length} of {wykaz.data.payload?.units?.length ?? 0} units shown · read{" "}
            <Czas wartosc={wykaz.data.observed_at} />
          </p>
        </>
      )}

      {doZamaskowania && (
        <PotwierdzenieCelu
          host={host}
          etykieta="Mask unit"
          opis={`${doZamaskowania.name} will not be startable, by the panel or by hand, and the change survives a reboot.`}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({
              action: "unit.mask.set",
              reason: powod,
              payload: { unit_toggle: { unit: doZamaskowania.name, enabled: true } },
            })
          }
          onAnuluj={() => setDoZamaskowania(null)}
        />
      )}
    </>
  );
}
