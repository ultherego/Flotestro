import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { bytes } from "../../lib/format";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Ustawienie = {
  key: string;
  current?: string;
  desired?: string;
  source?: string;
  managed: boolean;
};

type ModulJadra = {
  name: string;
  size_bytes: number;
  used_by?: string[];
  blacklisted: boolean;
};

type Snapshot = {
  release?: string;
  command_line?: string;
  settings?: Ustawienie[];
  modules?: ModulJadra[];
  blacklist?: string[];
  managed_config?: string;
  managed_path?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Zamiar = { akcja: string; etykieta: string; opis: string; payload: Record<string, unknown> };

/**
 * Ustawienia jadra i moduly.
 *
 * Panel nie enumeruje calego /proc/sys: jest tam kilka tysiecy kluczy,
 * z ktorych wieksza czesc nie odpowiada na zadne pytanie operatora. Pokazujemy
 * profil oraz to, co panel sam zapisal, a reszte da sie doczytac na zadanie.
 */
export function Jadro() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "kernel");
  const [zamiar, setZamiar] = useState<Zamiar | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [filtr, setFiltr] = useState("");
  const [klucz, setKlucz] = useState("");
  const [wartosc, setWartosc] = useState("");

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      setZamiar(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its kernel settings yet.</Pusto>;

  const moduly = (snapshot?.modules ?? []).filter((wpis) =>
    filtr ? wpis.name.toLowerCase().includes(filtr.toLowerCase()) : true,
  );

  return (
    <>
      <p className="podtytul">
        A profile of settings, not all of /proc/sys — there are thousands of
        keys there and most answer no question anyone asks. Anything the panel
        wrote is listed too, with the value the kernel currently applies.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Kernel settings could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Kernel</th><td>{snapshot?.release || "—"}</td></tr>
          {/* Czesc ustawien da sie zmienic wylacznie w linii polecen jadra
              i dopiero po restarcie - dlatego jest widoczna. */}
          <tr><th>Command line</th><td className="zrodlo">{snapshot?.command_line || "—"}</td></tr>
          <tr><th>Managed file</th><td>{snapshot?.managed_path}</td></tr>
        </tbody>
      </table>

      <h2>Settings</h2>
      <table>
        <thead>
          <tr><th>Key</th><th>Current</th><th>Desired</th><th>Owner</th></tr>
        </thead>
        <tbody>
          {(snapshot?.settings ?? []).map((ustawienie) => (
            <tr key={ustawienie.key}>
              <td>{ustawienie.key}</td>
              <td>{ustawienie.current ?? <span className="znacznik nieznany">unknown</span>}</td>
              {/* Rozne wartosci znacza ustawienie, ktore czeka na restart
                  albo zostalo zmienione poza panelem. */}
              <td>
                {ustawienie.desired ?? "—"}
                {ustawienie.desired && ustawienie.desired !== ustawienie.current && (
                  <span className="znacznik nieznany"> not applied yet</span>
                )}
              </td>
              <td>{ustawienie.managed ? "Flotestro" : "kernel default or host admin"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="filtry">
        <input value={klucz} onChange={(e) => setKlucz(e.target.value)} placeholder="Key, e.g. vm.swappiness" style={{ minWidth: 240 }} />
        <input value={wartosc} onChange={(e) => setWartosc(e.target.value)} placeholder="Value" style={{ width: 140 }} />
        <button
          onClick={() =>
            setZamiar({
              akcja: "sysctl.ensure",
              etykieta: "Set kernel setting",
              opis: `${klucz} will be set to ${wartosc} on ${host.hostname}, both now and after reboot. If the kernel does not take it immediately, the result says so.`,
              payload: { kernel: { settings: { [klucz]: wartosc } } },
            })
          }
          disabled={!klucz || !wartosc}
        >
          Set
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      <h2>Modules</h2>
      <div className="filtry">
        <input value={filtr} onChange={(e) => setFiltr(e.target.value)} placeholder="Filter modules" />
        <span className="zrodlo">
          {(snapshot?.modules ?? []).length} loaded · {(snapshot?.blacklist ?? []).length} blocked
        </span>
      </div>
      <table>
        <thead>
          <tr><th>Module</th><th>Size</th><th>Used by</th><th>State</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {moduly.slice(0, 60).map((wpis) => (
            <tr key={wpis.name}>
              <td>{wpis.name}</td>
              <td>{bytes(wpis.size_bytes)}</td>
              <td>{(wpis.used_by ?? []).join(", ") || "—"}</td>
              <td>{wpis.blacklisted ? "blocked by Flotestro" : "loaded"}</td>
              <td>
                <button
                  className="wtorny"
                  onClick={() =>
                    setZamiar({
                      akcja: "kernel.module.blacklist",
                      etykieta: wpis.blacklisted ? "Unblock module" : "Block module",
                      opis: wpis.blacklisted
                        ? `${wpis.name} will be allowed to load again.`
                        : `${wpis.name} will be blocked from loading. A module already loaded stays loaded until reboot, and one pulled in by the initramfs needs that rebuilt too.`,
                      payload: { kernel: { module: wpis.name, blacklist: !wpis.blacklisted } },
                    })
                  }
                >
                  {wpis.blacklisted ? "Unblock" : "Block"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {moduly.length > 60 && (
        <p className="zrodlo">Showing 60 of {moduly.length} modules; narrow the filter to see the rest.</p>
      )}

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Kernel state read <Czas wartosc={snapshot.observed_at} />
        </p>
      )}

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta={zamiar.etykieta}
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({ action: zamiar.akcja, reason: powod, payload: zamiar.payload })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}
