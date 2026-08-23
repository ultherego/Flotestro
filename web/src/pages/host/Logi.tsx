import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Pusto } from "../../components/ui";
import { useHost } from "./wspolne";
import { usePodgladDziennika } from "../../lib/strumien";

type WynikDziennika = { lines?: string[]; truncated?: boolean };
type WynikPliku = {
  path?: string;
  lines?: string[];
  truncated?: boolean;
  size_bytes?: number;
  allowlist?: string;
};

type Proba = { status?: string; error_code?: string; message?: string; detail?: Record<string, unknown> };

/**
 * Logi hosta.
 *
 * Odczyt jest zawsze na zadanie i zawsze ograniczony: dziennik liczba linii,
 * plik dodatkowo allowlista administratora hosta. Panel nie indeksuje logow -
 * prowadzi od hosta do hosta, a nie odpytuje calej floty naraz.
 */
export function Logi() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [zrodlo, setZrodlo] = useState<"journal" | "file">("journal");
  const [podglad, setPodglad] = useState<string | null>(null);
  const [wstrzymane, setWstrzymane] = useState(false);
  const [jednostka, setJednostka] = useState("");
  const [priorytet, setPriorytet] = useState("");
  const [od, setOd] = useState("");
  const [sciezka, setSciezka] = useState("/var/log/syslog");
  const [linii, setLinii] = useState(200);
  const [linie, setLinie] = useState<string[] | null>(null);
  const [stopka, setStopka] = useState("");
  const [blad, setBlad] = useState("");

  const strumien = usePodgladDziennika(podglad, wstrzymane);

  // Podglad idzie tym samym strumieniem co postep operacji, wiec jedno
  // polaczenie na karte wystarcza.
  const sledz = useMutation({
    mutationFn: async () => {
      const zadanie = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "journal.follow",
        payload: {
          journal: {
            unit: jednostka || undefined,
            lines: 50,
            max_priority: priorytet ? Number(priorytet) : undefined,
            follow_seconds: 300,
          },
        },
      });
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      return zadanie;
    },
    onSuccess: (zadanie) => {
      setBlad("");
      setLinie(null);
      setWstrzymane(false);
      setPodglad(`/api/v1/jobs/${zadanie.id}/events`);
    },
    onError: (error) => setBlad(error instanceof Error ? error.message : String(error)),
  });

  const czytaj = useMutation({
    mutationFn: async () => {
      const tresc =
        zrodlo === "journal"
          ? {
              action: "journal.read",
              payload: {
                journal: {
                  unit: jednostka || undefined,
                  lines: linii,
                  max_priority: priorytet ? Number(priorytet) : undefined,
                  since: od || undefined,
                },
              },
            }
          : { action: "logfile.read", payload: { logfile: { path: sciezka, lines: linii } } };

      const zadanie = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });

      // Odczyt idzie przez zadanie, wiec ekran czeka na jego wynik.
      for (let proba = 0; proba < 30; proba++) {
        await new Promise((gotowe) => setTimeout(gotowe, 1500));
        const proby = await api.get<{ items: Proba[] }>(`/api/v1/jobs/${zadanie.id}/attempts`);
        const ostatnia = proby.items[proby.items.length - 1];
        if (!ostatnia?.status) continue;
        return ostatnia;
      }
      throw new Error("The host did not answer in time.");
    },
    onSuccess: (proba) => {
      setBlad("");
      const szczegoly = proba.detail as (WynikDziennika & WynikPliku) | undefined;
      if (proba.status !== "succeeded") {
        setLinie(null);
        // Odmowa niesie powod: operator ma wiedziec, czy pliku nie ma,
        // czy jest poza dozwolonym zakresem.
        setBlad(proba.message || proba.error_code || "The host refused the read.");
        return;
      }
      setLinie(szczegoly?.lines ?? []);
      const czesci: string[] = [];
      if (szczegoly?.truncated) czesci.push("output truncated");
      if (szczegoly?.size_bytes) czesci.push(`file ${Math.round(szczegoly.size_bytes / 1024)} KiB`);
      if (szczegoly?.allowlist) czesci.push(`allowlist: ${szczegoly.allowlist}`);
      setStopka(czesci.join(" · "));
    },
    onError: (error) => {
      setLinie(null);
      setBlad(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <>
      <div className="formularz">
        <div className="filtry">
          <label className="przelacznik">
            <input
              type="radio"
              checked={zrodlo === "journal"}
              onChange={() => { setZrodlo("journal"); setLinie(null); }}
            />
            journald
          </label>
          <label className="przelacznik">
            <input
              type="radio"
              checked={zrodlo === "file"}
              onChange={() => { setZrodlo("file"); setLinie(null); }}
            />
            log file
          </label>
        </div>

        {zrodlo === "journal" ? (
          <div className="filtry">
            <input placeholder="unit (optional)" value={jednostka} onChange={(e) => setJednostka(e.target.value)} />
            <select value={priorytet} onChange={(e) => setPriorytet(e.target.value)}>
              <option value="">any priority</option>
              <option value="3">error and above</option>
              <option value="4">warning and above</option>
              <option value="6">info and above</option>
            </select>
            <input placeholder="since, e.g. -1h" value={od} onChange={(e) => setOd(e.target.value)} />
          </div>
        ) : (
          <div className="filtry">
            <input
              placeholder="/var/log/syslog"
              value={sciezka}
              onChange={(e) => setSciezka(e.target.value)}
              style={{ minWidth: 320 }}
            />
          </div>
        )}

        <div className="filtry">
          <label className="przelacznik">
            lines
            <input
              type="number"
              min={1}
              max={2000}
              value={linii}
              onChange={(e) => setLinii(Number(e.target.value))}
              style={{ width: 90 }}
            />
          </label>
          <button onClick={() => czytaj.mutate()} disabled={czytaj.isPending || host.connection_state !== "online"}>
            {czytaj.isPending ? "Reading…" : "Read"}
          </button>
          {/* Podglad na zywo dotyczy wylacznie dziennika: plik nie ma
              zdarzen, ktore da sie sledzic bez odpytywania hosta w kolko. */}
          {zrodlo === "journal" && !podglad && (
            <button
              className="wtorny"
              onClick={() => sledz.mutate()}
              disabled={sledz.isPending || host.connection_state !== "online"}
            >
              {sledz.isPending ? "Starting…" : "Follow"}
            </button>
          )}
          {podglad && (
            <>
              <button className="wtorny" onClick={() => setWstrzymane((stan) => !stan)}>
                {wstrzymane ? "Resume" : "Pause"}
              </button>
              <button className="wtorny" onClick={() => setPodglad(null)}>Stop</button>
            </>
          )}
        </div>
        {/* Odczyt pliku jest ograniczony zakresem, ktory nalezy do hosta,
            a nie do panelu. */}
        {zrodlo === "file" && (
          <p className="zrodlo" style={{ margin: 0 }}>
            Only paths on the host's allowlist can be read, and symlinks are not followed.
          </p>
        )}
      </div>

      {blad && <p className="blad-strony" style={{ marginTop: 12 }}>{blad}</p>}

      {podglad && (
        <>
          <h2>Live</h2>
          {/* Limit jest widoczny: operator ma wiedziec, ze podglad skonczy
              sie sam i ze czesc linii moze zostac pominieta. */}
          <p className="podtytul">
            Streaming for up to 5 minutes, capped at 32 KiB/s.
            {wstrzymane && " Paused — the host keeps sending, the screen does not."}
            {strumien.pominiete > 0 && ` ${strumien.pominiete} lines dropped by the rate limit.`}
          </p>
          {strumien.linie.length === 0 ? (
            <Pusto>Waiting for the first lines…</Pusto>
          ) : (
            <pre style={{ marginTop: 8, maxHeight: 520, overflowY: "auto" }}>
              {strumien.linie.join("\n")}
            </pre>
          )}
        </>
      )}

      {linie !== null && !podglad && (
        <>
          <h2>Output</h2>
          {linie.length === 0 ? (
            <Pusto>Nothing matched.</Pusto>
          ) : (
            <pre style={{ marginTop: 8, maxHeight: 520, overflowY: "auto" }}>{linie.join("\n")}</pre>
          )}
          {stopka && <p className="zrodlo" style={{ marginTop: 8 }}>{stopka}</p>}
        </>
      )}
    </>
  );
}
