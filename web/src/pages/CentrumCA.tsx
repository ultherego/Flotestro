import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Authority } from "../lib/types";
import { Blad, Czas, Pusto } from "../components/ui";

/**
 * CA floty.
 *
 * Wymiana ma dwie fazy, bo jednofazowa nie dziala: certyfikat serwera
 * wystawiony CA, ktorego agent nie zna, odcina host przy najblizszym
 * restarcie panelu. Ekran prowadzi przez obie fazy i pokazuje warunek
 * przejscia miedzy nimi - liczbe hostow, ktore nowego CA jeszcze nie znaja.
 */
export function CentrumCA({ zglosBlad }: { zglosBlad: (blad: ApiError | null) => void }) {
  const queryClient = useQueryClient();
  const [powod, setPowod] = useState("");

  const zapytanie = useQuery({
    queryKey: ["pki"],
    queryFn: () => api.get<{ authorities: Authority[] }>("/api/v1/pki"),
    retry: false,
    refetchInterval: 30_000,
  });

  const odswiez = () => queryClient.invalidateQueries({ queryKey: ["pki"] });
  const naBledzie = (blad: unknown) => zglosBlad(blad instanceof ApiError ? blad : null);

  const przygotuj = useMutation({
    mutationFn: () => api.post("/api/v1/pki/prepare", { reason: powod.trim() }),
    onSuccess: () => { setPowod(""); odswiez(); },
    onError: naBledzie,
  });
  const przekaz = useMutation({
    mutationFn: () => api.post("/api/v1/pki/activate", { reason: powod.trim() }),
    onSuccess: () => { setPowod(""); odswiez(); },
    onError: naBledzie,
  });
  const usun = useMutation({
    mutationFn: ({ fingerprint, reason }: { fingerprint: string; reason: string }) =>
      api.del(`/api/v1/pki/${fingerprint}?reason=${encodeURIComponent(reason)}`),
    onSuccess: odswiez,
    onError: naBledzie,
  });

  if (zapytanie.error instanceof ApiError && zapytanie.error.forbidden) {
    return <Pusto>You do not have permission to view the fleet CA.</Pusto>;
  }
  if (zapytanie.error) return <Blad error={zapytanie.error} />;

  const lista = zapytanie.data?.authorities ?? [];
  const oczekujace = lista.find((ca) => ca.state === "pending");
  const powodGotowy = powod.trim().length >= 8;

  return (
    <>
      <p className="podtytul">
        Agent certificates are issued by the fleet CA. Rotation happens in two
        phases: the new CA first reaches agents as their certificates are renewed,
        and only then takes over signing.
      </p>

      <table>
        <thead>
          <tr>
            <th>State</th><th>Serial</th><th>Valid until</th>
            <th>Certificates</th><th>Notes</th><th /></tr>
        </thead>
        <tbody>
          {lista.map((ca) => (
            <tr key={ca.fingerprint}>
              <td><StanCA stan={ca.state} /></td>
              <td title={ca.fingerprint}>{ca.serial.slice(0, 14)}…</td>
              <td><Czas wartosc={ca.not_after} /></td>
              <td>{ca.hosts_using}</td>
              <td className="zrodlo">
                {ca.state === "pending" && (
                  ca.ready_to_activate
                    ? "the whole fleet already knows this CA"
                    : `${ca.hosts_missing} hosts do not know it yet`
                )}
                {ca.state === "retired" && ca.hosts_using > 0 &&
                  "still used by hosts"}
                {ca.state === "active" && "signs new certificates"}
              </td>
              <td>
                {ca.state === "retired" && ca.hosts_using === 0 && (
                  <button
                    onClick={() => {
                      const reason = window.prompt("Reason for removing this CA from the trust set (min. 8 characters):");
                      if (reason) usun.mutate({ fingerprint: ca.fingerprint, reason });
                    }}
                  >
                    Remove from trust set
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="formularz" style={{ marginTop: 24 }}>
        <h2>{oczekujace ? "Phase 2: hand over signing" : "Phase 1: prepare a new CA"}</h2>
        <p className="podtytul">
          {oczekujace
            ? oczekujace.ready_to_activate
              ? "The whole fleet already knows the new CA. After the handover the previous CA stays trusted, so current agent certificates remain valid."
              : `Nowe CA jest juz rozsylane. Przekazanie podpisywania bedzie mozliwe, gdy wszystkie hosty odnowia certyfikaty (pozostalo ${oczekujace.hosts_missing}).`
            : "The new CA will join the trust set and reach agents as their certificates are renewed. Signing stays with the current CA."}
        </p>
        <label>Reason for the change
          <input
            value={powod}
            onChange={(zdarzenie) => setPowod(zdarzenie.target.value)}
            placeholder="e.g. planned CA rotation before expiry"
          />
        </label>
        <div className="operacje">
          {oczekujace ? (
            <button
              disabled={!powodGotowy || !oczekujace.ready_to_activate || przekaz.isPending}
              onClick={() => przekaz.mutate()}
            >
              Hand signing over to the new CA
            </button>
          ) : (
            <button disabled={!powodGotowy || przygotuj.isPending} onClick={() => przygotuj.mutate()}>
              Prepare a new CA
            </button>
          )}
        </div>
      </div>
    </>
  );
}

function StanCA({ stan }: { stan: Authority["state"] }) {
  switch (stan) {
    case "active":
      return <span className="znacznik ok">signing</span>;
    case "pending":
      return <span className="znacznik uwaga">prepared</span>;
    default:
      return <span className="znacznik">retired</span>;
  }
}
