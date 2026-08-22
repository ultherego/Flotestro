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
    return <Pusto>Brak uprawnienia do przegladu CA floty.</Pusto>;
  }
  if (zapytanie.error) return <Blad error={zapytanie.error} />;

  const lista = zapytanie.data?.authorities ?? [];
  const oczekujace = lista.find((ca) => ca.state === "pending");
  const powodGotowy = powod.trim().length >= 8;

  return (
    <>
      <p className="podtytul">
        Certyfikaty agentow sa wystawiane przez CA floty. Wymiana odbywa sie
        w dwoch fazach: nowe CA najpierw trafia do agentow przy odnawianiu
        certyfikatow, a dopiero potem przejmuje podpisywanie.
      </p>

      <table>
        <thead>
          <tr>
            <th>Stan</th><th>Numer seryjny</th><th>Wazne do</th>
            <th>Certyfikaty</th><th>Uwagi</th><th /></tr>
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
                    ? "cala flota zna juz to CA"
                    : `${ca.hosts_missing} hostow jeszcze go nie zna`
                )}
                {ca.state === "retired" && ca.hosts_using > 0 &&
                  "wciaz uzywane przez hosty"}
                {ca.state === "active" && "podpisuje nowe certyfikaty"}
              </td>
              <td>
                {ca.state === "retired" && ca.hosts_using === 0 && (
                  <button
                    onClick={() => {
                      const reason = window.prompt("Powod usuniecia CA ze zbioru zaufania (min. 8 znakow):");
                      if (reason) usun.mutate({ fingerprint: ca.fingerprint, reason });
                    }}
                  >
                    Usun ze zbioru
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="formularz" style={{ marginTop: 24 }}>
        <h2>{oczekujace ? "Faza 2: przekazanie podpisywania" : "Faza 1: przygotowanie nowego CA"}</h2>
        <p className="podtytul">
          {oczekujace
            ? oczekujace.ready_to_activate
              ? "Cala flota zna juz nowe CA. Po przekazaniu podpisywania dotychczasowe CA zostaje uznawane, wiec obecne certyfikaty agentow pozostaja wazne."
              : `Nowe CA jest juz rozsylane. Przekazanie podpisywania bedzie mozliwe, gdy wszystkie hosty odnowia certyfikaty (pozostalo ${oczekujace.hosts_missing}).`
            : "Nowe CA zostanie wlaczone do zbioru zaufania i rozeslane do agentow przy odnawianiu ich certyfikatow. Podpisywanie pozostanie przy dotychczasowym CA."}
        </p>
        <label>Powod zmiany
          <input
            value={powod}
            onChange={(zdarzenie) => setPowod(zdarzenie.target.value)}
            placeholder="np. planowa wymiana CA przed wygasnieciem"
          />
        </label>
        <div className="operacje">
          {oczekujace ? (
            <button
              disabled={!powodGotowy || !oczekujace.ready_to_activate || przekaz.isPending}
              onClick={() => przekaz.mutate()}
            >
              Przekaz podpisywanie nowemu CA
            </button>
          ) : (
            <button disabled={!powodGotowy || przygotuj.isPending} onClick={() => przygotuj.mutate()}>
              Przygotuj nowe CA
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
      return <span className="znacznik ok">podpisuje</span>;
    case "pending":
      return <span className="znacznik uwaga">przygotowane</span>;
    default:
      return <span className="znacznik">wycofane</span>;
  }
}
