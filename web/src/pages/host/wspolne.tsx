import { useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, InventoryRevision, Job } from "../../lib/types";

/** Kontekst hosta pochodzi z layoutu, wiec zakladka nie pobiera go ponownie. */
export function useHost(): Host {
  return useOutletContext<{ host: Host }>().host;
}

/** Inventory jest wspolne dla zakladek, wiec dzieli jeden klucz cache. */
export function useInventory(hostID: string) {
  return useQuery({
    queryKey: ["inventory", hostID],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${hostID}/inventory`),
    retry: false,
  });
}

/**
 * Zlecenie operacji prowadzi do planu, a nie do natychmiastowej zmiany.
 * Operacja mutujaca trafia do stanu oczekiwania na zatwierdzenie.
 */
export function ZlecOperacje({
  host, opis, akcja, payload, etykieta,
}: { host: Host; opis: string; akcja: string; payload: unknown; etykieta: string }) {
  const queryClient = useQueryClient();
  const [wynik, setWynik] = useState<string>("");

  const mutacja = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action: akcja, payload }),
    onSuccess: (zadanie) => {
      setWynik(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setWynik(error instanceof Error ? error.message : String(error)),
  });

  return (
    <div style={{ marginTop: 24 }}>
      <h2>Request an operation</h2>
      <p className="podtytul">{opis}</p>
      {/* Cel powtorzony przy samym przycisku: operator zatwierdza konkretna
          maszyne, a nie "ten host, ktory chyba mam otwarty". */}
      <p className="zrodlo" style={{ marginBottom: 10 }}>
        Target: {host.hostname}
        {host.management_address ? ` · ${host.management_address}` : " · address unknown"}
        {` · ${host.site} / ${host.environment}`}
      </p>
      <button onClick={() => mutacja.mutate()} disabled={mutacja.isPending}>
        {mutacja.isPending ? "Requesting…" : etykieta}
      </button>
      {wynik && <p className="zrodlo" style={{ marginTop: 10 }}>{wynik}</p>}
      <p style={{ marginTop: 12 }}>
        <Link to="/jobs">See all jobs</Link>
      </p>
    </div>
  );
}
