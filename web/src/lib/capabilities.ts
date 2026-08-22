import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * Zdolnosci instalacji. Flotestro jest panelem zarzadzania flota; integracja
 * z katalogiem tozsamosci i z zewnetrznym dostawca logowania sa opcjonalne.
 *
 * Interfejs nie moze pokazywac sekcji, ktore w danej instalacji nie maja
 * pokrycia: przycisk prowadzacy do bledu 501 jest gorszy niz jego brak.
 */
export type Capabilities = {
  identity_provider: boolean;
  issuer?: string;
  directory: boolean;
  directory_write: boolean;
  local_users: boolean;
};

const domyslne: Capabilities = {
  identity_provider: false,
  directory: false,
  directory_write: false,
  local_users: false,
};

export function useCapabilities(): Capabilities {
  const { data } = useQuery({
    queryKey: ["capabilities"],
    queryFn: () => api.get<Capabilities>("/api/v1/capabilities"),
    staleTime: Infinity,
  });
  // Do czasu odpowiedzi zakladamy brak modulow. Pokazanie sekcji, ktora
  // zaraz znika, wprowadzalo by w blad co do konfiguracji instalacji.
  return data ?? domyslne;
}
