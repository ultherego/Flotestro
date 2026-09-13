import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * The capabilities of the installation. Flotestro is a fleet management
 * panel; the integration with an identity directory and with an external
 * login provider are optional.
 *
 * The interface must not show sections that have no backing in the given
 * installation: a button leading to a 501 error is worse than its absence.
 */
export type Capabilities = {
  identity_provider: boolean;
  issuer?: string;
  directory: boolean;
  directory_write: boolean;
  local_users: boolean;
  // campaign_v2 says whether the backend runs campaigns with a planning
  // phase. The bulk wizard without it would end with an error after the
  // form is filled in.
  campaign_v2: boolean;
};

const defaults: Capabilities = {
  identity_provider: false,
  directory: false,
  directory_write: false,
  local_users: false,
  campaign_v2: false,
};

export function useCapabilities(): Capabilities {
  const { data } = useQuery({
    queryKey: ["capabilities"],
    queryFn: () => api.get<Capabilities>("/api/v1/capabilities"),
    staleTime: Infinity,
  });
  // Until the answer arrives no modules are assumed. Showing a section that
  // disappears a moment later would mislead about the installation's
  // configuration.
  return data ?? defaults;
}
