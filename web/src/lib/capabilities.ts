import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * The capabilities of the installation.
 */
export type Capabilities = {
  identity_provider: boolean;
  issuer?: string;
  directory: boolean;
  directory_write: boolean;
  local_users: boolean;
  // campaign_v2 says whether the backend runs campaigns with a planning
  // phase.
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
  // Until the answer arrives no modules are assumed.
  return data ?? defaults;
}
