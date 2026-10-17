import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "./api";

/**
 * The teams as every screen but the register reads them.
 *
 * A team is a boundary of authority rather than a label, so the host list's
 * filter, the placement on a host page and the binding form of the access
 * screen all have to mean the same rows by it - one query key, one cache.
 */

/** One team as the register lists it, with the hosts placed in it counted. */
export type Team = {
  id: string;
  name: string;
  description?: string;
  created_by?: string;
  /** The hosts placed in the team; the deletion says how many it releases. */
  hosts: number;
  created_at: string;
  updated_at: string;
};

/**
 * The teams as every other screen reads them: the filter on the host list,
 * the placement on a host page and the binding form of the access screen all
 * need the same names, and they all narrow nothing - a team name is printed.
 */
export function useTeams(enabled = true) {
  return useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<Team>>("/api/v1/teams"),
    enabled,
    staleTime: 60 * 1000,
    retry: false,
  });
}
