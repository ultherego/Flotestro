import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { CampaignTarget } from "./types";
import { OPERATIONS_INTERVAL } from "./stream";

/** One page of a campaign's targets, in the order of the rollout. */
export type TargetPage = {
  items: CampaignTarget[];
  count: number;
  /** How many targets match the filter across every page. */
  total: number;
  next_cursor?: string;
};

export type TargetFilter = { state?: string; wave?: number; search?: string };

/** How many targets one request fetches; a screen grows page by page. */
export const TARGET_PAGE = 200;

/**
 * The targets of a campaign, page by page and filtered on the server.
 *
 * A campaign on ten thousand hosts must not become ten thousand rows in
 * the browser, and "the failed ones" is a question the database answers
 * better than a screen scanning a list. The query key starts with the
 * campaign, so a stream event refreshing the campaign refreshes every page.
 */
export function useTargets(campaignID: string, filter: TargetFilter) {
  return useInfiniteQuery({
    queryKey: ["campaign-targets", campaignID, filter],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: String(TARGET_PAGE) });
      if (filter.state) params.set("state", filter.state);
      if (filter.wave !== undefined && filter.wave >= 0) params.set("wave", String(filter.wave));
      if (filter.search) params.set("q", filter.search);
      if (pageParam) params.set("cursor", pageParam);
      return api.get<TargetPage>(`/api/v1/campaigns/${campaignID}/targets?${params}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: campaignID !== "",
    refetchInterval: OPERATIONS_INTERVAL,
  });
}

/** The rows loaded so far, in one list. */
export function loadedTargets(data?: { pages: TargetPage[] }): CampaignTarget[] {
  return data?.pages.flatMap((page) => page.items) ?? [];
}

/** The states a target can be in, for the filter. */
export const TARGET_STATES = [
  "pending", "awaiting_budget", "planning", "running", "rebooting", "verifying",
  "succeeded", "failed", "skipped", "ineligible", "canceled",
];
