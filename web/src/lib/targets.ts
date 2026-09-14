import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { CampaignTarget } from "./types";
import { OPERATIONS_INTERVAL } from "./stream";

/**
 * A target as the targets endpoint returns it: the campaign target and,
 * while the host's operation waits on its host, the resource lock it
 * waits on as the agent named it ("units held by task <id>
 * (schedule.run_now)"). Empty once the operation starts.
 */
export type TargetRow = CampaignTarget & { blocker?: string };

/** One page of a campaign's targets, in the order of the rollout. */
export type TargetPage = {
  items: TargetRow[];
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
export function loadedTargets(data?: { pages: TargetPage[] }): TargetRow[] {
  return data?.pages.flatMap((page) => page.items) ?? [];
}

/**
 * The link between a campaign and the campaign that compensates it, as
 * the server returns it on a campaign. A compensating campaign names the
 * original by identifier and name; the original lists the campaigns
 * ordered to undo it. Both sides come from the compensating campaign's
 * record - the original is never rewritten. The count of changed hosts is
 * the number a compensation runs on; the server keeps it at zero until
 * the campaign settles, since a compensation is refused before that.
 */
export type CompensationLinks = {
  compensates_campaign_id?: string;
  compensates_campaign_name?: string;
  compensated_by?: { id: string; name: string; state: string }[];
  changed_hosts?: number;
};

/**
 * The bounds of the wait for a rebooted host, in seconds, as the server
 * validates them. The default is what a campaign waits when the order
 * says nothing; the form starts there so the approver reads the bound
 * that will apply.
 */
export const REBOOT_TIMEOUT = { min: 60, max: 7200, default: 900 };

/**
 * The states a target can be in, for the filter, in the order a host moves
 * through them. The task of a host shows in three of them: dispatched
 * until the agent reports a start, awaiting_lock while it waits for a
 * resource of the host, running once it started.
 */
export const TARGET_STATES = [
  "pending", "awaiting_budget", "queued_offline", "planning", "dispatched", "awaiting_lock",
  "running", "rebooting", "verifying",
  "succeeded", "no_change", "failed", "unknown", "skipped", "ineligible", "excluded", "canceled",
];

/**
 * The states a campaign has settled in: nothing changes on any host any
 * more, the report is on record, and a compensation can be ordered. A
 * canceling campaign is not among them - its hosts are still at work.
 */
export const SETTLED_CAMPAIGN_STATES = [
  "completed", "completed_with_issues", "failed", "plan_failed", "expired", "canceled",
];

/** One executable step of a target: plan, execute, reboot, verify or compensate. */
export type CampaignStep = {
  id: string;
  campaign_id: string;
  target_id: string;
  host_id: string;
  hostname?: string;
  step_key: string;
  /** The step this one waited for; absent for the first step of the host. */
  depends_on?: string;
  /** The digest of the plan the step ran under; absent for the plan step and for a campaign without a planner. */
  plan_hash?: string;
  state: "pending" | "running" | "succeeded" | "failed" | "skipped" | "canceled";
  /** The task of the latest attempt; absent for a step settled without one. */
  job_id?: string;
  attempts: number;
  /** Why the step ended the way it did; never empty for a failed, skipped or canceled step. */
  reason?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  updated_at?: string;
  wave: number;
  position: number;
};

/** One page of a campaign's steps, cut between hosts. */
export type StepPage = {
  items: CampaignStep[];
  count: number;
  next_cursor?: string;
  /** The order the steps of one host run in, from the server's contract. */
  step_order: string[];
};

/**
 * The steps of one host in a campaign.
 *
 * The strip is read for one host at a time - the one the operator opened
 * from the target table - so the request names the host and gets a page
 * of one. The key starts with the campaign, so a stream event refreshing
 * the campaign refreshes the strip too.
 */
export function useTargetSteps(campaignID: string, hostID: string) {
  return useQuery({
    queryKey: ["campaign-steps", campaignID, hostID],
    queryFn: () => api.get<StepPage>(`/api/v1/campaigns/${campaignID}/steps?host_id=${hostID}&limit=1`),
    enabled: campaignID !== "" && hostID !== "",
    refetchInterval: OPERATIONS_INTERVAL,
  });
}
