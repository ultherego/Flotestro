import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/** One entry of the guide to error codes the panel serves. */
export type ErrorGuide = {
  code: string;
  stage: string;
  retry: "never" | "automatic" | "after_change" | "after_replan" | "read_state";
  meaning: string;
  action: string;
  counts_as_failure: boolean;
};

/**
 * The guide to error codes, read once per session. A code answers what
 * happened and what can safely be done next; the screens show that on
 * hover instead of leaving the operator with a bare identifier.
 */
export function useErrorGuides(): Map<string, ErrorGuide> {
  const { data } = useQuery({
    queryKey: ["errors"],
    queryFn: () => api.get<{ items: ErrorGuide[] }>("/api/v1/errors"),
    staleTime: Infinity,
  });
  return new Map((data?.items ?? []).map((guide) => [guide.code, guide]));
}
