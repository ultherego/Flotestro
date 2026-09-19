import { useT } from "../i18n";

/**
 * The head of a fleet view.
 */
export type Coverage = {
  total_hosts: number;
  evaluated_hosts: number;
  unknown_hosts: number;
  partial?: boolean;
  partial_reason?: string;
  unknown_reasons?: Record<string, number>;
};

/** Why an answer is not the whole fleet, as the server names it. */
export const PARTIAL_REASONS: Record<string, string> = {
  time_budget: "the sweep ran out of its time budget; the hosts it did not reach are counted as unknown",
  cap_reached: "a cap on rows ended the answer before its last row",
};

/** Why a host is unknown to a view, as the server names it. */
export const UNKNOWN_REASONS: Record<string, string> = {
  no_observation: "never reported this",
  unavailable: "could not be read",
  stale_observation: "last report too old to trust",
  not_reached: "not reached by this sweep",
  no_definition: "nothing is defined to run here",
  no_assessment: "never assessed",
};

/**
 * The counters as one sentence. It is a pure function so the wording is
 * checked without a screen: "300 of 1001 hosts evaluated · 701 unknown".
 */
export function coverageSentence(
  coverage: Coverage,
  t: (text: string, params?: Record<string, string | number>) => string,
): string {
  const evaluated = t("{n} of {total} hosts evaluated", {
    n: coverage.evaluated_hosts, total: coverage.total_hosts,
  });
  return `${evaluated} · ${t("{n} unknown", { n: coverage.unknown_hosts })}`;
}

/**
 * The reasons the unknown hosts are unknown, longest group first, as one
 * phrase. Empty when the view could not tell them apart.
 */
export function unknownBreakdown(
  coverage: Coverage,
  t: (text: string, params?: Record<string, string | number>) => string,
): string {
  const reasons = Object.entries(coverage.unknown_reasons ?? {}).filter(([, count]) => count > 0);
  if (!reasons.length) return "";
  return reasons
    .sort((a, b) => b[1] - a[1])
    .map(([code, count]) => `${count} ${UNKNOWN_REASONS[code] ? t(UNKNOWN_REASONS[code]) : code}`)
    .join(", ");
}

/**
 * One line under the page header with the coverage of the view, and a
 * badge beside it when the answer is not the whole fleet.
 */
export function FleetCoverage({ coverage }: { coverage?: Coverage }) {
  const t = useT();
  if (!coverage) return null;
  const breakdown = unknownBreakdown(coverage, t);
  const reason = coverage.partial_reason ?? "";
  return (
    <p className="source" data-testid="fleet-coverage">
      <span title={breakdown || undefined}>{coverageSentence(coverage, t)}</span>
      {breakdown && <span>{` (${breakdown})`}</span>}
      {coverage.partial && (
        <>
          {" "}
          <span className="badge warn" data-testid="fleet-partial">
            {t("partial answer")}
          </span>
          {" "}
          <span>{PARTIAL_REASONS[reason] ? t(PARTIAL_REASONS[reason]) : reason}</span>
        </>
      )}
    </p>
  );
}
