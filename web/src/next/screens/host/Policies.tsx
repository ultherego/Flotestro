import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../../lib/api";
import { absoluteTime, relativeTime } from "../../../lib/format";
import { POLICY_VERDICTS, type Host, type PolicyResult, type PolicyVerdict } from "../../../lib/types";
import { ruleSummary, verdictLabel, verdictTone } from "../../../pages/Policies";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Card, Empty, Pill, Problem, Table, type Segment, type Tone,
} from "../../kit";

/**
 * What the declared state says about this machine.
 *
 * Every rule of every policy that selects the host, judged against the
 * inventory the host itself reported. Nothing here is ordered from the
 * panel: a verdict is a reading, and the policy it comes from is where it
 * is changed.
 *
 * A verdict nobody has taken yet is not a pass. Until the evaluation
 * arrives the counts are unknown and the band says so, because a row of
 * four noughts over a host nobody has judged reads as a clean host.
 */

/** A verdict a minute old is current enough; the loop keeps it so. */
const POLICIES_INTERVAL = 60 * 1000;

/** The results by policy, in the order the server gave them (by name). */
export function groupByPolicy(
  results: PolicyResult[],
): { policyID: string; name: string; results: PolicyResult[] }[] {
  const groups: { policyID: string; name: string; results: PolicyResult[] }[] = [];
  for (const result of results) {
    let group = groups.find((entry) => entry.policyID === result.policy_id);
    if (!group) {
      group = { policyID: result.policy_id, name: result.policy_name || result.policy_id, results: [] };
      groups.push(group);
    }
    group.results.push(result);
  }
  return groups;
}

/** The verdicts counted, every verdict a key; zero is shown, not hidden. */
export function countVerdicts(results: PolicyResult[]): Record<PolicyVerdict, number> {
  const counts: Record<PolicyVerdict, number> = { compliant: 0, drift: 0, error: 0, not_applicable: 0 };
  for (const result of results) {
    if (result.verdict in counts) counts[result.verdict] += 1;
  }
  return counts;
}

/**
 * The verdict that decides how a policy reads at a glance: an error beats
 * a drift, a drift beats a pass. A policy whose every rule is beside the
 * point is beside the point.
 */
export function worstVerdict(results: PolicyResult[]): PolicyVerdict | undefined {
  for (const verdict of ["error", "drift", "compliant", "not_applicable"] as PolicyVerdict[]) {
    if (results.some((one) => one.verdict === verdict)) return verdict;
  }
  return undefined;
}

export function Policies({ host }: { host: Host }) {
  const t = useT();

  const results = useQuery({
    queryKey: ["host-policies", host.id],
    queryFn: () => api.get<Collection<PolicyResult>>(`/api/v1/hosts/${host.id}/policies`),
    refetchInterval: POLICIES_INTERVAL,
    retry: false,
  });

  if (results.error) return <Problem>{String(results.error)}</Problem>;

  const rows = results.data?.items ?? [];
  const groups = groupByPolicy(rows);
  // Nothing is counted until the evaluation arrives: the band then says
  // "not counted" rather than drawing a host with nothing against it.
  const counts = results.data ? countVerdicts(rows) : undefined;
  const segments: Segment[] = POLICY_VERDICTS.map((verdict) => ({
    label: verdictLabel(verdict, t),
    value: counts?.[verdict],
    tone: verdictTone(verdict) as Tone,
  }));

  return (
    <Board screen="next_host_policies" catalogue={HOST_POLICIES} drawn={{
      verdicts: (
        <Card
          title={t("Verdicts")}
          note={t("What the declared state says about this host, rule by rule.")}
          foot={results.data
            ? t("{n} rules over {p} policies", { n: rows.length, p: groups.length })
            : undefined}
        >
          <Band segments={segments} testId="verdicts" />
        </Card>
      ),
      policies: (
        <Card title={t("Policies that select this host")} flush>
          <Table
            rows={groups}
            keyOf={(one) => one.policyID}
            loading={results.isLoading}
            rowTestId={(one) => `policy-${one.name}`}
            testId="policies"
            empty={t("No policy selects this host.")}
            columns={[
              {
                key: "name",
                head: t("Policy"),
                cell: (one) => (
                  // The policy's own record is not in the new panel yet, so
                  // the link leaves it rather than landing on nothing.
                  <Link to={`/policies/${one.policyID}`}>{one.name}</Link>
                ),
              },
              {
                key: "verdict",
                head: t("Verdict"),
                cell: (one) => {
                  const worst = worstVerdict(one.results);
                  return worst
                    ? <Pill tone={verdictTone(worst) as Tone}>{verdictLabel(worst, t)}</Pill>
                    : <Pill tone="unknown">{t("unknown")}</Pill>;
                },
              },
              { key: "rules", head: t("Rules"), num: true, cell: (one) => one.results.length },
              {
                key: "version",
                head: t("Version"),
                num: true,
                minor: true,
                cell: (one) => one.results[0]?.version ?? "—",
              },
              {
                key: "when",
                head: t("Evaluated"),
                minor: true,
                cell: (one) => (
                  <span title={absoluteTime(one.results[0]?.evaluated_at)}>
                    {relativeTime(one.results[0]?.evaluated_at)}
                  </span>
                ),
              },
            ]}
          />
        </Card>
      ),
      rules: (
        <Card
          title={t("Rules")}
          note={rows.length > 0 ? t("Every rule of every policy that selects this host.") : undefined}
          flush
        >
          {!results.isLoading && rows.length === 0 ? (
            <Empty
              icon="security"
              action={<Link className="fl-btn fl-quiet" to="/policies">{t("Open the policies")}</Link>}
            >
              {t("No policy selects this host, or none has been evaluated yet. A policy selects hosts by tag, site or environment and is evaluated on the next inventory.")}
            </Empty>
          ) : (
            <Table
              rows={rows}
              keyOf={(one, index) => `${one.policy_id}-${one.rule_index}-${index}`}
              loading={results.isLoading}
              testId="rules"
              rowTestId={(one) => `rule-${one.policy_id}-${one.rule_index}`}
              columns={[
                {
                  key: "policy",
                  head: t("Policy"),
                  cell: (one) => <Link to={`/policies/${one.policy_id}`}>{one.policy_name || one.policy_id}</Link>,
                },
                {
                  key: "rule",
                  head: t("Rule"),
                  tight: true,
                  cell: (one) => <code>{one.rule ? ruleSummary(one.rule) : `#${one.rule_index}`}</code>,
                },
                {
                  key: "verdict",
                  head: t("Verdict"),
                  cell: (one) => <Pill tone={verdictTone(one.verdict) as Tone}>{verdictLabel(one.verdict, t)}</Pill>,
                },
                { key: "reason", head: t("Reason"), cell: (one) => one.reason || "—" },
                {
                  key: "revision",
                  head: (
                    <span title={t("The inventory revision the rule was judged against.")}>
                      {t("Judged against")}
                    </span>
                  ),
                  tight: true,
                  minor: true,
                  cell: (one) => (one.observed_revision ? <code>{one.observed_revision.slice(0, 12)}</code> : "—"),
                },
                {
                  key: "when",
                  head: t("Evaluated"),
                  minor: true,
                  cell: (one) => (
                    <span title={absoluteTime(one.evaluated_at)}>{relativeTime(one.evaluated_at)}</span>
                  ),
                },
              ]}
            />
          )}
        </Card>
      ),
    }} />
  );
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_POLICIES: BoardEntry[] = [
  { key: "verdicts", title: "Verdicts", width: 7, height: 2 },
  { key: "policies", title: "Policies that select this host", width: 5, height: 2 },
  { key: "rules", title: "Rules", width: 12, height: 4 },
];

/** The name this module's arrangement is stored under. */
export const HOST_POLICIES_SCREEN = "next_host_policies";
