import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import type { PolicyResult, PolicyVerdict } from "../../lib/types";
import { POLICY_VERDICTS } from "../../lib/types";
import { ErrorBox, Empty, Time } from "../../components/ui";
import { EmptyState } from "../../components/layout";
import { absoluteTime } from "../../lib/format";
import { ModuleHeader, ModulePage, Section, Summary, Table, Widgets, useHost } from "./shared";
import { VerdictChip, ruleSummary, verdictLabel, verdictTone } from "../Policies";
import { useT } from "../../i18n";

/**
 * The verdicts of every policy that selects this host, grouped by policy.
 */
export function HostPolicies() {
  const t = useT();
  const host = useHost();
  const results = useQuery({
    queryKey: ["host-policies", host.id],
    queryFn: () => api.get<Collection<PolicyResult>>(`/api/v1/hosts/${host.id}/policies`),
    refetchInterval: 60 * 1000,
  });
  const rows = results.data?.items ?? [];
  const byPolicy = groupByPolicy(rows);
  const counts = countVerdicts(rows);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Policies")}
        description={t("What the declared state says about this host: every rule of every policy that selects it, judged from the inventory the host reports.")}
      />
      {results.error ? (
        <ErrorBox error={results.error} />
      ) : !results.data ? (
        <Empty>{t("Loading…")}</Empty>
      ) : (
        <Widgets>
          {/* A bar of four zeros says nothing the empty state below does not;
              the verdicts are summed only once there is a verdict. */}
          {rows.length > 0 && (
            <Summary
              title={t("Verdicts")}
              description={t("{n} rules over {p} policies", { n: rows.length, p: byPolicy.length })}
              segments={POLICY_VERDICTS.map((verdict) => ({
                label: verdictLabel(verdict, t), value: counts[verdict], tone: verdictTone(verdict),
              }))}
            />
          )}
          {byPolicy.length === 0 ? (
            <Section title={t("Policies")} span={12}>
              {/* The way to a first policy stands where the list would: an
                  empty card does not say what fills it. */}
              <EmptyState action={<Link className="button" to="/policies">{t("Open the policies")}</Link>}>
                {t("No policy selects this host, or none has been evaluated yet. A policy selects hosts by tag, site or environment and is evaluated on the next inventory.")}
              </EmptyState>
            </Section>
          ) : byPolicy.map((group) => (
            <Section
              key={group.policyID}
              span={12}
              flush
              title={<Link to={`/policies/${group.policyID}`}>{group.name}</Link>}
              count={group.results.length}
              description={t("version {v}, evaluated {when}", { v: group.results[0].version, when: absoluteTime(group.results[0].evaluated_at) })}
            >
              <Table>
                <thead>
                  <tr><th>{t("Rule")}</th><th>{t("Verdict")}</th><th>{t("Reason")}</th><th title={t("The inventory revision the rule was judged against.")}>{t("Judged against")}</th><th>{t("Evaluated")}</th></tr>
                </thead>
                <tbody>
                  {group.results.map((result) => (
                    <tr key={result.rule_index}>
                      <td className="mono">{result.rule ? ruleSummary(result.rule) : `#${result.rule_index}`}</td>
                      <td><VerdictChip verdict={result.verdict} /></td>
                      <td>{result.reason || "—"}</td>
                      <td className="mono">{result.observed_revision ? result.observed_revision.slice(0, 12) : "—"}</td>
                      <td><Time value={result.evaluated_at} /></td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Section>
          ))}
        </Widgets>
      )}
    </ModulePage>
  );
}

/** The results by policy, in the order the server gave them (by name). */
export function groupByPolicy(results: PolicyResult[]): { policyID: string; name: string; results: PolicyResult[] }[] {
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
