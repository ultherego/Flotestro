import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { Policy, PolicyRule, PolicyVerdict, PolicyRemediationMode, Whoami } from "../lib/types";
import { POLICY_MODES } from "../lib/types";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader } from "../components/layout";
import { StatusBar, type WidgetTone } from "../components/widgets";
import { useT } from "../i18n";

/* ---------------------------------------------------------------------- */
/* The vocabulary of a policy.                                             */
/* ---------------------------------------------------------------------- */

/**
 * The colour of a verdict. Drift is a warning: the host is where the policy
 * does not want it, and somebody decides what happens.
 */
export function verdictTone(verdict: PolicyVerdict | string): WidgetTone {
  switch (verdict) {
    case "compliant": return "ok";
    case "drift": return "warn";
    case "error": return "error";
    default: return "unknown";
  }
}

/** The verdicts in the order the bars and the tables show them. */
export const VERDICT_ORDER: PolicyVerdict[] = ["compliant", "drift", "error", "not_applicable"];

/**
 * The shares of a compliance bar: one segment per verdict, in the fixed
 * order, as fractions of the total.
 */
export function complianceShares(counts: Partial<Record<PolicyVerdict, number>> | undefined): { verdict: PolicyVerdict; count: number; share: number }[] {
  const total = VERDICT_ORDER.reduce((sum, verdict) => sum + (counts?.[verdict] ?? 0), 0);
  if (total === 0) return [];
  return VERDICT_ORDER
    .map((verdict) => ({ verdict, count: counts?.[verdict] ?? 0, share: (counts?.[verdict] ?? 0) / total }))
    .filter((segment) => segment.count > 0);
}

/** One line per rule: the declaration in the words the server uses. */
export function ruleSummary(rule: PolicyRule): string {
  switch (rule.kind) {
    case "package_installed": return `package ${rule.name ?? ""} installed`;
    case "package_absent": return `package ${rule.name ?? ""} absent`;
    case "unit_state": {
      const halves = [];
      if (rule.enabled !== undefined) halves.push(rule.enabled ? "enabled" : "disabled");
      if (rule.active !== undefined) halves.push(rule.active ? "active" : "inactive");
      return `unit ${rule.unit ?? ""} ${halves.join(" and ")}`.trim();
    }
    case "file_content": return `file ${rule.path ?? ""} at ${(rule.sha256 ?? "").slice(0, 12)}`;
    case "sysctl": return `sysctl ${rule.key ?? ""} = ${rule.value ?? ""}`;
    case "ssh_key_present": return `key ${rule.fingerprint ?? ""} on ${rule.user ?? ""}`;
    default: return rule.kind;
  }
}

/**
 * The state of a policy in one word for the list: never published, a
 * draft on top of a version, or published as it stands.
 */
export function policyStanding(policy: Pick<Policy, "version" | "draft" | "enabled">): "unpublished" | "draft" | "disabled" | "published" {
  if (policy.version === 0) return "unpublished";
  if (!policy.enabled) return "disabled";
  if (policy.draft) return "draft";
  return "published";
}

type Translate = (text: string, params?: Record<string, string | number>) => string;

export function verdictLabel(verdict: PolicyVerdict | string, t: Translate): string {
  switch (verdict) {
    case "compliant": return t("compliant");
    case "drift": return t("drift");
    case "error": return t("error");
    case "not_applicable": return t("not applicable");
    default: return verdict;
  }
}

export function modeLabel(mode: PolicyRemediationMode | string, t: Translate): string {
  switch (mode) {
    case "report": return t("report only");
    case "campaign": return t("campaign, awaiting approval");
    case "automatic": return t("automatic, approved at publication");
    default: return mode;
  }
}

/* ---------------------------------------------------------------------- */
/* The compliance bar.                                                     */
/* ---------------------------------------------------------------------- */

/**
 * The verdicts of a policy as one stacked bar, compliant first and the rest
 * in the fixed order, with the counts beside it.
 */
export function ComplianceBar({ counts }: { counts: Policy["counts"] | undefined }) {
  const t = useT();
  const segments = complianceShares(counts);
  if (segments.length === 0) return <span className="badge unknown">{t("not evaluated")}</span>;
  return (
    <span className="meter" title={segments.map((segment) => `${verdictLabel(segment.verdict, t)}: ${segment.count}`).join(", ")}>
      <span className="meter-track" style={{ display: "inline-flex", overflow: "hidden" }}>
        {segments.map((segment) => (
          <span
            key={segment.verdict}
            className={`meter-fill ${verdictTone(segment.verdict)}`}
            style={{ width: `${Math.round(segment.share * 100)}%`, display: "inline-block" }}
          />
        ))}
      </span>
      <span className="meter-value">
        {segments.map((segment) => (
          <span key={segment.verdict} className={`badge ${verdictTone(segment.verdict)}`}>{segment.count}</span>
        ))}
      </span>
    </span>
  );
}

/** A verdict as a chip. */
export function VerdictChip({ verdict }: { verdict: PolicyVerdict | string }) {
  const t = useT();
  return <span className={`badge ${verdictTone(verdict)}`}>{verdictLabel(verdict, t)}</span>;
}

/* ---------------------------------------------------------------------- */
/* The page.                                                               */
/* ---------------------------------------------------------------------- */

/** The list refreshes with the loop: a verdict a minute old is current enough. */
const POLICIES_INTERVAL = 60 * 1000;

/**
 * The desired-state policies of the fleet.
 */
export function Policies() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [mode, setMode] = useState<PolicyRemediationMode>("report");
  const { data, error } = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.get<Collection<Policy>>("/api/v1/policies"),
    refetchInterval: POLICIES_INTERVAL,
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canWrite = (whoami.data?.permissions ?? []).includes("policy.write");
  const create = useMutation({
    mutationFn: () => api.post<Policy>("/api/v1/policies", {
      name: name.trim(), description: "", selector: {}, rules: [], remediation_mode: mode,
    }),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      navigate(`/policies/${created.id}`);
    },
  });

  if (error) return <ErrorBox error={error} />;
  const loaded = data !== undefined;
  const policies = data?.items ?? [];
  const published = policies.filter((policy) => policy.version > 0);
  const drafts = policies.filter((policy) => policy.version === 0 || policy.draft);
  const drifting = policies.filter((policy) => (policy.counts?.drift ?? 0) > 0);
  const erring = policies.filter((policy) => (policy.counts?.error ?? 0) > 0);

  return (
    <>
      <PageHeader
        icon="security"
        title={t("Policies")}
        description={t("What is to be true on a group of hosts: a package installed, a unit running, a file at a known content, a setting at a value, a key on an account. The panel judges every host from its inventory; a drift is reported, or turned into a campaign that waits for approval.")}
        actions={canWrite && !creating && <button onClick={() => setCreating(true)}>{t("New policy")}</button>}
      />

      {creating && (
        <Card title={t("New policy")} description={t("A draft: the rules and the hosts are written on its page, and nothing is judged until it is published.")}>
          <FieldGrid>
            <Field label={t("Name")}>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("e.g. baseline-cron")} autoFocus />
            </Field>
            <Field label={t("Remediation")} hint={t("What happens to a drift; automatic needs its own permission at the publication.")}>
              <select value={mode} onChange={(e) => setMode(e.target.value as PolicyRemediationMode)}>
                {POLICY_MODES.map((value) => <option key={value} value={value}>{modeLabel(value, t)}</option>)}
              </select>
            </Field>
          </FieldGrid>
          {create.error instanceof ApiError && <p className="hm-message error">{create.error.message}</p>}
          <Actions>
            <button onClick={() => create.mutate()} disabled={name.trim() === "" || create.isPending}>{t("Create the draft")}</button>
            <button className="secondary" onClick={() => setCreating(false)}>{t("Cancel")}</button>
          </Actions>
        </Card>
      )}

      <div className="widgets">
        <Card className="span-12" title={t("Standing")} description={loaded ? t("{n} policies", { n: policies.length }) : undefined}>
          <StatusBar segments={[
            { label: t("Published"), value: loaded ? published.length : undefined, tone: "info" },
            { label: t("Drafts"), value: loaded ? drafts.length : undefined, tone: "neutral" },
            { label: t("With drift"), value: loaded ? drifting.length : undefined, tone: "warn" },
            { label: t("With errors"), value: loaded ? erring.length : undefined, tone: "error" },
          ]} />
        </Card>

        <Card className="span-12" flush>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : policies.length === 0 ? (
            <EmptyState action={canWrite && !creating && <button onClick={() => setCreating(true)}>{t("New policy")}</button>}>
              {t("No policy is declared. Without one the panel reports what the hosts are, not what they should be.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Name")}</th>
                  <th>{t("Version")}</th>
                  <th>{t("Remediation")}</th>
                  <th>{t("Rules")}</th>
                  <th>{t("Compliance")}</th>
                  <th>{t("Last evaluated")}</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td><Link to={`/policies/${policy.id}`}>{policy.name}</Link></td>
                    <td><Standing policy={policy} /></td>
                    <td>{modeLabel(policy.remediation_mode, t)}</td>
                    <td className="num">{policy.rules.length}</td>
                    <td><ComplianceBar counts={policy.counts} /></td>
                    <td>{policy.last_evaluated_at ? <Time value={policy.last_evaluated_at} /> : <span className="badge unknown">{t("never")}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

/** The version with the standing beside it. */
export function Standing({ policy }: { policy: Pick<Policy, "version" | "draft" | "enabled"> }) {
  const t = useT();
  switch (policyStanding(policy)) {
    case "unpublished":
      return <span className="badge unknown">{t("not published")}</span>;
    case "disabled":
      return <>v{policy.version} <span className="badge unknown">{t("disabled")}</span></>;
    case "draft":
      return <>v{policy.version} <span className="badge warn">{t("draft on top")}</span></>;
    default:
      return <>v{policy.version}</>;
  }
}
