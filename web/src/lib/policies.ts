import type { Policy, PolicyRemediationMode, PolicyRule, PolicyVerdict } from "./types";
import type { StateTone } from "./tone";
import type { Translate } from "../i18n";

/**
 * The vocabulary of a policy: what a verdict is called and coloured, what a
 * rule declares in words, and where a policy stands.
 *
 * The policy list, the policy page and the host's own compliance tab all
 * say these, and they have to say the same ones: a verdict called "drift"
 * on one screen and something else on another is two products.
 */

/**
 * The colour of a verdict. Drift is a warning: the host is where the policy
 * does not want it, and somebody decides what happens.
 */
export function verdictTone(verdict: PolicyVerdict | string): StateTone {
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
 * The shares of a compliance reading: one segment per verdict, in the fixed
 * order, as fractions of the total. A policy nobody evaluated has none.
 */
export function complianceShares(
  counts: Partial<Record<PolicyVerdict, number>> | undefined,
): { verdict: PolicyVerdict; count: number; share: number }[] {
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
 * The state of a policy in one word for the list: never published, a draft
 * on top of a version, disabled, or published as it stands.
 */
export function policyStanding(
  policy: Pick<Policy, "version" | "draft" | "enabled">,
): "unpublished" | "draft" | "disabled" | "published" {
  if (policy.version === 0) return "unpublished";
  if (!policy.enabled) return "disabled";
  if (policy.draft) return "draft";
  return "published";
}

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
