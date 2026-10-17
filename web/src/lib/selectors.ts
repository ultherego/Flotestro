import type { SelectorExpression } from "./types";

/**
 * The selector language: the rows a builder offers, and the expression the
 * server reads.
 *
 * Three screens compose a selector - the group editor, the bulk wizard and
 * the policy editor - and a fourth reads one back. They all have to mean the
 * same thing by a row, so the rows, the facts they may name and the two
 * translations between rows and expression live here rather than in whichever
 * screen happened to need them first.
 */

/** One row of the selector builder: a fact about the host and its value. */
export type Rule = { field: RuleField; value: string; negated: boolean };

export type RuleField =
  | "tag" | "group" | "site" | "environment" | "os_family" | "os_version" | "capability"
  | "connection_state" | "lifecycle_state" | "owner" | "channel"
  | "security_updates" | "reboot_required" | "failed_units" | "agent_version"
  | "relay" | "failure_domain";

/** The facts a rule can name, in the order the builder offers them. */
export const RULE_FIELDS: RuleField[] = [
  "tag", "group", "site", "environment", "os_family", "os_version", "capability",
  "connection_state", "lifecycle_state", "owner", "channel",
  "security_updates", "reboot_required", "failed_units", "agent_version",
  "relay", "failure_domain",
];

/**
 * The rows as the expression the server will read: one leaf per row, a
 * negated row wrapped in `not`, and the rows joined by `all` or `any`. A row
 * with no value is not a rule yet and is left out.
 */
export function buildExpression(rules: Rule[], combine: "all" | "any"): SelectorExpression | null {
  const leaves = rules
    .filter((rule) => rule.value.trim() !== "")
    .map((rule): SelectorExpression => {
      // Every leaf the builder offers is a string on the wire; the channel
      // is typed narrower in the view, which is what the cast is for.
      const leaf = { [rule.field]: rule.value.trim() } as SelectorExpression;
      return rule.negated ? { not: leaf } : leaf;
    });
  if (leaves.length === 0) return null;
  if (leaves.length === 1) return leaves[0];
  return combine === "all" ? { all: leaves } : { any: leaves };
}

/** The expression in one line for people; the same shape the server logs. */
export function describeExpression(expression?: SelectorExpression | null): string {
  if (!expression) return "";
  if (expression.all) return `(${expression.all.map(describeExpression).join(" and ")})`;
  if (expression.any) return `(${expression.any.map(describeExpression).join(" or ")})`;
  if (expression.not) return `not ${describeExpression(expression.not)}`;
  const [field, value] = Object.entries(expression).find(([, v]) => typeof v === "string") ?? ["nothing", ""];
  return value ? `${field}=${value}` : field;
}
