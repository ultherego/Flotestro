import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Attempt } from "../lib/types";
import { bytes } from "../lib/format";
import { Time } from "./ui";
import { useT } from "../i18n";

/**
 * The per-host plan: what the operator really consents to.
 *
 * The order is one, but the change on every host differs: a file with
 * different content, a rule of a different shape, a disk under the same
 * path with a different UUID. The plan computed on the host says what
 * happens there - or why not.
 */
/** One package of a package plan: the name and the versions it moves between. */
export type PackageChange = {
  name: string;
  current_version?: string;
  candidate_version?: string;
  security?: boolean;
  // The repository the candidate comes from, when the manager names it.
  origin?: string;
};

/** Where the bytes of a package change go, file system by file system. */
export type SpaceFact = {
  path: string;
  filesystem?: string;
  available_bytes?: number;
  needed_bytes?: number;
  purpose?: string;
  basis?: string;
};

/**
 * The facts a package plan carries beyond its list of packages: the
 * fields of the package_plan detail the agent answers with. A group of a
 * campaign and a job attempt both carry them at the top level of the
 * detail, next to the changes.
 */
export type PackagePlanFacts = {
  kind?: string;
  mode?: string;
  manager?: string;
  reboot_predicted?: boolean;
  download_bytes?: number;
  space?: SpaceFact[];
};

export type HostPlan = {
  action?: string;
  // A file or firewall plan names its changes in words; a package plan
  // lists the packages with their versions.
  changes?: (string | PackageChange)[];
  refusal?: string;
  validator_failed?: boolean;
  validator_output?: string;
  requested_source?: string;
  resolved_source?: string;
  ruleset_hash?: string;
  plan_hash?: string;
  // The text the network adapter applies: the nmstate document of the
  // touched interface or the netplan file after the merge.
  document?: string;
  // The commands a firewall driven by its command line (ufw) runs, as the
  // operator would type them.
  commands?: string[];
};

/** How many package changes the summary spells out before it counts the rest. */
const CHANGES_SHOWN = 6;

/**
 * One change of a plan as words: a sentence stays as it is, a package
 * reads as its name and the versions it moves between, so a plan of
 * forty packages is a list an operator can skim, not forty objects.
 */
export function changeText(change: string | PackageChange): string {
  if (typeof change === "string") return change;
  const versions = change.current_version && change.candidate_version
    ? ` ${change.current_version} → ${change.candidate_version}`
    : change.candidate_version ? ` ${change.candidate_version}` : "";
  return `${change.name}${versions}${change.security ? " (security)" : ""}`;
}

/** The changes of a plan as one line, the first few spelled out and the rest counted. */
export function changesSummary(changes: (string | PackageChange)[], shown = CHANGES_SHOWN): string {
  const words = changes.slice(0, shown).map(changeText);
  const rest = changes.length - words.length;
  return rest > 0 ? `${words.join(", ")} +${rest}` : words.join(", ");
}

const ACTION_NAMES: Record<string, string> = {
  create: "will be created",
  update: "will change",
  no_change: "already in desired state",
  remove: "will be removed",
  remove_absent: "already absent",
};

export function isHostPlan(kind: string | undefined): boolean {
  return kind === "file_plan" || kind === "firewall_plan" || kind === "mount_plan" || kind === "network_plan" || kind === "dns_plan" || kind === "ssh_plan" || kind === "kernel_module_plan" || kind === "time_plan" || kind === "device_plan" || kind === "certificate_plan" || kind === "backup_plan" || kind === "trust_plan" || kind === "renewal_plan";
}

/**
 * The plan summary as one line: the action in words and the first few
 * changes, for a row of a job list. A whole plan reads in PlanChanges.
 */
export function PlanSummary({ plan }: { plan: HostPlan }) {
  const t = useT();
  if (plan.refusal) {
    return <span className="badge error">{t("refused: {reason}", { reason: plan.refusal })}</span>;
  }
  if (plan.validator_failed) {
    return (
      <span className="badge error">
        {t("validator failed")}{plan.validator_output ? `: ${plan.validator_output.slice(0, 200)}` : ""}
      </span>
    );
  }
  const parts = [planWords(plan, t)];
  if (plan.changes?.length) parts.push(changesSummary(plan.changes));
  // The source resolved to a UUID is what goes to the host; the path from
  // the order stays only for comparison.
  if (plan.resolved_source && plan.resolved_source !== plan.requested_source) {
    parts.push(`${plan.requested_source} → ${plan.resolved_source}`);
  }
  return (
    <>
      <span>{parts.join(" · ")}</span>
      <PlanVerbatim plan={plan} />
    </>
  );
}

/**
 * The document or the commands of a plan, verbatim: the summary names the
 * change, but that text is exactly what lands on the host and the operator
 * consents to it, not to a paraphrase. Nothing for a plan without either.
 */
export function PlanVerbatim({ plan }: { plan: HostPlan }) {
  const t = useT();
  const verbatim = plan.document
    ? { label: t("Document"), text: plan.document }
    : plan.commands?.length
      ? { label: t("Commands"), text: plan.commands.join("\n") }
      : null;
  if (!verbatim) return null;
  return (
    <>
      <div className="source">{verbatim.label}</div>
      <pre className="hm-log hm-mono">{verbatim.text}</pre>
    </>
  );
}

/** A change of a plan that is a package rather than a sentence. */
export function isPackageChange(change: string | PackageChange): change is PackageChange {
  return typeof change === "object" && change !== null && typeof change.name === "string";
}

/** How many rows the changes table shows before the operator asks for the rest. */
const ROWS_SHOWN = 8;

/**
 * The changes of a plan as a table the operator can read: a package plan
 * is one row per package with the version it has now and the one it gets,
 * sorted by name, folded to the first few rows with the rest on request.
 * A plan that names its changes in words (a file, a rule) is a plain list.
 */
export function PlanChanges({ changes, shown = ROWS_SHOWN }: { changes?: (string | PackageChange)[]; shown?: number }) {
  const t = useT();
  const [all, setAll] = useState(false);
  if (!changes || changes.length === 0) return null;
  const packages = changes.filter(isPackageChange)
    .sort((a, b) => a.name.localeCompare(b.name));
  const sentences = changes.filter((change): change is string => typeof change === "string");
  if (packages.length === 0) {
    return (
      <ul className="plan-changes-list">
        {sentences.map((change, index) => <li key={`${index}:${change}`}>{change}</li>)}
      </ul>
    );
  }
  const rows = all ? packages : packages.slice(0, shown);
  const security = packages.filter((change) => change.security).length;
  const folded = packages.length > shown;
  return (
    <div className="plan-changes">
      <table className="plan-changes-table">
        <thead>
          <tr>
            <th>{t("Package")}</th>
            <th>{t("Now")}</th>
            <th>{t("After")}</th>
            <th>{t("Note")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((change) => (
            <tr key={change.name}>
              <td className="mono">{change.name}</td>
              {/* A package without a current version is new on the host;
                  one without a candidate goes away. A dash says so, not
                  an empty cell that looks like a number missing. */}
              <td className="mono source">{change.current_version || "—"}</td>
              <td className="mono">{change.candidate_version || "—"}</td>
              <td>
                {change.security && <span className="badge warn">{t("security")}</span>}
                {change.origin && <span className="source plan-origin">{change.origin}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="plan-changes-foot">
        <span className="source">
          {t("{n} packages", { n: packages.length })}
          {security > 0 && ` · ${t("{n} security", { n: security })}`}
        </span>
        {folded && (
          <button type="button" className="secondary plan-toggle" onClick={() => setAll(!all)}>
            {all ? t("Show fewer") : t("Show all {n}", { n: packages.length })}
          </button>
        )}
      </div>
      {sentences.length > 0 && (
        <ul className="plan-changes-list">
          {sentences.map((change, index) => <li key={`${index}:${change}`}>{change}</li>)}
        </ul>
      )}
    </div>
  );
}

const PACKAGE_MODES: Record<string, string> = {
  upgrade: "packages will be upgraded",
  install: "packages will be installed",
  remove: "packages will be removed",
};

/**
 * The operation of a plan in words. A host plan names its action; a
 * package plan names its mode, and the manager that carries it out, since
 * "apt" and "dnf" read the same order differently.
 */
export function planWords(plan: HostPlan & PackagePlanFacts, t: (text: string, params?: Record<string, string | number>) => string): string {
  if (plan.action) return ACTION_NAMES[plan.action] ? t(ACTION_NAMES[plan.action]) : plan.action;
  if (plan.kind === "package_plan" || plan.mode || plan.manager) {
    const mode = PACKAGE_MODES[plan.mode ?? "upgrade"];
    const words = mode ? t(mode) : plan.mode ?? t("plan");
    return plan.manager ? `${words} (${plan.manager})` : words;
  }
  return t("plan");
}

/**
 * What a package plan says besides its packages: whether a reboot follows,
 * how much comes down the wire, and whether every file system has room.
 * The line stays empty for a plan that carries none of it.
 */
export function PlanFacts({ plan }: { plan: PackagePlanFacts }) {
  const t = useT();
  const purposes: Record<string, string> = {
    download: t("download cache"), install: t("installed files"), boot: t("boot files"),
  };
  const facts: { key: string; text: string; warn?: boolean }[] = [];
  if (plan.reboot_predicted) facts.push({ key: "reboot", text: t("reboot predicted"), warn: true });
  if (plan.download_bytes) facts.push({ key: "download", text: t("download {size}", { size: bytes(plan.download_bytes) }) });
  for (const fact of plan.space ?? []) {
    const known = Boolean(fact.basis) && fact.basis !== "unknown";
    const short = known && (fact.needed_bytes ?? 0) > (fact.available_bytes ?? 0);
    const purpose = purposes[fact.purpose ?? ""] ?? fact.purpose ?? "";
    facts.push({
      key: `${fact.purpose}:${fact.path}`,
      warn: short,
      text: known
        ? t("{path} ({purpose}): needs {needed}, {available} free", {
            path: fact.path, purpose, needed: bytes(fact.needed_bytes), available: bytes(fact.available_bytes),
          })
        : t("{path} ({purpose}): need unknown, {available} free", { path: fact.path, purpose, available: bytes(fact.available_bytes) }),
    });
  }
  if (facts.length === 0) return null;
  return (
    <div className="plan-facts">
      {facts.map((fact) => (
        <span key={fact.key} className={fact.warn ? "badge warn" : "source"}>{fact.text}</span>
      ))}
    </div>
  );
}

/** One shape of a campaign's change and the hosts that get it, as the panel serves it. */
export type PlanGroup = {
  plan_hash: string;
  count: number;
  hosts: string[];
  // The plan content arrives in the shape of a job result: a host plan
  // carries its plan under "plan", a package plan is the detail itself.
  plan?: { plan?: Record<string, unknown> } & Record<string, unknown>;
  expires_at: string;
};

/** How many host names the header of a group spells out before it counts the rest. */
const HOSTS_SHOWN = 12;

/**
 * One group of plans of a campaign: a header with the hosts, the
 * fingerprint and the expiry, then the plan itself - the operation in
 * words, its facts and the table of changes. A hundred hosts with the
 * same diff are one group, so the operator reads the diff once.
 */
export function PlanGroupView({ group, action }: { group: PlanGroup; action?: string }) {
  const t = useT();
  const plan = (group.plan?.plan ?? group.plan ?? {}) as HostPlan & PackagePlanFacts;
  const named = group.hosts.slice(0, HOSTS_SHOWN);
  const more = group.hosts.length - named.length;
  const trouble = Boolean(plan.refusal || plan.validator_failed);
  return (
    <section className="plan-group" data-testid="plan-group">
      <div className="plan-group-head">
        <span className="plan-group-hosts" title={group.hosts.join("\n")}>
          <strong>{t("{n} hosts", { n: group.count })}</strong>
          <span className="source"> {named.join(", ")}{more > 0 && ` +${more}`}</span>
        </span>
        <span className="source">{t("Plan fingerprint")} <span className="mono" title={group.plan_hash}>{group.plan_hash.slice(0, 16)}</span></span>
        {/* A plan is bound in time as well as by its digest: past the expiry
            the hosts are not started on it and the campaign is planned again. */}
        <span className="source">{t("Valid until")} <Time value={group.expires_at} /></span>
      </div>
      <div className="plan-group-body">
        {trouble ? (
          <PlanSummary plan={plan} />
        ) : (
          <>
            <div className="plan-group-words">
              {action && <span className="mono">{action}</span>}
              {action && " · "}
              <span>{planWords(plan, t)}</span>
              {/* The source resolved to a UUID is what goes to the host. */}
              {plan.resolved_source && plan.resolved_source !== plan.requested_source && (
                <span className="source"> · {plan.requested_source} → {plan.resolved_source}</span>
              )}
            </div>
            <PlanFacts plan={plan} />
            <PlanChanges changes={plan.changes} />
            <PlanVerbatim plan={plan} />
          </>
        )}
      </div>
    </section>
  );
}

/** The host plan read from the last attempt of the planning operation. */
export function JobPlan({ jobId }: { jobId: string }) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <span className="source">{t("plan unavailable")}</span>;
  const attempt = [...(data?.items ?? [])].reverse().find((item) => isHostPlan(item.detail?.kind as string));
  if (!attempt) return <span className="source">—</span>;
  return <PlanSummary plan={(attempt.detail?.plan ?? {}) as HostPlan} />;
}
