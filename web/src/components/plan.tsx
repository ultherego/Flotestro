import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Attempt } from "../lib/types";
import { useT } from "../i18n";

/**
 * The per-host plan: what the operator really consents to.
 *
 * The order is one, but the change on every host differs: a file with
 * different content, a rule of a different shape, a disk under the same
 * path with a different UUID. The plan computed on the host says what
 * happens there - or why not.
 */
type HostPlan = {
  action?: string;
  changes?: string[];
  refusal?: string;
  validator_failed?: boolean;
  validator_output?: string;
  requested_source?: string;
  resolved_source?: string;
  ruleset_hash?: string;
  plan_hash?: string;
};

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

/** The plan summary from the typed result of a planning operation. */
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
  const parts = [plan.action && ACTION_NAMES[plan.action] ? t(ACTION_NAMES[plan.action]) : plan.action ?? t("plan")];
  if (plan.changes?.length) parts.push(plan.changes.join(", "));
  // The source resolved to a UUID is what goes to the host; the path from
  // the order stays only for comparison.
  if (plan.resolved_source && plan.resolved_source !== plan.requested_source) {
    parts.push(`${plan.requested_source} → ${plan.resolved_source}`);
  }
  return <span>{parts.join(" · ")}</span>;
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
