import { useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, InventoryFragment, InventoryRevision, Job } from "../../lib/types";
import { Time } from "../../components/ui";
import { useT } from "../../i18n";

/** The host context comes from the layout, so a tab does not fetch it again. */
export function useHost(): Host {
  return useOutletContext<{ host: Host }>().host;
}

/** The inventory is shared by the tabs, so it shares one cache key. */
export function useInventory(hostID: string) {
  return useQuery({
    queryKey: ["inventory", hostID],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${hostID}/inventory`),
    retry: false,
  });
}

/**
 * A tab fetches its own inventory module. Each has its own revision and its
 * own observation timestamp, so the freshness describes what the operator
 * looks at, not the whole host report.
 */
export function useModule<T>(hostID: string, module: string) {
  return useQuery({
    queryKey: ["inventory", hostID, module],
    queryFn: () => api.get<InventoryFragment<T>>(`/api/v1/hosts/${hostID}/inventory/${module}`),
    retry: false,
  });
}

/**
 * The tab footer: where the data comes from and how fresh it is. An unread
 * module says why - an empty module and an unread module are two different
 * things.
 */
export function ModuleFreshness({ fragment }: { fragment?: InventoryFragment<unknown> }) {
  const t = useT();
  if (!fragment) return null;
  return (
    <p className="source" style={{ marginTop: 16 }}>
      {t("Source: {source}, revision {revision}, observed", { source: fragment.source, revision: fragment.revision.slice(0, 12) })}{" "}
      <Time value={fragment.observed_at} />
      {fragment.unavailable_reason && ` · ${t("could not be read: {reason}", { reason: fragment.unavailable_reason })}`}
    </p>
  );
}

/**
 * Ordering an operation leads to a plan, not to an immediate change. A
 * mutating operation lands in the awaiting-approval state.
 */
export function RequestOperation({
  host, description, action, payload, label,
}: { host: Host; description: string; action: string; payload: unknown; label: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [result, setResult] = useState<string>("");

  const mutation = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action, payload }),
    onSuccess: (job) => {
      setResult(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setResult(error instanceof Error ? error.message : String(error)),
  });

  return (
    <div style={{ marginTop: 24 }}>
      <h2>{t("Request an operation")}</h2>
      <p className="subtitle">{description}</p>
      {/* The target repeated right at the button: the operator approves a
          specific machine, not "the host I think I have open". */}
      <p className="source" style={{ marginBottom: 10 }}>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </p>
      <button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
        {mutation.isPending ? t("Requesting…") : label}
      </button>
      {result && <p className="source" style={{ marginTop: 10 }}>{result}</p>}
      <p style={{ marginTop: 12 }}>
        <Link to="/jobs">{t("See all jobs")}</Link>
      </p>
    </div>
  );
}
