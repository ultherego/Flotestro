import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, Job } from "../../lib/types";
import { Time, ConnectionState } from "../../components/ui";
import { module as findModule } from "./modules";
import { useT } from "../../i18n";

/**
 * The persistent host header. An operator switching modules must know
 * without checking anything which machine they work on - so the target
 * identity is part of the layout, not text repeated by the individual
 * screens. The first line is the identity, the second the facts as chips:
 * a fact read at a glance is a fact that gets read.
 */
export function ContextBar({ host, segment, campaign }: {
  host: Host;
  segment: string;
  /** The campaign the operator came from; it keeps the way back in view. */
  campaign?: string | null;
}) {
  const t = useT();
  return (
    <div className="host-header">
      {campaign && (
        <p className="host-header-crumb source">
          <Link to={`/campaigns/${campaign}`}>← {t("Back to the campaign")}</Link>
        </p>
      )}
      <div className="host-header-title">
        <ConnectionDot state={host.connection_state} />
        <h1 className="host-header-name">{host.hostname}</h1>
        <ConnectionState state={host.connection_state} />
        <MaintenanceWindow host={host} />
      </div>
      <div className="host-header-facts">
        <ManagementAddress host={host} />
        <span className="chip" title={t("site / environment")}>{host.site} / {host.environment}</span>
        <span className="chip" title={t("operating system")}>
          {host.os_distribution || host.os_family || t("unknown OS")} {host.os_version}
        </span>
        <span className="chip" title={t("architecture and agent version")}>
          {host.architecture || t("unknown arch")} · {t("agent {version}", { version: host.agent_version || t("unknown") })}
        </span>
        <span className="chip" title={t("last seen")}>
          {t("seen")} <Time value={host.last_seen_at} />
        </span>
        <RefreshInventory host={host} segment={segment} />
      </div>
    </div>
  );
}

/** The connection state as a dot, in the same colours as the badge. */
function ConnectionDot({ state }: { state: Host["connection_state"] }) {
  const kind = state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={`dot ${kind}`} aria-hidden="true" />;
}

/**
 * An inventory refresh on demand.
 *
 * The panel shows the image from before the last cycle, so an operator who
 * just changed something on the host by hand or prepares a campaign must be
 * able to ask "how is it now". The button is in the bar, not in a tab,
 * because it concerns the whole host; the scope follows from the open tab -
 * what the operator looks at is refreshed, not the whole host at every
 * click.
 */
function RefreshInventory({ host, segment }: { host: Host; segment: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [jobID, setJobID] = useState("");
  const [message, setMessage] = useState("");
  // The scope is taken from the tab registry: it knows which inventory
  // module the open view lives off. A tab without a module (Jobs,
  // Overview) refreshes the whole host - narrowing to something that does
  // not exist would refresh nothing.
  const scope = findModule(segment)?.inventory;

  // The job ends only once the new revision is saved, so the button follows
  // it to the end. Otherwise "refreshed" would only mean "ordered", and the
  // operator would look at the old image believing it is new.
  const state = useQuery({
    queryKey: ["job", jobID],
    queryFn: () => api.get<Job>(`/api/v1/jobs/${jobID}`),
    enabled: jobID !== "",
    refetchInterval: (query) =>
      finished((query.state.data as Job | undefined)?.state) ? false : 2000,
  });

  useEffect(() => {
    const result = state.data;
    if (!result || !finished(result.state)) return;
    setJobID("");
    if (result.state !== "succeeded") {
      setMessage(result.result_error_code || result.result_message || result.state);
      return;
    }
    setMessage(result.result_message || t("inventory refreshed"));
    // The new image is in the panel, so the views of this host are to show
    // it. There is no single inventory key: every tab reads its own, so
    // everything concerning this machine is invalidated.
    queryClient.invalidateQueries({
      predicate: (query) => query.queryKey.includes(host.id),
    });
  }, [state.data, host.id, queryClient, t]);

  const order = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "inventory.refresh",
        payload: { inventory: scope ? { modules: [scope] } : {} },
      }),
    onSuccess: (created) => {
      setMessage("");
      setJobID(created.id);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const busy = order.isPending || jobID !== "";
  const description = scope
    ? t("ask the host to re-read its {module} module now", { module: scope })
    : t("ask the host to re-read its whole inventory now");
  return (
    <span className="chip inventory-refresh">
      <button
        type="button"
        className="link"
        disabled={busy || host.connection_state !== "online"}
        title={host.connection_state === "online" ? description : t("the host is not connected")}
        onClick={() => order.mutate()}
      >
        {busy ? t("refreshing…") : t("refresh")}
      </button>
      {message && <span className="message">{message}</span>}
    </span>
  );
}

/** The terminal job states. Outside them it is worth asking further. */
function finished(state: string | undefined): boolean {
  return ["succeeded", "failed", "timed_out", "canceled", "expired"].includes(state ?? "");
}

/**
 * The maintenance window badge. It is in the bar, not in the power tab,
 * because it concerns every operation on this host: whoever starts doing
 * anything is to know that somebody else already works on this machine.
 */
function MaintenanceWindow({ host }: { host: Host }) {
  const t = useT();
  if (!host.maintenance) return null;
  const until = new Date(host.maintenance.until);
  if (Number.isNaN(until.getTime()) || until.getTime() <= Date.now()) return null;
  const description = [host.maintenance.reason, host.maintenance.set_by && t("set by {who}", { who: host.maintenance.set_by })]
    .filter(Boolean)
    .join(" · ");
  return (
    <span className="badge warn" title={description || t("maintenance window")}>
      {t("maintenance until {time} UTC", { time: until.toISOString().slice(0, 16).replace("T", " ") })}
    </span>
  );
}

/**
 * The management address with its origin. An undetermined address is shown
 * as undetermined: a host may have many addresses and giving any of them as
 * the management address would mislead the operator.
 */
function ManagementAddress({ host }: { host: Host }) {
  const t = useT();
  if (!host.management_address) {
    return (
      <span className="chip unknown" title={t("no address has been observed for this host yet")}>
        {t("address unknown")}
      </span>
    );
  }
  const description =
    host.management_address_source === "session"
      ? t("address seen by the control plane on its end of the connection")
      : host.management_address_source === "agent"
        ? t("address reported by the host itself; it connects through a relay")
        : t("address set manually by an operator");
  return (
    <span className="chip" title={description}>
      <span className="chip-mono">{host.management_address}</span>
      <span className="chip-tag">{host.management_address_source}</span>
    </span>
  );
}
