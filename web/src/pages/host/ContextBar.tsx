import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { refusalName, type Host, type Job, type Whoami } from "../../lib/types";
import { relativeTime } from "../../lib/format";
import { Time, ConnectionState } from "../../components/ui";
import { module as findModule } from "./modules";
import { hostTitle, useDocumentTitle } from "../../lib/title";
import { useT } from "../../i18n";

/**
 * The persistent host header.
 */
export function ContextBar({ host, segment, campaign }: {
  host: Host;
  segment: string;
  /** The campaign the operator came from; it keeps the way back in view. */
  campaign?: string | null;
}) {
  const t = useT();
  // The tab carries the machine and the module: the bar is the one place
  // that knows both, whichever screen is open under it.
  const moduleName = findModule(segment)?.name;
  useDocumentTitle(hostTitle(host, moduleName ? t(moduleName) : segment));
  return (
    <div className="host-header">
      {campaign && (
        <p className="host-header-crumb source">
          <Link to={`/campaigns/${campaign}`}>← {t("Back to the campaign")}</Link>
        </p>
      )}
      {/* The name and the address stand in the top bar; repeating them
          here would only push the facts down. */}
      <div className="host-header-title">
        <ConnectionState state={host.connection_state} />
        <ConnectionRefusal host={host} />
        <MaintenanceWindow host={host} />
      </div>
      <div className="host-header-facts">
        <HostIdentifier host={host} />
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
        <HostActions host={host} />
      </div>
      <Tags host={host} />
    </div>
  );
}

/**
 * The tags of the host as chips, with an editor in place.
 */
function Tags({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canEdit = (whoami.data?.permissions ?? []).includes("host.tag.write");
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [message, setMessage] = useState("");

  const save = useMutation({
    mutationFn: (tags: string[]) => api.put<Host>(`/api/v1/hosts/${host.id}/tags`, { tags }),
    onSuccess: () => {
      setEditing(false);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const open = () => {
    setText(host.tags.join(" "));
    setMessage("");
    setEditing(true);
  };

  return (
    <div className="host-header-facts">
      {host.tags.map((tag) => (
        <Link key={tag} className="chip" to={`/hosts?tag=${encodeURIComponent(tag)}`} title={t("show every host tagged {tag}", { tag })}>
          {tag}
        </Link>
      ))}
      {host.tags.length === 0 && !editing && (
        <span className="chip unknown" title={t("nobody has tagged this host yet")}>{t("no tags")}</span>
      )}
      {canEdit && !editing && (
        <span className="chip inventory-refresh">
          <button type="button" className="link" onClick={open}>{t("edit tags")}</button>
        </span>
      )}
      {editing && (
        <span className="inventory-refresh">
          <input
            value={text}
            placeholder={t("tags separated by spaces, e.g. role=db tier=gold")}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") save.mutate(splitTags(text));
              if (e.key === "Escape") setEditing(false);
            }}
            autoFocus
            style={{ minWidth: 260 }}
          />
          <button type="button" className="link" disabled={save.isPending} onClick={() => save.mutate(splitTags(text))}>
            {save.isPending ? t("saving…") : t("Save")}
          </button>
          <button type="button" className="link" disabled={save.isPending} onClick={() => setEditing(false)}>
            {t("Cancel")}
          </button>
          {message && <span className="message">{message}</span>}
        </span>
      )}
    </div>
  );
}

/** The typed tags as a list: words, in the order the server will sort anyway. */
function splitTags(text: string): string[] {
  return text.split(/\s+/).map((tag) => tag.trim()).filter(Boolean);
}

/**
 * An inventory refresh on demand.
 */
function RefreshInventory({ host, segment }: { host: Host; segment: string }) {
  const t = useT();
  // The scope is taken from the tab registry: it knows which inventory
  // module the open view lives off.
  const scope = findModule(segment)?.inventory;
  const refresh = useInventoryRefresh(host, scope);

  const description = scope
    ? t("ask the host to re-read its {module} module now", { module: scope })
    : t("ask the host to re-read its whole inventory now");
  return (
    <span className="chip inventory-refresh">
      <button
        type="button"
        className="link"
        disabled={refresh.busy || host.connection_state !== "online"}
        title={host.connection_state === "online" ? description : t("the host is not connected")}
        onClick={refresh.order}
      >
        {refresh.busy ? t("refreshing…") : t("refresh")}
      </button>
      {refresh.message && <span className="message">{refresh.message}</span>}
    </span>
  );
}

/**
 * The order of an inventory refresh and its outcome.
 */
function useInventoryRefresh(host: Host, scope?: string) {
  const t = useT();
  const queryClient = useQueryClient();
  const [jobID, setJobID] = useState("");
  const [message, setMessage] = useState("");

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
    // it.
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

  return {
    busy: order.isPending || jobID !== "",
    message,
    order: () => order.mutate(),
  };
}

/**
 * The identifier of the host, short, with a copy of the whole.
 */
function HostIdentifier({ host }: { host: Host }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(host.id);
    setCopied(true);
  };
  return (
    <span className="chip inventory-refresh" title={host.id}>
      <span className="chip-tag">{t("id")}</span>
      <span className="chip-mono" data-testid="host-id">{host.id.slice(0, 8)}</span>
      <button type="button" className="link" onClick={copy} title={t("copy the full identifier")}>
        {copied ? t("copied") : t("copy")}
      </button>
    </span>
  );
}

/**
 * The actions an operator reaches for from any tab: a whole-host inventory
 * refresh, the logs, and a reboot - the last one a link to the power tab,
 * where the order is confirmed, not a button that reboots from a menu.
 */
function HostActions({ host }: { host: Host }) {
  const t = useT();
  const refresh = useInventoryRefresh(host);
  const online = host.connection_state === "online";
  return (
    <details className="chip inventory-refresh" style={{ position: "relative" }}>
      <summary style={{ cursor: "pointer", listStyle: "none" }}>{t("Actions")} ▾</summary>
      <div
        style={{
          position: "absolute", top: "100%", left: 0, zIndex: 5, minWidth: 220, marginTop: 4, padding: 8,
          display: "flex", flexDirection: "column", gap: 6, background: "var(--bg-panel)",
          border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", whiteSpace: "normal",
        }}
      >
        <button
          type="button"
          className="link"
          disabled={refresh.busy || !online}
          title={online ? t("ask the host to re-read its whole inventory now") : t("the host is not connected")}
          onClick={refresh.order}
        >
          {refresh.busy ? t("refreshing…") : t("Refresh the whole inventory")}
        </button>
        {refresh.message && <span className="message">{refresh.message}</span>}
        <Link to={`/hosts/${host.id}/logs`}>{t("Open the logs")}</Link>
        <Link to={`/hosts/${host.id}/power`}>{t("Reboot (power tab)")}</Link>
        <Link to={`/hosts/${host.id}/jobs`}>{t("Jobs of this host")}</Link>
      </div>
    </details>
  );
}

/** The terminal job states. Outside them it is worth asking further. */
function finished(state: string | undefined): boolean {
  return ["succeeded", "failed", "timed_out", "canceled", "expired"].includes(state ?? "");
}

/**
 * The refusal badge: the gateway turned the host away, and this is why.
 */
function ConnectionRefusal({ host }: { host: Host }) {
  const t = useT();
  const refusal = host.last_connection_refusal;
  if (!refusal || host.connection_state === "online") return null;
  return (
    <Link
      className="badge error"
      to={`/hosts/${host.id}/overview`}
      title={refusal.detail || t("the gateway refused the last connection of this host")}
      data-testid="connection-refusal-badge"
    >
      {t("connection refused: {reason} {when}", {
        reason: t(refusalName(refusal.code)),
        when: relativeTime(refusal.at),
      })}
    </Link>
  );
}

/**
 * The maintenance window badge.
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
 * The management address with its origin.
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
