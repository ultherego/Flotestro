import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { refusalName, type Host, type Job, type Whoami } from "../../lib/types";
import { relativeTime } from "../../lib/format";
import { Time, ConnectionState } from "../../components/ui";
import { module as findModule } from "./modules";
import { useT } from "../../i18n";

/**
 * The persistent host header. An operator switching modules must know
 * without checking anything which machine they work on - the top bar
 * names it, and this card under the bar carries its state and facts, so
 * the identity is part of the layout, not text repeated by the individual
 * screens. The first line is the state, the second the facts as chips: a
 * fact read at a glance is a fact that gets read.
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
      {/* The name and the address stand in the top bar; repeating them
          here would only push the facts down. */}
      <div className="host-header-title">
        <ConnectionState state={host.connection_state} />
        <ConnectionRefusal host={host} />
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
      <Tags host={host} />
    </div>
  );
}

/**
 * The tags of the host as chips, with an editor in place.
 *
 * Tags are what the operator recorded about the machine - its role, its
 * tier, its team - and a campaign selector reads them, so they stand in the
 * bar next to the facts the host reports. Editing replaces the whole list:
 * the field shows what is there and the save sends what is typed, so two
 * operators editing at once see the second write in full rather than a
 * merge nobody asked for. The editor is gated like every other host write:
 * whoever cannot change the tags sees them and no button.
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
 * The refusal badge: the gateway turned the host away, and this is why.
 *
 * It stands next to the connection state because it changes what that
 * state means - an offline host with a refusal is alive and knocking, not
 * away - and it leads to the lifecycle card of the overview, where the
 * identity recovery that answers it is ordered.
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
