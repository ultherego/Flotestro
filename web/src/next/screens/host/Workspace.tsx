import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useCapabilities } from "../../../lib/capabilities";
import { DEFAULT_MODULE, groupedModules, module as moduleOf, modules } from "../../../lib/modules";
import { OPERATIONS_INTERVAL, REFRESH_INTERVAL } from "../../../lib/stream";
import { relativeTime, absoluteTime } from "../../../lib/format";
import { refusalName, type Host, type Job, type Whoami } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Shell, type Face } from "../../Shell";
import {
  Bones, Button, Copy, Empty, Head, HeadSlot, Menu, MenuItem, Pill, Problem, Tag, Tags, type Tone,
} from "../../kit";
import { module as findModule } from "../../../lib/modules";
import { addressSourceMeaning } from "./Overview";
import { HOST_MODULES } from "./modules";

/**
 * One machine, and everything the panel can say or do about it.
 *
 * The rail stops being the fleet here and becomes this host's modules,
 * grouped the way the registry groups them, with the way back at the top.
 * A module this host has no backing for stays listed and says why: left
 * out, it reads as a panel that forgot it exists.
 */

/** The module named in the address, drawn with the host it is about. */
function Module({ module, host }: { module: string; host: Host }) {
  const Drawn = HOST_MODULES[module];
  return Drawn ? <Drawn host={host} /> : null;
}

export function HostWorkspace() {
  const t = useT();
  const { id = "", module = DEFAULT_MODULE } = useParams();
  const installation = useCapabilities();
  // A host opened from a campaign keeps the way back in the address: the
  // operator came from a piece of work, and the rail cannot know that.
  const [address] = useSearchParams();
  const campaign = address.get("campaign");

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    // The head carries the connection state, so it refreshes itself: a
    // stale answer to "is this machine there" is worse than none.
    refetchInterval: REFRESH_INTERVAL,
  });

  const data = host.data;
  const entry = moduleOf(module);
  const face: Face = {
    back: { to: "/hosts", label: "All hosts" },
    groups: data
      ? groupedModules(modules(data, installation)).map((group) => ({
          key: group.key,
          label: group.title,
          items: group.items.map((one) => ({
            to: `/hosts/${id}/${one.segment}`,
            label: one.name,
            icon: one.icon,
            unavailable: one.available ? undefined : one.missingReason,
          })),
        }))
      : [],
  };

  return (
    <Shell
      trail={{
        section: "Hosts",
        to: "/hosts",
        host: data,
        module: data ? findModule(module)?.name : undefined,
      }}
      face={face}
    >
      {host.error ? <Problem>{String(host.error)}</Problem> : !data ? <Bones rows={4} /> : (
        <>
          <HostHead host={data} segment={module} campaign={campaign} />
          {HOST_MODULES[module] ? <Module module={module} host={data} /> : (
            <>
              <Head
                title={t(entry?.name ?? module)}
                lead={t("This module is still being rewritten.")}
              />
              {/* Until 16.10 this offered the panel being replaced, because
                  a module not yet rewritten was still there. There is no
                  second panel now: an unknown module is an unknown module. */}
              <Empty icon="search">
                {t("This host reports no module of that name.")}
              </Empty>
            </>
          )}
        </>
      )}
    </Shell>
  );
}

/**
 * Which machine this is, in one band: its name, whether it answers, where
 * it stands and what it runs. Everything a reader needs to be sure they
 * are looking at the host they meant.
 *
 * It stands above all twenty-seven modules, so it carries what an
 * operator reaches for whichever module is open - the inventory read
 * again, the logs, the jobs, the way to the power module - and what they
 * have to know before reading anything under it: that the gateway is
 * turning this host away, or that somebody has declared a window on it.
 * What is rarely wanted is behind one word rather than beside the name:
 * a head of six buttons is a head nobody reads.
 */
function HostHead({ host, segment, campaign }: {
  host: Host;
  segment: string;
  /** The campaign the operator came from; it keeps the way back in view. */
  campaign?: string | null;
}) {
  const t = useT();
  const tone: Tone = host.connection_state === "online" ? "ok"
    : host.connection_state === "offline" ? "error"
    : host.connection_state === "stale" ? "warn" : "unknown";
  // The scope is taken from the module registry: it knows which inventory
  // module the open view lives off.
  const scope = findModule(segment)?.inventory;
  const refresh = useInventoryRefresh(host);
  const online = host.connection_state === "online";
  const refusal = host.last_connection_refusal;
  const maintenance = maintenanceUntil(host);
  return (
    <Head
      crumb={campaign
        ? <Link to={`/campaigns/${encodeURIComponent(campaign)}`}>{t("Back to the campaign")}</Link>
        : undefined}
      title={host.hostname}
      lead={
        <Tags>
          <Pill tone={tone} title={host.last_seen_at ? absoluteTime(host.last_seen_at) : undefined}>
            {t(host.connection_state)}
          </Pill>
          {/* The gateway turned this host away, and this is why. A machine
              that is merely not connected is one thing; one that knocked
              and was refused is another, and the difference is the whole
              of what an operator does next. */}
          {refusal && !online && (
            <Pill
              tone="error"
              title={refusal.detail || t("the gateway refused the last connection of this host")}
            >
              {t("connection refused: {reason} {when}", {
                reason: t(refusalName(refusal.code)),
                when: relativeTime(refusal.at),
              })}
            </Pill>
          )}
          {maintenance && (
            <Pill tone="warn" title={maintenanceReason(t, host) || t("maintenance window")}>
              {t("maintenance until {time} UTC", { time: maintenance.toISOString().slice(0, 16).replace("T", " ") })}
            </Pill>
          )}
          <HostIdentifier host={host} />
          <ManagementAddress host={host} />
          <Tag title={t("site / environment")}>{host.site} / {host.environment}</Tag>
          <Tag title={t("operating system")}>
            {host.os_distribution || host.os_family || t("unknown")}
            {host.os_version ? ` ${host.os_version}` : ""}
          </Tag>
          <Tag title={t("architecture and agent version")}>
            {host.architecture || t("unknown arch")} · {t("agent {version}", { version: host.agent_version || t("unknown") })}
          </Tag>
          {host.last_seen_at && (
            <Tag title={t("last seen")}>{t("seen")} {relativeTime(host.last_seen_at)}</Tag>
          )}
          <HostTags host={host} />
          {refresh.message && (
            <Pill tone={refresh.tone} title={refresh.message}>{refresh.message}</Pill>
          )}
        </Tags>
      }
      actions={
        <>
          {/* The slot the screens under this one put their own actions
              in, so "Arrange this screen" stands beside the machine's
              name like every other screen's does. */}
          <HeadSlot />
          {/* The module that is open is read again from here, because the
              reader is looking at it: what the whole inventory costs is
              not worth paying to see one list again. */}
          {scope && (
            <Button
              kind="quiet"
              testId="refresh-module"
              disabled={refresh.busy || !online}
              title={online
                ? t("ask the host to re-read its {module} module now", { module: scope })
                : t("the host is not connected")}
              onClick={() => refresh.order(scope)}
            >
              {refresh.busy ? t("Refreshing…") : t("Refresh {module}", { module: scope })}
            </Button>
          )}
          <Menu label={t("Actions")} testId="host-actions">
            <MenuItem
              testId="refresh-inventory"
              disabled={refresh.busy || !online}
              title={online
                ? t("ask the host to re-read its whole inventory now")
                : t("the host is not connected")}
              onClick={() => refresh.order()}
            >
              {t("Refresh the whole inventory")}
            </MenuItem>
            <MenuItem to={`/hosts/${host.id}/logs`} icon="logs">{t("Open the logs")}</MenuItem>
            <MenuItem to={`/hosts/${host.id}/jobs`} icon="jobs">{t("Jobs of this host")}</MenuItem>
            {/* A way to the power module and not a button that reboots
                from a menu: the order is confirmed where it is placed. */}
            <MenuItem to={`/hosts/${host.id}/power`} icon="power">{t("Reboot (power module)")}</MenuItem>
          </Menu>
        </>
      }
    />
  );
}

/** The end of the maintenance window, while it has not passed. */
function maintenanceUntil(host: Host): Date | undefined {
  if (!host.maintenance) return undefined;
  const until = new Date(host.maintenance.until);
  if (Number.isNaN(until.getTime()) || until.getTime() <= Date.now()) return undefined;
  return until;
}

/** Why the window was declared and by whom, as one line for the pointer. */
function maintenanceReason(t: Translate, host: Host): string {
  return [
    host.maintenance?.reason,
    host.maintenance?.set_by && t("set by {who}", { who: host.maintenance.set_by }),
  ].filter(Boolean).join(" · ");
}

/**
 * The identifier of the host, short, with a copy of the whole.
 *
 * Eight characters are what a person reads; the whole of it is what a
 * ticket, a log search or a support request needs.
 */
function HostIdentifier({ host }: { host: Host }) {
  const t = useT();
  return (
    <>
      <Tag title={host.id}>
        {t("id")} <span className="fl-mono" data-testid="host-id">{host.id.slice(0, 8)}</span>
      </Tag>
      <Copy value={host.id} title={t("copy the full identifier")} testId="copy-host-id" />
    </>
  );
}

/**
 * The management address, and where it came from.
 *
 * An address the host reported about itself and one the control plane
 * saw at its own end of the connection are not the same fact, and the
 * difference is what tells an operator whether the machine is behind a
 * relay or whether somebody typed the address in by hand.
 */
function ManagementAddress({ host }: { host: Host }) {
  const t = useT();
  if (!host.management_address) {
    return (
      <Tag title={t("no address has been observed for this host yet")}>{t("address unknown")}</Tag>
    );
  }
  return (
    <Tag title={t(addressSourceMeaning(host.management_address_source))}>
      <span className="fl-mono">{host.management_address}</span>
      {" "}
      <span className="fl-faint" data-testid="address-source">
        {host.management_address_source ?? t("unknown")}
      </span>
    </Tag>
  );
}

/**
 * The tags of the host, and the way to change them in place.
 *
 * Tags are what the fleet is selected by - a campaign, a policy and a
 * filter all read them - so correcting one is the most ordinary thing
 * done to a host, and it does not deserve a screen of its own. Whoever
 * may not write them sees them as links and nothing else.
 */
function HostTags({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const canEdit = usePermissions().has("host.tag.write");
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [message, setMessage] = useState("");

  const save = useMutation({
    mutationFn: (tags: string[]) => api.put<Host>(`/api/v1/hosts/${host.id}/tags`, { tags }),
    onSuccess: () => {
      setEditing(false);
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (editing) {
    return (
      <>
        <input
          value={text}
          aria-label={t("Tags")}
          placeholder={t("tags separated by spaces, e.g. role=db tier=gold")}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") save.mutate(splitTags(text));
            if (event.key === "Escape") setEditing(false);
          }}
          autoFocus
          data-testid="tags-input"
        />
        <Button kind="quiet" testId="tags-save" disabled={save.isPending} onClick={() => save.mutate(splitTags(text))}>
          {save.isPending ? t("Saving…") : t("Save")}
        </Button>
        <Button kind="word" testId="tags-cancel" disabled={save.isPending} onClick={() => setEditing(false)}>
          {t("Cancel")}
        </Button>
        {message && <Pill tone="error">{message}</Pill>}
      </>
    );
  }
  return (
    <>
      {host.tags.length > 0
        ? host.tags.map((tag) => (
            <Tag
              key={tag}
              to={`/hosts?tag=${encodeURIComponent(tag)}`}
              title={t("show every host tagged {tag}", { tag })}
            >
              {tag}
            </Tag>
          ))
        : <Tag title={t("nobody has tagged this host yet")}>{t("no tags")}</Tag>}
      {canEdit && (
        <Button
          kind="word"
          testId="edit-tags"
          onClick={() => { setText(host.tags.join(" ")); setMessage(""); setEditing(true); }}
        >
          {t("Edit tags")}
        </Button>
      )}
    </>
  );
}

/** The typed tags as a list: words, in the order the server will sort anyway. */
export function splitTags(text: string): string[] {
  return text.split(/\s+/).map((tag) => tag.trim()).filter(Boolean);
}

/** The permissions of the signed-in operator, for the gates of this head. */
function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/** The job states nothing further is going to happen in. */
const TERMINAL = ["succeeded", "failed", "timed_out", "canceled", "cancelled", "expired", "rejected"];

/**
 * An inventory read again on demand, and how it came out.
 *
 * The order is placed like any other operation and then followed to its
 * end: an inventory refresh that only says "ordered" leaves the reader
 * watching a page that has not changed, wondering whether it worked. On
 * success every question this panel has asked about this host is asked
 * again, because the picture on the screen is now the old one.
 */
function useInventoryRefresh(host: Host) {
  const t = useT();
  const queryClient = useQueryClient();
  const [jobID, setJobID] = useState("");
  const [message, setMessage] = useState("");
  const [tone, setTone] = useState<Tone>("info");

  const state = useQuery({
    queryKey: ["job", jobID],
    queryFn: () => api.get<Job>(`/api/v1/jobs/${jobID}`),
    enabled: jobID !== "",
    refetchInterval: (query) =>
      TERMINAL.includes((query.state.data as Job | undefined)?.state ?? "") ? false : OPERATIONS_INTERVAL,
  });

  useEffect(() => {
    const result = state.data;
    if (!result || !TERMINAL.includes(result.state)) return;
    setJobID("");
    if (result.state !== "succeeded") {
      setTone("error");
      setMessage(result.result_error_code || result.result_message || result.state);
      return;
    }
    setTone("ok");
    setMessage(result.result_message || t("inventory refreshed"));
    // The new picture is in the panel, so every view of this host is to
    // show it rather than what was read before.
    void queryClient.invalidateQueries({
      predicate: (query) => query.queryKey.includes(host.id),
    });
  }, [state.data, host.id, queryClient, t]);

  const order = useMutation({
    mutationFn: (scope: string) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "inventory.refresh",
        payload: { inventory: scope ? { modules: [scope] } : {} },
      }),
    onSuccess: (created) => {
      setMessage("");
      setJobID(created.id);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setTone("error");
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return {
    busy: order.isPending || jobID !== "",
    message,
    tone,
    /** Without a scope the whole inventory is read again. */
    order: (scope?: string) => order.mutate(scope ?? ""),
  };
}
