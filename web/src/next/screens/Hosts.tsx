import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { relativeTime, absoluteTime } from "../../lib/format";
import type { FleetActivity, Host, Relay, Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Actions, Bars, Bones, Button, Card, Check, Dot, Field, Fields, Find, Grid, HeadActions, Meter, Modal,
  Note, Pill, Problem, Seg, Stack, Table, Tag, Tags, TwoLine, type Column, type Tone,
} from "../kit";

/**
 * The fleet as a list: what each host is, whether it answers, and what it
 * is carrying that somebody may have to deal with.
 *
 * The narrowing is the server's - the counts beside the filters are taken
 * over the whole fleet the reader may see, not over the page that happens
 * to be loaded, so a filter never lies about how much is behind it.
 *
 * What can be done from here is done to the rows that are ticked, and only
 * by whoever may: the checkboxes belong to the Bulk workspace and are not
 * drawn for a reader who cannot open it, the metadata editor belongs to
 * whoever may write tags or maintenance windows, and the link into
 * enrolment to whoever may order one. Every one of those changes carries a
 * reason into the trail, asked for in the dialog rather than in the list.
 */

type Page = { items: Host[]; next_cursor?: string; total?: number };
type Connection = "" | "online" | "stale" | "offline" | "unknown";

/** The shortest reason the bulk edit is accepted with. */
export const MIN_REASON = 8;

/** The permissions the writes of this screen stand behind. */
const TAG_PERMISSION = "host.tag.write";
const MAINTENANCE_PERMISSION = "host.maintenance.write";
const ENROLL_PERMISSION = "host.enroll.create";
const RELAY_PERMISSION = "host.enroll.read";
const CAMPAIGN_PERMISSION = "campaign.read";

/** The permissions of the signed-in operator, for the gates of this screen. */
function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

export function Hosts() {
  const t = useT();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const connection = (params.get("connection_state") ?? "") as Connection;
  const relay = params.get("relay") ?? "";
  // The tags the list is narrowed by. They come from the address because a
  // tag on a host's own screen links here: "every host with this role".
  const tags = params.getAll("tag");
  const tagKey = tags.join(" ");

  const permissions = usePermissions();
  const canAdd = permissions.has(ENROLL_PERMISSION);
  // The bulk workspace is where a selection goes; whoever cannot read
  // campaigns has no such workspace and sees no checkboxes.
  const canSelect = permissions.has(CAMPAIGN_PERMISSION);
  // The metadata editor is for whoever may write tags or maintenance
  // windows; the server judges each host on its own anyway.
  const canTag = permissions.has(TAG_PERMISSION);
  const canMaintain = permissions.has(MAINTENANCE_PERMISSION);
  const canSetMetadata = canTag || canMaintain;
  // The relays, for the filter by route: read only by whoever may list
  // them; for the rest the filter is still reachable through the address.
  const canSeeRelays = permissions.has(RELAY_PERMISSION);

  // The rows ticked for what is done to several hosts at once.
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [editing, setEditing] = useState(false);

  const query = useMemo(() => {
    const out = new URLSearchParams();
    if (connection) out.set("connection_state", connection);
    if (relay) out.set("relay", relay);
    // Every tag has to be on the host, so they travel one by one.
    for (const tag of tagKey.split(" ").filter(Boolean)) out.append("tag", tag);
    if (search.trim()) out.set("q", search.trim());
    out.set("limit", "50");
    return out;
  }, [connection, relay, tagKey, search]);

  const hosts = useInfiniteQuery({
    queryKey: ["hosts", query.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(query);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page>(`/api/v1/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    // A host's state changes through its heartbeat, not only through
    // somebody pressing something here.
    refetchInterval: REFRESH_INTERVAL,
  });

  // The facets are counted in the database over the whole visible fleet, so
  // they do not depend on which page is loaded.
  const activity = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    refetchInterval: REFRESH_INTERVAL,
  });

  const relays = useQuery({
    queryKey: ["relays"],
    queryFn: () => api.get<{ items: Relay[] }>("/api/v1/relays"),
    enabled: canSeeRelays,
    staleTime: 60 * 1000,
  });

  if (hosts.error) return <Problem>{String(hosts.error)}</Problem>;

  const rows = (hosts.data?.pages ?? []).flatMap((page) => page.items);
  const a = activity.data;
  const count = (state: string) => a?.by_connection_state.find((one) => one.key === state)?.count ?? 0;
  const facet = (key: string) => (key === "" || key === "unknown" ? t("unknown") : key);
  const setConnection = (value: Connection) => {
    const next = new URLSearchParams(params);
    if (value) next.set("connection_state", value); else next.delete("connection_state");
    setParams(next, { replace: true });
  };
  const setRelay = (value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set("relay", value); else next.delete("relay");
    setParams(next, { replace: true });
  };
  const dropTags = () => {
    const next = new URLSearchParams(params);
    next.delete("tag");
    setParams(next, { replace: true });
  };
  /** The address of this list narrowed to one tag. */
  const tagAddress = (tag: string) => `/next/hosts?${new URLSearchParams([["tag", tag]])}`;

  const tick = (id: string, on: boolean) => setSelected((current) => {
    const next = new Set(current);
    if (on) next.add(id); else next.delete(id);
    return next;
  });
  // The header box ticks what is loaded, not what matches: a page not yet
  // fetched has hosts nobody has seen, and a campaign must not reach them
  // from a box that looked like "all".
  const allLoadedTicked = rows.length > 0 && rows.every((one) => selected.has(one.id));
  // The editor works on the loaded rows that are ticked: a host ticked and
  // then filtered out of view is not edited unseen.
  const chosen = rows.filter((one) => selected.has(one.id));
  const openInBulk = () => {
    const address = new URLSearchParams();
    for (const id of selected) address.append("host_id", id);
    navigate(`/next/bulk?${address}`);
  };

  /* The checkbox column exists only for a reader who has somewhere to take
     a selection; for everybody else the list is a list. */
  const pick: Column<Host>[] = canSelect ? [{
    key: "pick",
    head: (
      <input
        type="checkbox"
        aria-label={t("select every loaded host")}
        checked={allLoadedTicked}
        onChange={(event) => setSelected(event.target.checked ? new Set(rows.map((one) => one.id)) : new Set())}
      />
    ),
    cell: (one) => (
      <input
        type="checkbox"
        aria-label={t("select {host}", { host: one.hostname })}
        checked={selected.has(one.id)}
        onChange={(event) => tick(one.id, event.target.checked)}
      />
    ),
  }] : [];

  return (
    <>
      {/* The link is seen by whoever can order an installation; for the
          rest it would lead only to a refusal. */}
      {canAdd && (
        <HeadActions><Link to="/next/hosts/new" className="fl-btn">{t("Add host")}</Link></HeadActions>
      )}

      <Grid>
        <Card span={9} flush
          title={t("The fleet")}
          tools={
            <>
              <Find value={search} onChange={setSearch} placeholder={t("Search hosts…")} testId="search" />
              <Seg
                value={connection}
                onChange={setConnection}
                options={[
                  { value: "", label: t("All") },
                  { value: "online", label: `${t("Online")} ${count("online")}` },
                  { value: "stale", label: `${t("Stale")} ${count("stale")}` },
                  { value: "offline", label: `${t("Offline")} ${count("offline")}` },
                ]}
              />
              {/* The route the hosts connect through: a relay by name for
                  whoever may list them. For the rest the filter is still
                  reachable through the address. */}
              {canSeeRelays && (
                <select
                  value={relay}
                  aria-label={t("Relay")}
                  data-testid="filter-relay"
                  onChange={(event) => setRelay(event.target.value)}
                >
                  <option value="">{t("relay: any")}</option>
                  {(relays.data?.items ?? []).map((one) => (
                    <option key={one.id} value={one.id}>{one.name}</option>
                  ))}
                  {relay && !(relays.data?.items ?? []).some((one) => one.id === relay) && (
                    <option value={relay}>{relay}</option>
                  )}
                </select>
              )}
              {tags.length > 0 && (
                <Button kind="quiet" testId="clear-tags" onClick={dropTags}>
                  {t("Tagged {tags} · clear", { tags: tags.join(" ") })}
                </Button>
              )}
            </>
          }
          foot={
            <>
              {/* What is offered for the rows that are ticked. It stands
                  under the list it acts on, and says how many it would
                  reach before it reaches them. */}
              {selected.size > 0 && (
                <Actions>
                  <Note>{t("{n} selected", { n: selected.size })}</Note>
                  <Button testId="open-bulk" onClick={openInBulk}>
                    {t("Open in Bulk workspace ({n})", { n: selected.size })}
                  </Button>
                  {canSetMetadata && (
                    <Button kind="quiet" testId="set-metadata" onClick={() => setEditing(true)}>
                      {t("Set metadata…")}
                    </Button>
                  )}
                  <Button kind="quiet" testId="clear-selection" onClick={() => { setSelected(new Set()); setEditing(false); }}>
                    {t("Clear selection")}
                  </Button>
                </Actions>
              )}
              {hosts.hasNextPage ? (
                <button type="button" className="fl-quiet fl-small"
                        onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
                  {hosts.isFetchingNextPage ? t("loading…") : t("Load more")}
                </button>
              ) : t("{n} hosts", { n: rows.length })}
            </>
          }
        >
          <Table
            rows={rows}
            keyOf={(one) => one.id}
            rowTestId={(one) => `host-${one.hostname}`}
            testId="hosts"
            loading={hosts.isLoading} empty={t("No host matches this.")}
            columns={[
              ...pick,
              {
                key: "host",
                head: t("Host"),
                cell: (one) => (
                  <TwoLine sub={one.management_address || t("address unknown")}>
                    <Link to={`/next/hosts/${one.id}`}>{one.hostname}</Link>
                    {/* A tag leads to every host that carries it, which is
                        what a tag is for. */}
                    {one.tags.length > 0 && (
                      <Tags>
                        {one.tags.map((tag) => (
                          <Tag key={tag} to={tagAddress(tag)} title={t("show every host tagged {tag}", { tag })}>
                            {tag}
                          </Tag>
                        ))}
                      </Tags>
                    )}
                  </TwoLine>
                ),
              },
              {
                key: "state",
                head: t("State"),
                cell: (one) => (
                  <Pill tone={stateTone(one.connection_state)} title={one.last_seen_at ? absoluteTime(one.last_seen_at) : undefined}>
                    {t(one.connection_state)}
                  </Pill>
                ),
              },
              {
                key: "seen",
                head: t("Last seen"),
                minor: true,
                cell: (one) => one.last_seen_at
                  ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                  : <span className="fl-faint">{t("never")}</span>,
              },
              {
                key: "system",
                head: t("System"),
                minor: true,
                cell: (one) => (
                  <TwoLine sub={one.agent_version ? `agent ${one.agent_version}` : undefined}>
                    {one.os_distribution || one.os_family || <span className="fl-faint">{t("unknown")}</span>}
                    {one.os_version ? ` ${one.os_version}` : ""}
                  </TwoLine>
                ),
              },
              {
                key: "place",
                head: t("Site / environment"),
                minor: true,
                cell: (one) => (
                  <Tags>
                    <Tag>{one.site}</Tag>
                    <Tag>{one.environment}</Tag>
                  </Tags>
                ),
              },
              {
                key: "updates",
                head: t("Updates"),
                num: true,
                cell: (one) => one.pending_updates === null
                  ? <span className="fl-faint">—</span>
                  : (
                    <Meter
                      share={Math.min(1, (one.pending_updates ?? 0) / 200)}
                      tone={(one.pending_security_updates ?? 0) > 0 ? "warn" : "accent"}
                      text={one.pending_updates}
                    />
                  ),
              },
              {
                key: "trouble",
                head: t("Needs a look"),
                cell: (one) => <Trouble host={one} />,
              },
            ]}
          />
        </Card>

        <Card span={3} title={t("Fleet composition")} note={t("Counted over the whole fleet you can see.")}>
          {a ? (
            <Stack>
              <Dimension label={t("Connection")} items={[
                { label: t("Online"), value: count("online"), tone: "ok" },
                { label: t("Stale"), value: count("stale"), tone: "warn" },
                { label: t("Offline"), value: count("offline"), tone: "error" },
                { label: t("Unknown"), value: count("unknown"), tone: "unknown" },
              ]} />
              <Dimension label={t("Systems")} items={a.by_os_family.map((f) => ({ label: facet(f.key), value: f.count, tone: "accent" as Tone }))} />
              <Dimension label={t("Agent builds")} items={a.by_agent_version.map((f) => ({ label: facet(f.key), value: f.count, tone: "neutral" as Tone }))} />
              <Dimension label={t("Sites")} items={a.by_site.map((f) => ({ label: facet(f.key), value: f.count, tone: "info" as Tone }))} />
            </Stack>
          ) : <Bones rows={4} />}
        </Card>

        {editing && chosen.length > 0 && (
          <Metadata
            hosts={chosen}
            canTag={canTag}
            canMaintain={canMaintain}
            onClose={() => setEditing(false)}
          />
        )}
      </Grid>
    </>
  );
}

/* ------------------------------------------- what is set on many at once */

/** The answer for one host: applied, or the code its own route refused with. */
type Outcome = { host_id: string; ok: boolean; code: string; detail?: string };
type BulkAnswer = { results: Outcome[]; applied: number; failed: number };

/** The draft; every field is optional and an untouched one changes nothing. */
type Draft = {
  tagsAdd: string;
  tagsRemove: string;
  owner: string;
  setOwner: boolean;
  failureDomain: string;
  setFailureDomain: boolean;
  site: string;
  environment: string;
  maintenance: "keep" | "open" | "close";
  until: string;
  windowReason: string;
};

const EMPTY: Draft = {
  tagsAdd: "", tagsRemove: "", owner: "", setOwner: false, failureDomain: "", setFailureDomain: false,
  site: "", environment: "", maintenance: "keep", until: "", windowReason: "",
};

/** The tags typed in one box: separated by commas or whitespace. */
export function splitTags(text: string): string[] {
  return text.split(/[\s,]+/).map((tag) => tag.trim()).filter(Boolean);
}

/** A local date-time from the input as an RFC 3339 instant. */
function instantOf(local: string): string {
  return new Date(local).toISOString();
}

/** What the draft would set, in the shape the server reads. */
export function metadataSet(draft: Draft): Record<string, unknown> {
  const set: Record<string, unknown> = {};
  const add = splitTags(draft.tagsAdd);
  const remove = splitTags(draft.tagsRemove);
  if (add.length > 0) set.tags_add = add;
  if (remove.length > 0) set.tags_remove = remove;
  if (draft.setOwner) set.owner = draft.owner.trim();
  if (draft.setFailureDomain) set.failure_domain = draft.failureDomain.trim();
  if (draft.site.trim() !== "") set.site = draft.site.trim();
  if (draft.environment.trim() !== "") set.environment = draft.environment.trim();
  // A window closed is a window set to nothing, which is not the same as a
  // window left alone: the first travels as null, the second not at all.
  if (draft.maintenance === "close") set.maintenance = null;
  // A window with no end is not a window yet: the form asks for one, and
  // nothing is composed from an empty date - new Date("") has no instant.
  if (draft.maintenance === "open" && draft.until !== "") {
    set.maintenance = { until: instantOf(draft.until), reason: draft.windowReason.trim() };
  }
  return set;
}

/**
 * What the panel records about the chosen hosts by hand: their tags, who
 * answers for them, where they stand and whether somebody is working on
 * them. A field left empty changes nothing; every host is judged in its
 * own scope and answered on its own.
 */
function Metadata({ hosts, canTag, canMaintain, onClose }: {
  hosts: Host[];
  canTag: boolean;
  canMaintain: boolean;
  onClose: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  const [answer, setAnswer] = useState<BulkAnswer | null>(null);
  const change = (delta: Partial<Draft>) => setDraft((previous) => ({ ...previous, ...delta }));
  const byID = new Map(hosts.map((one) => [one.id, one]));

  const submit = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<BulkAnswer>("/api/v1/hosts/bulk-metadata", body),
    onSuccess: (result) => {
      setAnswer(result);
      setMessage("");
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      void queryClient.invalidateQueries({ queryKey: ["fleet-activity"] });
      for (const one of hosts) void queryClient.invalidateQueries({ queryKey: ["host", one.id] });
    },
    onError: (error) => {
      setConfirming(false);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const set = metadataSet(draft);
  const windowReady = draft.maintenance !== "open" || (draft.until !== "" && draft.windowReason.trim() !== "");
  const touches = Object.keys(set).length > 0;
  const ready = touches && windowReady;
  const moves = draft.site.trim() !== "" || draft.environment.trim() !== "";

  return (
    <Card
      span={12}
      title={t("Set metadata on {n} hosts", { n: hosts.length })}
      note={t("What the panel records about these hosts by hand. A field left empty changes nothing; every host is judged in its own scope and answered on its own.")}
      tools={<Button kind="quiet" testId="metadata-close" onClick={onClose}>{t("Close")}</Button>}
    >
      <Fields>
        {canTag && (
          <>
            <Field label={t("Add tags")} hint={t("key or key=value, separated by commas; added to what each host already carries.")}>
              <input
                value={draft.tagsAdd}
                placeholder="patched=2026-09, role=web"
                onChange={(event) => change({ tagsAdd: event.target.value })}
                data-testid="bulk-tags-add"
              />
            </Field>
            <Field label={t("Remove tags")} hint={t("Taken off the hosts that carry them; the others are left as they are.")}>
              <input
                value={draft.tagsRemove}
                placeholder="legacy"
                onChange={(event) => change({ tagsRemove: event.target.value })}
                data-testid="bulk-tags-remove"
              />
            </Field>
            <Field label={t("Owner")} hint={t("Tick to set; empty hands the hosts back to nobody.")}>
              <Check checked={draft.setOwner} onChange={(on) => change({ setOwner: on })}>{t("set the owner")}</Check>
              <input
                value={draft.owner}
                placeholder={t("platform team")}
                onChange={(event) => change({ owner: event.target.value, setOwner: true })}
                data-testid="bulk-owner"
              />
            </Field>
            <Field label={t("Failure domain")} hint={t("Tick to set; empty takes the hosts out from under the domain budgets.")}>
              <Check checked={draft.setFailureDomain} onChange={(on) => change({ setFailureDomain: on })}>
                {t("set the failure domain")}
              </Check>
              <input
                value={draft.failureDomain}
                placeholder={t("rack-12, zone-b")}
                onChange={(event) => change({ failureDomain: event.target.value, setFailureDomain: true })}
                data-testid="bulk-failure-domain"
              />
            </Field>
            <Field label={t("Site")} hint={t("Moves the hosts; empty keeps each host where it stands.")}>
              <input
                value={draft.site}
                onChange={(event) => change({ site: event.target.value })}
                data-testid="bulk-site"
              />
            </Field>
            <Field label={t("Environment")} hint={t("Moves the hosts; empty keeps each host's environment.")}>
              <input
                value={draft.environment}
                onChange={(event) => change({ environment: event.target.value })}
                data-testid="bulk-environment"
              />
            </Field>
          </>
        )}
        {/* A window says somebody is working on these machines: campaigns
            skip them and their alerts stay quiet. It always has an end. */}
        {canMaintain && (
          <>
            <Field label={t("Maintenance window")}>
              <select
                value={draft.maintenance}
                onChange={(event) => change({ maintenance: event.target.value as Draft["maintenance"] })}
                data-testid="bulk-maintenance"
              >
                <option value="keep">{t("leave as it is")}</option>
                <option value="open">{t("open until…")}</option>
                <option value="close">{t("close")}</option>
              </select>
            </Field>
            {draft.maintenance === "open" && (
              <>
                <Field label={t("Until")} hint={t("At most 30 days ahead.")}>
                  <input
                    type="datetime-local"
                    value={draft.until}
                    onChange={(event) => change({ until: event.target.value })}
                    data-testid="bulk-until"
                  />
                </Field>
                <Field label={t("Window reason")} hint={t("What the next person on call will read.")}>
                  <input
                    value={draft.windowReason}
                    onChange={(event) => change({ windowReason: event.target.value })}
                    data-testid="bulk-window-reason"
                  />
                </Field>
              </>
            )}
          </>
        )}
      </Fields>
      {moves && (
        <Note>
          {t("A move changes who may manage the host, which budgets its changes load and which groups it stands in, from the next order on; nothing already planned is re-evaluated.")}
        </Note>
      )}
      <Actions>
        <Button
          testId="bulk-apply"
          disabled={!ready || submit.isPending}
          title={ready ? undefined : t("Nothing is set yet, so there is nothing to apply.")}
          onClick={() => { setMessage(""); setConfirming(true); }}
        >
          {t("Apply to {n} hosts…", { n: hosts.length })}
        </Button>
      </Actions>
      {message && <Note>{message}</Note>}

      {answer && (
        <>
          <Note>
            <span data-testid="bulk-summary">
              {t("{applied} applied, {failed} refused.", { applied: answer.applied, failed: answer.failed })}
            </span>
          </Note>
          <Table
            rows={answer.results}
            keyOf={(one) => one.host_id}
            testId="bulk-outcomes"
            rowTestId={(one) => `bulk-outcome-${one.host_id}`}
            columns={[
              { key: "host", head: t("Host"), cell: (one) => {
                const host = byID.get(one.host_id);
                return host ? <Link to={`/next/hosts/${host.id}`}>{host.hostname}</Link> : one.host_id;
              } },
              { key: "outcome", head: t("Outcome"), cell: (one) => (
                <Pill tone={one.ok ? "ok" : "error"}>{one.ok ? t("applied") : one.code}</Pill>
              ) },
              { key: "detail", head: t("Detail"), minor: true, cell: (one) => one.detail || "—" },
            ]}
          />
        </>
      )}

      {confirming && (
        <Modal
          title={t("Set metadata on {n} hosts", { n: hosts.length })}
          onClose={() => setConfirming(false)}
          actions={
            <>
              <Button kind="quiet" testId="bulk-cancel" onClick={() => setConfirming(false)} disabled={submit.isPending}>
                {t("Cancel")}
              </Button>
              <Button
                testId="bulk-confirm"
                disabled={reason.trim().length < MIN_REASON || submit.isPending}
                onClick={() => submit.mutate({
                  host_ids: hosts.map((one) => one.id),
                  reason: reason.trim(),
                  set,
                })}
              >
                {submit.isPending ? t("Requesting…") : t("Apply to {n} hosts", { n: hosts.length })}
              </Button>
            </>
          }
        >
          <Note>
            {t("{n} hosts are changed, each in its own scope: a host whose change is refused is answered on its own and the others are still applied.", { n: hosts.length })}
          </Note>
          <Tags>
            {hosts.map((one) => <Tag key={one.id}>{one.hostname}</Tag>)}
          </Tags>
          <Fields>
            <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
              <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="bulk-reason" />
            </Field>
          </Fields>
        </Modal>
      )}
    </Card>
  );
}

/** What this host is carrying that somebody may have to deal with. */
function Trouble({ host }: { host: Host }) {
  const t = useT();
  const marks: { label: string; tone: Tone }[] = [];
  if (host.package_database_broken) marks.push({ label: t("package database"), tone: "error" });
  if ((host.failed_units ?? 0) > 0) marks.push({ label: t("{n} failed units", { n: host.failed_units ?? 0 }), tone: "error" });
  if (host.reboot_required) marks.push({ label: t("reboot"), tone: "warn" });
  if ((host.pending_security_updates ?? 0) > 0) {
    marks.push({ label: t("{n} security", { n: host.pending_security_updates ?? 0 }), tone: "warn" });
  }
  if (host.maintenance) marks.push({ label: t("maintenance"), tone: "info" });
  if (marks.length === 0) return <span className="fl-faint">—</span>;
  return (
    <Tags>
      {marks.map((mark) => <Pill key={mark.label} tone={mark.tone}>{mark.label}</Pill>)}
    </Tags>
  );
}

/** One dimension of the fleet: a heading, then the bars under it. */
function Dimension({ label, items }: { label: string; items: { label: string; value: number; tone: Tone }[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="fl-subhead">{label}</h3>
      <Bars items={items} />
    </div>
  );
}

function stateTone(state: Host["connection_state"]): Tone {
  return state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
}

/** The dot the list uses where there is no room for the word. */
export { Dot };
