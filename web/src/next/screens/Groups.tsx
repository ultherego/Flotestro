import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, LIST_PAGE, loadedItems, type Collection, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, relativeTime } from "../../lib/format";
import { REFRESH_INTERVAL } from "../../lib/stream";
import type { Host, HostGroup, SelectorExpression, Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { useToast } from "../../components/Toast";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Find,
  Grid, Kpi, Kpis, Modal, Note, Pill, Problem, Readout, Screen, Seg, Stack, Table, Tag, Toolbar,
  TwoLine, type Segment, type Tone,
} from "../kit";

/**
 * The groups: a saved answer to "which hosts".
 *
 * Two kinds of answer live in one list and the list says which is which,
 * because they age differently - a member list is what somebody wrote
 * down, a selector is a question asked again every time it is read. A
 * selector that has stopped resolving names nobody only because nobody
 * could ask it, so its size is never a nought.
 */

/** One campaign or policy whose selector names a group, as the API lists it. */
type GroupReference = { id: string; name: string; state: string };

/** Where a group is named; the server sends it with one group, never with the list. */
export type GroupUsage = { campaigns: GroupReference[]; policies: GroupReference[] };

/** The single-group answer: the record and the records that name it. */
type GroupDetail = HostGroup & { used_by?: GroupUsage };

/** What a selector resolves to now: the count, and as many names as fit. */
type Preview = { count: number; sample: string[]; selector: string };

/** How the list is read: by name, or biggest first. */
export type GroupOrder = "name" | "size";

/**
 * The groups whose name or description carries the text, case aside.
 *
 * This is the one list in the panel the server will not narrow: `GET
 * /api/v1/host-groups` takes no query and answers with the whole
 * collection the reader may see, so there is no page here to mistake for
 * the answer. The card says how many of how many are drawn all the same.
 */
export function matchingGroups<T extends Pick<HostGroup, "name" | "description">>(items: T[], search: string): T[] {
  const needle = search.trim().toLowerCase();
  if (!needle) return items;
  return items.filter((group) =>
    group.name.toLowerCase().includes(needle) || (group.description ?? "").toLowerCase().includes(needle));
}

/**
 * The groups in the order asked for.
 *
 * A group whose size nobody could read goes last rather than first: by
 * size it is not the smallest group, it is the group nobody counted.
 */
export function orderGroups<T extends Pick<HostGroup, "name" | "member_count">>(items: T[], order: GroupOrder): T[] {
  const sorted = [...items];
  if (order === "name") return sorted.sort((a, b) => a.name.localeCompare(b.name));
  return sorted.sort((a, b) => {
    if (a.member_count === undefined && b.member_count === undefined) return a.name.localeCompare(b.name);
    if (a.member_count === undefined) return 1;
    if (b.member_count === undefined) return -1;
    return b.member_count - a.member_count || a.name.localeCompare(b.name);
  });
}

/** The saved expression in one line, in the shape the server logs it. */
export function describeSelector(expression?: SelectorExpression | null): string {
  if (!expression) return "";
  if (expression.all) return `(${expression.all.map(describeSelector).join(" and ")})`;
  if (expression.any) return `(${expression.any.map(describeSelector).join(" or ")})`;
  if (expression.not) return `not ${describeSelector(expression.not)}`;
  const [field, value] = Object.entries(expression).find(([, one]) => typeof one === "string") ?? ["nothing", ""];
  return value ? `${field}=${value}` : field;
}

/** One row of the builder: a fact about a host, its value, and whether it is denied. */
export type Rule = { field: RuleField; value: string; negated: boolean };

export type RuleField =
  | "tag" | "group" | "site" | "environment" | "os_family" | "os_version" | "capability"
  | "connection_state" | "lifecycle_state" | "owner" | "channel"
  | "security_updates" | "reboot_required" | "failed_units" | "agent_version"
  | "relay" | "failure_domain";

/** The facts a rule may name, in the order the builder offers them. */
export const RULE_FIELDS: RuleField[] = [
  "tag", "group", "site", "environment", "os_family", "os_version", "capability",
  "connection_state", "lifecycle_state", "owner", "channel",
  "security_updates", "reboot_required", "failed_units", "agent_version",
  "relay", "failure_domain",
];

/** The facts a host reports as yes or no; a host that never reported is on neither side. */
const YES_NO_FIELDS: RuleField[] = ["security_updates", "reboot_required", "failed_units"];

/**
 * The rows as the expression the server reads: one leaf per row, a denied
 * row wrapped in `not`, and the rows joined by `all` or `any`. A row with
 * no value is not a rule yet and is left out.
 */
export function selectorOf(rules: Rule[], combine: "all" | "any"): SelectorExpression | null {
  const leaves = rules
    .filter((rule) => rule.value.trim() !== "")
    .map((rule): SelectorExpression => {
      // Every leaf the builder offers is a string on the wire; the release
      // channel is typed narrower in the view, which is what the cast is for.
      const leaf = { [rule.field]: rule.value.trim() } as SelectorExpression;
      return rule.negated ? { not: leaf } : leaf;
    });
  if (leaves.length === 0) return null;
  if (leaves.length === 1) return leaves[0];
  return combine === "all" ? { all: leaves } : { any: leaves };
}

/**
 * The saved expression read back as rows of the builder: one leaf per row,
 * a `not` around a leaf as that row's denial, and the rows joined by all or
 * any.
 *
 * `exact` says whether the rows are the whole of it. A selector deeper than
 * a flat list of leaves cannot be shown as rows without losing part of
 * itself, so it is edited as it was written instead - silently flattening
 * it would save a different selector from the one that was read.
 */
export function rulesOf(expression?: SelectorExpression | null): { rules: Rule[]; combine: "all" | "any"; exact: boolean } {
  const empty = { rules: [{ field: "tag", value: "", negated: false } as Rule], combine: "all" as const, exact: false };
  if (!expression) return { ...empty, exact: true };
  const leaves = expression.all ?? expression.any ?? [expression];
  const combine: "all" | "any" = expression.any ? "any" : "all";
  const rules: Rule[] = [];
  let exact = true;
  for (const leaf of leaves) {
    const rule = leafRule(leaf);
    if (rule) rules.push(rule); else exact = false;
  }
  if (rules.length === 0) return { ...empty, exact: false };
  return { rules, combine, exact };
}

/** One row from one leaf, or null when the leaf is not a plain fact about a host. */
function leafRule(leaf: SelectorExpression): Rule | null {
  const negated = leaf.not !== undefined;
  const fact = leaf.not ?? leaf;
  if (fact.all || fact.any || fact.not) return null;
  const entry = Object.entries(fact).find(([key, value]) =>
    typeof value === "string" && value !== "" && RULE_FIELDS.includes(key as RuleField));
  if (!entry) return null;
  return { field: entry[0] as RuleField, value: entry[1] as string, negated };
}

/**
 * The sentence a deletion says about what names the group: nothing when
 * nothing does, otherwise every campaign and policy by name, so the
 * operator reads what stops resolving before pressing the button.
 */
export function namedBy(usage: GroupUsage | undefined, t: (key: string, vars?: Record<string, string | number>) => string): string {
  if (!usage) return "";
  const names = [
    ...usage.campaigns.map((one) => t("campaign {name}", { name: one.name })),
    ...usage.policies.map((one) => t("policy {name}", { name: one.name })),
  ];
  if (names.length === 0) return "";
  return t("Its selector is named by: {list}. They will stop resolving.", { list: names.join(", ") });
}

/**
 * The groups, or one of them.
 *
 * The address decides: `/next/groups` is the catalogue, and
 * `/next/groups/<id>` opens that group on its own, so a group somebody
 * is looking at can be sent to somebody else and reloaded where it was.
 */
export function Groups() {
  const { id = "" } = useParams();
  return id ? <OneGroup id={id} /> : <GroupList />;
}

/**
 * The bulk workspace opened on this group, inside the new panel.
 *
 * Given hosts picked out of the group's own table, those hosts go by
 * identifier and the group is left out: an expression decides alone in an
 * order, so a group named beside a list would quietly widen it back to the
 * whole group.
 */
export function campaignAddress(name: string, hostIDs: string[] = []): string {
  const params = new URLSearchParams({ name });
  if (hostIDs.length === 0) params.set("group", name);
  for (const one of hostIDs) params.append("host_id", one);
  return `/next/bulk?${params}`;
}

/** What the reader is allowed to do, as the server answers it. */
function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/** A new read with this group as its selector, inside the new panel. */
export function readAddress(name: string): string {
  return `/next/reads?${new URLSearchParams({ action: "journal.read", group: name })}`;
}

/** How a host's connection reads as a tone; nobody's guess is unknown. */
export function connectionTone(state?: string): Tone {
  if (state === "online") return "ok";
  if (state === "offline") return "error";
  if (state === "stale") return "warn";
  return "unknown";
}

function GroupList() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [order, setOrder] = useState<GroupOrder>("name");
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<HostGroup>>("/api/v1/host-groups"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const canWrite = usePermissions().has("host.group.write");

  const items = groups.data?.items ?? [];
  const shown = useMemo(() => orderGroups(matchingGroups(items, search), order), [items, search, order]);
  const loaded = groups.data !== undefined;

  const kinds: Segment[] = [
    { label: t("Selector"), value: loaded ? items.filter((one) => one.kind === "dynamic").length : undefined, tone: "info" },
    { label: t("Member list"), value: loaded ? items.filter((one) => one.kind === "static").length : undefined, tone: "neutral" },
  ];

  const broken = items.filter((one) => one.unresolvable);
  // The biggest groups, counted over the ones that have a size: a group
  // nobody could count has no bar, because a bar of nothing reads as a
  // group of nobody.
  const counted = items.filter((one) => one.member_count !== undefined);
  const biggest = [...counted].sort((a, b) => (b.member_count ?? 0) - (a.member_count ?? 0)).slice(0, 8);
  const uncounted = items.length - counted.length;

  if (groups.error) return <Problem>{String(groups.error)}</Problem>;

  return (
    <>
      {deleting && <DeleteGroup groups={items} onClose={() => setDeleting(false)} />}
      <Board screen={GROUPS_SCREEN} catalogue={GROUPS} drawn={{
        kinds: (
          <Card
            title={t("How the groups answer")}
            note={t("A member list is what somebody wrote down; a selector is asked again every time it is read.")}
          >
            <Band segments={kinds} testId="group-kinds" />
          </Card>
        ),
        biggest: (
          <Card title={t("The biggest groups")} note={uncounted > 0 ? t("{n} groups have no size to show.", { n: uncounted }) : undefined}>
            {biggest.length === 0
              ? <Empty>{loaded ? t("No group has a size to show.") : t("Reading the groups…")}</Empty>
              : (
                <Bars items={biggest.map((one) => ({
                  label: <Link to={`/next/groups/${one.id}`}>{one.name}</Link>,
                  value: one.member_count ?? 0,
                }))} />
              )}
          </Card>
        ),
        broken: (
          <Card title={t("Selectors that do not resolve")} note={t("A group that names something gone resolves to nobody until it is changed.")}>
            {broken.length === 0
              ? <Empty>{loaded ? t("Every selector resolves.") : t("Reading the groups…")}</Empty>
              : (
                <Facts>
                  {broken.map((one) => (
                    <Fact key={one.id} label={<Link to={`/next/groups/${one.id}`}>{one.name}</Link>}>
                      <span className="fl-error">{one.unresolvable}</span>
                    </Fact>
                  ))}
                </Facts>
              )}
          </Card>
        ),
        form: creating && <CreateGroup onDone={() => setCreating(false)} />,
        list: (
          <Card
            title={t("Groups")}
            note={loaded ? t("{shown} of {total} groups", { shown: shown.length, total: items.length }) : undefined}
            tools={canWrite && (
              <>
                <button type="button" onClick={() => setCreating(true)} disabled={creating} data-testid="new-group">
                  {t("New group")}
                </button>
                <button type="button" className="fl-danger" onClick={() => setDeleting(true)} disabled={items.length === 0} data-testid="delete-a-group">
                  {t("Delete a group…")}
                </button>
              </>
            )}
            flush
          >
            <Toolbar
              end={
                <Seg
                  value={order}
                  onChange={setOrder}
                  options={[{ value: "name" as const, label: t("by name") }, { value: "size" as const, label: t("by size") }]}
                />
              }
            >
              <Find value={search} onChange={setSearch} placeholder={t("Search by name or description")} testId="group-search" />
            </Toolbar>
            <Table
              rows={shown}
              keyOf={(one) => one.id}
              rowTestId={(one) => `group-${one.name}`}
              empty={groups.isLoading
                ? t("Reading the groups…")
                : items.length === 0
                  ? t("No group yet. A campaign can still name hosts by site, environment, tags or a list.")
                  : t("No group matches this.")}
              columns={[
                { key: "name", head: t("Group"), cell: (one) => (
                  <TwoLine sub={one.description}>
                    <Link to={`/next/groups/${one.id}`}>{one.name}</Link>
                  </TwoLine>
                ) },
                { key: "kind", head: t("Kind"), cell: (one) => (
                  one.kind === "dynamic"
                    ? <Pill tone="info" title={t("resolved from its selector every time it is read")}>{t("selector")}</Pill>
                    : <Pill tone="neutral" title={t("a member list kept by hand")}>{t("member list")}</Pill>
                ) },
                { key: "selector", head: t("Answers"), tight: true, cell: (one) => (
                  one.kind === "dynamic"
                    ? <code title={describeSelector(one.selector)}>{describeSelector(one.selector)}</code>
                    : <span className="fl-faint">{t("the hosts written into it")}</span>
                ) },
                // A size the server could not give is unknown, not nought:
                // a selector that stopped resolving names nobody only
                // because nobody could ask it.
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => (
                  one.unresolvable
                    ? <Pill tone="error" title={one.unresolvable}>{t("unresolvable")}</Pill>
                    : one.member_count === undefined
                      ? <Pill tone="unknown">{t("unknown")}</Pill>
                      : one.member_count
                ) },
                { key: "by", head: t("Created by"), minor: true, tight: true, cell: (one) => (
                  one.created_by ? <span title={one.created_by}>{one.created_by}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "updated", head: t("Updated"), minor: true, cell: (one) => (
                  <span title={absoluteTime(one.updated_at)}>{relativeTime(one.updated_at)}</span>
                ) },
              ]}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * Deleting a group.
 *
 * A row carries no buttons, so the deletion is reached from the card and
 * names its subject here: which group, what stops resolving when it goes,
 * and the one button that does it. Reading the record first is what makes
 * the sentence about campaigns and policies possible at all - the list
 * answer does not carry it.
 */
function DeleteGroup({ groups, chosen: about = "", onClose, onDeleted }: {
  groups: HostGroup[];
  /** The group the deletion is already about; the group's own screen names it. */
  chosen?: string;
  onClose: () => void;
  /** What follows the deletion where the screen was about that group. */
  onDeleted?: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [id, setId] = useState(about);
  const [message, setMessage] = useState("");
  const chosen = groups.find((one) => one.id === id);

  const detail = useQuery({
    queryKey: ["host-group", id],
    queryFn: () => api.get<GroupDetail>(`/api/v1/host-groups/${id}`),
    enabled: id !== "",
    retry: false,
  });
  const remove = useMutation({
    mutationFn: () => api.del<void>(`/api/v1/host-groups/${id}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Group {name} deleted", { name: chosen?.name ?? "" }));
      onClose();
      onDeleted?.();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const named = namedBy(detail.data?.used_by, t);

  return (
    <Modal
      title={t("Delete a group")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={remove.isPending}>{t("Cancel")}</button>
          <button
            type="button"
            className="fl-danger"
            disabled={!chosen || remove.isPending}
            onClick={() => { setMessage(""); remove.mutate(); }}
            data-testid="group-delete"
          >
            {remove.isPending ? t("Deleting…") : t("Delete")}
          </button>
        </>
      }
    >
      {about
        ? <Note>{t("The group {name} goes; no host is touched.", { name: chosen?.name ?? about })}</Note>
        : (
          <Fields>
            <Field label={t("Group")} wide hint={t("The group goes; no host is touched.")}>
              <select value={id} onChange={(event) => { setId(event.target.value); setMessage(""); }} data-testid="group-to-delete">
                <option value="">{t("choose a group…")}</option>
                {groups.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
              </select>
            </Field>
          </Fields>
        )}
      {chosen && (
        <Note>{t("A selector that names it stops resolving; a campaign already ordered keeps the snapshot it froze.")}</Note>
      )}
      {named && <Banner tone="warn">{named}</Banner>}
      {message && <Problem>{message}</Problem>}
    </Modal>
  );
}

/**
 * A new group.
 *
 * It stands on the page rather than over it: whoever writes a selector
 * reads the list behind it to see what the fleet is already divided by,
 * and a dialog would take that away.
 */
function CreateGroup({ onDone }: { onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState<HostGroup["kind"]>("static");
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [rules, setRules] = useState<Rule[]>([{ field: "tag", value: "", negated: false }]);
  const [combine, setCombine] = useState<"all" | "any">("all");
  const [message, setMessage] = useState("");
  const selector = selectorOf(rules, combine);

  const create = useMutation({
    mutationFn: () => api.post<HostGroup>("/api/v1/host-groups", {
      name: name.trim(),
      description: description.trim(),
      kind,
      selector: kind === "dynamic" ? selector : undefined,
      host_ids: kind === "static" ? [...members] : undefined,
    }),
    onSuccess: (group) => {
      void queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Group {name} created", { name: group.name }));
      onDone();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const ready = name.trim() !== "" && (kind === "static" ? members.size > 0 : selector !== null);

  return (
    <Card
      title={t("New group")}
      note={t("The name is what a campaign selector will use; keep it short and without spaces.")}
      foot={
        <Actions>
          <button type="button" onClick={() => { setMessage(""); create.mutate(); }} disabled={!ready || create.isPending} data-testid="create-group">
            {create.isPending ? t("Creating…") : t("Create group")}
          </button>
          <button type="button" className="fl-quiet" onClick={onDone} disabled={create.isPending}>{t("Cancel")}</button>
          {message && <Problem>{message}</Problem>}
        </Actions>
      }
    >
      <Fields>
        <Field label={t("Name")}>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("e.g. databases-gold")} data-testid="group-name" />
        </Field>
        <Field label={t("Description")}>
          <input value={description} onChange={(event) => setDescription(event.target.value)} data-testid="group-description" />
        </Field>
        <Field
          label={t("Kind")}
          hint={kind === "static"
            ? t("A list you keep by hand; hosts join and leave it when you say so.")
            : t("A selector the server resolves every time it is read; a host tagged tomorrow is in the group tomorrow.")}
        >
          <select value={kind} onChange={(event) => setKind(event.target.value as HostGroup["kind"])} data-testid="group-kind">
            <option value="static">{t("member list: the hosts you pick")}</option>
            <option value="dynamic">{t("selector: whatever matches, when it is read")}</option>
          </select>
        </Field>
      </Fields>
      {kind === "static"
        ? <MemberChooser chosen={members} onChange={setMembers} />
        : (
          <>
            <SelectorRules rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
            <SelectorPreview selector={selector} />
          </>
        )}
    </Card>
  );
}

/**
 * The rows a selector is built from.
 *
 * A row is a fact and a value, and it may be denied; the rows are joined
 * by all or by any, and the sentence underneath is the same one the
 * server will write into the trail.
 */
function SelectorRules({ rules, combine, onRules, onCombine }: {
  rules: Rule[];
  combine: "all" | "any";
  onRules: (rules: Rule[]) => void;
  onCombine: (combine: "all" | "any") => void;
}) {
  const t = useT();
  const selector = selectorOf(rules, combine);
  const update = (index: number, delta: Partial<Rule>) =>
    onRules(rules.map((rule, at) => (at === index ? { ...rule, ...delta } : rule)));
  const names: Record<RuleField, string> = {
    tag: t("tag"), group: t("group"), site: t("site"), environment: t("environment"),
    os_family: t("os family"), os_version: t("os version"), capability: t("capability"),
    connection_state: t("connection state"), lifecycle_state: t("lifecycle state"), owner: t("owner"),
    channel: t("release channel"), security_updates: t("security updates waiting"),
    reboot_required: t("reboot required"), failed_units: t("failed units"),
    agent_version: t("agent version"), relay: t("relay"), failure_domain: t("failure domain"),
  };
  return (
    <>
      <h3 className="fl-subhead">{t("Selector")}</h3>
      <Toolbar>
        <span className="fl-note">{t("the host has to match")}</span>
        <select value={combine} onChange={(event) => onCombine(event.target.value as "all" | "any")} aria-label={t("the host has to match")}>
          <option value="all">{t("every rule")}</option>
          <option value="any">{t("any rule")}</option>
        </select>
      </Toolbar>
      {rules.map((rule, index) => (
        <Toolbar key={index}>
          <Check checked={rule.negated} onChange={(value) => update(index, { negated: value })}>{t("not")}</Check>
          <select
            value={rule.field}
            onChange={(event) => update(index, { field: event.target.value as RuleField, value: "" })}
            aria-label={t("the fact")}
          >
            {RULE_FIELDS.map((field) => <option key={field} value={field}>{names[field]}</option>)}
          </select>
          <RuleValue rule={rule} onChange={(value) => update(index, { value })} />
          <button
            type="button"
            className="fl-quiet fl-small"
            onClick={() => onRules(rules.filter((_, at) => at !== index))}
            disabled={rules.length === 1}
          >
            {t("Remove")}
          </button>
        </Toolbar>
      ))}
      <Actions>
        <button type="button" className="fl-quiet fl-small" onClick={() => onRules([...rules, { field: "tag", value: "", negated: false }])}>
          {t("Add a rule")}
        </button>
        <span className="fl-note fl-mono">{selector ? describeSelector(selector) : t("no rule has a value yet")}</span>
      </Actions>
    </>
  );
}

/** The value of one rule, asked for the way that fact is written. */
function RuleValue({ rule, onChange }: { rule: Rule; onChange: (value: string) => void }) {
  const t = useT();
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<HostGroup>>("/api/v1/host-groups"),
    enabled: rule.field === "group",
    staleTime: 60 * 1000,
  });
  const label = t("the value");
  if (YES_NO_FIELDS.includes(rule.field)) {
    return (
      <select value={rule.value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
        <option value="">{t("pick yes or no…")}</option>
        <option value="true">{t("yes")}</option>
        <option value="false">{t("no")}</option>
      </select>
    );
  }
  switch (rule.field) {
    case "connection_state":
      return (
        <select value={rule.value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
          <option value="">{t("pick a state…")}</option>
          {["online", "offline", "stale", "unknown"].map((one) => <option key={one} value={one}>{t(one)}</option>)}
        </select>
      );
    case "lifecycle_state":
      return (
        <select value={rule.value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
          <option value="">{t("pick a state…")}</option>
          {["active", "quarantined", "recovery", "retiring", "retired"].map((one) => <option key={one} value={one}>{t(one)}</option>)}
        </select>
      );
    case "group":
      return (
        <select value={rule.value} onChange={(event) => onChange(event.target.value)} aria-label={label}>
          <option value="">{t("pick a group…")}</option>
          {(groups.data?.items ?? []).map((one) => <option key={one.id} value={one.name}>{one.name}</option>)}
        </select>
      );
    default:
      return (
        <input
          value={rule.value}
          onChange={(event) => onChange(event.target.value)}
          aria-label={label}
          data-testid={`rule-value-${rule.field}`}
          placeholder={rule.field === "tag"
            ? t("key or key=value")
            : rule.field === "capability"
              ? t("e.g. packages.apt")
              : rule.field === "agent_version"
                ? t("< 0.49.0")
                : t("value")}
        />
      );
  }
}

/**
 * What the selector under construction resolves to now.
 *
 * The question goes to the server as the rows settle, because the count
 * is the caller's own: a selector matching the fleet matches rather less
 * of it for somebody who may read one site.
 */
function SelectorPreview({ selector }: { selector: SelectorExpression | null }) {
  const t = useT();
  const written = selector ? JSON.stringify(selector) : "";
  const settled = useDebounced(written);
  const preview = useQuery({
    queryKey: ["host-group-preview", settled],
    queryFn: () => api.get<Preview>(`/api/v1/host-groups/preview?expression=${encodeURIComponent(settled)}`),
    enabled: settled !== "",
    staleTime: 10 * 1000,
    retry: false,
  });
  if (!selector) return null;
  const stale = settled !== written;
  return (
    <div data-testid="selector-preview">
      <h3 className="fl-subhead">{t("Matches now")}</h3>
      {preview.error
        ? <Problem>{String(preview.error)}</Problem>
        : preview.isLoading || stale || !preview.data
          ? <Note>{t("Counting…")}</Note>
          : (
            <>
              <Note>
                {t("{n} hosts", { n: preview.data.count })}
                {preview.data.count > preview.data.sample.length
                  ? ` · ${t("first {n} shown", { n: preview.data.sample.length })}`
                  : ""}
              </Note>
              {preview.data.sample.length > 0 && <p className="fl-mono fl-note">{preview.data.sample.join(", ")}</p>}
            </>
          )}
    </div>
  );
}

/**
 * The hosts written into a member list.
 *
 * The search goes to the server, so a hostname nobody has loaded is still
 * findable; what is ticked survives the search, because a list built in
 * three searches is still one list.
 */
function MemberChooser({ chosen, onChange, testId = "member-search" }: {
  chosen: Set<string>;
  onChange: (next: Set<string>) => void;
  /** The search box's own name, so two choosers on one screen stay apart. */
  testId?: string;
}) {
  const t = useT();
  const [search, setSearch] = useState("");
  const settled = useDebounced(search.trim());
  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (settled) params.set("q", settled);
  const hosts = useInfiniteQuery({
    queryKey: ["hosts", params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Host>>(`/api/v1/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const toggle = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id); else next.add(id);
    onChange(next);
  };

  return (
    <>
      <h3 className="fl-subhead">{t("Members")}</h3>
      <Toolbar end={<span className="fl-note">{t("{n} chosen", { n: chosen.size })}</span>}>
        <Find value={search} onChange={setSearch} placeholder={t("Search hostname, address, machine ID or owner")} testId={testId} />
        {/* Every host the search turned up, in one press. It adds the
            loaded rows and keeps what earlier searches ticked: a list
            built out of three searches is still one list. */}
        <Button
          kind="quiet"
          onClick={() => onChange(new Set([...chosen, ...rows.map((one) => one.id)]))}
          disabled={rows.length === 0}
          testId="choose-listed"
        >
          {t("Choose every listed host")}
        </Button>
        <Button kind="quiet" onClick={() => onChange(new Set())} disabled={chosen.size === 0} testId="clear-chosen">
          {t("Clear")}
        </Button>
      </Toolbar>
      {hosts.error
        ? <Problem>{String(hosts.error)}</Problem>
        : (
          <Table
            rows={rows}
            keyOf={(one) => one.id}
            rowTestId={(one) => `member-${one.hostname}`}
            empty={hosts.isLoading ? t("Reading the hosts…") : t("No host matches this.")}
            columns={[
              { key: "host", head: t("Host"), cell: (one) => (
                <Check checked={chosen.has(one.id)} onChange={() => toggle(one.id)}>{one.hostname}</Check>
              ) },
              { key: "state", head: t("State"), cell: (one) => (
                <Pill tone={connectionTone(one.connection_state)}>{t(one.connection_state)}</Pill>
              ) },
              { key: "site", head: t("Site"), minor: true, cell: (one) => one.site },
              { key: "environment", head: t("Environment"), minor: true, cell: (one) => one.environment },
              { key: "tags", head: t("Tags"), minor: true, tight: true, cell: (one) => (
                one.tags.length > 0 ? <code>{one.tags.join(" ")}</code> : <span className="fl-faint">—</span>
              ) },
            ]}
          />
        )}
      {hosts.hasNextPage && (
        <Actions>
          <button type="button" className="fl-quiet fl-small" onClick={() => void hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
            {t("Load more ({n} left)", { n: total - rows.length })}
          </button>
        </Actions>
      )}
    </>
  );
}

/**
 * Changing a group in place: the name a selector names it by, the
 * description, and - for a group that answers with a selector - the rule
 * itself.
 *
 * The write carries the version the form was built on, so a selector
 * somebody else changed in the meantime is not overwritten from a stale
 * screen: the server refuses it and the reader is told to read it again.
 * The kind never changes here - turning a list into a selector is a
 * different group, and the server says so.
 */
function EditGroup({ group, etag, onDone }: { group: GroupDetail; etag: string; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const saved = rulesOf(group.selector);
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? "");
  const [rules, setRules] = useState<Rule[]>(saved.rules);
  const [combine, setCombine] = useState<"all" | "any">(saved.combine);
  // A selector the rows cannot hold opens as it was written, because the
  // rows would save a smaller selector than the one that was read.
  const [asJSON, setAsJSON] = useState(!saved.exact);
  const [written, setWritten] = useState(JSON.stringify(group.selector ?? {}, null, 2));
  const [message, setMessage] = useState("");
  const dynamic = group.kind === "dynamic";

  const parsed = useMemo((): { selector: SelectorExpression | null; problem: string } => {
    if (!asJSON) return { selector: selectorOf(rules, combine), problem: "" };
    try {
      const value = JSON.parse(written) as SelectorExpression;
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { selector: null, problem: t("the selector has to be a JSON object") };
      }
      return { selector: value, problem: "" };
    } catch {
      return { selector: null, problem: t("the selector is not valid JSON") };
    }
  }, [asJSON, rules, combine, written, t]);

  const ready = name.trim() !== "" && (!dynamic || parsed.selector !== null);

  const save = useMutation({
    mutationFn: () => api.put<HostGroup>(
      `/api/v1/host-groups/${group.id}`,
      {
        name: name.trim(),
        description: description.trim(),
        selector: dynamic ? parsed.selector : undefined,
      },
      etag ? { headers: { "If-Match": etag } } : undefined,
    ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-group", group.id] });
      void queryClient.invalidateQueries({ queryKey: ["host-group-hosts", group.id] });
      void queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Group {name} saved", { name: name.trim() }));
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 412) {
        // The record moved under the editor. The screen reads it again and
        // the form is built from the version that is there now, so the word
        // about it has to outlive the form it was typed in.
        void queryClient.invalidateQueries({ queryKey: ["host-group", group.id] });
        toast.error(t("The group changed since it was read; the form now shows the current version, start the edit again."));
        onDone();
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <Card
      span={12}
      title={t("Edit group")}
      note={dynamic
        ? t("The name a selector names it by, the description, and the rule the server compiles.")
        : t("The name a selector names it by and the description; the members are edited on their own.")}
      foot={
        <Actions>
          <Button
            onClick={() => { setMessage(""); save.mutate(); }}
            disabled={!ready || save.isPending}
            testId="save-group"
          >
            {save.isPending ? t("Saving…") : t("Save changes")}
          </Button>
          <Button kind="quiet" onClick={onDone} disabled={save.isPending} testId="cancel-edit">{t("Cancel")}</Button>
          {message && <Problem>{message}</Problem>}
        </Actions>
      }
    >
      <Stack>
        <Fields>
          <Field label={t("Name")}>
            <input value={name} onChange={(event) => setName(event.target.value)} data-testid="edit-name" />
          </Field>
          <Field label={t("Description")}>
            <input value={description} onChange={(event) => setDescription(event.target.value)} data-testid="edit-description" />
          </Field>
        </Fields>
        {dynamic && (asJSON
          ? (
            <>
              <h3 className="fl-subhead">{t("Selector")}</h3>
              {!saved.exact && (
                <Note>{t("The saved selector is deeper than the builder's rows can say, so it is edited as written.")}</Note>
              )}
              <Fields>
                <Field label={t("As the server reads it")} wide>
                  <textarea
                    className="fl-mono"
                    rows={10}
                    value={written}
                    spellCheck={false}
                    onChange={(event) => setWritten(event.target.value)}
                    data-testid="edit-selector-json"
                  />
                </Field>
              </Fields>
              {parsed.problem && <Problem>{parsed.problem}</Problem>}
              {saved.exact && (
                <Actions>
                  <Button
                    kind="quiet"
                    testId="back-to-rules"
                    onClick={() => {
                      // The rows take the written selector back when it
                      // still fits them, and stay as they were when it
                      // does not.
                      const back = rulesOf(parsed.selector);
                      if (parsed.selector && back.exact) {
                        setRules(back.rules);
                        setCombine(back.combine);
                      }
                      setAsJSON(false);
                    }}
                  >
                    {t("Back to the rules")}
                  </Button>
                </Actions>
              )}
            </>
          )
          : (
            <>
              <SelectorRules rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
              <Actions>
                <Button
                  kind="quiet"
                  testId="edit-as-json"
                  onClick={() => {
                    setWritten(JSON.stringify(parsed.selector ?? group.selector ?? {}, null, 2));
                    setAsJSON(true);
                  }}
                >
                  {t("Edit as JSON")}
                </Button>
              </Actions>
            </>
          ))}
        {dynamic && <SelectorPreview selector={parsed.selector} />}
      </Stack>
    </Card>
  );
}

/**
 * The members of a list group, replaced whole.
 *
 * It opens on what the group holds now, so a save without a change changes
 * nothing; and a host left unticked leaves the group, which is said above
 * the list rather than discovered afterwards.
 */
function EditMembers({ id, chosen, onChosen, onDone }: {
  id: string;
  chosen: Set<string>;
  onChosen: (next: Set<string>) => void;
  onDone: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");

  const save = useMutation({
    mutationFn: () => api.put<HostGroup>(`/api/v1/host-groups/${id}/members`, { host_ids: [...chosen] }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-group", id] });
      void queryClient.invalidateQueries({ queryKey: ["host-group-hosts", id] });
      void queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Members saved"));
      onDone();
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  return (
    <Card
      span={12}
      title={t("Members")}
      note={t("The list is replaced whole: a host left unticked leaves the group.")}
      foot={
        <Actions>
          <Button onClick={() => { setMessage(""); save.mutate(); }} disabled={save.isPending} testId="save-members">
            {save.isPending ? t("Saving…") : t("Save members ({n})", { n: chosen.size })}
          </Button>
          <Button kind="quiet" onClick={onDone} disabled={save.isPending} testId="cancel-members">{t("Cancel")}</Button>
          {message && <Problem>{message}</Problem>}
        </Actions>
      }
    >
      <MemberChooser chosen={chosen} onChange={onChosen} testId="edit-member-search" />
    </Card>
  );
}

/* ------------------------------------------------------------ one group */

/** A record that names a group in its selector, as the detail card lists it. */
type NamedBy = { key: string; kind: string; name: string; state: string; to?: string };

/**
 * One group: what it answers with, what names it elsewhere, and the hosts
 * it resolves to now.
 *
 * The three are one screen because they are one question. A selector
 * read without the campaigns that name it is a rule nobody can change
 * safely, and a size read without the members is a number nobody can
 * check. A size the server could not give stays unknown here as well:
 * the record is the same record the row above came from.
 */
function OneGroup({ id }: { id: string }) {
  const t = useT();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const settled = useDebounced(search.trim());
  const permissions = usePermissions();
  const canWrite = permissions.has("host.group.write");
  // Whoever may not order a campaign is shown no door to one, and no
  // boxes to pick the hosts an order would name.
  const seesCampaigns = permissions.has("campaign.read");
  const [editing, setEditing] = useState(false);
  const [editingMembers, setEditingMembers] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [picked, setPicked] = useState<Set<string>>(new Set());

  // The record comes with its tag: the edit form writes back on exactly the
  // version it was built from, and a write over a newer one is refused.
  const group = useQuery({
    queryKey: ["host-group", id, "detail"],
    queryFn: () => api.getWithMeta<GroupDetail>(`/api/v1/host-groups/${id}`),
    retry: false,
    refetchInterval: REFRESH_INTERVAL,
  });

  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (settled) params.set("q", settled);
  const hosts = useInfiniteQuery({
    queryKey: ["host-group-hosts", id, params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Host>>(`/api/v1/host-groups/${id}/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: group.data !== undefined,
    refetchInterval: REFRESH_INTERVAL,
  });

  const help = (
    <p>
      {t("One group: the answer it saves to the question which hosts, what names that answer elsewhere in the panel, and the hosts it resolves to now. A member list changes only when somebody changes it; a selector is asked again every time it is read, so a host tagged this morning is in the group this morning.")}
    </p>
  );

  if (group.error) {
    const missing = group.error instanceof ApiError && group.error.status === 404;
    return (
      <Screen title={t("Group")} icon="groups" help={help}>
        <Card>
          {missing
            ? (
              <Empty icon="groups" action={<Link to="/next/groups">{t("All groups")}</Link>}>
                {t("No group with the identifier {id} exists in this installation.", { id })}
              </Empty>
            )
            : <Problem>{String(group.error)}</Problem>}
        </Card>
      </Screen>
    );
  }
  if (!group.data) {
    return (
      <Screen title={t("Group")} icon="groups" help={help}>
        <Card><Bones rows={4} /></Card>
      </Screen>
    );
  }

  const one = group.data.data;
  const etag = group.data.etag;
  const dynamic = one.kind === "dynamic";
  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const usage = one.used_by;
  const named: NamedBy[] = [
    ...(usage?.campaigns ?? []).map((campaign) => ({
      key: `campaign-${campaign.id}`, kind: t("campaign"), name: campaign.name,
      state: campaign.state, to: `/next/campaigns/${campaign.id}`,
    })),
    ...(usage?.policies ?? []).map((policy) => ({
      key: `policy-${policy.id}`, kind: t("policy"), name: policy.name, state: policy.state,
    })),
  ];
  const kindPill = dynamic
    ? <Pill tone="info" title={t("resolved from its selector every time it is read")}>{t("selector")}</Pill>
    : <Pill tone="neutral" title={t("a member list kept by hand")}>{t("member list")}</Pill>;
  const pick = (hostID: string) => setPicked((before) => {
    const after = new Set(before);
    if (after.has(hostID)) after.delete(hostID); else after.add(hostID);
    return after;
  });
  const allLoadedPicked = rows.length > 0 && rows.every((host) => picked.has(host.id));

  return (
    <Screen
      title={one.name}
      icon="groups"
      help={help}
      lead={
        <>
          {kindPill}{" "}
          <Tag>{t("created by {who}", { who: one.created_by })}</Tag>{" "}
          <Tag>{t("updated {when}", { when: relativeTime(one.updated_at) })}</Tag>
        </>
      }
      actions={
        <>
          {seesCampaigns && (
            <Button kind="quiet" onClick={() => navigate(campaignAddress(one.name))} testId="campaign-on-group">
              {t("Start a campaign on this group")}
            </Button>
          )}
          <Button kind="quiet" onClick={() => navigate(readAddress(one.name))} testId="read-on-group">
            {t("Run a read on this group")}
          </Button>
          {canWrite && !editing && (
            <Button kind="quiet" onClick={() => { setEditingMembers(false); setEditing(true); }} testId="edit-group">
              {t("Edit")}
            </Button>
          )}
          {canWrite && one.kind === "static" && !editingMembers && (
            <Button
              kind="quiet"
              testId="edit-members"
              /* The list is replaced whole, so the editor may only open on
                 the whole of it: seeded from a part, a save would drop
                 every member nobody had loaded yet. */
              disabled={hosts.isLoading || hosts.hasNextPage}
              title={hosts.hasNextPage
                ? t("Load the rest of the members first: the list is replaced whole.")
                : undefined}
              onClick={() => {
                // The editor opens on what the group holds now, so a save
                // without a change changes nothing.
                setMembers(new Set(rows.map((host) => host.id)));
                setEditing(false);
                setEditingMembers(true);
              }}
            >
              {t("Edit members")}
            </Button>
          )}
          {canWrite && (
            <Button kind="danger" onClick={() => setDeleting(true)} testId="delete-group">
              {t("Delete")}
            </Button>
          )}
          <Button kind="quiet" onClick={() => navigate("/next/groups")} testId="all-groups">
            {t("All groups")}
          </Button>
        </>
      }
      banner={one.unresolvable
        ? <Banner tone="error">{t("The selector does not resolve: {reason}", { reason: one.unresolvable })}</Banner>
        : undefined}
    >
      <Kpis>
        {/* A group that does not resolve names nobody only because nobody
            could ask it, so its size is an em dash and not a nought. */}
        <Kpi
          hero
          icon="groups"
          label={t("Hosts")}
          value={one.unresolvable ? null : one.member_count ?? null}
          note={dynamic ? t("resolved every time it is read") : t("written into the list by hand")}
          testId="kpi-group-hosts"
        />
        <Kpi
          icon="campaigns"
          label={t("Named by")}
          value={usage ? named.length : null}
          note={t("campaigns and policies whose selector names this group")}
          testId="kpi-group-named-by"
        />
      </Kpis>

      {deleting && (
        <DeleteGroup
          groups={[one]}
          chosen={one.id}
          onClose={() => setDeleting(false)}
          onDeleted={() => navigate("/next/groups")}
        />
      )}

      <Grid>
        {/* The form is rebuilt whenever the version under it moves, so a
            record somebody else changed is never edited from a stale copy. */}
        {editing && <EditGroup key={etag} group={one} etag={etag} onDone={() => setEditing(false)} />}
        {editingMembers && (
          <EditMembers id={id} chosen={members} onChosen={setMembers} onDone={() => setEditingMembers(false)} />
        )}

        <Card span={5} title={t("Group")} note={one.description || t("Nobody wrote what it is for.")}>
          <Facts>
            <Fact label={t("Name")} mono>{one.name}</Fact>
            <Fact label={t("Kind")}>{kindPill}</Fact>
            <Fact label={t("Hosts")}>
              {one.unresolvable
                ? <Pill tone="error" title={one.unresolvable}>{t("unresolvable")}</Pill>
                : one.member_count === undefined
                  ? <Pill tone="unknown">{t("unknown")}</Pill>
                  : one.member_count}
            </Fact>
            <Fact label={t("Created by")} mono>{one.created_by}</Fact>
            <Fact label={t("Created")}>
              <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
            </Fact>
            <Fact label={t("Updated")}>
              <span title={absoluteTime(one.updated_at)}>{relativeTime(one.updated_at)}</span>
            </Fact>
          </Facts>
        </Card>

        <Card
          span={7}
          title={t("What it answers with")}
          note={dynamic
            ? t("The rule the server compiles into a host query; the members below are today's answer to it.")
            : t("A list kept by hand; it changes when somebody changes it and at no other time.")}
        >
          {dynamic
            ? (
              <Stack>
                <Readout label={t("Selector")} value={describeSelector(one.selector)} testId="group-selector" />
                <Readout
                  label={t("As the server reads it")}
                  value={JSON.stringify(one.selector ?? null, null, 2)}
                  lines={10}
                  testId="group-selector-json"
                />
              </Stack>
            )
            : <Note>{t("The hosts below are the list itself; nothing is resolved.")}</Note>}
        </Card>

        <Card
          span={12}
          title={t("Used by")}
          note={dynamic
            ? t("A change of the selector reaches every policy listed at its next check; a campaign keeps the snapshot it froze.")
            : t("A change of the members reaches every policy listed at its next check; a campaign keeps the snapshot it froze.")}
          flush
        >
          <Table
            rows={named}
            keyOf={(row) => row.key}
            rowTestId={(row) => `uses-${row.name}`}
            testId="group-used-by"
            empty={t("No campaign and no policy names this group in its selector.")}
            columns={[
              { key: "kind", head: t("Record"), cell: (row) => row.kind },
              { key: "name", head: t("Name"), cell: (row) => (
                row.to ? <Link to={row.to}>{row.name}</Link> : row.name
              ) },
              { key: "state", head: t("State"), cell: (row) => <Pill tone="neutral">{t(row.state)}</Pill> },
            ]}
          />
        </Card>

        <Card
          span={12}
          title={t("Members")}
          note={t("What the group resolves to for you. Somebody who may read one site sees that site's share of it and no more.")}
          flush
          foot={(hosts.hasNextPage || picked.size > 0)
            ? (
              <Actions>
                {picked.size > 0 && (
                  <>
                    <span className="fl-note" data-testid="members-picked">
                      {t("{n} picked", { n: picked.size })}
                    </span>
                    <Button
                      onClick={() => navigate(campaignAddress(one.name, [...picked]))}
                      testId="campaign-on-picked"
                    >
                      {t("Open in the bulk workspace ({n})", { n: picked.size })}
                    </Button>
                    <Button kind="quiet" onClick={() => setPicked(new Set())} testId="clear-picked">
                      {t("Clear the selection")}
                    </Button>
                  </>
                )}
                {hosts.hasNextPage && (
                  <Button
                    kind="quiet"
                    onClick={() => void hosts.fetchNextPage()}
                    disabled={hosts.isFetchingNextPage}
                    testId="more-members"
                  >
                    {t("Load more ({n} left)", { n: total - rows.length })}
                  </Button>
                )}
              </Actions>
            )
            : undefined}
        >
          <Toolbar end={hosts.data ? <span>{t("{n} hosts", { n: total })}</span> : undefined}>
            <Find
              value={search}
              onChange={setSearch}
              placeholder={t("Search hostname, address, machine ID or owner")}
              testId="member-search"
            />
          </Toolbar>
          {hosts.error
            ? <Problem>{String(hosts.error)}</Problem>
            : (
              <Table
                rows={rows}
                keyOf={(host) => host.id}
                rowTestId={(host) => `member-${host.hostname}`}
                testId="group-members"
                loading={hosts.isLoading}
                empty={settled
                  ? t("No member of this group matches this.")
                  : t("The group resolves to no host you can see.")}
                columns={[
                  // The box ticks what is loaded and never "all": a page
                  // nobody has fetched holds hosts nobody has seen, and an
                  // order must not reach them from a box that read as all.
                  ...(seesCampaigns ? [{
                    key: "pick",
                    head: rows.length > 0 ? (
                      <input
                        type="checkbox"
                        checked={allLoadedPicked}
                        onChange={(event) => setPicked(event.target.checked ? new Set(rows.map((host) => host.id)) : new Set())}
                        aria-label={t("Pick every loaded host")}
                        data-testid="pick-all-members"
                      />
                    ) : undefined,
                    cell: (host: Host) => (
                      <input
                        type="checkbox"
                        checked={picked.has(host.id)}
                        onChange={() => pick(host.id)}
                        aria-label={t("Pick {host}", { host: host.hostname })}
                      />
                    ),
                  }] : []),
                  { key: "host", head: t("Host"), cell: (host) => (
                    <TwoLine sub={host.environment ? `${host.site} / ${host.environment}` : host.site}>
                      <Link to={`/next/hosts/${host.id}`}>{host.hostname}</Link>
                    </TwoLine>
                  ) },
                  { key: "state", head: t("State"), cell: (host) => (
                    <Pill tone={connectionTone(host.connection_state)}>{t(host.connection_state)}</Pill>
                  ) },
                  { key: "system", head: t("System"), minor: true, cell: (host) => (
                    [host.os_distribution || host.os_family, host.os_version].filter(Boolean).join(" ")
                      || <Pill tone="unknown">{t("unknown")}</Pill>
                  ) },
                  { key: "tags", head: t("Tags"), minor: true, tight: true, cell: (host) => (
                    host.tags.length > 0 ? <code>{host.tags.join(" ")}</code> : "—"
                  ) },
                  { key: "seen", head: t("Last seen"), minor: true, cell: (host) => (
                    host.last_seen_at
                      ? <span title={absoluteTime(host.last_seen_at)}>{relativeTime(host.last_seen_at)}</span>
                      : t("— never reported")
                  ) },
                ]}
              />
            )}
        </Card>
      </Grid>
    </Screen>
  );
}

export const GROUPS_SCREEN = "next_groups";

export const GROUPS: BoardEntry[] = [
  { key: "kinds", title: "How the groups answer", width: 5, height: 1 },
  { key: "biggest", title: "The biggest groups", width: 4, height: 2 },
  { key: "broken", title: "Selectors that do not resolve", width: 3, height: 2 },
  { key: "form", title: "New group", width: 12, height: 4 },
  { key: "list", title: "Groups", width: 12, height: 5 },
];
