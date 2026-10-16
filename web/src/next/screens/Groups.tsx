import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, LIST_PAGE, loadedItems, type Collection, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Host, HostGroup, SelectorExpression, Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { useToast } from "../../components/Toast";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Banner, Bars, Card, Check, Empty, Fact, Facts, Field, Fields, Find, Modal,
  Note, Pill, Problem, Seg, Table, Toolbar, TwoLine, type Segment,
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

export function Groups() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [order, setOrder] = useState<GroupOrder>("name");
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<HostGroup>>("/api/v1/host-groups"),
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canWrite = (whoami.data?.permissions ?? []).includes("host.group.write");

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
                  label: <Link to={`/groups/${one.id}`}>{one.name}</Link>,
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
                    <Fact key={one.id} label={<Link to={`/groups/${one.id}`}>{one.name}</Link>}>
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
                    <Link to={`/groups/${one.id}`}>{one.name}</Link>
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
function DeleteGroup({ groups, onClose }: { groups: HostGroup[]; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [id, setId] = useState("");
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
      <Fields>
        <Field label={t("Group")} wide hint={t("The group goes; no host is touched.")}>
          <select value={id} onChange={(event) => { setId(event.target.value); setMessage(""); }} data-testid="group-to-delete">
            <option value="">{t("choose a group…")}</option>
            {groups.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
          </select>
        </Field>
      </Fields>
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
function MemberChooser({ chosen, onChange }: { chosen: Set<string>; onChange: (next: Set<string>) => void }) {
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
        <Find value={search} onChange={setSearch} placeholder={t("Search hostname, address, machine ID or owner")} testId="member-search" />
        <button type="button" className="fl-quiet fl-small" onClick={() => onChange(new Set())} disabled={chosen.size === 0}>
          {t("Clear")}
        </button>
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

export const GROUPS_SCREEN = "next_groups";

export const GROUPS: BoardEntry[] = [
  { key: "kinds", title: "How the groups answer", width: 5, height: 3 },
  { key: "biggest", title: "The biggest groups", width: 4, height: 3 },
  { key: "broken", title: "Selectors that do not resolve", width: 3, height: 3 },
  { key: "form", title: "New group", width: 12, height: 6 },
  { key: "list", title: "Groups", width: 12, height: 7 },
];
