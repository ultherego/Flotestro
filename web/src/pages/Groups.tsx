import { useMemo, useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, loadedItems, LIST_PAGE, type Collection, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import type { Host, HostGroup, SelectorExpression, Whoami } from "../lib/types";
import { REFRESH_INTERVAL } from "../lib/stream";
import { ConnectionState, Empty, ErrorBox, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/** One campaign or policy whose selector names a group, as the API lists it. */
export type GroupReference = { id: string; name: string; state: string };

/** Where a group is named; read with one group, never with the list. */
export type GroupUsage = { campaigns: GroupReference[]; policies: GroupReference[] };

/** The single-group answer: the record and the records that name it. */
export type GroupDetail = HostGroup & { used_by?: GroupUsage };

/** What a selector resolves to now: the count and a sample of names. */
export type SelectorPreviewView = { count: number; sample: string[]; selector: string };

/** How the list is ordered: by name, or by size with the biggest first. */
export type GroupSort = "name" | "size";

/**
 * The groups whose name or description carries the text, case aside. An
 * empty search keeps everything.
 */
export function filterGroups<T extends Pick<HostGroup, "name" | "description">>(items: T[], search: string): T[] {
  const needle = search.trim().toLowerCase();
  if (!needle) return items;
  return items.filter((group) =>
    group.name.toLowerCase().includes(needle) || (group.description ?? "").toLowerCase().includes(needle));
}

/**
 * The groups in the chosen order. By size the biggest comes first and a
 * group whose size is not known comes last: unknown is not zero, so it
 * must not sort as the smallest.
 */
export function sortGroups<T extends Pick<HostGroup, "name" | "member_count">>(items: T[], sort: GroupSort): T[] {
  const sorted = [...items];
  if (sort === "name") return sorted.sort((a, b) => a.name.localeCompare(b.name));
  return sorted.sort((a, b) => {
    if (a.member_count === undefined && b.member_count === undefined) return a.name.localeCompare(b.name);
    if (a.member_count === undefined) return 1;
    if (b.member_count === undefined) return -1;
    return b.member_count - a.member_count || a.name.localeCompare(b.name);
  });
}

/**
 * The address of the campaign wizard with the group as the target, or -
 * when hosts were ticked on the group's table - those hosts alone by
 * identifier: an expression decides alone in an order, so a group next
 * to a list would silently outvote the ticks. The order is named after
 * the group; the operator renames it in the wizard. The group travels
 * under `group`, the way the wizard keeps it.
 */
export function bulkAddress(groupName: string, hostIDs: string[] = []): string {
  const params = new URLSearchParams({ name: groupName });
  if (hostIDs.length === 0) params.set("group", groupName);
  for (const id of hostIDs) params.append("host_id", id);
  return `/bulk?${params}`;
}

/** The address of a new read with the group as its selector. */
export function readsAddress(groupName: string): string {
  const params = new URLSearchParams({ action: "journal.read", group: groupName });
  return `/reads?${params}`;
}

/**
 * The saved expression as rows of the builder: one leaf per row, a `not`
 * around a leaf as the row's negation, and the rows joined by all or any.
 * `exact` is false when the expression is deeper than rows can say - an
 * `any` inside an `all`, a `not` around a branch - and then the rows are
 * only a start: saving them would replace what was written.
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

/** One row from a leaf, or null when the leaf is not a fact about a host. */
function leafRule(leaf: SelectorExpression): Rule | null {
  const negated = leaf.not !== undefined;
  const fact = leaf.not ?? leaf;
  if (fact.all || fact.any || fact.not) return null;
  const entry = Object.entries(fact).find(([key, value]) => typeof value === "string" && value !== "" && RULE_FIELDS.includes(key as RuleField));
  if (!entry) return null;
  return { field: entry[0] as RuleField, value: entry[1] as string, negated };
}

/**
 * The sentence a delete dialog says about what names the group: nothing
 * when nothing does, otherwise the campaigns and policies by name so the
 * operator knows what stops resolving.
 */
export function usageSentence(usage: GroupUsage | undefined, t: (key: string, vars?: Record<string, string | number>) => string): string {
  if (!usage) return "";
  const names = [
    ...usage.campaigns.map((campaign) => t("campaign {name}", { name: campaign.name })),
    ...usage.policies.map((policy) => t("policy {name}", { name: policy.name })),
  ];
  if (names.length === 0) return "";
  return t("Its selector is named by: {list}. They will stop resolving.", { list: names.join(", ") });
}

/**
 * Host groups: a saved answer to "which hosts".
 *
 * A static group is a list somebody keeps by hand; a dynamic one is a
 * selector the server resolves every time it is read, so a host tagged
 * tomorrow is in the group tomorrow. A campaign names a group instead of
 * repeating the list, and the snapshot it freezes says what the group
 * resolved to at that moment. The page lists the groups with their sizes,
 * creates one, and opens one to show the hosts it resolves to now.
 */
export function Groups() {
  const { id = "" } = useParams();
  return id ? <GroupPage id={id} /> : <GroupList />;
}

function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/**
 * The question "delete this group?" with what it reaches: the group is
 * read once more before the dialog, because the list does not carry the
 * campaigns and policies that name it, and the dialog is where they are
 * to be read. The answer resolves true when the group is gone.
 */
function useDeleteGroup(): (group: Pick<HostGroup, "id" | "name">) => Promise<boolean> {
  const t = useT();
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  return async (group) => {
    let usage: GroupUsage | undefined;
    try {
      usage = (await api.get<GroupDetail>(`/api/v1/host-groups/${group.id}`)).used_by;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
      return false;
    }
    const named = usageSentence(usage, t);
    const { ok } = await confirm({
      title: t("Delete the group {name}?", { name: group.name }),
      body: (
        <>
          <p>{t("A selector that names it will stop resolving; a campaign already ordered keeps its snapshot.")}</p>
          {named && <p className="page-error">{named}</p>}
        </>
      ),
      confirmLabel: t("Delete"),
      danger: true,
    });
    if (!ok) return false;
    try {
      await api.del<void>(`/api/v1/host-groups/${group.id}`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
      return false;
    }
    queryClient.invalidateQueries({ queryKey: ["host-groups"] });
    toast.success(t("Group {name} deleted", { name: group.name }));
    return true;
  };
}

function GroupList() {
  const t = useT();
  const permissions = usePermissions();
  const canWrite = permissions.has("host.group.write");
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<HostGroup>>("/api/v1/host-groups"),
    refetchInterval: REFRESH_INTERVAL,
  });
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<GroupSort>("name");
  const deleteGroup = useDeleteGroup();
  const items = groups.data?.items ?? [];
  const shown = useMemo(() => sortGroups(filterGroups(items, search), sort), [items, search, sort]);

  if (groups.error) return <ErrorBox error={groups.error} />;

  return (
    <>
      <PageHeader
        icon="groups"
        title={t("Groups")}
        description={t("A group is a saved answer to “which hosts”: a list kept by hand, or a selector the server resolves every time it is read.")}
        actions={canWrite && !creating && (
          <button className="primary" onClick={() => setCreating(true)}>{t("New group")}</button>
        )}
      />

      <div className="widgets">
        {creating && (
          <div className="span-12">
            <CreateGroup onDone={() => setCreating(false)} />
          </div>
        )}

        <Card className="span-12" flush>
          {items.length > 0 && (
            <Toolbar end={<span>{t("{n} of {total} groups", { n: shown.length, total: items.length })}</span>}>
              <input placeholder={t("Search by name or description")} aria-label={t("Search by name or description")} value={search} onChange={(e) => setSearch(e.target.value)} />
              <select value={sort} onChange={(e) => setSort(e.target.value as GroupSort)} aria-label={t("Sort")}>
                <option value="name">{t("sort by name")}</option>
                <option value="size">{t("sort by size")}</option>
              </select>
            </Toolbar>
          )}
          {groups.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : items.length === 0 ? (
            <EmptyState action={canWrite && !creating && <button className="secondary" onClick={() => setCreating(true)}>{t("New group")}</button>}>
              {t("No groups yet. A campaign can still name hosts by site, environment, tags or a list.")}
            </EmptyState>
          ) : shown.length === 0 ? (
            <EmptyState>{t("No group matches the search.")}</EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Group")}</th><th>{t("Kind")}</th><th>{t("Selector")}</th>
                  <th className="num">{t("Hosts")}</th><th>{t("Created by")}</th><th>{t("Updated")}</th>
                  {canWrite && <th></th>}
                </tr>
              </thead>
              <tbody>
                {shown.map((group) => (
                  <tr key={group.id}>
                    <td>
                      <div className="fp-host-cell">
                        <Link to={`/groups/${group.id}`}>{group.name}</Link>
                        {group.description && <span className="source">{group.description}</span>}
                      </div>
                    </td>
                    <td><KindBadge kind={group.kind} /></td>
                    <td className="source">{group.kind === "dynamic" ? describeExpression(group.selector) : t("member list")}</td>
                    {/* A count the server could not give is shown as
                        unknown, not as zero: an unresolvable selector
                        names nobody only because nobody could ask. */}
                    <td className="num">
                      {group.unresolvable
                        ? <span className="badge error" title={group.unresolvable}>{t("unresolvable")}</span>
                        : group.member_count === undefined
                          ? <span className="badge unknown">{t("unknown")}</span>
                          : group.member_count}
                    </td>
                    <td>{group.created_by}</td>
                    <td><Time value={group.updated_at} /></td>
                    {canWrite && (
                      <td className="num">
                        <button type="button" className="danger" onClick={() => deleteGroup(group)}>{t("Delete")}</button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

function KindBadge({ kind }: { kind: HostGroup["kind"] }) {
  const t = useT();
  return kind === "dynamic"
    ? <span className="badge ok" title={t("resolved from its selector every time it is read")}>{t("dynamic")}</span>
    : <span className="badge" title={t("a member list kept by hand")}>{t("static")}</span>;
}

/**
 * The form for a new group. The kind is chosen up front, because it does
 * not change afterwards: a list turned into a selector would keep members
 * nobody sees, and the other way round would lose a selector somebody
 * wrote.
 */
function CreateGroup({ onDone }: { onDone: () => void }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState<HostGroup["kind"]>("static");
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [rules, setRules] = useState<Rule[]>([{ field: "tag", value: "", negated: false }]);
  const [combine, setCombine] = useState<"all" | "any">("all");
  const [errorMessage, setErrorMessage] = useState("");
  const expression = buildExpression(rules, combine);

  const create = useMutation({
    mutationFn: () =>
      api.post<HostGroup>("/api/v1/host-groups", {
        name: name.trim(),
        description: description.trim(),
        kind,
        selector: kind === "dynamic" ? expression : undefined,
        host_ids: kind === "static" ? [...members] : undefined,
      }),
    onSuccess: (group) => {
      queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Group {name} created", { name: group.name }));
      onDone();
      navigate(`/groups/${group.id}`);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  const ready = name.trim() !== "" && (kind === "static" ? members.size > 0 : expression !== null);

  return (
    <Card
      title={t("New group")}
      description={t("The name is what a campaign selector will use; keep it short and without spaces.")}
    >
      <FieldGrid>
        <Field label={t("Name")}>
          <input placeholder={t("e.g. databases-gold")} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t("Description")}>
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label={t("Kind")} hint={kind === "static"
          ? t("A list you keep by hand; hosts join and leave it when you say so.")
          : t("A selector the server resolves every time it is read; a host tagged tomorrow is in the group tomorrow.")}>
          <select value={kind} onChange={(e) => setKind(e.target.value as HostGroup["kind"])}>
            <option value="static">{t("static: a member list")}</option>
            <option value="dynamic">{t("dynamic: a selector")}</option>
          </select>
        </Field>
      </FieldGrid>

      {kind === "static" ? (
        <HostChooser selected={members} onChange={setMembers} />
      ) : (
        <>
          <SelectorBuilder rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
          <SelectorPreview expression={expression} />
        </>
      )}

      <Actions>
        <button onClick={() => create.mutate()} disabled={!ready || create.isPending}>
          {create.isPending ? t("Creating…") : t("Create group")}
        </button>
        <button className="secondary" onClick={onDone} disabled={create.isPending}>{t("Cancel")}</button>
        {errorMessage && <p className="page-error">{errorMessage}</p>}
      </Actions>
    </Card>
  );
}

/**
 * The host list with a checkbox per row, for a static group. It reads the
 * same paged list as the host page and grows the same way; the chosen
 * hosts are kept by identifier, so a host chosen on one page stays chosen
 * when the search changes.
 */
export function HostChooser({ selected, onChange, title }: {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  // The heading over the list; a group calls its hosts members, an
  // order calls them targets.
  title?: string;
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
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    onChange(next);
  };

  return (
    <>
      <h4 className="widget-subhead">{title ?? t("Members")}</h4>
      <Toolbar end={<span>{t("{n} chosen", { n: selected.size })}</span>}>
        <input placeholder={t("Search hostname, address, machine ID or owner")} aria-label={t("Search hostname, address, machine ID or owner")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <button type="button" className="secondary" onClick={() => onChange(new Set([...selected, ...rows.map((host) => host.id)]))}>
          {t("Choose every listed host")}
        </button>
        <button type="button" className="secondary" onClick={() => onChange(new Set())} disabled={selected.size === 0}>
          {t("Clear")}
        </button>
      </Toolbar>
      {hosts.error ? <ErrorBox error={hosts.error} /> : hosts.isLoading ? (
        <Empty>{t("Loading…")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th></th><th>{t("Host")}</th><th>{t("State")}</th><th>{t("Site")}</th><th>{t("Environment")}</th><th>{t("Tags")}</th></tr>
          </thead>
          <tbody>
            {rows.map((host) => (
              <tr key={host.id}>
                <td><input type="checkbox" checked={selected.has(host.id)} onChange={() => toggle(host.id)} /></td>
                <td>{host.hostname}</td>
                <td><ConnectionState state={host.connection_state} /></td>
                <td>{host.site}</td>
                <td>{host.environment}</td>
                <td className="source">{host.tags.join(" ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {hosts.hasNextPage && (
        <p>
          <button type="button" className="secondary" onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
            {t("Load more ({n} left)", { n: total - rows.length })}
          </button>
        </p>
      )}
    </>
  );
}

/** One row of the selector builder: a fact about the host and its value. */
export type Rule = { field: RuleField; value: string; negated: boolean };

export type RuleField =
  | "tag" | "group" | "site" | "environment" | "os_family" | "os_version" | "capability"
  | "connection_state" | "lifecycle_state" | "owner" | "channel"
  | "security_updates" | "reboot_required" | "failed_units" | "agent_version"
  | "relay" | "failure_domain";

/** The facts a rule can name, in the order the builder offers them. */
export const RULE_FIELDS: RuleField[] = [
  "tag", "group", "site", "environment", "os_family", "os_version", "capability",
  "connection_state", "lifecycle_state", "owner", "channel",
  "security_updates", "reboot_required", "failed_units", "agent_version",
  "relay", "failure_domain",
];

/** The facts a host reports as yes or no; a host that has not reported is on neither side. */
const YES_NO_FIELDS: RuleField[] = ["security_updates", "reboot_required", "failed_units"];

/**
 * The rows as the expression the server will read: one leaf per row, a
 * negated row wrapped in `not`, and the rows joined by `all` or `any`.
 * Null means nothing to send - no row has a value yet.
 */
export function buildExpression(rules: Rule[], combine: "all" | "any"): SelectorExpression | null {
  const leaves = rules
    .filter((rule) => rule.value.trim() !== "")
    .map((rule): SelectorExpression => {
      // Every leaf the builder offers is a string on the wire; the channel
      // is typed narrower in the view, which is what the cast is for.
      const leaf = { [rule.field]: rule.value.trim() } as SelectorExpression;
      return rule.negated ? { not: leaf } : leaf;
    });
  if (leaves.length === 0) return null;
  if (leaves.length === 1) return leaves[0];
  return combine === "all" ? { all: leaves } : { any: leaves };
}

/** The expression in one line for people; the same shape the server logs. */
export function describeExpression(expression?: SelectorExpression | null): string {
  if (!expression) return "";
  if (expression.all) return `(${expression.all.map(describeExpression).join(" and ")})`;
  if (expression.any) return `(${expression.any.map(describeExpression).join(" or ")})`;
  if (expression.not) return `not ${describeExpression(expression.not)}`;
  const [field, value] = Object.entries(expression).find(([, v]) => typeof v === "string") ?? ["nothing", ""];
  return value ? `${field}=${value}` : field;
}

/**
 * The selector builder: rows of field and value, joined by all or any.
 * It builds the typed structure the server compiles, so what is shown as
 * the expression is exactly what will be sent - there is no text to
 * parse and nothing to get wrong in translation.
 */
export function SelectorBuilder({ rules, combine, onRules, onCombine }: {
  rules: Rule[];
  combine: "all" | "any";
  onRules: (rules: Rule[]) => void;
  onCombine: (combine: "all" | "any") => void;
}) {
  const t = useT();
  const expression = buildExpression(rules, combine);
  const update = (index: number, delta: Partial<Rule>) =>
    onRules(rules.map((rule, i) => (i === index ? { ...rule, ...delta } : rule)));
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
      <h4 className="widget-subhead">{t("Selector")}</h4>
      <Toolbar>
        <span>{t("the host has to match")}</span>
        <select value={combine} onChange={(e) => onCombine(e.target.value as "all" | "any")}>
          <option value="all">{t("every rule")}</option>
          <option value="any">{t("any rule")}</option>
        </select>
      </Toolbar>
      {rules.map((rule, index) => (
        <Toolbar key={index}>
          <label className="toggle" title={t("the rule holds when the fact is not on the host")}>
            <input type="checkbox" checked={rule.negated} onChange={(e) => update(index, { negated: e.target.checked })} />{" "}
            {t("not")}
          </label>
          <select value={rule.field} onChange={(e) => update(index, { field: e.target.value as RuleField, value: "" })}>
            {RULE_FIELDS.map((field) => <option key={field} value={field}>{names[field]}</option>)}
          </select>
          <RuleValue rule={rule} onChange={(value) => update(index, { value })} />
          <button type="button" className="secondary" onClick={() => onRules(rules.filter((_, i) => i !== index))} disabled={rules.length === 1}>
            {t("Remove")}
          </button>
        </Toolbar>
      ))}
      <Actions>
        <button type="button" className="secondary" onClick={() => onRules([...rules, { field: "tag", value: "", negated: false }])}>
          {t("Add a rule")}
        </button>
        <span className="source">
          {expression ? describeExpression(expression) : t("no rule has a value yet")}
        </span>
      </Actions>
    </>
  );
}

/**
 * The value of a rule. A state is picked from the states that exist; a
 * group from the saved groups; the rest is typed, because the panel does
 * not keep a list of sites or owners.
 */
function RuleValue({ rule, onChange }: { rule: Rule; onChange: (value: string) => void }) {
  const t = useT();
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<HostGroup>>("/api/v1/host-groups"),
    enabled: rule.field === "group",
    staleTime: 60 * 1000,
  });
  if (YES_NO_FIELDS.includes(rule.field)) {
    return (
      <select value={rule.value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{t("pick yes or no…")}</option>
        <option value="true">{t("yes")}</option>
        <option value="false">{t("no")}</option>
      </select>
    );
  }
  if (rule.field === "agent_version") {
    return (
      <input value={rule.value} placeholder={t("< 0.49.0")}
        onChange={(e) => onChange(e.target.value)} />
    );
  }
  switch (rule.field) {
    case "connection_state":
      return (
        <select value={rule.value} onChange={(e) => onChange(e.target.value)}>
          <option value="">{t("pick a state…")}</option>
          {["online", "offline", "stale", "unknown"].map((state) => <option key={state} value={state}>{t(state)}</option>)}
        </select>
      );
    case "lifecycle_state":
      return (
        <select value={rule.value} onChange={(e) => onChange(e.target.value)}>
          <option value="">{t("pick a state…")}</option>
          {["active", "quarantined", "recovery", "retiring", "retired"].map((state) => <option key={state} value={state}>{t(state)}</option>)}
        </select>
      );
    case "group":
      return (
        <select value={rule.value} onChange={(e) => onChange(e.target.value)}>
          <option value="">{t("pick a group…")}</option>
          {(groups.data?.items ?? []).map((group) => <option key={group.id} value={group.name}>{group.name}</option>)}
        </select>
      );
    default:
      return (
        <input
          placeholder={rule.field === "tag" ? t("key or key=value") : rule.field === "capability" ? t("e.g. packages.apt") : t("value")}
          value={rule.value}
          onChange={(e) => onChange(e.target.value)}
        />
      );
  }
}

/**
 * What the selector under construction resolves to now, asked of the
 * server as the rows change and answered with the count against the
 * caller's scope and a sample of names. The call waits for the typing to
 * settle; a selector the server refuses - a group that does not exist, a
 * cycle - shows the refusal in place of a count, not a zero.
 */
export function SelectorPreview({ expression }: { expression: SelectorExpression | null }) {
  const t = useT();
  const encoded = useDebounced(expression ? JSON.stringify(expression) : "");
  const preview = useQuery({
    queryKey: ["host-group-preview", encoded],
    queryFn: () => api.get<SelectorPreviewView>(`/api/v1/host-groups/preview?expression=${encodeURIComponent(encoded)}`),
    enabled: encoded !== "",
    staleTime: 10 * 1000,
    retry: false,
  });
  if (!expression) return null;
  const stale = encoded !== JSON.stringify(expression);
  return (
    <div data-testid="selector-preview">
      <h4 className="widget-subhead">{t("Matches now")}</h4>
      {preview.error ? (
        <p className="page-error">{preview.error instanceof ApiError ? preview.error.message : String(preview.error)}</p>
      ) : preview.isLoading || stale || !preview.data ? (
        <p className="source">{t("Counting…")}</p>
      ) : (
        <>
          <p>
            <strong>{t("{n} hosts", { n: preview.data.count })}</strong>
            {preview.data.count > preview.data.sample.length && (
              <span className="source"> {t("first {n} shown", { n: preview.data.sample.length })}</span>
            )}
          </p>
          {preview.data.sample.length > 0 && <p className="mono">{preview.data.sample.join(", ")}</p>}
        </>
      )}
    </div>
  );
}

/**
 * The form that changes a group in place: the name, the description and,
 * for a dynamic group, the selector. The write goes back with the tag the
 * group was read with, so an edit over somebody else's change is refused
 * rather than winning quietly. The kind does not change here; that is a
 * new group.
 *
 * A selector too deep for the builder's rows is edited as its JSON: the
 * rows would only approximate it, and a save from them would replace
 * what somebody wrote by hand.
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
  const [asJSON, setAsJSON] = useState(!saved.exact);
  const [jsonText, setJsonText] = useState(JSON.stringify(group.selector ?? {}, null, 2));
  const [errorMessage, setErrorMessage] = useState("");

  const parsed = useMemo((): { expression: SelectorExpression | null; error: string } => {
    if (!asJSON) return { expression: buildExpression(rules, combine), error: "" };
    try {
      const value = JSON.parse(jsonText) as SelectorExpression;
      if (!value || typeof value !== "object" || Array.isArray(value)) return { expression: null, error: t("the selector has to be a JSON object") };
      return { expression: value, error: "" };
    } catch {
      return { expression: null, error: t("the selector is not valid JSON") };
    }
  }, [asJSON, rules, combine, jsonText, t]);
  const dynamic = group.kind === "dynamic";
  const ready = name.trim() !== "" && (!dynamic || parsed.expression !== null);

  const save = useMutation({
    mutationFn: () =>
      api.put<HostGroup>(`/api/v1/host-groups/${group.id}`, {
        name: name.trim(),
        description: description.trim(),
        selector: dynamic ? parsed.expression : undefined,
      }, etag ? { headers: { "If-Match": etag } } : undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["host-group", group.id] });
      queryClient.invalidateQueries({ queryKey: ["host-group-hosts", group.id] });
      queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Group {name} saved", { name: name.trim() }));
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 412) {
        // The record moved under the editor; the page refetches, the form
        // is rebuilt from the current version, and the word about it has
        // to outlive the form.
        queryClient.invalidateQueries({ queryKey: ["host-group", group.id] });
        toast.error(t("The group changed since it was read; the form now shows the current version, start the edit again."));
        return;
      }
      setErrorMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <Card className="span-12" title={t("Edit group")} description={dynamic
      ? t("The name a selector names it by, the description, and the rule the server compiles.")
      : t("The name a selector names it by and the description; the members are edited on their own.")}>
      <FieldGrid>
        <Field label={t("Name")}>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t("Description")}>
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </FieldGrid>
      {dynamic && (
        <>
          {asJSON ? (
            <>
              <h4 className="widget-subhead">{t("Selector")}</h4>
              {!saved.exact && (
                <p className="source">{t("The saved selector is deeper than the builder's rows can say, so it is edited as written.")}</p>
              )}
              <textarea rows={10} style={{ width: "100%", fontFamily: "var(--font-mono)", fontSize: 12 }} value={jsonText} onChange={(e) => setJsonText(e.target.value)} />
              {parsed.error && <p className="page-error">{parsed.error}</p>}
              {saved.exact && (
                <p>
                  <button type="button" className="secondary" onClick={() => {
                    // The rows take the JSON back when it still fits
                    // them; otherwise they stay as they were.
                    const back = rulesOf(parsed.expression);
                    if (parsed.expression && back.exact) {
                      setRules(back.rules);
                      setCombine(back.combine);
                    }
                    setAsJSON(false);
                  }}>
                    {t("Back to the rules")}
                  </button>
                </p>
              )}
            </>
          ) : (
            <>
              <SelectorBuilder rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
              <p>
                <button type="button" className="secondary" onClick={() => {
                  setJsonText(JSON.stringify(parsed.expression ?? group.selector ?? {}, null, 2));
                  setAsJSON(true);
                }}>
                  {t("Edit as JSON")}
                </button>
              </p>
            </>
          )}
          <SelectorPreview expression={parsed.expression} />
        </>
      )}
      <Actions>
        <button onClick={() => { setErrorMessage(""); save.mutate(); }} disabled={!ready || save.isPending}>
          {save.isPending ? t("Saving…") : t("Save changes")}
        </button>
        <button className="secondary" onClick={onDone} disabled={save.isPending}>{t("Cancel")}</button>
        {errorMessage && <p className="page-error">{errorMessage}</p>}
      </Actions>
    </Card>
  );
}

/**
 * The campaigns and the policies whose selector names the group. A
 * campaign that ended keeps its selector for the trail and is listed with
 * its state; an enabled policy resolves the group at every check, so an
 * edit of the selector reaches it at the next one.
 */
function UsedBy({ usage, kind }: { usage: GroupUsage; kind: HostGroup["kind"] }) {
  const t = useT();
  const total = usage.campaigns.length + usage.policies.length;
  return (
    <Card className="span-12" title={t("Used by")} description={total === 0
      ? t("No campaign or policy names this group in its selector.")
      : kind === "dynamic"
        ? t("A change of the selector reaches every policy listed at its next check; a campaign keeps the snapshot it froze.")
        : t("A change of the members reaches every policy listed at its next check; a campaign keeps the snapshot it froze.")}>
      {total > 0 && (
        <table>
          <thead>
            <tr><th>{t("Record")}</th><th>{t("Name")}</th><th>{t("State")}</th></tr>
          </thead>
          <tbody>
            {usage.campaigns.map((campaign) => (
              <tr key={`campaign-${campaign.id}`}>
                <td>{t("campaign")}</td>
                <td><Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link></td>
                <td><span className="badge">{t(campaign.state)}</span></td>
              </tr>
            ))}
            {usage.policies.map((policy) => (
              <tr key={`policy-${policy.id}`}>
                <td>{t("policy")}</td>
                <td><Link to={`/policies/${policy.id}`}>{policy.name}</Link></td>
                <td><span className="badge">{t(policy.state)}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

/**
 * One group: what it is, and the hosts it resolves to now. For a static
 * group the member list can be replaced here; for a dynamic one the
 * selector is the definition, and the list under it is today's answer.
 */
function GroupPage({ id }: { id: string }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const permissions = usePermissions();
  const canWrite = permissions.has("host.group.write");
  const seesCampaigns = permissions.has("campaign.read");
  const deleteGroup = useDeleteGroup();
  // The record comes with its tag: the edit form writes back on that
  // version, and a write over a newer one is refused by the server.
  const group = useQuery({
    queryKey: ["host-group", id],
    queryFn: () => api.getWithMeta<GroupDetail>(`/api/v1/host-groups/${id}`),
    refetchInterval: REFRESH_INTERVAL,
  });
  const [search, setSearch] = useState("");
  const settled = useDebounced(search.trim());
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
    refetchInterval: REFRESH_INTERVAL,
  });
  const [editing, setEditing] = useState(false);
  const [editingMembers, setEditingMembers] = useState(false);
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("");

  const saveMembers = useMutation({
    mutationFn: () => api.put<HostGroup>(`/api/v1/host-groups/${id}/members`, { host_ids: [...members] }),
    onSuccess: () => {
      setEditingMembers(false);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["host-group", id] });
      queryClient.invalidateQueries({ queryKey: ["host-group-hosts", id] });
      queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      toast.success(t("Members saved"));
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (group.error) return <ErrorBox error={group.error} />;
  if (!group.data) return <Empty>{t("Loading…")}</Empty>;
  const g = group.data.data;
  const etag = group.data.etag;
  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const toggle = (hostID: string, on: boolean) => {
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(hostID); else next.delete(hostID);
      return next;
    });
  };
  // The header box ticks what is loaded, not what the group resolves to:
  // a page not yet fetched has hosts nobody has seen, and a campaign
  // must not reach them from a box that looked like "all".
  const allLoadedSelected = rows.length > 0 && rows.every((host) => selected.has(host.id));

  return (
    <>
      <PageHeader
        icon="groups"
        breadcrumb={[{ label: t("Groups"), to: "/groups" }]}
        title={<>{g.name} <KindBadge kind={g.kind} /></>}
        description={g.description || (g.kind === "dynamic" ? t("Resolved from its selector every time it is read.") : t("A member list kept by hand."))}
        actions={(
          <>
            {/* The wizard and the read form open with the group as the
                target; whoever cannot order a campaign is not shown the
                door to it. */}
            {seesCampaigns && (
              <button className="secondary" onClick={() => navigate(bulkAddress(g.name))}>{t("Start a campaign on this group")}</button>
            )}
            <button className="secondary" onClick={() => navigate(readsAddress(g.name))}>{t("Run a read on this group")}</button>
            {canWrite && !editing && (
              <button className="secondary" onClick={() => { setMessage(""); setEditing(true); }}>{t("Edit")}</button>
            )}
            {canWrite && g.kind === "static" && !editingMembers && (
              <button className="secondary" onClick={() => {
                // The editor starts from what the group resolves to now,
                // so a save without a change changes nothing.
                setMembers(new Set(rows.map((host) => host.id)));
                setMessage("");
                setEditingMembers(true);
              }}>
                {t("Edit members")}
              </button>
            )}
            {canWrite && (
              <button className="danger" onClick={async () => { if (await deleteGroup(g)) navigate("/groups"); }}>
                {t("Delete")}
              </button>
            )}
          </>
        )}
      />

      <div className="widgets">
        {editing && (
          <EditGroup key={etag} group={g} etag={etag} onDone={() => setEditing(false)} />
        )}

        {g.kind === "dynamic" && !editing && (
          <Card className="span-12" title={t("Selector")} description={t("The rule the server compiles into the host query; the list below is today's answer.")}>
            <p className="mono">{describeExpression(g.selector)}</p>
            <pre>{JSON.stringify(g.selector, null, 2)}</pre>
            {g.unresolvable && <p className="page-error">{t("The selector does not resolve: {reason}", { reason: g.unresolvable })}</p>}
          </Card>
        )}

        {g.used_by && <UsedBy usage={g.used_by} kind={g.kind} />}

        {editingMembers && (
          <Card className="span-12" title={t("Members")} description={t("The list is replaced whole: a host left unchecked leaves the group.")}>
            <HostChooser selected={members} onChange={setMembers} />
            <Actions>
              <button onClick={() => saveMembers.mutate()} disabled={saveMembers.isPending}>
                {saveMembers.isPending ? t("Saving…") : t("Save members ({n})", { n: members.size })}
              </button>
              <button className="secondary" onClick={() => setEditingMembers(false)} disabled={saveMembers.isPending}>{t("Cancel")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          </Card>
        )}

        <Card className="span-12" flush>
          <Toolbar end={hosts.data && <span>{t("{n} hosts", { n: total })}</span>}>
            <input placeholder={t("Search hostname, address, machine ID or owner")} aria-label={t("Search hostname, address, machine ID or owner")} value={search} onChange={(e) => setSearch(e.target.value)} />
            {message && !editingMembers && <span className="page-error">{message}</span>}
          </Toolbar>
          {hosts.error ? <ErrorBox error={hosts.error} /> : hosts.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : rows.length === 0 ? (
            <EmptyState>{t("The group resolves to no host you can see.")}</EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  {seesCampaigns && (
                    <th>
                      <input
                        type="checkbox"
                        aria-label={t("Select every loaded host")}
                        checked={allLoadedSelected}
                        onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((host) => host.id)) : new Set())}
                      />
                    </th>
                  )}
                  <th>{t("Host")}</th><th>{t("State")}</th><th>{t("System")}</th><th>{t("Site")}</th>
                  <th>{t("Environment")}</th><th>{t("Tags")}</th><th>{t("Last seen")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((host) => (
                  <tr key={host.id}>
                    {seesCampaigns && (
                      <td><input type="checkbox" checked={selected.has(host.id)} onChange={(e) => toggle(host.id, e.target.checked)} /></td>
                    )}
                    <td><Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link></td>
                    <td><ConnectionState state={host.connection_state} /></td>
                    <td>{host.os_distribution || host.os_family || "—"} {host.os_version}</td>
                    <td>{host.site}</td>
                    <td>{host.environment}</td>
                    <td className="source">{host.tags.join(" ")}</td>
                    <td><Time value={host.last_seen_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {hosts.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => hosts.fetchNextPage()} disabled={hosts.isFetchingNextPage}>
                {t("Load more ({n} left)", { n: total - rows.length })}
              </button>
            </p>
          )}
          {selected.size > 0 && (
            <div
              data-testid="selection-bar"
              style={{
                position: "sticky", bottom: 0, zIndex: 4,
                display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
                padding: "10px 16px", background: "var(--bg-panel)", borderTop: "1px solid var(--border)",
              }}
            >
              <span>{t("{n} selected", { n: selected.size })}</span>
              <button type="button" className="primary" onClick={() => navigate(bulkAddress(g.name, [...selected]))}>
                {t("Open in Bulk workspace ({n})", { n: selected.size })}
              </button>
              <button type="button" className="secondary" onClick={() => setSelected(new Set())}>{t("Clear selection")}</button>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
