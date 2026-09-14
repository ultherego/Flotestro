import { useState } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, loadedItems, LIST_PAGE, type Collection, type Page } from "../lib/api";
import { useDebounced } from "../lib/debounce";
import type { Host, HostGroup, SelectorExpression, Whoami } from "../lib/types";
import { REFRESH_INTERVAL } from "../lib/stream";
import { ConnectionState, Empty, ErrorBox, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { useT } from "../i18n";

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

  if (groups.error) return <ErrorBox error={groups.error} />;
  const items = groups.data?.items ?? [];

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
          {groups.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : items.length === 0 ? (
            <EmptyState action={canWrite && !creating && <button className="secondary" onClick={() => setCreating(true)}>{t("New group")}</button>}>
              {t("No groups yet. A campaign can still name hosts by site, environment, tags or a list.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Group")}</th><th>{t("Kind")}</th><th>{t("Selector")}</th>
                  <th className="num">{t("Hosts")}</th><th>{t("Created by")}</th><th>{t("Updated")}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((group) => (
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
        <SelectorBuilder rules={rules} combine={combine} onRules={setRules} onCombine={setCombine} />
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
export function HostChooser({ selected, onChange }: { selected: Set<string>; onChange: (next: Set<string>) => void }) {
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
      <h4 className="widget-subhead">{t("Members")}</h4>
      <Toolbar end={<span>{t("{n} chosen", { n: selected.size })}</span>}>
        <input placeholder={t("Search hostname, address, machine ID or owner")} value={search} onChange={(e) => setSearch(e.target.value)} />
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
  | "tag" | "group" | "site" | "environment" | "os_family" | "capability"
  | "connection_state" | "lifecycle_state" | "owner";

/** The facts a rule can name, in the order the builder offers them. */
export const RULE_FIELDS: RuleField[] = [
  "tag", "group", "site", "environment", "os_family", "capability",
  "connection_state", "lifecycle_state", "owner",
];

/**
 * The rows as the expression the server will read: one leaf per row, a
 * negated row wrapped in `not`, and the rows joined by `all` or `any`.
 * Null means nothing to send - no row has a value yet.
 */
export function buildExpression(rules: Rule[], combine: "all" | "any"): SelectorExpression | null {
  const leaves = rules
    .filter((rule) => rule.value.trim() !== "")
    .map((rule): SelectorExpression => {
      const leaf: SelectorExpression = {};
      leaf[rule.field] = rule.value.trim();
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
    os_family: t("os family"), capability: t("capability"),
    connection_state: t("connection state"), lifecycle_state: t("lifecycle state"), owner: t("owner"),
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
 * One group: what it is, and the hosts it resolves to now. For a static
 * group the member list can be replaced here; for a dynamic one the
 * selector is the definition, and the list under it is today's answer.
 */
function GroupPage({ id }: { id: string }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canWrite = permissions.has("host.group.write");
  const group = useQuery({
    queryKey: ["host-group", id],
    queryFn: () => api.get<HostGroup>(`/api/v1/host-groups/${id}`),
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
  const [editingMembers, setEditingMembers] = useState(false);
  const [members, setMembers] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("");

  const saveMembers = useMutation({
    mutationFn: () => api.put<HostGroup>(`/api/v1/host-groups/${id}/members`, { host_ids: [...members] }),
    onSuccess: () => {
      setEditingMembers(false);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["host-group", id] });
      queryClient.invalidateQueries({ queryKey: ["host-group-hosts", id] });
      queryClient.invalidateQueries({ queryKey: ["host-groups"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });
  const remove = useMutation({
    mutationFn: () => api.del<void>(`/api/v1/host-groups/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["host-groups"] });
      navigate("/groups");
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (group.error) return <ErrorBox error={group.error} />;
  if (!group.data) return <Empty>{t("Loading…")}</Empty>;
  const g = group.data;
  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;

  return (
    <>
      <PageHeader
        icon="groups"
        breadcrumb={[{ label: t("Groups"), to: "/groups" }]}
        title={<>{g.name} <KindBadge kind={g.kind} /></>}
        description={g.description || (g.kind === "dynamic" ? t("Resolved from its selector every time it is read.") : t("A member list kept by hand."))}
        actions={canWrite && (
          <>
            {g.kind === "static" && !editingMembers && (
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
            <button
              className="danger"
              disabled={remove.isPending}
              onClick={() => {
                if (window.confirm(t("Delete the group {name}? A selector that names it will stop resolving.", { name: g.name }))) remove.mutate();
              }}
            >
              {t("Delete")}
            </button>
          </>
        )}
      />

      <div className="widgets">
        {g.kind === "dynamic" && (
          <Card className="span-12" title={t("Selector")} description={t("The rule the server compiles into the host query; the list below is today's answer.")}>
            <p className="mono">{describeExpression(g.selector)}</p>
            <pre>{JSON.stringify(g.selector, null, 2)}</pre>
            {g.unresolvable && <p className="page-error">{t("The selector does not resolve: {reason}", { reason: g.unresolvable })}</p>}
          </Card>
        )}

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
            <input placeholder={t("Search hostname, address, machine ID or owner")} value={search} onChange={(e) => setSearch(e.target.value)} />
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
                  <th>{t("Host")}</th><th>{t("State")}</th><th>{t("System")}</th><th>{t("Site")}</th>
                  <th>{t("Environment")}</th><th>{t("Tags")}</th><th>{t("Last seen")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((host) => (
                  <tr key={host.id}>
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
        </Card>
      </div>
    </>
  );
}
