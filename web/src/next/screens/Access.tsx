import { useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import { copyToClipboard } from "../../lib/clipboard";
import { absoluteTime, relativeTime, toInstant } from "../../lib/format";
import type { ApiToken, GroupMapping, Principal, RoleBinding, Whoami } from "../../lib/types";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Banner, Bars, Bones, Card, Check, Empty, Fact, Facts, Field, Fields, HeadActions, Kpi, Modal, Note, Pager, Pill, Problem, Seg, Stack, Table, Tabs, Tags, Toolbar, type Tone,
} from "../kit";

/**
 * Who may sign in to this installation, and what each of them may do.
 *
 * The screen the owner named: every row carried seven buttons, so a page of
 * fifty carried three hundred and fifty and none of them was the one
 * anybody wanted. A row says what a subject is; everything that can be done
 * to one lives behind its name, and what can be done to many lives in a bar
 * that appears when many are chosen and says how many it acts on.
 *
 * "Who may sign in" and "the identities" are two answers to one question -
 * the first includes the people of the directory the panel has never seen -
 * so they are two scopes of one table rather than two tables with two
 * filters and two pagers under them.
 */

/* ----------------------------------------------------------- the facts */

/** What the panel knows about an identity's password; never the password. */
type PasswordState = {
  set_at: string;
  set_by: string;
  must_change: boolean;
  locked_until?: string;
  failed_attempts: number;
  last_used_at?: string;
};

/** An identity as the listing carries it. `password` absent means it has none. */
type ListedPrincipal = Principal & { disabled_at?: string; password?: PasswordState };

/** A page of identities, with the counts the server took over the whole match. */
type PrincipalList = Collection<ListedPrincipal> & {
  total?: number;
  by_kind?: Record<string, number>;
  by_role?: Record<string, number>;
  without_bindings?: number;
};

/** A live browser session of an identity. A token is not one of these. */
type SessionView = {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  idle_expires_at: string;
  remote_addr?: string;
  user_agent?: string;
  acr?: string;
};

/** A freshly issued token, shown once and never fetched again. */
type IssuedToken = { subject: string; token: string; token_expires_at?: string };

/** One role somebody holds, as the holders listing writes it. */
type HolderRole = { role: string; scope: string; from: string; group?: string };

/**
 * Somebody who may sign in, whether or not the panel has ever seen them.
 *
 * A directory account in a mapped group holds its role before it has a
 * record here: the record is made at the first sign-in. A screen that
 * listed only the records would tell an administrator that the person who
 * administers the fleet has no access.
 */
type Holder = {
  subject: string;
  display_name?: string;
  kind: string;
  principal_id?: string;
  signed_in: boolean;
  groups?: string[];
  directory_disabled?: boolean;
  roles: HolderRole[];
};

type Holders = {
  items: Holder[];
  count: number;
  directory: { configured: boolean; read: boolean; reason?: string; users?: number };
};

/** A team, as a grant has to name one: only what this screen prints. */
type TeamChoice = { id: string; name: string };

/** One role of the installation, as the catalogue lists it. */
type RoleInfo = { role: string; built_in?: boolean; description?: string; permissions: string[] };

/**
 * The scope of a binding as the server keeps it. Every category is
 * optional here because a record written before a category existed has not
 * got it, and a reader that assumed one would read "narrowed" as "all".
 */
export type BindingScope = {
  site?: string;
  environment?: string;
  team_scope?: { mode?: string; team_id?: string };
  owners?: string[];
  tags?: string[];
};

/** The two vocabularies a binding may be written in; they never mix. */
export type GrantScope = "site" | "team";

/**
 * One role somebody holds, from wherever it comes.
 *
 * The two listings answer differently - a binding carries the scope as a
 * record, a holder carries it as a sentence the server already wrote - so
 * the row keeps whichever arrived and the cell reads the one it has.
 */
type Held = {
  role: string;
  scope?: BindingScope;
  /** The scope as the holders listing phrases it. */
  words?: string;
  from: "binding" | "group";
  group?: string;
  valid_until?: string;
};

/**
 * One subject in the list, whichever scope it was read in.
 *
 * What a scope could not say is undefined rather than nought: the holders
 * listing says nothing about tokens, and a column that drew a nought there
 * would say this service holds none.
 */
type Row = {
  subject: string;
  name: string;
  kind: string;
  /** The record the panel keeps, where it has one. */
  id?: string;
  roles: Held[];
  tokens?: ApiToken[];
  password?: PasswordState;
  disabled_at?: string;
  /** Known only in the scope that reads the directory. */
  groups?: string[];
  directory_disabled?: boolean;
  /** Whether the panel has a record of this subject at all. */
  known: boolean;
};

/* -------------------------------------------------------- the readings */

/** The reason every change of the access rules is recorded with. */
const REASON_MIN_LENGTH = 8;
/** The lifetime of a token when the form does not say; the server's own default. */
const DEFAULT_TOKEN_TTL_HOURS = 720;
/** The longest life the server gives a token: a year. */
const MAX_TOKEN_TTL_HOURS = 8760;

/** A reason long enough for the trail. */
export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= REASON_MIN_LENGTH;
}

/** A scope part that names no site or environment: the asterisk, or nothing. */
function anyScope(value: string | undefined): boolean {
  return !value || value === "*";
}

/** A list category that names every value: absent, empty of narrowing, or an asterisk. */
export function anyList(values: string[] | undefined): boolean {
  return !values || values.length === 0 || values.includes("*");
}

/** The team a binding is bound to, or nothing when it covers any team. */
export function scopeTeam(scope: BindingScope | undefined): string {
  return scope?.team_scope?.mode === "exact" ? scope.team_scope.team_id ?? "" : "";
}

/** Which vocabulary a binding is written in. */
export function scopeKind(scope: BindingScope | undefined): GrantScope {
  return scopeTeam(scope) ? "team" : "site";
}

/** How far a scope reaches, which is the thing a reader checks first. */
export type Reach = "fleet" | "nothing" | "narrowed";

/**
 * A scope in one sentence, with how far it reaches said apart from it.
 *
 * Every category that narrows is named. A category left out of the
 * sentence is one somebody later reads as "all", and the two ends of the
 * range - the whole fleet, and a rule that reaches no host at all - are
 * said as such rather than left to be worked out from four asterisks.
 */
export function readScope(t: Translate, scope: BindingScope | undefined, teamName?: string): {
  words: string;
  reach: Reach;
} {
  const team = scopeTeam(scope);
  const owners = anyList(scope?.owners) ? "" : (scope?.owners ?? []).join(", ");
  const tags = anyList(scope?.tags) ? "" : (scope?.tags ?? []).join(", ");
  // An empty list is not a missing list: it names no value, so the rule
  // reaches nothing. That is a mistake somebody has to see, not infer.
  const nothing = scope?.owners?.length === 0 || scope?.tags?.length === 0;
  const parts: string[] = [];
  if (team) parts.push(t("team {team}", { team: teamName || team }));
  else {
    parts.push(anyScope(scope?.site) ? t("any site") : t("site {site}", { site: scope?.site ?? "" }));
    parts.push(anyScope(scope?.environment)
      ? t("any environment")
      : t("environment {environment}", { environment: scope?.environment ?? "" }));
  }
  if (owners) parts.push(t("owner {owners}", { owners }));
  if (tags) parts.push(t("tag {tags}", { tags }));
  if (nothing) return { words: t("reaches nothing"), reach: "nothing" };
  if (!team && anyScope(scope?.site) && anyScope(scope?.environment) && !owners && !tags) {
    return { words: t("the whole fleet"), reach: "fleet" };
  }
  return { words: parts.join(" · "), reach: "narrowed" };
}

/** The colour of a reach: the whole fleet is a thing to notice, nothing is a fault. */
export function reachTone(reach: Reach): Tone {
  return reach === "fleet" ? "warn" : reach === "nothing" ? "error" : "neutral";
}

/** A comma-separated field as the list the server reads. */
export function valueList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((part) => part.trim()).filter((part) => part !== "");
}

/**
 * A comma-separated list as a mapping takes it. Nothing typed returns
 * undefined, which the caller leaves OUT of the request: a missing category
 * is every one of them and an empty list is none, and sending the wrong one
 * of those two either widens a rule or makes it reach nobody.
 */
export function listFromText(text: string): string[] | undefined {
  const values = valueList(text);
  return values.length > 0 ? values : undefined;
}

/** The fields one grant is written from. */
export type GrantFields = {
  role: string; site: string; environment: string; team: string;
  owners: string; tags: string; validUntil: string; reason: string;
};

/** The request one grant makes: the route and the whole body. */
export function grantRequest(principalID: string, kind: GrantScope, fields: GrantFields): {
  path: string;
  body: Record<string, unknown>;
} {
  const common = { role: fields.role, valid_until: toInstant(fields.validUntil), reason: fields.reason.trim() };
  if (kind === "team") {
    return { path: `/api/v1/principals/${principalID}/team-roles`, body: { ...common, team: fields.team.trim() } };
  }
  // The team is said in words even where the binding does not narrow by
  // one: the server refuses a grant that leaves it out, because a team
  // omitted by accident would widen the grant in silence.
  return {
    path: `/api/v1/principals/${principalID}/roles`,
    body: {
      ...common,
      site: fields.site.trim(),
      environment: fields.environment.trim(),
      team_scope: { mode: "any" },
      owners: valueList(fields.owners),
      tags: valueList(fields.tags),
    },
  };
}

/**
 * The scope a grant is about to write, read the way the server will read
 * it. The form shows this before sending, so an operator sees what the
 * binding reaches rather than what they typed into four boxes.
 */
export function previewScope(kind: GrantScope, fields: GrantFields): BindingScope {
  if (kind === "team") {
    return {
      site: "*", environment: "*",
      team_scope: { mode: "exact", team_id: fields.team.trim() },
      owners: ["*"], tags: ["*"],
    };
  }
  const owners = valueList(fields.owners);
  const tags = valueList(fields.tags);
  return {
    site: fields.site.trim() || "*",
    environment: fields.environment.trim() || "*",
    team_scope: { mode: "any" },
    owners: owners.length === 0 ? ["*"] : owners,
    tags: tags.length === 0 ? ["*"] : tags,
  };
}

/** Whether a token ends within the coming week. */
export function expiresSoon(token: Pick<ApiToken, "expires_at">, now = Date.now(), days = 7): boolean {
  if (!token.expires_at) return false;
  const at = new Date(token.expires_at).getTime();
  if (Number.isNaN(at)) return false;
  return at > now && at - now <= days * 24 * 60 * 60 * 1000;
}

/** A binding whose day has passed stays on the record and grants nothing. */
export function expired(validUntil: string | undefined, now = Date.now()): boolean {
  if (!validUntil) return false;
  const at = new Date(validUntil).getTime();
  return !Number.isNaN(at) && at <= now;
}

/* ------------------------------------------------------- the two scopes */

/** The identities the panel keeps records of, as rows of the one table. */
export function rowsOfPrincipals(items: ListedPrincipal[]): Row[] {
  return items.map((one) => ({
    subject: one.subject,
    name: one.display_name ?? "",
    kind: one.kind,
    id: one.id,
    // The field may not arrive at all, and one missing key used to take the
    // whole screen down.
    roles: (one.bindings ?? []).map((binding: RoleBinding) => ({
      role: binding.role,
      scope: binding.scope as BindingScope,
      from: "binding" as const,
      valid_until: binding.valid_until,
    })),
    tokens: one.tokens ?? [],
    password: one.password,
    disabled_at: one.disabled_at,
    known: true,
  }));
}

/**
 * Everybody who may sign in, as rows of the same table.
 *
 * The directory's people come first whatever else is on: an administrator
 * asking who has access means the people, and the panel's own records are
 * tokens, runners and whatever a suite left behind.
 */
export function rowsOfHolders(items: Holder[]): Row[] {
  const fromDirectory = (holder: Holder) => holder.roles.some((role) => role.from === "group");
  return [...items]
    .sort((a, b) => {
      const bySource = Number(fromDirectory(b)) - Number(fromDirectory(a));
      return bySource !== 0 ? bySource : a.subject.localeCompare(b.subject);
    })
    .map((holder) => ({
      subject: holder.subject,
      name: holder.display_name ?? "",
      kind: holder.kind,
      id: holder.principal_id,
      roles: holder.roles.map((role) => ({
        role: role.role,
        words: shortScope(role.scope),
        from: role.from === "group" ? ("group" as const) : ("binding" as const),
        group: role.group,
      })),
      // This listing says nothing about tokens or passwords, and nothing
      // said is not nothing held.
      tokens: undefined,
      groups: holder.groups,
      directory_disabled: holder.directory_disabled,
      known: holder.signed_in || holder.principal_id !== undefined,
    }));
}

/** The scope as the holders listing writes it, with the categories that say nothing left out. */
export function shortScope(scope: string): string {
  return scope.split(" ").filter((part) => !part.endsWith("=*")).join(" ");
}

/* --------------------------------------------------------- the filter */

/** Which population the one table is drawn over. */
export type Scope = "signin" | "identities";

/** The named fields the list is narrowed by. */
export type Filter = {
  subject: string;
  name: string;
  role: string;
  kind: string;
  status: "enabled" | "disabled";
};

export const NO_FILTER: Filter = { subject: "", name: "", role: "", kind: "", status: "enabled" };

/** Whether anything is asked of the panel beyond what the server narrowed. */
export function narrowsHere(filter: Filter): boolean {
  return filter.name.trim() !== "" || filter.role !== "" || filter.kind !== "";
}

/**
 * The rows a filter leaves, field by field.
 *
 * The server narrows by one pattern over the subject OR the name, so it
 * hands back a superset of what these named fields ask for; this says what
 * each field actually means. The count under the table says which of the
 * two numbers it is quoting, because "50 of 1805" over a page the panel
 * then narrowed again is the fault this screen was rewritten for.
 */
export function narrowRows(rows: Row[], filter: Filter): Row[] {
  const has = (value: string, needle: string) =>
    value.toLowerCase().includes(needle.trim().toLowerCase());
  return rows.filter((row) =>
    (!filter.subject.trim() || has(row.subject, filter.subject))
    && (!filter.name.trim() || has(row.name, filter.name))
    && (!filter.kind || row.kind === filter.kind)
    && (!filter.role || row.roles.some((one) => one.role === filter.role)));
}

/** What a subject's state is, as the one word in colour the list shows. */
export function statusOf(t: Translate, row: Row): { label: string; tone: Tone } {
  if (row.disabled_at) return { label: t("Disabled"), tone: "unknown" };
  if (row.directory_disabled) return { label: t("Locked in the directory"), tone: "error" };
  if (!row.known) return { label: t("Not signed in yet"), tone: "info" };
  return { label: t("Enabled"), tone: "ok" };
}

/* ------------------------------------------------------------ the asks */

/** A change waiting for its reason. One shape, so one dialog answers them all. */
type Ask =
  | { kind: "disable"; rows: Row[] }
  | { kind: "enable"; rows: Row[] }
  | { kind: "revoke-tokens"; rows: Row[] }
  | { kind: "issue-token"; row: Row }
  | { kind: "revoke-token"; row: Row; token: ApiToken }
  | { kind: "revoke-role"; row: Row; held: Held; teamName: string }
  | { kind: "end-session"; row: Row; session: SessionView }
  | { kind: "clear-password"; row: Row }
  | { kind: "remove-mapping"; mapping: GroupMapping };

/* ---------------------------------------------------------- the screen */

export function Access() {
  const t = useT();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const open = params.get("who") ?? "";

  const [scope, setScope] = useState<Scope>("signin");
  // What is typed, and what the list is actually drawn from. They are two
  // things because the filter has an Apply: a list that re-reads the server
  // on every keystroke cannot be filled in by somebody who types slowly.
  const [draft, setDraft] = useState<Filter>(NO_FILTER);
  const [filter, setFilter] = useState<Filter>(NO_FILTER);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const [picked, setPicked] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);
  const [ask, setAsk] = useState<Ask | null>(null);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [refusal, setRefusal] = useState<ApiError | null>(null);

  const onError = (error: unknown) => setRefusal(error instanceof ApiError ? error : null);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["principals"] });
    void queryClient.invalidateQueries({ queryKey: ["access-holders"] });
  };

  /* The roles and the teams are read rather than assumed. An installation
     defines roles of its own, so a form offering the product's six would
     offer six of however many there are. */
  const catalogue = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<Collection<RoleInfo>>("/api/v1/roles"),
    retry: false,
    staleTime: 60 * 1000,
  });
  const teams = useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<TeamChoice>>("/api/v1/teams"),
    retry: false,
    staleTime: 60 * 1000,
  });
  const teamName = (id: string) => teams.data?.items.find((team) => team.id === id)?.name ?? id;
  const roleNames = (catalogue.data?.items ?? []).map((one) => one.role);

  // The identities narrow on the server: an installation whose suites had
  // been running for a month had 1805 of them, and the person looking for
  // their own name could not find it among the leftovers.
  const asked = new URLSearchParams();
  if (filter.status === "disabled") {
    asked.set("disabled", "true");
  } else {
    asked.set("limit", String(size));
    asked.set("offset", String((page - 1) * size));
    const needle = filter.subject.trim() || filter.name.trim();
    if (needle) asked.set("q", needle);
  }
  const principals = useQuery({
    queryKey: ["principals", asked.toString()],
    queryFn: () => api.get<PrincipalList>(`/api/v1/principals?${asked}`),
    retry: false,
  });
  const holders = useQuery({
    queryKey: ["access-holders"],
    queryFn: () => api.get<Holders>("/api/v1/access/holders"),
    retry: false,
    staleTime: 60 * 1000,
  });

  const error = scope === "signin" ? holders.error : principals.error;
  if (error instanceof ApiError && error.forbidden) {
    return <Empty>{t("You do not have permission to manage access.")}</Empty>;
  }
  if (error) return <Problem>{String(error)}</Problem>;

  /* One population, chosen by the scope. The server pages the identities;
     the directory answers with everybody at once, so that scope is paged
     here and the count below says which of the two it is quoting. */
  const serverPaged = scope === "identities" && filter.status !== "disabled";
  const read = scope === "signin"
    ? rowsOfHolders(holders.data?.items ?? [])
    : rowsOfPrincipals(principals.data?.items ?? []);
  const wanted = read.filter((row) =>
    scope === "identities" || (filter.status === "disabled" ? !!row.directory_disabled : !row.directory_disabled));
  const narrowed = narrowRows(wanted, filter);
  const rows = serverPaged ? narrowed : narrowed.slice((page - 1) * size, page * size);
  const total = serverPaged ? principals.data?.total ?? 0 : narrowed.length;
  const loading = scope === "signin" ? holders.isLoading : principals.isLoading;

  const openRow = rows.find((row) => row.subject === open)
    ?? narrowed.find((row) => row.subject === open);
  const chosen = rows.filter((row) => picked.includes(row.subject) && row.id);

  const address = (subject: string) => {
    const next = new URLSearchParams(params);
    if (subject) next.set("who", subject); else next.delete("who");
    return { search: `?${next}` };
  };
  const close = () => {
    const next = new URLSearchParams(params);
    next.delete("who");
    setParams(next, { replace: true });
  };
  const apply = () => { setFilter(draft); setPage(1); setPicked([]); };
  const reset = () => { setDraft(NO_FILTER); setFilter(NO_FILTER); setPage(1); setPicked([]); };

  /* --------------------------------------------------- what the asks do */

  const settled = () => { setAsk(null); refresh(); };
  const disable = useMutation({
    mutationFn: async ({ rows: many, reason }: { rows: Row[]; reason: string }) => {
      // One at a time rather than all at once: the trail reads in the order
      // the administrator meant, and a refusal stops the rest.
      for (const row of many) {
        await api.del(`/api/v1/principals/${row.id}?reason=${encodeURIComponent(reason)}`);
      }
    },
    onSuccess: () => { setPicked([]); settled(); }, onError,
  });
  const enable = useMutation({
    mutationFn: async ({ rows: many, reason }: { rows: Row[]; reason: string }) => {
      for (const row of many) await api.post(`/api/v1/principals/${row.id}/enable`, { reason });
    },
    onSuccess: () => { setPicked([]); settled(); }, onError,
  });
  const revokeTokens = useMutation({
    mutationFn: async ({ rows: many, reason }: { rows: Row[]; reason: string }) => {
      for (const row of many) {
        for (const token of row.tokens ?? []) {
          await api.del(`/api/v1/principals/${row.id}/tokens/${token.id}?reason=${encodeURIComponent(reason)}`);
        }
      }
    },
    onSuccess: () => { setPicked([]); settled(); }, onError,
  });
  const [tokenDescription, setTokenDescription] = useState("");
  const [tokenTTL, setTokenTTL] = useState(String(DEFAULT_TOKEN_TTL_HOURS));
  const ttlHours = Number.parseInt(tokenTTL, 10);
  const ttlValid = Number.isInteger(ttlHours) && ttlHours >= 1 && ttlHours <= MAX_TOKEN_TTL_HOURS;
  const issueToken = useMutation({
    mutationFn: ({ row, reason }: { row: Row; reason: string }) =>
      api.post<IssuedToken>(`/api/v1/principals/${row.id}/tokens`, {
        reason, description: tokenDescription.trim(), token_ttl_hours: ttlHours,
      }),
    onSuccess: (token) => { setIssued(token); setCopied(false); setTokenDescription(""); settled(); },
    onError,
  });
  const revokeToken = useMutation({
    mutationFn: ({ row, token, reason }: { row: Row; token: ApiToken; reason: string }) =>
      api.del(`/api/v1/principals/${row.id}/tokens/${token.id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: settled, onError,
  });
  const revokeRole = useMutation({
    mutationFn: ({ row, held, reason }: { row: Row; held: Held; reason: string }) => {
      const team = scopeTeam(held.scope);
      // A team binding is keyed on its team, not on the site and the
      // environment it leaves at the asterisk, so it has its own route.
      if (team) return api.del(`/api/v1/principals/${row.id}/team-roles/${held.role}`, { team, reason });
      const site = held.scope?.site === "*" ? "" : held.scope?.site ?? "";
      const environment = held.scope?.environment === "*" ? "" : held.scope?.environment ?? "";
      return api.del(`/api/v1/principals/${row.id}/roles/${held.role}`, { site, environment, reason });
    },
    onSuccess: settled, onError,
  });
  const endSession = useMutation({
    mutationFn: ({ row, session, reason }: { row: Row; session: SessionView; reason: string }) =>
      api.del(`/api/v1/principals/${row.id}/sessions/${session.id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: () => {
      setAsk(null);
      void queryClient.invalidateQueries({ queryKey: ["principal-sessions"] });
    },
    onError,
  });
  const clearPassword = useMutation({
    mutationFn: ({ row, reason }: { row: Row; reason: string }) =>
      api.del(`/api/v1/principals/${row.id}/password?reason=${encodeURIComponent(reason.trim())}`),
    onSuccess: settled, onError,
  });
  const removeMapping = useMutation({
    mutationFn: ({ mapping, reason }: { mapping: GroupMapping; reason: string }) =>
      api.del(`/api/v1/group-mappings/${mapping.id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: () => {
      setAsk(null);
      void queryClient.invalidateQueries({ queryKey: ["group-mappings"] });
    },
    onError,
  });

  const busy = disable.isPending || enable.isPending || revokeTokens.isPending || issueToken.isPending
    || revokeToken.isPending || revokeRole.isPending || endSession.isPending || clearPassword.isPending;

  /* ------------------------------------------------------- what is drawn */

  const kinds = scope === "identities" && filter.status !== "disabled"
    ? Object.entries(principals.data?.by_kind ?? {})
    : Object.entries(narrowed.reduce<Record<string, number>>((all, row) => {
        all[row.kind] = (all[row.kind] ?? 0) + 1;
        return all;
      }, {}));
  const byRole = scope === "identities" && filter.status !== "disabled"
    ? Object.entries(principals.data?.by_role ?? {})
    : [];
  const kindOptions = [...new Set(read.map((row) => row.kind))].sort();

  return (
    <>
      <HeadActions><button type="button" onClick={() => { setCreating(true); close(); }} data-testid="create-identity">
            {t("Create identity")}
          </button></HeadActions>

      {refusal && <Refusal error={refusal} close={() => setRefusal(null)} />}

      {/* The value of a new token is in the answer that minted it and
          nowhere else: the panel keeps only its digest. */}
      {issued && (
        <Banner
          tone="info"
          actions={
            <>
              <button type="button" onClick={() => { void copyToClipboard(issued.token).then(setCopied); }}>
                {copied ? t("Token copied") : t("Copy token")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setIssued(null)}>{t("Close")}</button>
            </>
          }
        >
          {t("Token for {subject} issued; it is shown once.", { subject: issued.subject })}{" "}
          <code>{issued.token}</code>
          {issued.token_expires_at && <> · {t("expires {when}", { when: absoluteTime(issued.token_expires_at) })}</>}
        </Banner>
      )}

      <Board screen={ACCESS_SCREEN} catalogue={ACCESS} drawn={{
        signin: (
          <Kpi
            hero
            icon="access"
            label={t("Who may sign in")}
            value={holders.data?.items.length ?? null}
            note={t("including the directory accounts the panel has never seen")}
          />
        ),
        identities: (
          <Kpi
            icon="accounts"
            label={t("Identities on record")}
            value={principals.data?.total ?? null}
            note={t("the records this panel keeps itself")}
          />
        ),
        norole: (
          <Kpi
            icon="identity"
            label={t("Without a role of their own")}
            value={principals.data?.without_bindings ?? null}
            tone={principals.data?.without_bindings ? "warn" : "ok"}
            note={t("their roles, if they have any, come from a group")}
          />
        ),

        filter: (
          <Card
            title={t("Find somebody")}
            note={t("The subject and the name go to the server; the role and the kind narrow the page it returned.")}
          >
            <Stack>
              <Fields>
                <Field label={t("Subject")} hint={t("The name the trail records.")}>
                  <input
                    value={draft.subject}
                    onChange={(event) => setDraft({ ...draft, subject: event.target.value })}
                    data-testid="filter-subject"
                  />
                </Field>
                <Field label={t("Name")}>
                  <input
                    value={draft.name}
                    onChange={(event) => setDraft({ ...draft, name: event.target.value })}
                    data-testid="filter-name"
                  />
                </Field>
                <Field label={t("Role")}>
                  <select
                    value={draft.role}
                    onChange={(event) => setDraft({ ...draft, role: event.target.value })}
                    data-testid="filter-role"
                  >
                    <option value="">{t("any role")}</option>
                    {roleNames.map((one) => <option key={one} value={one}>{one}</option>)}
                  </select>
                </Field>
                <Field label={t("Kind")}>
                  <select
                    value={draft.kind}
                    onChange={(event) => setDraft({ ...draft, kind: event.target.value })}
                    data-testid="filter-kind"
                  >
                    <option value="">{t("any kind")}</option>
                    {kindOptions.map((one) => <option key={one} value={one}>{one}</option>)}
                  </select>
                </Field>
                <Field label={t("Status")}>
                  <select
                    value={draft.status}
                    onChange={(event) => setDraft({ ...draft, status: event.target.value as Filter["status"] })}
                    data-testid="filter-status"
                  >
                    <option value="enabled">{t("Enabled")}</option>
                    <option value="disabled">{t("Disabled")}</option>
                  </select>
                </Field>
              </Fields>
              <Actions>
                <button type="button" onClick={apply} data-testid="filter-apply">{t("Apply")}</button>
                <button type="button" className="fl-quiet" onClick={reset} data-testid="filter-reset">
                  {t("Reset")}
                </button>
              </Actions>
            </Stack>
          </Card>
        ),

        create: creating && (
          <CreateIdentity
            roles={roleNames}
            onDone={(token) => { setCreating(false); if (token) { setIssued(token); setCopied(false); } refresh(); }}
            onCancel={() => setCreating(false)}
            onError={onError}
          />
        ),

        list: (
          <Card
            title={scope === "signin" ? t("Who may sign in") : t("Identities on record")}
            flush
            tools={
              <Seg
                value={scope}
                label={t("Whose access to show")}
                onChange={(next) => { setScope(next); setPage(1); setPicked([]); }}
                options={[
                  { value: "signin", label: t("Who may sign in") },
                  { value: "identities", label: t("Identities on record") },
                ]}
              />
            }
            foot={
              <>
                <Pager page={page} size={size} total={total} onPage={setPage} onSize={setSize} />
                {/* The one count says what it counted. Where the panel
                    narrowed the page further than the server did, it says so
                    rather than letting the range above pass for the answer. */}
                {serverPaged && narrowsHere(filter) && (
                  <Note>
                    {t("{shown} of the {listed} the server sent match the name, the role and the kind.", {
                      shown: rows.length, listed: principals.data?.items.length ?? 0,
                    })}
                  </Note>
                )}
                {chosen.length > 0 && (
                  <Banner
                    tone="info"
                    actions={
                      <>
                        {filter.status === "disabled"
                          ? (
                            <button type="button" onClick={() => setAsk({ kind: "enable", rows: chosen })}
                                    data-testid="bulk-enable">
                              {t("Enable")}
                            </button>
                          )
                          : (
                            <button type="button" className="fl-danger"
                                    onClick={() => setAsk({ kind: "disable", rows: chosen })}
                                    data-testid="bulk-disable">
                              {t("Disable")}
                            </button>
                          )}
                        <button type="button" className="fl-danger"
                                onClick={() => setAsk({ kind: "revoke-tokens", rows: chosen })}
                                data-testid="bulk-revoke">
                          {t("Revoke their tokens")}
                        </button>
                        <button type="button" className="fl-quiet" onClick={() => setPicked([])}>
                          {t("Clear the selection")}
                        </button>
                      </>
                    }
                  >
                    <span data-testid="bulk-count">
                      {t("{n} chosen; what follows acts on all of them.", { n: chosen.length })}
                    </span>
                  </Banner>
                )}
              </>
            }
          >
            <Toolbar
              end={
                scope === "signin"
                  ? <Note>{t("The directory answers with everybody at once, so this scope is narrowed here.")}</Note>
                  : undefined
              }
            >
              <Note>
                {filter.status === "disabled"
                  ? t("The identities somebody disabled, who could be let back in.")
                  : t("A row says what a subject is. What can be done to one is behind its name.")}
              </Note>
            </Toolbar>
            <Table
              rows={rows}
              keyOf={(row) => row.subject}
              rowTestId={(row) => `row-${row.subject}`}
              testId="access-rows"
              loading={loading} empty={t("Nobody matches this.")}
              columns={[
                {
                  key: "pick",
                  head: (
                    <input
                      type="checkbox"
                      aria-label={t("Choose every row listed")}
                      data-testid="pick-all"
                      checked={chosen.length > 0 && chosen.length === rows.filter((row) => row.id).length}
                      onChange={(event) => setPicked(
                        event.target.checked ? rows.filter((row) => row.id).map((row) => row.subject) : [],
                      )}
                    />
                  ),
                  cell: (row) => (
                    <input
                      type="checkbox"
                      aria-label={t("Choose {subject}", { subject: row.subject })}
                      data-testid={`pick-${row.subject}`}
                      // Somebody the panel has no record of cannot be
                      // disabled: there is nothing yet to disable.
                      disabled={!row.id}
                      checked={picked.includes(row.subject)}
                      onChange={(event) => setPicked(event.target.checked
                        ? [...picked, row.subject]
                        : picked.filter((one) => one !== row.subject))}
                    />
                  ),
                },
                {
                  key: "subject",
                  head: t("Subject"),
                  tight: true,
                  cell: (row) => (
                    <Link to={address(row.subject)} data-testid={`open-${row.subject}`} title={row.subject}>
                      {row.subject}
                    </Link>
                  ),
                },
                {
                  key: "name",
                  head: t("Name"),
                  cell: (row) => row.name
                    ? row.name
                    : <span className="fl-faint" title={t("unknown")}>—</span>,
                },
                { key: "kind", head: t("Kind"), minor: true, cell: (row) => <Pill dot={false}>{row.kind}</Pill> },
                {
                  key: "roles",
                  head: t("Roles and scopes"),
                  cell: (row) => <RoleCells t={t} row={row} teamName={teamName} />,
                },
                {
                  key: "tokens",
                  head: t("Tokens"),
                  num: true,
                  minor: true,
                  cell: (row) => row.tokens === undefined
                    // This scope was not asked about tokens, and a nought
                    // here would say this service holds none.
                    ? <span className="fl-faint" title={t("unknown in this scope")}>—</span>
                    : row.tokens.length,
                },
                {
                  key: "password",
                  head: t("Password"),
                  minor: true,
                  cell: (row) => <PasswordCell t={t} row={row} />,
                },
                {
                  key: "status",
                  head: t("Status"),
                  cell: (row) => {
                    const state = statusOf(t, row);
                    return <Pill tone={state.tone}>{state.label}</Pill>;
                  },
                },
              ]}
            />
          </Card>
        ),

        record: openRow !== undefined && (
          <Record
            row={openRow}
            roles={roleNames}
            teams={teams.data?.items ?? []}
            teamName={teamName}
            busy={busy}
            onClose={close}
            onAsk={setAsk}
            onError={onError}
            onChanged={refresh}
          />
        ),

        kinds: (
          <Card
            title={t("By kind and by role")}
            note={serverPaged
              // The fault the owner named by name: this card counted the
              // fifty on screen and said it had counted the fleet.
              ? t("Counted over all {n} that match, not only the {listed} listed.", {
                  n: principals.data?.total ?? 0, listed: rows.length,
                })
              : t("Counted over the {n} listed.", { n: narrowed.length })}
          >
            {kinds.length === 0 && byRole.length === 0
              ? (loading ? <Bones rows={3} /> : <Empty>{t("Nothing to count here.")}</Empty>)
              : (
                <Stack>
                  <Bars items={kinds.map(([kind, n]) => ({ label: kind, value: n, tone: "info" as Tone }))} />
                  {byRole.length > 0 && (
                    <>
                      <h3 className="fl-subhead">{t("Direct roles")}</h3>
                      <Bars items={byRole.map(([role, n]) => ({ label: role, value: n, tone: "ok" as Tone }))} />
                    </>
                  )}
                  <Note>
                    {principals.data?.without_bindings === undefined
                      ? t("How many hold no role of their own is unknown here.")
                      : t("{n} hold no role of their own.", { n: principals.data.without_bindings })}
                  </Note>
                </Stack>
              )}
          </Card>
        ),

        mappings: <Mappings roles={roleNames} onAsk={setAsk} onError={onError} />,
      }} />

      {ask && (
        <AskFor
          ask={ask}
          t={t}
          teamName={teamName}
          busy={busy}
          blocked={ask.kind === "issue-token" && !ttlValid}
          onCancel={() => setAsk(null)}
          onConfirm={(reason) => {
            switch (ask.kind) {
              case "disable": return disable.mutate({ rows: ask.rows, reason });
              case "enable": return enable.mutate({ rows: ask.rows, reason });
              case "revoke-tokens": return revokeTokens.mutate({ rows: ask.rows, reason });
              case "issue-token": return issueToken.mutate({ row: ask.row, reason });
              case "revoke-token": return revokeToken.mutate({ row: ask.row, token: ask.token, reason });
              case "revoke-role": return revokeRole.mutate({ row: ask.row, held: ask.held, reason });
              case "end-session": return endSession.mutate({ row: ask.row, session: ask.session, reason });
              case "clear-password": return clearPassword.mutate({ row: ask.row, reason });
              case "remove-mapping": return removeMapping.mutate({ mapping: ask.mapping, reason });
            }
          }}
        >
          {ask.kind === "issue-token" && (
            <>
              <Field label={t("Description")} hint={t("What the token is for; the listing shows it.")} wide>
                <input value={tokenDescription} onChange={(event) => setTokenDescription(event.target.value)} />
              </Field>
              <Field
                label={t("Lifetime in hours")}
                hint={t("Default {n}; at most {max} (a year).", { n: DEFAULT_TOKEN_TTL_HOURS, max: MAX_TOKEN_TTL_HOURS })}
                wide
              >
                <input type="number" min={1} max={MAX_TOKEN_TTL_HOURS} value={tokenTTL}
                       onChange={(event) => setTokenTTL(event.target.value)} />
              </Field>
            </>
          )}
        </AskFor>
      )}
    </>
  );
}

/* ----------------------------------------------------------- the cells */

/** The roles in a cell: words only, because a role is edited in the record. */
function RoleCells({ t, row, teamName }: { t: Translate; row: Row; teamName: (id: string) => string }) {
  if (row.roles.length === 0) {
    return <span className="fl-faint">{t("no role of their own; one may come from a group")}</span>;
  }
  const shown = row.roles.slice(0, 3);
  return (
    <Tags>
      {shown.map((held, index) => {
        const team = scopeTeam(held.scope);
        const reading = held.scope
          ? readScope(t, held.scope, team ? teamName(team) : undefined)
          : { words: held.words || t("the whole fleet"), reach: (held.words ? "narrowed" : "fleet") as Reach };
        const gone = expired(held.valid_until);
        return (
          <Pill key={`${held.role}-${index}`} tone={gone ? "unknown" : reachTone(reading.reach)}
                title={`${held.role} · ${reading.words}`}>
            {held.role} · {reading.words}
            {gone && <> · {t("expired")}</>}
            {held.from === "group" && held.group && <> · {t("from the group {group}", { group: held.group })}</>}
          </Pill>
        );
      })}
      {row.roles.length > shown.length && (
        <Pill dot={false}>{t("and {n} more", { n: row.roles.length - shown.length })}</Pill>
      )}
    </Tags>
  );
}

/** Whether somebody signs in here with a password is a fact, not a button. */
function PasswordCell({ t, row }: { t: Translate; row: Row }) {
  if (row.tokens === undefined && !row.password) {
    return <span className="fl-faint" title={t("unknown in this scope")}>—</span>;
  }
  if (!row.password) return <span className="fl-faint">{t("none")}</span>;
  const locked = row.password.locked_until && new Date(row.password.locked_until).getTime() > Date.now();
  return locked
    ? <Pill tone="error">{t("locked")}</Pill>
    : <span>{t("set")}</span>;
}

/* ---------------------------------------------------------- the record */

type RecordTab = "identity" | "roles" | "tokens" | "password";

/**
 * One subject, opened from its name.
 *
 * The four tabs are the four things a subject is: who it is, what it may
 * do, what it signs in with, and the password it has here. Revoking a token
 * and granting a role are rare, deliberate acts, and putting them one click
 * deep is the difference between a list that can be read and a control
 * panel that has to be navigated.
 */
function Record({ row, roles, teams, teamName, busy, onClose, onAsk, onError, onChanged }: {
  row: Row;
  roles: string[];
  teams: TeamChoice[];
  teamName: (id: string) => string;
  busy: boolean;
  onClose: () => void;
  onAsk: (ask: Ask) => void;
  onError: (error: unknown) => void;
  onChanged: () => void;
}) {
  const t = useT();
  const [tab, setTab] = useState<RecordTab>("identity");

  /* The holders listing carries neither tokens nor a password, so the
     record reads the identity itself rather than drawing an empty tab over
     a subject that has both. */
  const full = useQuery({
    queryKey: ["principals", "one", row.subject],
    queryFn: () => api.get<PrincipalList>(`/api/v1/principals?q=${encodeURIComponent(row.subject)}&limit=25`),
    enabled: row.id !== undefined && row.tokens === undefined,
    retry: false,
  });
  const read = full.data?.items.find((one) => one.id === row.id);
  const subject: Row = read ? { ...rowsOfPrincipals([read])[0], groups: row.groups } : row;

  const live = !subject.disabled_at;
  const tabs: { value: RecordTab; label: string; count?: number }[] = [
    { value: "identity", label: t("Identity") },
    { value: "roles", label: t("Roles and scopes"), count: subject.roles.length },
  ];
  if (subject.id) {
    tabs.push({ value: "tokens", label: t("Tokens and sessions"), count: subject.tokens?.length });
    tabs.push({ value: "password", label: t("Password") });
  }

  return (
    <Card
      title={subject.subject}
      note={subject.name || t("no name given")}
      tools={<button type="button" className="fl-quiet" onClick={onClose} data-testid="record-close">{t("Close")}</button>}
    >
      <Stack>
        <Tabs
          value={tabs.some((one) => one.value === tab) ? tab : "identity"}
          onChange={setTab}
          tabs={tabs}
        />

        {tab === "identity" && (
          <Stack>
            <Facts>
              <Fact label={t("Subject")}><span className="fl-mono">{subject.subject}</span></Fact>
              <Fact label={t("Name")}>
                {subject.name || <span className="fl-faint" title={t("unknown")}>—</span>}
              </Fact>
              <Fact label={t("Kind")}>{subject.kind}</Fact>
              <Fact label={t("Status")}>
                {(() => { const state = statusOf(t, subject); return <Pill tone={state.tone}>{state.label}</Pill>; })()}
              </Fact>
              <Fact label={t("Disabled")}>
                {subject.disabled_at
                  ? absoluteTime(subject.disabled_at)
                  : <span className="fl-faint">{t("not disabled")}</span>}
              </Fact>
              <Fact label={t("Groups of the provider")}>
                {subject.groups === undefined
                  ? <span className="fl-faint" title={t("unknown in this scope")}>—</span>
                  : subject.groups.length === 0
                    ? <span className="fl-faint">{t("none")}</span>
                    : subject.groups.join(", ")}
              </Fact>
            </Facts>
            {!subject.known && (
              <Note>
                {t("The panel has never seen this account. A role granted now waits for their first sign-in.")}
              </Note>
            )}
            {subject.id && (
              <Actions>
                {live
                  ? (
                    <button type="button" className="fl-danger" disabled={busy}
                            onClick={() => onAsk({ kind: "disable", rows: [subject] })} data-testid="record-disable">
                      {t("Disable")}
                    </button>
                  )
                  : (
                    <button type="button" disabled={busy}
                            onClick={() => onAsk({ kind: "enable", rows: [subject] })} data-testid="record-enable">
                      {t("Enable")}
                    </button>
                  )}
              </Actions>
            )}
          </Stack>
        )}

        {tab === "roles" && (
          <RolesTab
            row={subject}
            roles={roles}
            teams={teams}
            teamName={teamName}
            busy={busy}
            onAsk={onAsk}
            onError={onError}
            onChanged={onChanged}
          />
        )}

        {tab === "tokens" && subject.id && (
          <TokensTab row={subject} busy={busy} onAsk={onAsk} />
        )}

        {tab === "password" && subject.id && (
          <PasswordTab row={subject} onAsk={onAsk} onError={onError} onChanged={onChanged} />
        )}
      </Stack>
    </Card>
  );
}

/** What a subject may do, and the form that grants one more. */
function RolesTab({ row, roles, teams, teamName, busy, onAsk, onError, onChanged }: {
  row: Row;
  roles: string[];
  teams: TeamChoice[];
  teamName: (id: string) => string;
  busy: boolean;
  onAsk: (ask: Ask) => void;
  onError: (error: unknown) => void;
  onChanged: () => void;
}) {
  const t = useT();
  const [kind, setKind] = useState<GrantScope>("site");
  const [fields, setFields] = useState<GrantFields>({
    role: roles[0] ?? "", site: "", environment: "", team: "", owners: "", tags: "", validUntil: "", reason: "",
  });
  const set = (over: Partial<GrantFields>) => setFields({ ...fields, ...over });

  const grant = useMutation({
    mutationFn: () => {
      // Somebody the panel has no record of is granted through the route
      // that writes the record down in advance: an ordinary grant would
      // make a second record at their first sign-in and the role would sit
      // on the one nobody uses.
      if (!row.id) {
        return api.post("/api/v1/access/holders/grant", {
          subject: row.subject, display_name: row.name,
          role: fields.role, site: fields.site.trim(), environment: fields.environment.trim(),
          reason: fields.reason.trim(),
        });
      }
      const request = grantRequest(row.id, kind, fields);
      return api.post(request.path, request.body);
    },
    onSuccess: () => { set({ reason: "", validUntil: "" }); onChanged(); },
    onError,
  });

  const preview = readScope(t, previewScope(kind, fields), fields.team ? teamName(fields.team) : undefined);
  const ready = fields.role !== "" && reasonGiven(fields.reason) && (kind === "site" || fields.team !== "");

  return (
    <Stack>
      <Table
        rows={row.roles}
        keyOf={(held, index) => `${held.role}-${index}`}
        rowTestId={(held) => `binding-${held.role}`}
        empty={t("No role of their own. A role may still come from a group of the provider.")}
        columns={[
          { key: "role", head: t("Role"), cell: (held) => held.role },
          {
            key: "scope",
            head: t("Granted over"),
            cell: (held) => {
              const team = scopeTeam(held.scope);
              const reading = held.scope
                ? readScope(t, held.scope, team ? teamName(team) : undefined)
                : { words: held.words || t("the whole fleet"), reach: (held.words ? "narrowed" : "fleet") as Reach };
              return <Pill tone={reachTone(reading.reach)}>{reading.words}</Pill>;
            },
          },
          {
            key: "until",
            head: t("Until"),
            minor: true,
            cell: (held) => !held.valid_until
              ? <span className="fl-faint">{t("until revoked")}</span>
              : expired(held.valid_until)
                ? <Pill tone="unknown">{t("expired")}</Pill>
                : absoluteTime(held.valid_until),
          },
          {
            key: "from",
            head: t("Where it comes from"),
            minor: true,
            cell: (held) => held.from === "group"
              ? t("the group {group}", { group: held.group ?? t("unknown") })
              : t("bound to this identity"),
          },
          {
            key: "act",
            actions: true,
            cell: (held) => held.from === "group"
              // A role a group grants is taken away by changing the mapping,
              // not by this record: removing it here would grant it back at
              // the next sign-in.
              ? <span className="fl-faint">{t("edit the mapping")}</span>
              : (
                <button
                  type="button"
                  className="fl-danger fl-small"
                  disabled={busy || !row.id}
                  onClick={() => onAsk({
                    kind: "revoke-role", row, held,
                    teamName: teamName(scopeTeam(held.scope)),
                  })}
                  data-testid={`revoke-${held.role}`}
                >
                  {t("Remove")}
                </button>
              ),
          },
        ]}
      />

      <h3 className="fl-subhead">{t("Grant a role")}</h3>
      <Fields>
        <Field label={t("Role")}>
          <select value={fields.role} onChange={(event) => set({ role: event.target.value })}
                  disabled={roles.length === 0} data-testid="grant-role">
            {roles.length === 0 && <option value="">{t("the catalogue has not been read yet")}</option>}
            {roles.map((one) => <option key={one} value={one}>{one}</option>)}
          </select>
        </Field>
        {row.id && (
          <Field
            label={t("Granted over")}
            hint={t("A team is a boundary that follows its hosts; a site and an environment are where the machines stand. A binding names one of the two, never both.")}
          >
            <select value={kind} onChange={(event) => setKind(event.target.value as GrantScope)}
                    data-testid="grant-scope-kind">
              <option value="site">{t("a site and an environment")}</option>
              <option value="team">{t("a team")}</option>
            </select>
          </Field>
        )}
        {kind === "site" || !row.id ? (
          <>
            <Field label={t("Site (empty = all)")}>
              <input value={fields.site} onChange={(event) => set({ site: event.target.value })} />
            </Field>
            <Field label={t("Environment (empty = all)")}>
              <input value={fields.environment} onChange={(event) => set({ environment: event.target.value })} />
            </Field>
            {row.id && (
              <>
                <Field
                  label={t("Owners (empty = all)")}
                  hint={t("A comma-separated list. The role then reaches only the hosts one of these people owns.")}
                >
                  <input value={fields.owners} onChange={(event) => set({ owners: event.target.value })}
                         data-testid="grant-owners" />
                </Field>
                <Field
                  label={t("Tags (empty = all)")}
                  hint={t("A comma-separated list. A host carrying any one of them is in scope; one carrying none of them is out of it.")}
                >
                  <input value={fields.tags} onChange={(event) => set({ tags: event.target.value })}
                         data-testid="grant-tags" />
                </Field>
              </>
            )}
          </>
        ) : (
          <Field
            label={t("Team")}
            hint={teams.length === 0
              ? t("No teams exist yet; a role can only be granted over a team somebody has created.")
              : t("The role follows the team as hosts are placed in it and taken out.")}
            wide
          >
            <select value={fields.team} onChange={(event) => set({ team: event.target.value })} data-testid="grant-team">
              <option value="">{t("choose a team")}</option>
              {teams.map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
            </select>
          </Field>
        )}
        {row.id && (
          <Field label={t("Valid until (empty = until revoked)")}>
            <input type="datetime-local" value={fields.validUntil}
                   onChange={(event) => set({ validUntil: event.target.value })} />
          </Field>
        )}
        <Field
          label={t("This grant will reach")}
          hint={t("The scope as the server will read it. Every category has to be satisfied at once, and only an asterisk widens one.")}
          wide
        >
          <span data-testid="grant-preview">
            <Pill tone={reachTone(preview.reach)}>{preview.words}</Pill>
          </span>
        </Field>
        <Field label={t("Reason (kept in the audit trail)")}
               hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
          <input value={fields.reason} onChange={(event) => set({ reason: event.target.value })}
                 data-testid="grant-reason" />
        </Field>
      </Fields>
      <Actions>
        <button type="button" disabled={!ready || grant.isPending} onClick={() => grant.mutate()}
                data-testid="grant-submit">
          {grant.isPending ? t("Working…") : t("Grant the role")}
        </button>
      </Actions>
    </Stack>
  );
}

/** What a subject signs in with that is not a password: tokens, and live sessions. */
function TokensTab({ row, busy, onAsk }: { row: Row; busy: boolean; onAsk: (ask: Ask) => void }) {
  const t = useT();
  const sessions = useQuery({
    queryKey: ["principal-sessions", row.id],
    queryFn: () => api.get<Collection<SessionView>>(`/api/v1/principals/${row.id}/sessions`),
    enabled: row.id !== undefined,
    retry: false,
  });

  return (
    <Stack>
      <Table
        rows={row.tokens ?? []}
        keyOf={(token) => token.id}
        rowTestId={(token) => `token-${token.id}`}
        empty={t("This identity has no token.")}
        columns={[
          {
            key: "what",
            head: t("Token"),
            tight: true,
            cell: (token) => <span className="fl-mono">{token.description || token.id.slice(0, 8)}</span>,
          },
          {
            key: "expires",
            head: t("Expires"),
            cell: (token) => !token.expires_at
              ? <span className="fl-faint">{t("never expires")}</span>
              : expiresSoon(token)
                ? <Pill tone="warn">{t("expires {when}", { when: relativeTime(token.expires_at) })}</Pill>
                : absoluteTime(token.expires_at),
          },
          {
            key: "used",
            head: t("Last used"),
            minor: true,
            cell: (token) => token.last_used_at
              ? relativeTime(token.last_used_at)
              : <span className="fl-faint">{t("never")}</span>,
          },
          {
            key: "act",
            actions: true,
            cell: (token) => (
              <button type="button" className="fl-danger fl-small" disabled={busy}
                      onClick={() => onAsk({ kind: "revoke-token", row, token })}
                      data-testid={`revoke-token-${token.id}`}>
                {t("Revoke")}
              </button>
            ),
          },
        ]}
      />
      <Actions>
        <button type="button" disabled={busy || !!row.disabled_at}
                onClick={() => onAsk({ kind: "issue-token", row })} data-testid="issue-token">
          {t("Issue token")}
        </button>
      </Actions>

      <h3 className="fl-subhead">{t("Live browser sessions")}</h3>
      {sessions.error
        ? <Problem>{String(sessions.error)}</Problem>
        : (
          <Table
            rows={sessions.data?.items ?? []}
            keyOf={(session) => session.id}
            rowTestId={(session) => `session-${session.id}`}
            loading={sessions.isLoading} empty={t("No live browser session. A token is not a session.")}
            columns={[
              {
                key: "id",
                head: t("Session"),
                tight: true,
                cell: (session) => (
                  <span className="fl-mono" title={session.id}>
                    {session.id.slice(0, 12)}{session.acr ? ` acr=${session.acr}` : ""}
                  </span>
                ),
              },
              { key: "in", head: t("Signed in"), cell: (session) => relativeTime(session.created_at) },
              { key: "seen", head: t("Last seen"), minor: true, cell: (session) => relativeTime(session.last_seen_at) },
              {
                key: "ends",
                head: t("Ends"),
                minor: true,
                cell: (session) => t("{when}, or {idle} idle", {
                  when: absoluteTime(session.expires_at), idle: relativeTime(session.idle_expires_at),
                }),
              },
              {
                key: "from",
                head: t("From"),
                minor: true,
                tight: true,
                cell: (session) => session.remote_addr
                  ? <span title={session.user_agent}>{session.remote_addr}</span>
                  : <span className="fl-faint" title={t("unknown")}>—</span>,
              },
              {
                key: "act",
                actions: true,
                cell: (session) => (
                  <button type="button" className="fl-danger fl-small"
                          onClick={() => onAsk({ kind: "end-session", row, session })}
                          data-testid={`end-${session.id}`}>
                    {t("End session")}
                  </button>
                ),
              },
            ]}
          />
        )}
    </Stack>
  );
}

/**
 * The password an administrator sets here, and never one it shows.
 *
 * A password somebody else chose has to be replaced by its owner at their
 * next sign-in, and the panel says so rather than leaving an administrator
 * to decide whether it matters.
 */
function PasswordTab({ row, onAsk, onError, onChanged }: {
  row: Row;
  onAsk: (ask: Ask) => void;
  onError: (error: unknown) => void;
  onChanged: () => void;
}) {
  const t = useT();
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const [reason, setReason] = useState("");
  const [weak, setWeak] = useState("");

  const set = useMutation({
    mutationFn: () => api.put(`/api/v1/principals/${row.id}/password`, {
      password, must_change: mustChange, reason: reason.trim(),
    }),
    onSuccess: () => { setPassword(""); setReason(""); setWeak(""); onChanged(); },
    onError: (error) => {
      // A refusal for a weak password is an answer to this form, not an
      // error of the screen: it belongs beside the field.
      if (error instanceof ApiError && error.code === "weak_password") { setWeak(error.message); return; }
      onError(error);
    },
  });

  const locked = row.password?.locked_until
    && new Date(row.password.locked_until).getTime() > Date.now();

  return (
    <Stack>
      <Note>
        {row.password
          ? t("Set by {who} on {when}.", { who: row.password.set_by, when: absoluteTime(row.password.set_at) })
          : t("This identity has no password here: it signs in through the provider, or not at all.")}
        {row.password?.must_change && <> {t("The owner has to replace it at their next sign-in.")}</>}
        {locked && row.password?.locked_until && (
          <> {t("Locked after {n} wrong passwords, until {when}.", {
            n: row.password.failed_attempts, when: absoluteTime(row.password.locked_until),
          })}</>
        )}
      </Note>
      <Fields>
        <Field
          label={t("New password")}
          hint={t("At least 12 characters. Length is the rule; the identity's own name and the words on every list are refused.")}
        >
          <input type="password" value={password} autoComplete="new-password"
                 onChange={(event) => setPassword(event.target.value)} data-testid="set-password" />
        </Field>
        <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })}>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="password-reason" />
        </Field>
      </Fields>
      <Check checked={mustChange} onChange={setMustChange}>
        {t("The owner replaces it at their next sign-in")}
      </Check>
      {weak !== "" && <Problem>{weak}</Problem>}
      <Actions>
        <button type="button" disabled={password === "" || !reasonGiven(reason) || set.isPending}
                onClick={() => set.mutate()} data-testid="save-password">
          {row.password ? t("Replace the password") : t("Set the password")}
        </button>
        {row.password && (
          <button type="button" className="fl-danger" onClick={() => onAsk({ kind: "clear-password", row })}
                  data-testid="clear-password">
            {t("Remove the password")}
          </button>
        )}
      </Actions>
    </Stack>
  );
}

/* --------------------------------------------------- the new identity */

type CreatedIdentity = { id: string; subject: string; token?: string; token_expires_at?: string };

/** A new local identity: a person with a token, or a service. */
function CreateIdentity({ roles, onDone, onCancel, onError }: {
  roles: string[];
  onDone: (token: IssuedToken | null) => void;
  onCancel: () => void;
  onError: (error: unknown) => void;
}) {
  const t = useT();
  const [subject, setSubject] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"user" | "service">("user");
  const [role, setRole] = useState("");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [withToken, setWithToken] = useState(true);
  const [ttl, setTTL] = useState(String(DEFAULT_TOKEN_TTL_HOURS));
  const [reason, setReason] = useState("");
  const hours = Number.parseInt(ttl, 10);
  const ttlValid = !withToken || (Number.isInteger(hours) && hours >= 1 && hours <= MAX_TOKEN_TTL_HOURS);

  const create = useMutation({
    mutationFn: () => api.post<CreatedIdentity>("/api/v1/principals", {
      subject: subject.trim(), display_name: name.trim(), kind,
      roles: role
        ? [{ role, site: site.trim(), environment: environment.trim(), valid_until: toInstant(validUntil) }]
        : [],
      issue_token: withToken, token_ttl_hours: withToken ? hours : 0,
      reason: reason.trim(),
    }),
    onSuccess: (made) => onDone(made.token
      ? { subject: made.subject, token: made.token, token_expires_at: made.token_expires_at }
      : null),
    onError,
  });

  return (
    <Card title={t("New identity")} note={t("A person signs in or holds a token; a service only holds tokens.")}>
      <Stack>
        <Fields>
          <Field label={t("Subject")} hint={t("The name the trail records; it cannot be changed later.")}>
            <input value={subject} onChange={(event) => setSubject(event.target.value)} data-testid="new-subject" />
          </Field>
          <Field label={t("Display name")}>
            <input value={name} onChange={(event) => setName(event.target.value)} />
          </Field>
          <Field label={t("Kind")}>
            <select value={kind} onChange={(event) => setKind(event.target.value as "user" | "service")}>
              <option value="user">{t("person (user)")}</option>
              <option value="service">{t("service")}</option>
            </select>
          </Field>
          <Field label={t("First role (empty = none yet)")}>
            <select value={role} onChange={(event) => setRole(event.target.value)}>
              <option value="">{t("none")}</option>
              {roles.map((one) => <option key={one} value={one}>{one}</option>)}
            </select>
          </Field>
          {role !== "" && (
            <>
              <Field label={t("Site (empty = all)")}>
                <input value={site} onChange={(event) => setSite(event.target.value)} />
              </Field>
              <Field label={t("Environment (empty = all)")}>
                <input value={environment} onChange={(event) => setEnvironment(event.target.value)} />
              </Field>
              <Field label={t("Valid until (empty = until revoked)")}>
                <input type="datetime-local" value={validUntil}
                       onChange={(event) => setValidUntil(event.target.value)} />
              </Field>
            </>
          )}
          {withToken && (
            <Field
              label={t("Lifetime in hours")}
              hint={t("Default {n}; at most {max} (a year).", { n: DEFAULT_TOKEN_TTL_HOURS, max: MAX_TOKEN_TTL_HOURS })}
            >
              <input type="number" min={1} max={MAX_TOKEN_TTL_HOURS} value={ttl}
                     onChange={(event) => setTTL(event.target.value)} />
            </Field>
          )}
          <Field label={t("Reason (kept in the audit trail)")}
                 hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="new-reason" />
          </Field>
        </Fields>
        <Check checked={withToken} onChange={setWithToken}>{t("Issue the first token now")}</Check>
        <Actions>
          <button type="button" data-testid="new-submit"
                  disabled={!subject.trim() || !reasonGiven(reason) || !ttlValid || create.isPending}
                  onClick={() => create.mutate()}>
            {create.isPending ? t("Working…") : t("Create identity")}
          </button>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={create.isPending}>
            {t("Cancel")}
          </button>
        </Actions>
      </Stack>
    </Card>
  );
}

/* -------------------------------------------------------- the mappings */

/**
 * The groups of the identity provider, and the role each of them hands out.
 *
 * This is the other way somebody gets access, and the one that reaches
 * people the panel has no record of. It is a table of rules rather than of
 * people, which is why it stands apart from the one above.
 */
function Mappings({ roles, onAsk, onError }: {
  roles: string[];
  onAsk: (ask: Ask) => void;
  onError: (error: unknown) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [form, setForm] = useState(false);
  const [group, setGroup] = useState("");
  const [role, setRole] = useState("");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [owners, setOwners] = useState("");
  const [tags, setTags] = useState("");
  const [reason, setReason] = useState("");

  const list = useQuery({
    queryKey: ["group-mappings"],
    queryFn: () => api.get<Collection<GroupMapping>>("/api/v1/group-mappings"),
    retry: false,
  });
  const add = useMutation({
    mutationFn: () => api.post<GroupMapping>("/api/v1/group-mappings", {
      group_name: group.trim(), role: role || roles[0] || "",
      site: site.trim(), environment: environment.trim(), reason: reason.trim(),
      // Left out rather than sent empty: the server reads a missing
      // category as every one of them and an empty list as none.
      ...(listFromText(owners) ? { owners: listFromText(owners) } : {}),
      ...(listFromText(tags) ? { tags: listFromText(tags) } : {}),
    }),
    onSuccess: () => {
      setForm(false); setGroup(""); setReason(""); setOwners(""); setTags("");
      void queryClient.invalidateQueries({ queryKey: ["group-mappings"] });
    },
    onError,
  });

  const mappings = list.data?.items ?? [];

  return (
    <Card
      title={t("Group mappings")}
      note={t("Counted over the {n} listed; the provider's groups are read in full.", { n: mappings.length })}
      tools={!form && (
        <button type="button" className="fl-quiet fl-small" onClick={() => setForm(true)} data-testid="add-mapping">
          {t("Add mapping")}
        </button>
      )}
    >
      <Stack>
        {list.error && <Problem>{String(list.error)}</Problem>}
        <Table
          rows={mappings}
          keyOf={(mapping) => mapping.id}
          rowTestId={(mapping) => `mapping-${mapping.group_name}`}
          loading={list.isLoading}
          empty={t("No mapping. Without one nobody gets a role from the identity provider.")}
          columns={[
            {
              key: "group",
              head: t("Group"),
              tight: true,
              cell: (mapping) => <span className="fl-mono">{mapping.group_name}</span>,
            },
            { key: "role", head: t("Role"), cell: (mapping) => mapping.role },
            {
              key: "scope",
              head: t("Granted over"),
              cell: (mapping) => {
                const reading = readScope(t, {
                  site: mapping.site, environment: mapping.environment,
                  owners: mapping.owners, tags: mapping.tags,
                });
                return <Pill tone={reachTone(reading.reach)}>{reading.words}</Pill>;
              },
            },
            { key: "by", head: t("Added by"), minor: true, tight: true, cell: (mapping) => mapping.created_by },
            {
              key: "when",
              head: t("When"),
              minor: true,
              cell: (mapping) => relativeTime(mapping.created_at),
            },
            {
              key: "act",
              actions: true,
              cell: (mapping) => (
                <button type="button" className="fl-danger fl-small"
                        onClick={() => onAsk({ kind: "remove-mapping", mapping })}
                        data-testid={`remove-mapping-${mapping.group_name}`}>
                  {t("Remove")}
                </button>
              ),
            },
          ]}
        />

        {form && (
          <>
            <h3 className="fl-subhead">{t("New mapping")}</h3>
            <Fields>
              <Field label={t("Identity provider group")}>
                <input value={group} onChange={(event) => setGroup(event.target.value)} data-testid="mapping-group" />
              </Field>
              <Field label={t("Role")}>
                <select value={role || roles[0] || ""} onChange={(event) => setRole(event.target.value)}
                        disabled={roles.length === 0}>
                  {roles.map((one) => <option key={one} value={one}>{one}</option>)}
                </select>
              </Field>
              <Field label={t("Site (empty = all)")}>
                <input value={site} onChange={(event) => setSite(event.target.value)} />
              </Field>
              <Field label={t("Environment (empty = all)")}>
                <input value={environment} onChange={(event) => setEnvironment(event.target.value)} />
              </Field>
              <Field label={t("Owners (empty = all)")} hint={t("Comma-separated. The role is held only over the hosts of these owners.")}>
                <input value={owners} onChange={(event) => setOwners(event.target.value)} />
              </Field>
              <Field label={t("Tags (empty = all)")} hint={t("Comma-separated. A host carrying any one of them is in scope.")}>
                <input value={tags} onChange={(event) => setTags(event.target.value)} />
              </Field>
              <Field label={t("Reason (kept in the audit trail)")}
                     hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
                <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="mapping-reason" />
              </Field>
            </Fields>
            <Actions>
              <button type="button" disabled={!group.trim() || !reasonGiven(reason) || add.isPending}
                      onClick={() => add.mutate()} data-testid="mapping-submit">
                {add.isPending ? t("Working…") : t("Add mapping")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setForm(false)}>{t("Cancel")}</button>
            </Actions>
          </>
        )}
      </Stack>
    </Card>
  );
}

/* ---------------------------------------------------------- the dialog */

/** What one ask is about, said in the words of what will happen. */
export function askTitle(t: Translate, ask: Ask): string {
  switch (ask.kind) {
    case "disable": return t("Disable {n} identities", { n: ask.rows.length });
    case "enable": return t("Enable {n} identities", { n: ask.rows.length });
    case "revoke-tokens": return t("Revoke the tokens of {n} identities", { n: ask.rows.length });
    case "issue-token": return t("Issue a token to {subject}", { subject: ask.row.subject });
    case "revoke-token": return t("Revoke a token of {subject}", { subject: ask.row.subject });
    case "revoke-role": return t("Remove {role} from {subject}", { role: ask.held.role, subject: ask.row.subject });
    case "end-session": return t("End a session of {subject}", { subject: ask.row.subject });
    case "clear-password": return t("Remove the password of {subject}", { subject: ask.row.subject });
    case "remove-mapping": return t("Remove the mapping of {group}", { group: ask.mapping.group_name });
  }
}

/** What it will do, named before it is done. */
function askText(t: Translate, ask: Ask, teamName: string): ReactNode {
  switch (ask.kind) {
    case "disable":
      return t("The sessions and the tokens of {who} end at once. The records stay, so the trail goes on naming them, and they can be enabled again later.", {
        who: ask.rows.map((row) => row.subject).join(", "),
      });
    case "enable":
      return t("{who} get their access back with the roles they held. The sessions and the tokens that ended stay ended.", {
        who: ask.rows.map((row) => row.subject).join(", "),
      });
    case "revoke-tokens":
      return t("{n} tokens of {who} stop working on their next request.", {
        n: ask.rows.reduce((sum, row) => sum + (row.tokens?.length ?? 0), 0),
        who: ask.rows.map((row) => row.subject).join(", "),
      });
    case "issue-token":
      return t("The value of the token is shown once, in the answer; the panel keeps only its digest.");
    case "revoke-token":
      return t("The token {token} stops working on its next request.", {
        token: ask.token.description || ask.token.id.slice(0, 8),
      });
    case "revoke-role":
      return scopeTeam(ask.held.scope)
        ? t("The identity loses {role} over the team {team}. The team and its hosts are untouched, and a role held through a group is not touched.", {
            role: ask.held.role, team: teamName,
          })
        : t("The identity loses {role} in {scope}; a role it holds through a group mapping is not touched.", {
            role: ask.held.role,
            scope: `${ask.held.scope?.site || "*"} / ${ask.held.scope?.environment || "*"}`,
          });
    case "end-session":
      return t("The browser session {session} is refused on its next request; the identity keeps its roles and its tokens.", {
        session: ask.session.id.slice(0, 12),
      });
    case "clear-password":
      return t("The identity can no longer sign in with a password here. Its tokens and its roles are untouched.");
    case "remove-mapping":
      return t("The group {group} stops granting {role}. Whoever holds the role through this mapping alone loses it on their next request.", {
        group: ask.mapping.group_name, role: ask.mapping.role,
      });
  }
}

/** The word on the button that does it. */
function askAction(t: Translate, ask: Ask): string {
  switch (ask.kind) {
    case "disable": return t("Disable");
    case "enable": return t("Enable");
    case "revoke-tokens": return t("Revoke");
    case "issue-token": return t("Issue token");
    case "revoke-token": return t("Revoke");
    case "revoke-role": return t("Remove");
    case "end-session": return t("End session");
    case "clear-password": return t("Remove the password");
    case "remove-mapping": return t("Remove");
  }
}

/**
 * The one dialog every change goes through.
 *
 * Nothing destructive happens without it, and nothing at all happens
 * without the reason the server keeps in the trail - so the reason is a
 * field of the dialog rather than something each form remembers to ask.
 */
function AskFor({ ask, t, teamName, busy, blocked, onConfirm, onCancel, children }: {
  ask: Ask;
  t: Translate;
  teamName: (id: string) => string;
  busy: boolean;
  blocked?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  const [reason, setReason] = useState("");
  const danger = ask.kind !== "enable" && ask.kind !== "issue-token";
  const team = ask.kind === "revoke-role" ? teamName(scopeTeam(ask.held.scope)) : "";
  return (
    <Modal
      title={askTitle(t, ask)}
      onClose={onCancel}
      actions={
        <>
          <button
            type="button"
            className={danger ? "fl-danger" : undefined}
            disabled={!reasonGiven(reason) || busy || blocked === true}
            onClick={() => onConfirm(reason.trim())}
            data-testid="ask-confirm"
          >
            {busy ? t("Working…") : askAction(t, ask)}
          </button>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
        </>
      }
    >
      <Note>{askText(t, ask, team)}</Note>
      <Fields>
        {children}
        <Field
          label={t("Reason (kept in the audit trail)")}
          hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })}
          wide
        >
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="ask-reason" />
        </Field>
      </Fields>
    </Modal>
  );
}

/* ------------------------------------------------------- the refusals */

/**
 * A refusal because of a stale authentication is not an error of the
 * screen: the panel offers signing in again and coming back to the same
 * place. Where somebody got in with a password there is nowhere to send
 * them, so they are asked for that password here.
 */
function Refusal({ error, close }: { error: ApiError; close: () => void }) {
  const t = useT();
  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami & { authentication?: string }>("/api/v1/whoami"),
    staleTime: 60 * 1000,
    retry: false,
  });
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [done, setDone] = useState(false);
  const reauthenticate = useMutation({
    mutationFn: () => api.post("/auth/password/reauthenticate", { password }),
    onSuccess: () => { setDone(true); setPassword(""); setAgain(""); },
    onError: (problem) => setAgain(problem instanceof Error ? problem.message : String(problem)),
  });

  if (error.code !== "reauthentication_required") {
    return (
      <Banner tone="error" actions={<button type="button" onClick={close}>{t("Close")}</button>}>
        {error.message}
      </Banner>
    );
  }
  if (me.data?.authentication === "password") {
    return (
      <Banner
        tone="warn"
        actions={done
          ? <button type="button" className="fl-quiet" onClick={close}>{t("Close")}</button>
          : (
            <>
              <input type="password" value={password} autoComplete="current-password"
                     onChange={(event) => setPassword(event.target.value)} data-testid="reauthenticate-field"
                     aria-label={t("The password you sign in with")} />
              <button type="button" disabled={password === "" || reauthenticate.isPending}
                      onClick={() => reauthenticate.mutate()} data-testid="reauthenticate">
                {t("Confirm")}
              </button>
              <button type="button" className="fl-quiet" onClick={close}>{t("Close")}</button>
            </>
          )}
      >
        {error.message}{" "}
        {done ? t("Done - try it again.") : t("Give the password you sign in with.")}
        {again !== "" && <> {again}</>}
      </Banner>
    );
  }
  return (
    <Banner
      tone="warn"
      actions={
        <>
          <button
            type="button"
            onClick={() => {
              const back = encodeURIComponent(window.location.pathname + window.location.search);
              window.location.href = `/auth/login?step_up=1&redirect=${back}`;
            }}
          >
            {t("Sign in again")}
          </button>
          <button type="button" className="fl-quiet" onClick={close}>{t("Close")}</button>
        </>
      }
    >
      {error.message}
    </Banner>
  );
}

/* ------------------------------------------------------------ the board */

export const ACCESS_SCREEN = "next_access";

export const ACCESS: BoardEntry[] = [
  { key: "signin", title: "Who may sign in", width: 4, height: 1 },
  { key: "identities", title: "Identities on record", width: 4, height: 1 },
  { key: "norole", title: "Without a role of their own", width: 4, height: 1 },
  { key: "filter", title: "Find somebody", width: 12, height: 1 },
  { key: "create", title: "New identity", width: 12, height: 4 },
  { key: "list", title: "The list", width: 12, height: 6 },
  { key: "record", title: "The opened identity", width: 12, height: 5 },
  { key: "kinds", title: "By kind and by role", width: 4, height: 2 },
  { key: "mappings", title: "Group mappings", width: 8, height: 3 },
];
