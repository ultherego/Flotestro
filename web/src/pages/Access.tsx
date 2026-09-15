import { Fragment, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ApiError, type Collection } from "../lib/api";
import type { AccessReview, ApiToken, GroupMapping, Principal, ReviewFlag, ReviewedPrincipal } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { toInstant } from "../lib/format";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, StatGrid, Stat, Toolbar } from "../components/layout";
import { Breakdown } from "../components/widgets";
import { CertificateAuthority } from "./CertificateAuthority";
import { useT } from "../i18n";

const ROLES = [
  "viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin",
];

/** The reason every change of the access rules is recorded with. */
const REASON_MIN_LENGTH = 8;

/** The lifetime of a token when the form does not say; the server's own default. */
const DEFAULT_TOKEN_TTL_HOURS = 720;
/** The longest life the server gives a token: a year. */
const MAX_TOKEN_TTL_HOURS = 8760;

const TABS = ["mappings", "identities", "roles", "review", "ca"] as const;
type Tab = (typeof TABS)[number];

/** The tab named in the address, or the first one for a name that is not a tab. */
export function tabFromParam(value: string | null): Tab {
  return (TABS as readonly string[]).includes(value ?? "") ? (value as Tab) : "mappings";
}

/**
 * Panel access management.
 *
 * These operations change the access rules themselves, so the panel demands
 * a fresh authentication and a reason. The reason lands in the audit trail
 * together with the description of the change.
 *
 * The tab lives in the address: the audit trail links here to one
 * identity, and a link to "the identities" has to open the identities.
 */
export function Access() {
  const t = useT();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = tabFromParam(searchParams.get("tab"));
  const setTab = (next: Tab) => setSearchParams({ tab: next });
  const [warning, setWarning] = useState<ApiError | null>(null);

  return (
    <>
      <PageHeader
        title={t("Access")}
        description={t("Mapping of identity provider groups to roles, plus local identities. A group in the token grants nothing by itself - the role comes from the mapping.")}
      />

      <div className="tabs">
        <button className={tab === "mappings" ? "active" : ""} onClick={() => setTab("mappings")}>
          {t("Group mappings")}
        </button>
        <button className={tab === "identities" ? "active" : ""} onClick={() => setTab("identities")}>
          {t("Identities")}
        </button>
        <button className={tab === "roles" ? "active" : ""} onClick={() => setTab("roles")}>
          {t("Roles")}
        </button>
        <button className={tab === "review" ? "active" : ""} onClick={() => setTab("review")}>
          {t("Access review")}
        </button>
        <button className={tab === "ca" ? "active" : ""} onClick={() => setTab("ca")}>
          {t("Fleet CA")}
        </button>
      </div>

      {tab === "ca" && <Warning error={warning} close={() => setWarning(null)} />}
      {tab === "mappings" && <Mappings />}
      {tab === "identities" && <Identities initialSearch={searchParams.get("q") ?? ""} />}
      {tab === "roles" && <Roles />}
      {tab === "review" && <Review />}
      {tab === "ca" && <CertificateAuthority reportError={setWarning} />}
    </>
  );
}

/** A reason long enough for the trail. */
function reasonGiven(reason: string): boolean {
  return reason.trim().length >= REASON_MIN_LENGTH;
}

/**
 * The confirmation of one change: what is about to happen, the reason it
 * is recorded with and the button that does it. The card stands beside
 * the list rather than over it, so the row it concerns stays in view; a
 * browser prompt would hide it and take the reason without the rule.
 */
function ConfirmCard({ title, text, action, danger = false, busy = false, disabled = false, onConfirm, onCancel, children }: {
  title: string;
  text: ReactNode;
  action: string;
  danger?: boolean;
  busy?: boolean;
  disabled?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  return (
    <Card
      className="span-3 fp-narrow"
      title={title}
      footer={
        <Actions>
          <button className={danger ? "danger" : undefined} disabled={!reasonGiven(reason) || busy || disabled} onClick={() => onConfirm(reason.trim())}>
            {busy ? t("Working…") : action}
          </button>
          <button className="secondary" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
        </Actions>
      }
    >
      <p className="source">{text}</p>
      <FieldGrid>
        {children}
        <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
          <input value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </FieldGrid>
    </Card>
  );
}

function Mappings() {
  const t = useT();
  const queryClient = useQueryClient();
  const [warning, setWarning] = useState<ApiError | null>(null);
  const [form, setForm] = useState(false);
  const [group, setGroup] = useState("");
  const [role, setRole] = useState("viewer");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [reason, setReason] = useState("");
  // The mapping about to be removed; the reason is asked beside the list.
  const [removing, setRemoving] = useState<GroupMapping | null>(null);

  const list = useQuery({
    queryKey: ["group-mappings"],
    queryFn: () => api.get<Collection<GroupMapping>>("/api/v1/group-mappings"),
    retry: false,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["group-mappings"] });

  const add = useMutation({
    mutationFn: () =>
      api.post<GroupMapping>("/api/v1/group-mappings", {
        group_name: group.trim(), role,
        site: site.trim(), environment: environment.trim(), reason: reason.trim(),
      }),
    onSuccess: () => { setForm(false); setGroup(""); setReason(""); refresh(); },
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/group-mappings/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: () => { setRemoving(null); refresh(); },
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  if (list.error instanceof ApiError && list.error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (list.error) return <ErrorBox error={list.error} />;

  const mappings = list.data?.items ?? [];
  const listed = t("among the {n} listed", { n: mappings.length });
  // The mappings by role and by reach: how many hand out which role, and
  // how many of them reach the whole fleet rather than one site or
  // environment. A fleet-wide operator mapping is the one to look at.
  const byRole = ROLES.map((role) => ({ role, count: mappings.filter((mapping) => mapping.role === role).length }));
  const fleetWide = mappings.filter((mapping) => !mapping.site && !mapping.environment).length;
  const aside = form || removing !== null;

  return (
    <>
      <Warning error={warning} close={() => setWarning(null)} />

      {/* The form opens beside the list it adds to; while it is closed the
          list has the row to itself. */}
      <div className="widgets">
        <Card
          className={aside ? "span-6" : "span-9"}
          title={t("Group mappings")}
          actions={!form && <button onClick={() => { setRemoving(null); setForm(true); }}>{t("Add mapping")}</button>}
          flush
        >
          {list.data?.items.length ? (
            <table>
              <thead>
                <tr><th>{t("Group")}</th><th>{t("Role")}</th><th>{t("Scope")}</th><th>{t("Added by")}</th><th>{t("When")}</th><th /></tr>
              </thead>
              <tbody>
                {list.data.items.map((mapping) => (
                  <tr key={mapping.id}>
                    <td className="mono">{mapping.group_name}</td>
                    <td>{mapping.role}</td>
                    <td className="source">
                      {mapping.site || "*"} / {mapping.environment || "*"}
                    </td>
                    <td className="source">{mapping.created_by}</td>
                    <td><Time value={mapping.created_at} /></td>
                    <td className="actions-cell">
                      <div className="row-actions">
                        <button className="danger" onClick={() => { setForm(false); setRemoving(mapping); }}>
                          {t("Remove")}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState action={!form && <button onClick={() => setForm(true)}>{t("Add mapping")}</button>}>
              {t("No mappings. Without them nobody gets a role from the identity provider.")}
            </EmptyState>
          )}
        </Card>

        {form && (
          <Card
            className="span-3 fp-narrow"
            title={t("New mapping")}
            footer={
              <Actions>
                <button disabled={!group.trim() || !reasonGiven(reason) || add.isPending}
                        onClick={() => add.mutate()}>
                  {t("Add mapping")}
                </button>
                <button className="secondary" onClick={() => setForm(false)}>{t("Cancel")}</button>
              </Actions>
            }
          >
            <FieldGrid>
              <Field label={t("Identity provider group")}>
                <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="flotestro-operators" />
              </Field>
              <Field label={t("Role")}>
                <select value={role} onChange={(e) => setRole(e.target.value)}>
                  {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
                </select>
              </Field>
              <Field label={t("Site (empty = all)")}>
                <input value={site} onChange={(e) => setSite(e.target.value)} placeholder="lab" />
              </Field>
              <Field label={t("Environment (empty = all)")}>
                <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="test" />
              </Field>
              <Field label={t("Reason for the change")} wide>
                <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("e.g. new on-call team")} />
              </Field>
            </FieldGrid>
          </Card>
        )}

        {removing && (
          <ConfirmCard
            key={removing.id}
            title={t("Remove mapping")}
            text={t("The group {group} stops granting {role} in {scope}. Whoever holds the role through this mapping alone loses it on their next request.", {
              group: removing.group_name, role: removing.role, scope: `${removing.site || "*"} / ${removing.environment || "*"}`,
            })}
            action={t("Remove")}
            danger
            busy={remove.isPending}
            onConfirm={(reason) => remove.mutate({ id: removing.id, reason })}
            onCancel={() => setRemoving(null)}
          />
        )}

        <Card className="span-3" title={t("By role")} description={listed}>
          {!list.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : (
            <>
              <Breakdown tone="info" items={byRole.map((row) => ({ label: row.role, value: row.count }))} />
              <h4 className="widget-subhead">{t("Reach")}</h4>
              <Breakdown items={[
                { label: t("Fleet-wide"), value: fleetWide, tone: "warn" },
                { label: t("Scoped"), value: mappings.length - fleetWide, tone: "ok" },
              ]} />
            </>
          )}
        </Card>
      </div>
    </>
  );
}

/** A freshly issued token, shown once and never fetched again. */
type IssuedToken = { subject: string; token: string; token_expires_at?: string };

/** An identity as the list carries it, with the moment it was disabled when it was. */
type ListedPrincipal = Principal & { disabled_at?: string };

/** A live browser session of an identity, as the panel lists it. */
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

/**
 * Whether a token ends within the coming week. A token that ends soon is
 * a question - is anybody going to renew it - not a defect; a token
 * without an end is not "soon" and not flagged here.
 */
export function expiresSoon(token: Pick<ApiToken, "expires_at">, now = Date.now(), days = 7): boolean {
  if (!token.expires_at) return false;
  const at = new Date(token.expires_at).getTime();
  if (Number.isNaN(at)) return false;
  return at > now && at - now <= days * 24 * 60 * 60 * 1000;
}

/**
 * Whether an identity matches a search: by subject, by display name or by
 * identifier, because the audit trail names identities by identifier and
 * links here with one. An empty search matches everything.
 */
export function matchesIdentity(principal: Pick<Principal, "id" | "subject" | "display_name">, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [principal.subject, principal.display_name ?? "", principal.id].some((value) => value.toLowerCase().includes(needle));
}

/** A change of one identity waiting for its reason. */
type Pending =
  | { kind: "disable"; principal: ListedPrincipal }
  | { kind: "enable"; principal: ListedPrincipal }
  | { kind: "issue-token"; principal: ListedPrincipal }
  | { kind: "revoke-token"; principal: ListedPrincipal; token: ApiToken }
  | { kind: "revoke-role"; principal: ListedPrincipal; role: string; site: string; environment: string }
  | { kind: "revoke-session"; principal: ListedPrincipal; session: SessionView };

function Identities({ initialSearch }: { initialSearch: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [warning, setWarning] = useState<ApiError | null>(null);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState(initialSearch);
  // The list answers one question at a time: who can act, or who could be
  // let back in.
  const [showDisabled, setShowDisabled] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [creating, setCreating] = useState(false);
  const [sessionsOf, setSessionsOf] = useState<ListedPrincipal | null>(null);
  const { data, error } = useQuery({
    queryKey: ["principals", showDisabled],
    queryFn: () => api.get<Collection<ListedPrincipal>>(showDisabled ? "/api/v1/principals?disabled=true" : "/api/v1/principals"),
    retry: false,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["principals"] });
  const onError = (error: unknown) => setWarning(error instanceof ApiError ? error : null);
  const settled = () => { setPending(null); refresh(); };

  // Every change here moves who can do what on the fleet, so each one asks
  // for a reason the same way the group mappings do; the panel demands
  // fresh authentication behind it.
  const disable = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: settled, onError,
  });
  const enable = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/principals/${id}/enable`, { reason }),
    onSuccess: settled, onError,
  });
  const revokeToken = useMutation({
    mutationFn: ({ id, token, reason }: { id: string; token: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}/tokens/${token}?reason=${encodeURIComponent(reason)}`),
    onSuccess: settled, onError,
  });
  const [tokenDescription, setTokenDescription] = useState("");
  const [tokenTTL, setTokenTTL] = useState(String(DEFAULT_TOKEN_TTL_HOURS));
  const ttlHours = Number.parseInt(tokenTTL, 10);
  const ttlValid = Number.isInteger(ttlHours) && ttlHours >= 1 && ttlHours <= MAX_TOKEN_TTL_HOURS;
  const issueToken = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<IssuedToken>(`/api/v1/principals/${id}/tokens`, {
        reason, description: tokenDescription.trim(), token_ttl_hours: ttlHours,
      }),
    onSuccess: (token) => { setIssued(token); setCopied(false); setTokenDescription(""); settled(); }, onError,
  });
  const revokeRole = useMutation({
    mutationFn: ({ id, role, site, environment, reason }:
      { id: string; role: string; site: string; environment: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}/roles/${role}`, { site, environment, reason }),
    onSuccess: settled, onError,
  });
  const revokeSession = useMutation({
    mutationFn: ({ id, session, reason }: { id: string; session: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}/sessions/${session}?reason=${encodeURIComponent(reason)}`),
    onSuccess: () => { setPending(null); queryClient.invalidateQueries({ queryKey: ["principal-sessions"] }); }, onError,
  });
  // A grant names the identity, the role, the scope and - when the access
  // is meant to end by itself - until when. Granting a role the identity
  // already has changes the validity alone.
  const [grant, setGrant] = useState<{ id: string; subject: string } | null>(null);
  const [grantRole, setGrantRole] = useState("viewer");
  const [grantSite, setGrantSite] = useState("");
  const [grantEnvironment, setGrantEnvironment] = useState("");
  const [grantUntil, setGrantUntil] = useState("");
  const [grantReason, setGrantReason] = useState("");
  const grantMutation = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/principals/${grant?.id}/roles`, {
        role: grantRole, site: grantSite.trim(), environment: grantEnvironment.trim(),
        valid_until: toInstant(grantUntil), reason: grantReason.trim(),
      }),
    onSuccess: () => { setGrant(null); setGrantReason(""); setGrantUntil(""); refresh(); }, onError,
  });

  // One side card at a time: opening one closes the others, so the row
  // the operator is working on is never beside two forms about two rows.
  const openGrant = (principal: ListedPrincipal) => { setPending(null); setCreating(false); setGrant({ id: principal.id, subject: principal.subject }); };
  const openPending = (next: Pending) => { setGrant(null); setCreating(false); setPending(next); };
  const openCreate = () => { setGrant(null); setPending(null); setCreating(true); };

  if (error instanceof ApiError && error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (error) return <ErrorBox error={error} />;

  const all = data?.items ?? [];
  const shown = all.filter((principal) => matchesIdentity(principal, search));

  // The identities by kind, and the roles their direct assignments hand
  // out; an identity without assignments is named, because its roles, if
  // any, come from the group mappings and are not visible here.
  const tally = (keys: (principal: Principal) => string[]) => Object.entries(
    all.reduce<Record<string, number>>((acc, principal) => { for (const k of keys(principal)) acc[k] = (acc[k] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const byKind = tally((principal) => [principal.kind]);
  const byRole = tally((principal) => (principal.bindings ?? []).map((binding) => binding.role));
  const unassigned = all.filter((principal) => (principal.bindings ?? []).length === 0).length;
  const aside = grant !== null || pending !== null || creating;

  return (
    <>
      <Warning error={warning} close={() => setWarning(null)} />

      {/* The value of a new token is in this answer and nowhere else: the
          panel keeps only its digest. */}
      {issued && (
        <div className="warning">
          <div>
            <strong>{t("Token for {subject} issued.", { subject: issued.subject })}</strong>{" "}
            {t("Shown once; copy it now.")}{" "}
            <code>{issued.token}</code>
            {issued.token_expires_at && <> · {t("expires")} <Time value={issued.token_expires_at} /></>}
          </div>
          <div className="operations">
            <button onClick={() => { navigator.clipboard?.writeText(issued.token); setCopied(true); }}>
              {copied ? t("Token copied") : t("Copy token")}
            </button>
            <button className="secondary" onClick={() => setIssued(null)}>{t("Close")}</button>
          </div>
        </div>
      )}

      <div className="widgets">
        <Card
          className={aside ? "span-6" : "span-9"}
          title={t("Identities")}
          actions={!creating && <button onClick={openCreate}>{t("Create identity")}</button>}
          flush
        >
          <Toolbar end={<span>{t("{n} identities", { n: shown.length })}</span>}>
            <input placeholder={t("subject, name or identifier")} value={search} onChange={(e) => setSearch(e.target.value)} />
            <select value={showDisabled ? "disabled" : "enabled"} onChange={(e) => { setShowDisabled(e.target.value === "disabled"); setPending(null); setSessionsOf(null); }}>
              <option value="enabled">{t("Enabled")}</option>
              <option value="disabled">{t("Disabled")}</option>
            </select>
          </Toolbar>
          {!data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : shown.length === 0 ? (
            <Empty>{all.length === 0 ? (showDisabled ? t("No disabled identities.") : t("No identities.")) : t("No identity matches the search.")}</Empty>
          ) : (
          <table>
            <thead>
              <tr><th>{t("Subject")}</th><th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Roles and scopes")}</th><th>{t("Tokens")}</th><th /></tr>
            </thead>
            <tbody>
              {shown.map((principal) => (
                <Fragment key={principal.id}>
                <tr>
                  <td className="mono">
                    {principal.subject}
                    {principal.disabled_at && (
                      <div className="source"><span className="badge unknown">{t("disabled")}</span> <Time value={principal.disabled_at} /></div>
                    )}
                  </td>
                  <td>{principal.display_name || "—"}</td>
                  <td className="source">{principal.kind}</td>
                  <td>
                    {/* The field may not arrive at all. The interface must not
                        fall over because of it: one missing key used to take the
                        whole screen down. */}
                    {(principal.bindings ?? []).length === 0
                      ? <span className="source">{t("no direct assignments; roles may come from group mappings")}</span>
                      : (principal.bindings ?? []).map((binding, index) => (
                          <div key={index} className="row-actions" style={{ justifyContent: "flex-start" }}>
                            <span>
                              {binding.role}
                              <span className="source">
                                {" "}{binding.scope.site || "*"} / {binding.scope.environment || "*"}
                              </span>
                              {/* A binding with a date ends by itself; one past its date
                                  stays on the record and grants nothing. */}
                              {binding.valid_until && (
                                new Date(binding.valid_until).getTime() <= Date.now()
                                  ? <> <span className="badge unknown">{t("expired")}</span></>
                                  : <span className="source"> · {t("until")} <Time value={binding.valid_until} /></span>
                              )}
                            </span>
                            {!principal.disabled_at && (
                              <button
                                className="secondary"
                                disabled={revokeRole.isPending}
                                onClick={() => openPending({
                                  kind: "revoke-role", principal, role: binding.role,
                                  site: binding.scope.site === "*" ? "" : binding.scope.site,
                                  environment: binding.scope.environment === "*" ? "" : binding.scope.environment,
                                })}
                              >
                                {t("Remove")}
                              </button>
                            )}
                          </div>
                        ))}
                  </td>
                  <td>
                    {(principal.tokens ?? []).length === 0
                      ? <span className="source">{t("none")}</span>
                      : (principal.tokens ?? []).map((token) => (
                          <div key={token.id} className="row-actions" style={{ justifyContent: "flex-start" }}>
                            <span>
                              {token.description || token.id.slice(0, 8)}
                              <span className="source">
                                {" "}{token.expires_at ? <>{t("expires")} <Time value={token.expires_at} /></> : t("never expires")}
                                {token.last_used_at && <> · {t("last used")} <Time value={token.last_used_at} /></>}
                              </span>
                              {expiresSoon(token) && <> <span className="badge warn">{t("expires soon")}</span></>}
                            </span>
                            <button
                              className="danger"
                              disabled={revokeToken.isPending}
                              onClick={() => openPending({ kind: "revoke-token", principal, token })}
                            >
                              {t("Revoke")}
                            </button>
                          </div>
                        ))}
                  </td>
                  <td className="actions-cell">
                    <div className="row-actions">
                      {principal.disabled_at ? (
                        <button disabled={enable.isPending} onClick={() => openPending({ kind: "enable", principal })}>
                          {t("Enable")}
                        </button>
                      ) : (
                        <>
                          <button className="secondary" onClick={() => openGrant(principal)}>
                            {t("Grant role")}
                          </button>
                          <button className="secondary" disabled={issueToken.isPending} onClick={() => openPending({ kind: "issue-token", principal })}>
                            {t("Issue token")}
                          </button>
                          <button
                            className={sessionsOf?.id === principal.id ? "" : "secondary"}
                            onClick={() => setSessionsOf(sessionsOf?.id === principal.id ? null : principal)}
                          >
                            {t("Sessions")}
                          </button>
                          <button className="danger" disabled={disable.isPending} onClick={() => openPending({ kind: "disable", principal })}>
                            {t("Disable")}
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
                {sessionsOf?.id === principal.id && (
                  <tr className="detail-row">
                    <td colSpan={6}>
                      <Sessions
                        principal={principal}
                        revoking={pending?.kind === "revoke-session" ? pending.session.id : null}
                        onRevoke={(session) => openPending({ kind: "revoke-session", principal, session })}
                      />
                    </td>
                  </tr>
                )}
                </Fragment>
              ))}
            </tbody>
          </table>
          )}
        </Card>

        {creating && (
          <CreateIdentity
            onCreated={(token) => { setCreating(false); if (token) { setIssued(token); setCopied(false); } refresh(); }}
            onCancel={() => setCreating(false)}
            onError={onError}
          />
        )}

        {grant && (
          <Card
            className="span-3 fp-narrow"
            title={t("Grant role to {subject}", { subject: grant.subject })}
            footer={
              <Actions>
                <button disabled={!reasonGiven(grantReason) || grantMutation.isPending}
                        onClick={() => grantMutation.mutate()}>
                  {t("Grant role")}
                </button>
                <button className="secondary" onClick={() => setGrant(null)}>{t("Cancel")}</button>
              </Actions>
            }
          >
            <FieldGrid>
              <Field label={t("Role")}>
                <select value={grantRole} onChange={(e) => setGrantRole(e.target.value)}>
                  {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
                </select>
              </Field>
              <Field label={t("Site (empty = all)")}>
                <input value={grantSite} onChange={(e) => setGrantSite(e.target.value)} placeholder="lab" />
              </Field>
              <Field label={t("Environment (empty = all)")}>
                <input value={grantEnvironment} onChange={(e) => setGrantEnvironment(e.target.value)} placeholder="test" />
              </Field>
              <Field label={t("Valid until (empty = until revoked)")}>
                <input type="datetime-local" value={grantUntil} onChange={(e) => setGrantUntil(e.target.value)} />
              </Field>
              <Field label={t("Reason for the change")} wide>
                <input value={grantReason} onChange={(e) => setGrantReason(e.target.value)} placeholder={t("e.g. on-call rotation until the end of the quarter")} />
              </Field>
            </FieldGrid>
          </Card>
        )}

        {pending?.kind === "disable" && (
          <ConfirmCard
            key={`disable-${pending.principal.id}`}
            title={t("Disable {subject}", { subject: pending.principal.subject })}
            text={t("The sessions and the tokens of the identity end at once. The row stays, so the trail keeps naming it, and the identity can be enabled again later.")}
            action={t("Disable")}
            danger
            busy={disable.isPending}
            onConfirm={(reason) => disable.mutate({ id: pending.principal.id, reason })}
            onCancel={() => setPending(null)}
          />
        )}
        {pending?.kind === "enable" && (
          <ConfirmCard
            key={`enable-${pending.principal.id}`}
            title={t("Enable {subject}", { subject: pending.principal.subject })}
            text={t("The identity gets its access back with the roles it held. The sessions and the tokens that ended stay ended; issue a new token afterwards if one is needed.")}
            action={t("Enable")}
            busy={enable.isPending}
            onConfirm={(reason) => enable.mutate({ id: pending.principal.id, reason })}
            onCancel={() => setPending(null)}
          />
        )}
        {pending?.kind === "issue-token" && (
          <ConfirmCard
            key={`issue-${pending.principal.id}`}
            title={t("Issue token to {subject}", { subject: pending.principal.subject })}
            text={t("The value of the token is shown once, in the answer; the panel keeps only its digest.")}
            action={t("Issue token")}
            busy={issueToken.isPending}
            disabled={!ttlValid}
            onConfirm={(reason) => issueToken.mutate({ id: pending.principal.id, reason })}
            onCancel={() => setPending(null)}
          >
            <Field label={t("Description")} hint={t("What the token is for; the listing shows it.")} wide>
              <input value={tokenDescription} onChange={(e) => setTokenDescription(e.target.value)} placeholder={t("e.g. backup runner on ci-01")} />
            </Field>
            <Field label={t("Lifetime in hours")} hint={t("Default {n}; at most {max} (a year).", { n: DEFAULT_TOKEN_TTL_HOURS, max: MAX_TOKEN_TTL_HOURS })} wide>
              <input type="number" min={1} max={MAX_TOKEN_TTL_HOURS} value={tokenTTL} onChange={(e) => setTokenTTL(e.target.value)} />
            </Field>
          </ConfirmCard>
        )}
        {pending?.kind === "revoke-token" && (
          <ConfirmCard
            key={`revoke-token-${pending.token.id}`}
            title={t("Revoke token of {subject}", { subject: pending.principal.subject })}
            text={t("The token {token} stops working on its next request.", { token: pending.token.description || pending.token.id.slice(0, 8) })}
            action={t("Revoke")}
            danger
            busy={revokeToken.isPending}
            onConfirm={(reason) => revokeToken.mutate({ id: pending.principal.id, token: pending.token.id, reason })}
            onCancel={() => setPending(null)}
          />
        )}
        {pending?.kind === "revoke-role" && (
          <ConfirmCard
            key={`revoke-role-${pending.principal.id}-${pending.role}-${pending.site}-${pending.environment}`}
            title={t("Remove role from {subject}", { subject: pending.principal.subject })}
            text={t("The identity loses {role} in {scope}; a role it holds through a group mapping is not touched.", {
              role: pending.role, scope: `${pending.site || "*"} / ${pending.environment || "*"}`,
            })}
            action={t("Remove")}
            danger
            busy={revokeRole.isPending}
            onConfirm={(reason) => revokeRole.mutate({
              id: pending.principal.id, role: pending.role, site: pending.site, environment: pending.environment, reason,
            })}
            onCancel={() => setPending(null)}
          />
        )}
        {pending?.kind === "revoke-session" && (
          <ConfirmCard
            key={`revoke-session-${pending.session.id}`}
            title={t("End session of {subject}", { subject: pending.principal.subject })}
            text={t("The browser session {session} is refused on its next request; the identity keeps its roles and its tokens.", { session: pending.session.id.slice(0, 12) })}
            action={t("End session")}
            danger
            busy={revokeSession.isPending}
            onConfirm={(reason) => revokeSession.mutate({ id: pending.principal.id, session: pending.session.id, reason })}
            onCancel={() => setPending(null)}
          />
        )}

        <Card className="span-3" title={t("By kind")} description={t("among the {n} listed", { n: all.length })}>
          {!data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : (
            <>
              <Breakdown tone="info" items={byKind.map(([kind, n]) => ({ label: kind, value: n }))} />
              <h4 className="widget-subhead">{t("Direct roles")}</h4>
              {byRole.length === 0 ? (
                <p className="fp-blank">{t("No direct assignments.")}</p>
              ) : (
                <Breakdown tone="ok" items={byRole.map(([role, n]) => ({ label: role, value: n }))} />
              )}
              <p className="fp-rest">{t("{n} without direct assignments", { n: unassigned })}</p>
            </>
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * The live browser sessions of one identity, under its row. A token is
 * not a session, so an automated identity has none here; a person may
 * have several, one per browser, and the one that should not be there is
 * ended by itself.
 */
function Sessions({ principal, revoking, onRevoke }: {
  principal: ListedPrincipal;
  revoking: string | null;
  onRevoke: (session: SessionView) => void;
}) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["principal-sessions", principal.id],
    queryFn: () => api.get<Collection<SessionView>>(`/api/v1/principals/${principal.id}/sessions`),
    retry: false,
  });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <p className="source">{t("Loading…")}</p>;
  if (data.items.length === 0) return <p className="source">{t("No live browser session. Tokens are not sessions.")}</p>;
  return (
    <table>
      <thead>
        <tr><th>{t("Session")}</th><th>{t("Signed in")}</th><th>{t("Last seen")}</th><th>{t("Ends")}</th><th>{t("From")}</th><th /></tr>
      </thead>
      <tbody>
        {data.items.map((session) => (
          <tr key={session.id}>
            <td className="mono" title={session.id}>
              {session.id.slice(0, 12)}
              {session.acr && <span className="source"> acr={session.acr}</span>}
            </td>
            <td><Time value={session.created_at} /></td>
            <td><Time value={session.last_seen_at} /></td>
            <td>
              <Time value={session.expires_at} />
              <div className="source">{t("or idle")} <Time value={session.idle_expires_at} /></div>
            </td>
            <td className="source">
              {session.remote_addr || "—"}
              {session.user_agent && <div title={session.user_agent}>{session.user_agent.slice(0, 60)}</div>}
            </td>
            <td className="actions-cell">
              <button className="danger" disabled={revoking === session.id} onClick={() => onRevoke(session)}>
                {t("End session")}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The answer of the creation: the identity, and the first token when one was asked for. */
type CreatedIdentity = { id: string; subject: string; token?: string; token_expires_at?: string };

/**
 * A new local identity: a person with a token or a service. One role may
 * be granted with it; the others come later, one by one, like every
 * other grant. The first token is issued in the same answer, because a
 * service without a token cannot do anything yet.
 */
function CreateIdentity({ onCreated, onCancel, onError }: {
  onCreated: (token: IssuedToken | null) => void;
  onCancel: () => void;
  onError: (error: unknown) => void;
}) {
  const t = useT();
  const [subject, setSubject] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [kind, setKind] = useState<"user" | "service">("user");
  const [role, setRole] = useState("");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [issueToken, setIssueToken] = useState(true);
  const [ttl, setTTL] = useState(String(DEFAULT_TOKEN_TTL_HOURS));
  const [reason, setReason] = useState("");
  const ttlHours = Number.parseInt(ttl, 10);
  const ttlValid = !issueToken || (Number.isInteger(ttlHours) && ttlHours >= 1 && ttlHours <= MAX_TOKEN_TTL_HOURS);
  const create = useMutation({
    mutationFn: () =>
      api.post<CreatedIdentity>("/api/v1/principals", {
        subject: subject.trim(), display_name: displayName.trim(), kind,
        roles: role ? [{ role, site: site.trim(), environment: environment.trim(), valid_until: toInstant(validUntil) }] : [],
        issue_token: issueToken, token_ttl_hours: issueToken ? ttlHours : 0,
        reason: reason.trim(),
      }),
    onSuccess: (created) => onCreated(created.token ? { subject: created.subject, token: created.token, token_expires_at: created.token_expires_at } : null),
    onError,
  });
  return (
    <Card
      className="span-3 fp-narrow"
      title={t("New identity")}
      footer={
        <Actions>
          <button disabled={!subject.trim() || !reasonGiven(reason) || !ttlValid || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? t("Working…") : t("Create identity")}
          </button>
          <button className="secondary" onClick={onCancel} disabled={create.isPending}>{t("Cancel")}</button>
        </Actions>
      }
    >
      <FieldGrid>
        <Field label={t("Subject")} hint={t("The name the trail records; it cannot be changed later.")}>
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="backup-runner" />
        </Field>
        <Field label={t("Display name")}>
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </Field>
        <Field label={t("Kind")} hint={t("A person signs in or holds a token; a service only holds tokens.")}>
          <select value={kind} onChange={(e) => setKind(e.target.value as "user" | "service")}>
            <option value="user">{t("person (user)")}</option>
            <option value="service">{t("service")}</option>
          </select>
        </Field>
        <Field label={t("First role (empty = none yet)")}>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">{t("none")}</option>
            {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
          </select>
        </Field>
        {role && (
          <>
            <Field label={t("Site (empty = all)")}>
              <input value={site} onChange={(e) => setSite(e.target.value)} placeholder="lab" />
            </Field>
            <Field label={t("Environment (empty = all)")}>
              <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="test" />
            </Field>
            <Field label={t("Valid until (empty = until revoked)")}>
              <input type="datetime-local" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} />
            </Field>
          </>
        )}
        <label className="toggle">
          <input type="checkbox" checked={issueToken} onChange={(e) => setIssueToken(e.target.checked)} />
          {t("Issue the first token now")}
        </label>
        {issueToken && (
          <Field label={t("Lifetime in hours")} hint={t("Default {n}; at most {max} (a year).", { n: DEFAULT_TOKEN_TTL_HOURS, max: MAX_TOKEN_TTL_HOURS })}>
            <input type="number" min={1} max={MAX_TOKEN_TTL_HOURS} value={ttl} onChange={(e) => setTTL(e.target.value)} />
          </Field>
        )}
        <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("e.g. nightly backup automation")} />
        </Field>
      </FieldGrid>
    </Card>
  );
}

/** One role of the catalogue with what it may do. */
type RoleInfo = { role: string; permissions: string[] };

/**
 * The permissions of the catalogue as rows and the roles as columns, with
 * the rows in a fixed order: the matrix is read down a column to learn
 * what a role may do and along a row to learn who may do a thing.
 */
export function permissionMatrix(roles: RoleInfo[]): { roles: string[]; permissions: string[]; has: (role: string, permission: string) => boolean } {
  const permissions = Array.from(new Set(roles.flatMap((role) => role.permissions))).sort();
  const held = new Set(roles.flatMap((role) => role.permissions.map((permission) => `${role.role} ${permission}`)));
  return {
    roles: roles.map((role) => role.role),
    permissions,
    has: (role, permission) => held.has(`${role} ${permission}`),
  };
}

/**
 * The role catalogue as a matrix. The roles are fixed in the panel and
 * are not edited here: the screen answers "what may an operator do" and
 * "who may approve", which the list of identities does not.
 */
function Roles() {
  const t = useT();
  const [search, setSearch] = useState("");
  const { data, error } = useQuery({
    queryKey: ["roles"],
    queryFn: () => api.get<Collection<RoleInfo>>("/api/v1/roles"),
    retry: false,
  });
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Card><Empty>{t("Loading…")}</Empty></Card>;
  const matrix = permissionMatrix(data.items);
  const needle = search.trim().toLowerCase();
  const rows = matrix.permissions.filter((permission) => !needle || permission.toLowerCase().includes(needle));
  return (
    <div className="widgets">
      <Card
        className="span-12"
        title={t("Roles")}
        description={t("What each role may do. The roles are fixed; an identity gets one through a direct grant or a group mapping.")}
        flush
      >
        <Toolbar end={<span>{t("{n} permissions", { n: rows.length })}</span>}>
          <input placeholder={t("permission, e.g. job.create")} value={search} onChange={(e) => setSearch(e.target.value)} />
        </Toolbar>
        {rows.length === 0 ? (
          <Empty>{t("No permission matches the search.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Permission")}</th>
                {matrix.roles.map((role) => <th key={role}>{role}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((permission) => (
                <tr key={permission}>
                  <td className="mono">{permission}</td>
                  {matrix.roles.map((role) => (
                    <td key={role} title={`${role}: ${permission}`}>
                      {matrix.has(role, permission) ? <span className="badge ok">{t("yes")}</span> : <span className="source">—</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

/**
 * The access review: every enabled identity with what it can do, when it
 * was last used and what the reviewer should look at. A flag is a question
 * for the reviewer, not a verdict - an administrator without an expiry may
 * be exactly what the installation wants, but somebody has to have said
 * so. The CSV is the same review for the record an auditor keeps.
 */
function Review() {
  const t = useT();
  const [only, setOnly] = useState<ReviewFlag | "flagged" | "all">("all");
  const { data, error } = useQuery({
    queryKey: ["access-review"],
    queryFn: () => api.get<AccessReview>("/api/v1/access/review"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (error) return <ErrorBox error={error} />;
  if (!data) return <Card><Empty>{t("Loading…")}</Empty></Card>;

  const count = (flag: ReviewFlag) => data.items.filter((principal) => principal.flags.includes(flag)).length;
  const shown = data.items.filter((principal) =>
    only === "all" ? true : only === "flagged" ? principal.flags.length > 0 : principal.flags.includes(only));

  return (
    <>
      <StatGrid>
        <Stat label={t("Identities")} value={data.count} hint={t("enabled identities")} />
        <Stat label={t("Flagged")} value={data.flagged} tone={data.flagged > 0 ? "warn" : "ok"} />
        <Stat label={t("Unused {n} days", { n: data.thresholds.unused_days })} value={count("unused_90_days")} tone={count("unused_90_days") > 0 ? "warn" : "ok"} />
        <Stat label={t("Admins without expiry")} value={count("admin_without_expiry")} tone={count("admin_without_expiry") > 0 ? "warn" : "ok"} />
        <Stat label={t("Expiring within {n} days", { n: data.thresholds.expires_soon_days })} value={count("expires_soon")} tone={count("expires_soon") > 0 ? "warn" : "ok"} />
        <Stat label={t("Tokens older than a year")} value={count("token_older_than_year")} tone={count("token_older_than_year") > 0 ? "warn" : "ok"} />
      </StatGrid>

      <div className="widgets">
        <Card
          className="span-12"
          title={t("Access review")}
          description={t("Reviewed {when}. Every enabled identity with its roles, tokens and last use; the flags say what to look at.", { when: new Date(data.reviewed_at).toLocaleString() })}
          actions={
            <>
              <select value={only} onChange={(e) => setOnly(e.target.value as ReviewFlag | "flagged" | "all")}>
                <option value="all">{t("All identities")}</option>
                <option value="flagged">{t("Flagged only")}</option>
                <option value="unused_90_days">{t("Unused {n} days", { n: data.thresholds.unused_days })}</option>
                <option value="expires_soon">{t("Expiring within {n} days", { n: data.thresholds.expires_soon_days })}</option>
                <option value="admin_without_expiry">{t("Admins without expiry")}</option>
                <option value="token_older_than_year">{t("Tokens older than a year")}</option>
              </select>
              {/* A plain link: the browser carries the session, and the answer is a file. */}
              <a className="button" href="/api/v1/access/review?format=csv" download>{t("Export CSV")}</a>
            </>
          }
          flush
        >
          {shown.length === 0 ? (
            <EmptyState>{t("No identity matches the filter.")}</EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Subject")}</th><th>{t("Kind")}</th><th>{t("Roles and scopes")}</th>
                  <th>{t("Last use")}</th><th>{t("Tokens")}</th><th>{t("Flags")}</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((principal) => <ReviewRow key={principal.id} principal={principal} />)}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

function ReviewRow({ principal }: { principal: ReviewedPrincipal }) {
  const t = useT();
  return (
    <tr>
      <td>
        <span className="mono">{principal.subject}</span>
        {principal.display_name && <div className="source">{principal.display_name}</div>}
      </td>
      <td className="source">{principal.kind}</td>
      <td>
        {principal.bindings.length === 0
          ? <span className="source">{t("no direct assignments; roles may come from group mappings")}</span>
          : principal.bindings.map((binding, index) => (
              <div key={index}>
                {binding.role}
                <span className="source"> {binding.scope.site || "*"} / {binding.scope.environment || "*"}</span>
                {binding.expired
                  ? <> <span className="badge unknown">{t("expired")}</span></>
                  : binding.valid_until && <span className="source"> · {t("until")} <Time value={binding.valid_until} /></span>}
              </div>
            ))}
      </td>
      <td>
        {principal.last_seen_at
          ? <>
              <Time value={principal.last_seen_at} />
              <div className="source">
                {principal.last_login_at && <>{t("login")} <Time value={principal.last_login_at} /></>}
                {principal.last_login_at && principal.last_token_use_at && " · "}
                {principal.last_token_use_at && <>{t("token")} <Time value={principal.last_token_use_at} /></>}
              </div>
            </>
          : <span className="badge unknown">{t("never")}</span>}
      </td>
      <td>
        {principal.tokens.length === 0
          ? <span className="source">{t("none")}</span>
          : principal.tokens.map((token) => (
              <div key={token.id}>
                {token.description || token.id.slice(0, 8)}
                <span className="source"> · {t("issued")} <Time value={token.created_at} /></span>
                {expiresSoon(token) && <> <span className="badge warn">{t("expires soon")}</span></>}
              </div>
            ))}
      </td>
      <td>
        {principal.flags.length === 0
          ? <span className="badge ok">{t("nothing to review")}</span>
          : principal.flags.map((flag) => <span key={flag} className="badge warn" style={{ marginRight: 6 }}>{t(FLAG_LABELS[flag])}</span>)}
      </td>
    </tr>
  );
}

/* The English label of each flag; the catalogue translates it. */
const FLAG_LABELS: Record<ReviewFlag, string> = {
  unused_90_days: "unused for 90 days",
  expires_soon: "expires soon",
  admin_without_expiry: "admin without expiry",
  token_older_than_year: "token older than a year",
};

/**
 * A refusal because of a stale authentication is not an application error:
 * the panel is to offer signing in again and come back to the same place.
 */
function Warning({ error, close }: { error: ApiError | null; close: () => void }) {
  const t = useT();
  if (!error) return null;

  if (error.code === "reauthentication_required") {
    return (
      <div className="warning">
        <div>
          <strong>{t("Re-authentication required.")}</strong> {error.message}
        </div>
        <div className="operations">
          <button
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname + window.location.search);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </button>
          <button className="secondary" onClick={close}>{t("Close")}</button>
        </div>
      </div>
    );
  }
  return (
    <div className="warning">
      <div>{error.message}</div>
      <div className="operations"><button onClick={close}>{t("Close")}</button></div>
    </div>
  );
}
