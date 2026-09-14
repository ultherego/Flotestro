import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { AccessReview, GroupMapping, Principal, ReviewFlag, ReviewedPrincipal } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { toInstant } from "../lib/format";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, StatGrid, Stat } from "../components/layout";
import { Breakdown } from "../components/widgets";
import { CertificateAuthority } from "./CertificateAuthority";
import { useT } from "../i18n";

const ROLES = [
  "viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin",
];

/**
 * Panel access management.
 *
 * These operations change the access rules themselves, so the panel demands
 * a fresh authentication and a reason. The reason lands in the audit trail
 * together with the description of the change.
 */
export function Access() {
  const t = useT();
  const [tab, setTab] = useState<"mappings" | "identities" | "review" | "ca">("mappings");
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
        <button className={tab === "review" ? "active" : ""} onClick={() => setTab("review")}>
          {t("Access review")}
        </button>
        <button className={tab === "ca" ? "active" : ""} onClick={() => setTab("ca")}>
          {t("Fleet CA")}
        </button>
      </div>

      {tab === "ca" && <Warning error={warning} close={() => setWarning(null)} />}
      {tab === "mappings" && <Mappings />}
      {tab === "identities" && <Identities />}
      {tab === "review" && <Review />}
      {tab === "ca" && <CertificateAuthority reportError={setWarning} />}
    </>
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
    onSuccess: refresh,
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

  return (
    <>
      <Warning error={warning} close={() => setWarning(null)} />

      {/* The form opens beside the list it adds to; while it is closed the
          list has the row to itself. */}
      <div className="widgets">
        <Card
          className={form ? "span-6" : "span-9"}
          title={t("Group mappings")}
          actions={!form && <button onClick={() => setForm(true)}>{t("Add mapping")}</button>}
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
                        <button
                          className="danger"
                          onClick={() => {
                            const reason = window.prompt(
                              t("Reason for removing the group mapping {group} (min. 8 characters):", { group: mapping.group_name }),
                            );
                            if (reason) remove.mutate({ id: mapping.id, reason });
                          }}
                        >
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
                <button disabled={!group.trim() || reason.trim().length < 8 || add.isPending}
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

function Identities() {
  const t = useT();
  const queryClient = useQueryClient();
  const [warning, setWarning] = useState<ApiError | null>(null);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["principals"],
    queryFn: () => api.get<Collection<Principal>>("/api/v1/principals"),
    retry: false,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["principals"] });
  const onError = (error: unknown) => setWarning(error instanceof ApiError ? error : null);

  // Every change here moves who can do what on the fleet, so each one asks
  // for a reason the same way the group mappings do; the panel demands
  // fresh authentication behind it.
  const ask = (question: string) => {
    const reason = window.prompt(question);
    return reason && reason.trim().length >= 8 ? reason.trim() : null;
  };
  const disable = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: refresh, onError,
  });
  const revokeToken = useMutation({
    mutationFn: ({ id, token, reason }: { id: string; token: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}/tokens/${token}?reason=${encodeURIComponent(reason)}`),
    onSuccess: refresh, onError,
  });
  const issueToken = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<IssuedToken>(`/api/v1/principals/${id}/tokens`, { reason }),
    onSuccess: (token) => { setIssued(token); setCopied(false); refresh(); }, onError,
  });
  const revokeRole = useMutation({
    mutationFn: ({ id, role, site, environment, reason }:
      { id: string; role: string; site: string; environment: string; reason: string }) =>
      api.del(`/api/v1/principals/${id}/roles/${role}`, { site, environment, reason }),
    onSuccess: refresh, onError,
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

  if (error instanceof ApiError && error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Card><Empty>{t("No identities.")}</Empty></Card>;

  // The identities by kind, and the roles their direct assignments hand
  // out; an identity without assignments is named, because its roles, if
  // any, come from the group mappings and are not visible here.
  const tally = (keys: (principal: Principal) => string[]) => Object.entries(
    data.items.reduce<Record<string, number>>((acc, principal) => { for (const k of keys(principal)) acc[k] = (acc[k] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const byKind = tally((principal) => [principal.kind]);
  const byRole = tally((principal) => (principal.bindings ?? []).map((binding) => binding.role));
  const unassigned = data.items.filter((principal) => (principal.bindings ?? []).length === 0).length;

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
        <Card className={grant ? "span-6" : "span-9"} title={t("Identities")} flush>
          <table>
            <thead>
              <tr><th>{t("Subject")}</th><th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Roles and scopes")}</th><th>{t("Tokens")}</th><th /></tr>
            </thead>
            <tbody>
              {data.items.map((principal) => (
                <tr key={principal.id}>
                  <td className="mono">{principal.subject}</td>
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
                            <button
                              className="secondary"
                              disabled={revokeRole.isPending}
                              onClick={() => {
                                const reason = ask(t("Reason for removing the role {role} from {subject} (min. 8 characters):", { role: binding.role, subject: principal.subject }));
                                if (reason) revokeRole.mutate({
                                  id: principal.id, role: binding.role,
                                  site: binding.scope.site === "*" ? "" : binding.scope.site,
                                  environment: binding.scope.environment === "*" ? "" : binding.scope.environment,
                                  reason,
                                });
                              }}
                            >
                              {t("Remove")}
                            </button>
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
                            </span>
                            <button
                              className="danger"
                              disabled={revokeToken.isPending}
                              onClick={() => {
                                const reason = ask(t("Reason for revoking the token of {subject} (min. 8 characters):", { subject: principal.subject }));
                                if (reason) revokeToken.mutate({ id: principal.id, token: token.id, reason });
                              }}
                            >
                              {t("Revoke")}
                            </button>
                          </div>
                        ))}
                  </td>
                  <td className="actions-cell">
                    <div className="row-actions">
                      <button
                        className="secondary"
                        onClick={() => setGrant({ id: principal.id, subject: principal.subject })}
                      >
                        {t("Grant role")}
                      </button>
                      <button
                        className="secondary"
                        disabled={issueToken.isPending}
                        onClick={() => {
                          const reason = ask(t("Reason for issuing a token to {subject} (min. 8 characters):", { subject: principal.subject }));
                          if (reason) issueToken.mutate({ id: principal.id, reason });
                        }}
                      >
                        {t("Issue token")}
                      </button>
                      <button
                        className="danger"
                        disabled={disable.isPending}
                        onClick={() => {
                          const reason = ask(t("Reason for disabling {subject} - the sessions and tokens end at once (min. 8 characters):", { subject: principal.subject }));
                          if (reason) disable.mutate({ id: principal.id, reason });
                        }}
                      >
                        {t("Disable")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        {grant && (
          <Card
            className="span-3 fp-narrow"
            title={t("Grant role to {subject}", { subject: grant.subject })}
            footer={
              <Actions>
                <button disabled={grantReason.trim().length < 8 || grantMutation.isPending}
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

        <Card className="span-3" title={t("By kind")} description={t("among the {n} listed", { n: data.items.length })}>
          <Breakdown tone="info" items={byKind.map(([kind, n]) => ({ label: kind, value: n }))} />
          <h4 className="widget-subhead">{t("Direct roles")}</h4>
          {byRole.length === 0 ? (
            <p className="fp-blank">{t("No direct assignments.")}</p>
          ) : (
            <Breakdown tone="ok" items={byRole.map(([role, n]) => ({ label: role, value: n }))} />
          )}
          <p className="fp-rest">{t("{n} without direct assignments", { n: unassigned })}</p>
        </Card>
      </div>
    </>
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
              const target = encodeURIComponent(window.location.pathname);
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
