import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import { copyToClipboard } from "../../lib/clipboard";
import { COMMON_TIME_ZONES, usePreferences, validTimeZone } from "../../lib/preferences";
import { LOCALES, useLocale } from "../../i18n";
import { SCALES } from "../../lib/scale";
import { THEMES } from "../../lib/theme";
import { useLook } from "../look";
import { relativeTime, absoluteTime } from "../../lib/format";
import type { ApiToken, Scope, Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { useToast } from "../../components/Toast";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Banner, Bones, Card, Empty, Fact, Facts, Field, Fields, Modal, Note, Pill, Problem,
  Seg, Table, Tag, Tags,
} from "../kit";

/**
 * Everything the person at the screen is, may do, and sets for themselves.
 *
 * Two kinds of preference live here and they are kept apart on purpose.
 * What is kept on the server under the person's identity - the language,
 * the theme, the zone times are read in, how long a page is - follows
 * them to another browser. What is this browser's - the size of the text
 * - stays here, because it answers to this screen and no other.
 *
 * The screen also holds the two things the owner of an identity does to
 * it and nobody else does for them: replacing the password it signs in
 * with, and minting or ending the tokens that act for it. A token's value
 * is in the answer that minted it and nowhere else, so it is shown once
 * and the panel keeps only a digest of it.
 */

type Session = {
  id: string;
  created_at: string;
  last_seen_at?: string;
  expires_at?: string;
  idle_expires_at?: string;
  user_agent?: string;
  /** Where the session is held from; the server writes one name or the other. */
  address?: string;
  remote_addr?: string;
  /** How the holder proved who they are, where the sign-in said so. */
  acr?: string;
  current?: boolean;
};

/** The identity with the identifier the principal routes are keyed on. */
type Identity = Whoami & { id?: string };

/** A freshly minted token, as the answer that minted it carries it. */
type IssuedToken = { subject?: string; token: string; token_expires_at?: string };

/** The permission minting or ending a token of an identity takes. */
export const TOKEN_PERMISSION = "principal.manage";

/** The shortest password this installation will take. */
export const PASSWORD_MIN_LENGTH = 12;

/** The reason every change to a token is recorded with. */
export const REASON_MIN_LENGTH = 8;

/** The lifetime of a token when the form does not say; the server's own default. */
export const DEFAULT_TOKEN_TTL_HOURS = 720;

/** The longest life the server gives a token: a year. */
export const MAX_TOKEN_TTL_HOURS = 8760;

/** A reason long enough for the trail. */
export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= REASON_MIN_LENGTH;
}

/**
 * Two hundred permission names in one cloud are read by nobody. They are
 * named area.action, so they fold into one row per area.
 */
export function groupPermissions(permissions: string[]): { area: string; actions: string[] }[] {
  const areas = new Map<string, string[]>();
  for (const permission of [...permissions].sort()) {
    const dot = permission.indexOf(".");
    const area = dot === -1 ? permission : permission.slice(0, dot);
    const action = dot === -1 ? "*" : permission.slice(dot + 1);
    const actions = areas.get(area) ?? [];
    if (!actions.includes(action)) actions.push(action);
    areas.set(area, actions);
  }
  return Array.from(areas, ([area, actions]) => ({ area, actions }));
}

/* The part of the panel each area of the permission names stands for.
   An area the screen does not know is shown as it came. */
const AREA_NAMES: Record<string, string> = {
  agent: "Agent",
  audit: "Audit trail",
  backup: "Backups",
  budget: "Budgets",
  campaign: "Campaigns",
  certificate: "Certificates",
  dns: "DNS",
  docker: "Containers",
  file: "Files",
  firewall: "Firewall",
  host: "Hosts",
  identity: "Directory",
  inventory: "Inventory",
  job: "Jobs",
  journal: "Logs",
  kernel: "Kernel",
  localuser: "Local accounts",
  logfile: "Log files",
  metrics: "Metrics",
  monitoring: "Monitoring",
  network: "Network",
  notification: "Notifications",
  packages: "Packages",
  pki: "Fleet CA",
  policy: "Policies",
  principal: "Identities and access",
  process: "Processes",
  relay: "Relays",
  schedule: "Schedules",
  secret: "Secrets",
  security: "Security checks",
  settings: "Settings",
  ssh: "SSH",
  storage: "Storage",
  system: "System",
  time: "Time",
  unit: "Services",
  vulnerability: "Vulnerabilities",
};

/** A scope part that names no site or environment: an asterisk, or nothing. */
function anyScope(value: string | undefined): boolean {
  return !value || value === "*";
}

export function Profile() {
  const t = useT();
  const { preferences, loaded, save, saving } = usePreferences();
  const { locale, setLocale } = useLocale();
  const { theme, setTheme, scale, setScale } = useLook();
  const [search] = useSearchParams();
  const [zone, setZone] = useState(preferences.time_zone);
  const [pageSize, setPageSize] = useState(preferences.page_size ? String(preferences.page_size) : "");
  const [landing, setLanding] = useState(preferences.landing_page);
  const [problem, setProblem] = useState("");
  const [saved, setSaved] = useState(false);
  const [changed, setChanged] = useState(false);

  // The fields start from what the server stored, once it has answered.
  useEffect(() => {
    if (!loaded) return;
    setZone(preferences.time_zone);
    setPageSize(preferences.page_size ? String(preferences.page_size) : "");
    setLanding(preferences.landing_page);
  }, [loaded, preferences.time_zone, preferences.page_size, preferences.landing_page]);

  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Identity>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const sessions = useQuery({
    queryKey: ["my-sessions"],
    queryFn: () => api.get<Collection<Session>>("/api/v1/me/sessions"),
    retry: false,
  });
  const tokens = useQuery({
    queryKey: ["my-tokens"],
    queryFn: () => api.get<Collection<ApiToken>>("/api/v1/me/tokens"),
    retry: false,
  });

  const store = async () => {
    setProblem("");
    setSaved(false);
    const size = pageSize.trim() === "" ? 0 : Number(pageSize);
    if (!validTimeZone(zone.trim())) {
      setProblem(t("The browser does not know that time zone."));
      return;
    }
    if (!Number.isFinite(size) || size < 0 || size > 500) {
      setProblem(t("A page holds between 1 and 500 rows."));
      return;
    }
    try {
      await save({ time_zone: zone.trim(), page_size: size, landing_page: landing.trim() });
      setSaved(true);
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
    }
  };

  const bindings = me.data?.bindings ?? [];
  const permissions = me.data?.permissions ?? [];
  const managesAccess = permissions.includes(TOKEN_PERMISSION);
  /* A sign-in that found a password somebody else chose sends the person
     here with this on the address. Two people know that password, so the
     screen says so above everything else until it has been replaced. */
  const mustChange = search.get("change_password") === "1" && !changed;
  const writing = useOwnTokens(me.data?.id, managesAccess, tokens.data?.items ?? [], tokens.isLoading);

  return (
    <>
      {mustChange && (
        <Banner tone="warn">
          <span data-testid="must-change-password">
            {t("Somebody else chose the password you signed in with, so two people know it. Replace it before you go on.")}
          </span>
        </Banner>
      )}
      {/* A new token and the question that ends one stand above the board:
          a container the reader has arranged away would take with it the
          one value the server will never show again. */}
      {writing.overlay}
      <Board screen={PROFILE_SCREEN} catalogue={PROFILE} drawn={{
        who: (
          <Card title={t("Who you are signed in as")}>
            <Facts>
              <Fact label={t("Name")}>{me.data?.display_name || <span className="fl-faint">—</span>}</Fact>
              <Fact label={t("Subject")}><span className="fl-mono">{me.data?.subject}</span></Fact>
              <Fact label={t("Kind")}>
                {me.data
                  ? (me.data.kind === "service" ? t("service") : t("person"))
                  : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Identifier")} mono>
                {me.data?.id || <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Roles")}>
                <Tags>
                  {(me.data?.roles ?? []).length > 0
                    ? me.data?.roles.map((role) => <Tag key={role}>{role}</Tag>)
                    : <Pill tone="unknown">{t("no roles")}</Pill>}
                </Tags>
              </Fact>
            </Facts>
            {managesAccess && (
              <Note>
                <Link to="/access">{t("Manage every identity on the access screen")}</Link>
              </Note>
            )}
          </Card>
        ),
        look: (
          <Card
            title={t("How the panel looks")}
            note={t("The theme and the language follow you to another browser; the size of the text belongs to this one.")}
          >
            <Fields>
              <Field label={t("Theme")}>
                <Seg
                  label={t("Theme")}
                  value={theme}
                  onChange={(code) => { setTheme(code); void save({ theme: code }); }}
                  options={THEMES.map((one) => ({ value: one.code, label: t(one.label) }))}
                />
              </Field>
              <Field label={t("Text size")} hint={t("Kept in this browser.")}>
                <Seg
                  label={t("Text size")}
                  value={scale}
                  onChange={setScale}
                  options={SCALES.map((one) => ({ value: one.code, label: one.label }))}
                />
              </Field>
              <Field label={t("Language")}>
                <Seg
                  label={t("Language")}
                  value={locale}
                  onChange={(code) => { setLocale(code); void save({ language: code }); }}
                  options={LOCALES.map((one) => ({ value: one.code, label: one.label }))}
                />
              </Field>
            </Fields>
          </Card>
        ),
        reading: (
          <Card
            title={t("How the panel reads to you")}
            note={t("Kept on the server under your identity.")}
            foot={saved ? t("Stored.") : undefined}
          >
            {problem && <Problem>{problem}</Problem>}
            <Fields>
              <Field label={t("Time zone")} hint={t("Empty reads every time in this browser's own zone.")}>
                <input
                  list="fl-zones"
                  value={zone}
                  onChange={(event) => setZone(event.target.value)}
                  placeholder={t("this browser's zone")}
                  data-testid="zone"
                />
                <datalist id="fl-zones">
                  {COMMON_TIME_ZONES.map((one) => <option key={one} value={one} />)}
                </datalist>
              </Field>
              <Field label={t("Rows per page")} hint={t("How many rows a list loads at once; empty for the panel's default, at most 500.")}>
                <input
                  type="number"
                  min={0}
                  max={500}
                  value={pageSize}
                  onChange={(event) => setPageSize(event.target.value)}
                  data-testid="page-size-preference"
                />
              </Field>
              <Field label={t("Landing page")} hint={t("The path the panel opens on after signing in, such as /hosts or /jobs; empty for the dashboard.")}>
                <input value={landing} onChange={(event) => setLanding(event.target.value)} placeholder="/dashboard" data-testid="landing" />
              </Field>
            </Fields>
            <Actions>
              <button type="button" onClick={store} disabled={saving} data-testid="store-preferences">
                {saving ? t("storing…") : t("Store")}
              </button>
            </Actions>
          </Card>
        ),
        password: <OwnPassword forced={mustChange} onChanged={() => setChanged(true)} />,
        bindings: (
          <Card
            title={t("Your roles and where they reach")}
            note={t("Each role with everything it is narrowed by. A category shown as any is one the binding does not narrow; a category naming values is one it does, and the role reaches nothing outside them.")}
            flush
          >
            <Table
              rows={bindings}
              keyOf={(one, index) => `${one.role}-${one.scope.site}-${one.scope.environment}-${index}`}
              loading={me.isLoading}
              empty={t("No binding: you can read nothing and change nothing until somebody grants a role.")}
              columns={[
                { key: "role", head: t("Role"), cell: (one) => one.role },
                { key: "site", head: t("Site"), cell: (one) => (
                  anyScope(one.scope.site)
                    ? <span className="fl-faint">{t("any site")}</span>
                    : <span className="fl-mono">{one.scope.site}</span>
                ) },
                { key: "environment", head: t("Environment"), cell: (one) => (
                  anyScope(one.scope.environment)
                    ? <span className="fl-faint">{t("any environment")}</span>
                    : <span className="fl-mono">{one.scope.environment}</span>
                ) },
                { key: "team", head: t("Team"), cell: (one) => (
                  one.scope.team_scope?.mode === "exact"
                    ? <span className="fl-mono">{one.scope.team_scope.team_id}</span>
                    : <span className="fl-faint">{t("any team")}</span>
                ) },
                { key: "owners", head: t("Owners"), minor: true, cell: (one) => (
                  <ScopeList values={one.scope.owners} every={t("any owner")} />
                ) },
                { key: "tags", head: t("Tags"), minor: true, cell: (one) => (
                  <ScopeList values={one.scope.tags} every={t("any tag")} />
                ) },
                { key: "until", head: t("Valid until"), minor: true, cell: (one) => {
                  const until = (one as { valid_until?: string }).valid_until;
                  return until
                    ? <span title={absoluteTime(until)}>{relativeTime(until)}</span>
                    : <span className="fl-faint">{t("until revoked")}</span>;
                } },
              ]}
            />
          </Card>
        ),
        permissions: (
          <Card
            title={t("What you may do")}
            note={t("Everything your roles allow, in any scope, by the part of the panel it concerns. The screens hide what is not here; the server refuses it either way.")}
            flush
          >
            <Table
              rows={groupPermissions(permissions)}
              keyOf={(one) => one.area}
              loading={me.isLoading}
              empty={t("No permission.")}
              columns={[
                { key: "area", head: t("Area"), cell: (one) => (
                  <span title={`${one.area}.*`}>{t(AREA_NAMES[one.area] ?? one.area)}</span>
                ) },
                { key: "allowed", head: t("Allowed"), cell: (one) => (
                  <Tags>
                    {one.actions.map((action) => (
                      <Tag key={action} title={`${one.area}.${action}`}>{action}</Tag>
                    ))}
                  </Tags>
                ) },
              ]}
            />
          </Card>
        ),
        sessions: (
          <Card title={t("Your sessions")} note={t("Where this identity is signed in.")} flush>
            <Table
              rows={sessions.data?.items ?? []}
              keyOf={(one) => one.id}
              loading={sessions.isLoading} empty={t("No session is recorded. Tokens are not sessions.")}
              columns={[
                { key: "where", head: t("From"), cell: (one) => (
                  <span className="fl-mono">{one.address || one.remote_addr || <span className="fl-faint">—</span>}</span>
                ) },
                { key: "agent", head: t("Browser"), minor: true, tight: true, cell: (one) => (
                  one.user_agent ? <span title={one.user_agent}>{one.user_agent}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "since", head: t("Signed in"), cell: (one) => (
                  <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
                ) },
                { key: "seen", head: t("Last seen"), cell: (one) => (
                  one.last_seen_at
                    ? <span title={absoluteTime(one.last_seen_at)}>{relativeTime(one.last_seen_at)}</span>
                    : <span className="fl-faint">—</span>
                ) },
                { key: "ends", head: t("Ends"), minor: true, cell: (one) => (
                  one.expires_at
                    ? (
                      <span title={one.idle_expires_at
                        ? t("or idle {when}", { when: absoluteTime(one.idle_expires_at) })
                        : absoluteTime(one.expires_at)}>
                        {relativeTime(one.expires_at)}
                      </span>
                    )
                    : <span className="fl-faint">—</span>
                ) },
                { key: "how", head: t("How"), minor: true, tight: true, cell: (one) => (
                  one.acr ? <span className="fl-mono">{one.acr}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "this", head: "", cell: (one) => (one.current ? <Pill tone="ok">{t("this one")}</Pill> : null) },
              ]}
            />
          </Card>
        ),
        tokens: writing.card,
      }} />
    </>
  );
}

/** One category of alternatives: everything, a named few, or nothing at all. */
function ScopeList({ values, every }: { values: Scope["owners"] | undefined; every: string }) {
  const t = useT();
  if (!values || values.includes("*")) return <span className="fl-faint">{every}</span>;
  if (values.length === 0) return <Pill tone="warn">{t("nothing")}</Pill>;
  return <span className="fl-mono">{values.join(", ")}</span>;
}

/**
 * Your own password, where this installation signs people in without a
 * provider.
 *
 * The one in force is asked for even though the session is already yours:
 * a session left open on a desk must not be enough to lock its owner out
 * of their own account. Neither password leaves this card except in the
 * body of the one request that changes it, and nothing of either is left
 * on the screen once it has gone.
 */
function OwnPassword({ forced, onChanged }: { forced: boolean; onChanged: () => void }) {
  const t = useT();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [refusal, setRefusal] = useState("");

  const change = useMutation({
    /* Both passwords go in the body. A query string is written to every
       access log, to the browser's history and to the referrer of the
       next request, so a secret never goes in one. */
    mutationFn: () => api.post("/api/v1/profile/password", { current, new: next }),
    onSuccess: () => {
      setCurrent(""); setNext(""); setAgain(""); setRefusal("");
      onChanged();
      toast.success(t("The password is changed; it is in force from the next sign-in."));
    },
    onError: (error) => setRefusal(error instanceof Error ? error.message : String(error)),
  });

  const mismatch = again !== "" && next !== again;
  const ready = current !== "" && next !== "" && !mismatch && !change.isPending;

  return (
    <Card
      title={t("Your password")}
      note={forced
        ? t("Somebody else chose the password you signed in with, so two people know it. Replace it here.")
        : t("The password you sign in with where this installation has no identity provider.")}
      foot={
        <Actions>
          <button type="button" disabled={!ready} onClick={() => change.mutate()} data-testid="change-password">
            {change.isPending ? t("changing…") : t("Change the password")}
          </button>
        </Actions>
      }
    >
      {refusal !== "" && <Problem><span data-testid="password-refusal">{refusal}</span></Problem>}
      <Fields>
        <Field label={t("The password in force")}>
          <input type="password" value={current} autoComplete="current-password"
                 onChange={(event) => setCurrent(event.target.value)} data-testid="current-password" />
        </Field>
        <Field
          label={t("The new password")}
          hint={t("At least {n} characters. Length is the rule; a word from every list is refused however it is spelled.", { n: PASSWORD_MIN_LENGTH })}
        >
          <input type="password" value={next} autoComplete="new-password"
                 onChange={(event) => setNext(event.target.value)} data-testid="new-password" />
        </Field>
        <Field label={t("The new password again")}>
          <input type="password" value={again} autoComplete="new-password"
                 onChange={(event) => setAgain(event.target.value)} data-testid="new-password-again" />
        </Field>
      </Fields>
      {mismatch && <Problem>{t("The two new passwords are not the same.")}</Problem>}
    </Card>
  );
}

/** What the token card is asking about; one thing at a time. */
type TokenAsk = { kind: "issue" } | { kind: "revoke"; token: ApiToken };

/**
 * The tokens that act for this identity: what is live, one more, and the
 * end of one.
 *
 * It hands back two pieces rather than one. The listing is a container of
 * the board like any other; the value of a new token and the question
 * that ends one stand above the board, because a container somebody has
 * arranged away must not be able to take the one showing of a secret with
 * it.
 */
function useOwnTokens(principal: string | undefined, allowed: boolean, tokens: ApiToken[], loading: boolean): {
  overlay: ReactNode;
  card: ReactNode;
} {
  const t = useT();
  const queryClient = useQueryClient();
  const [ask, setAsk] = useState<TokenAsk | null>(null);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [copied, setCopied] = useState(false);
  const [refusal, setRefusal] = useState("");
  const [description, setDescription] = useState("");
  const [ttl, setTtl] = useState(String(DEFAULT_TOKEN_TTL_HOURS));

  const refused = (error: unknown) => {
    setAsk(null);
    setRefusal(error instanceof Error ? error.message : String(error));
  };
  const settled = () => {
    setAsk(null);
    setRefusal("");
    void queryClient.invalidateQueries({ queryKey: ["my-tokens"] });
  };

  const hours = Number.parseInt(ttl, 10);
  const ttlValid = Number.isInteger(hours) && hours >= 1 && hours <= MAX_TOKEN_TTL_HOURS;

  const issue = useMutation({
    mutationFn: (reason: string) =>
      api.post<IssuedToken>(`/api/v1/principals/${principal}/tokens`, {
        reason, description: description.trim(), token_ttl_hours: hours,
      }),
    onSuccess: (token) => { setIssued(token); setCopied(false); setDescription(""); settled(); },
    onError: refused,
  });
  const revoke = useMutation({
    /* The identifier of the token goes in the path, never its value: a
       path is written down in every log there is, and the value is the
       secret the token is. */
    mutationFn: ({ token, reason }: { token: ApiToken; reason: string }) =>
      api.del(`/api/v1/principals/${principal}/tokens/${token.id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: settled,
    onError: refused,
  });

  const busy = issue.isPending || revoke.isPending;
  const can = allowed && principal !== undefined;
  const denied = t("This needs the permission {permission}, which the platform administrator holds.", { permission: TOKEN_PERMISSION });

  const overlay = (
    <>
      {issued && (
        <Banner
          tone="info"
          actions={
            <>
              <button type="button" onClick={() => { void copyToClipboard(issued.token).then(setCopied); }}
                      data-testid="copy-token">
                {copied ? t("Token copied") : t("Copy token")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setIssued(null)} data-testid="close-token">
                {t("Close")}
              </button>
            </>
          }
        >
          <span data-testid="issued-token">
            {t("Your token is issued. It is shown once, here, and the panel keeps only a digest of it.")}{" "}
            <code>{issued.token}</code>
            {issued.token_expires_at && <> · {t("expires {when}", { when: absoluteTime(issued.token_expires_at) })}</>}
          </span>
        </Banner>
      )}
      {ask && (
        <AskAboutToken
          ask={ask}
          busy={busy}
          blocked={ask.kind === "issue" && !ttlValid}
          onClose={() => setAsk(null)}
          onConfirm={(reason) => ask.kind === "issue"
            ? issue.mutate(reason)
            : revoke.mutate({ token: ask.token, reason })}
        >
          {ask.kind === "issue" && (
            <>
              <Field label={t("Description")} hint={t("What the token is for; the listing shows it.")} wide>
                <input value={description} onChange={(event) => setDescription(event.target.value)}
                       data-testid="token-description" />
              </Field>
              <Field
                label={t("Lifetime in hours")}
                hint={t("Default {n}; at most {max} (a year).", { n: DEFAULT_TOKEN_TTL_HOURS, max: MAX_TOKEN_TTL_HOURS })}
                wide
              >
                <input type="number" min={1} max={MAX_TOKEN_TTL_HOURS} value={ttl}
                       onChange={(event) => setTtl(event.target.value)} data-testid="token-ttl" />
              </Field>
            </>
          )}
        </AskAboutToken>
      )}
    </>
  );

  const card = (
    <Card
      title={t("Your API tokens")}
      note={t("The API tokens issued to your identity. A value is shown once, when the token is issued, and nowhere again.")}
      tools={
        <button type="button" onClick={() => { setAsk({ kind: "issue" }); setRefusal(""); }}
                disabled={!can || ask !== null} title={can ? undefined : denied} data-testid="issue-token">
          {t("Issue a token…")}
        </button>
      }
      foot={can ? undefined : <Note>{denied}</Note>}
      flush
    >
      {refusal !== "" && <Problem><span data-testid="token-refusal">{refusal}</span></Problem>}
      {loading && tokens.length === 0
        ? <Bones rows={3} />
        : tokens.length === 0
          ? <Empty>{t("No live token. A token acts for you where a browser cannot: a script, a pipeline, another machine.")}</Empty>
          : (
            <Table
              rows={tokens}
              keyOf={(one) => one.id}
              rowTestId={(one) => `token-${one.id}`}
              columns={[
                { key: "id", head: t("Token"), tight: true, cell: (one) => (
                  <span className="fl-mono" title={one.id}>{one.id.slice(0, 12)}</span>
                ) },
                { key: "description", head: t("Description"), cell: (one) => (
                  one.description || <Pill tone="unknown">{t("nobody wrote one")}</Pill>
                ) },
                { key: "created", head: t("Issued"), cell: (one) => (
                  <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
                ) },
                { key: "used", head: t("Last used"), minor: true, cell: (one) => (
                  one.last_used_at
                    ? <span title={absoluteTime(one.last_used_at)}>{relativeTime(one.last_used_at)}</span>
                    : <span className="fl-faint">{t("never used")}</span>
                ) },
                { key: "expires", head: t("Expires"), minor: true, cell: (one) => (
                  one.expires_at
                    ? <span title={absoluteTime(one.expires_at)}>{relativeTime(one.expires_at)}</span>
                    : <span className="fl-faint">{t("never")}</span>
                ) },
                { key: "act", head: "", actions: true, cell: (one) => (
                  <button
                    type="button"
                    className="fl-danger"
                    disabled={!can || ask !== null}
                    title={can ? undefined : denied}
                    onClick={() => { setAsk({ kind: "revoke", token: one }); setRefusal(""); }}
                    data-testid={`revoke-token-${one.id}`}
                  >
                    {t("Revoke")}
                  </button>
                ) },
              ]}
            />
          )}
    </Card>
  );

  return { overlay, card };
}

/**
 * The question a token asks before it is minted or ended, and the reason
 * that goes with it into the trail.
 */
function AskAboutToken({ ask, busy, blocked, onConfirm, onClose, children }: {
  ask: TokenAsk;
  busy: boolean;
  blocked: boolean;
  onConfirm: (reason: string) => void;
  onClose: () => void;
  children?: ReactNode;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const ending = ask.kind === "revoke";
  return (
    <Modal
      title={ending ? t("Revoke a token") : t("Issue a token")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
          <button
            type="button"
            className={ending ? "fl-danger" : undefined}
            disabled={!reasonGiven(reason) || busy || blocked}
            onClick={() => onConfirm(reason.trim())}
            data-testid="token-confirm"
          >
            {busy ? t("Working…") : ending ? t("Revoke the token") : t("Issue the token")}
          </button>
        </>
      }
    >
      <Note>
        {ending
          ? t("Whatever signs in with this token stops at once, and nothing will say which script that was. The value cannot be read back, so it cannot be put anywhere else first.")
          : t("The value is in the answer and nowhere else: read it off the screen when it comes, because the panel keeps only a digest of it.")}
      </Note>
      <Fields>
        {children}
        <Field
          label={t("Reason (kept in the audit trail)")}
          hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })}
          wide
        >
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="token-reason" />
        </Field>
      </Fields>
    </Modal>
  );
}

export const PROFILE_SCREEN = "next_profile";

export const PROFILE: BoardEntry[] = [
  { key: "who", title: "Who you are signed in as", width: 5, height: 2 },
  { key: "look", title: "How the panel looks", width: 7, height: 2 },
  { key: "reading", title: "How the panel reads to you", width: 7, height: 2 },
  { key: "password", title: "Your password", width: 5, height: 2 },
  { key: "bindings", title: "Your roles and where they reach", width: 12, height: 2 },
  { key: "permissions", title: "What you may do", width: 12, height: 3 },
  { key: "sessions", title: "Your sessions", width: 12, height: 2 },
  { key: "tokens", title: "Your API tokens", width: 12, height: 2 },
];
