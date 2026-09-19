import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { ApiToken, Whoami } from "../lib/types";
import { COMMON_TIME_ZONES, usePreferences, validTimeZone } from "../lib/preferences";
import { LOCALES, useLocale, useT } from "../i18n";
import { THEMES, type Theme } from "../lib/theme";
import { absoluteTime, absoluteTimeIn } from "../lib/format";
import { Empty, ErrorBox, Pair, Pairs, Time } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { useToast } from "../components/Toast";

/**
 * The person at the screen: who the panel takes them for, what they may do
 * and where, where they are signed in, and how they like the panel.
 */

/** A live browser session of the caller, as the API lists it. */
type OwnSession = {
  id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  idle_expires_at: string;
  remote_addr?: string;
  user_agent?: string;
  acr?: string;
  amr?: string[];
};

/** The identity with the identifier the principal routes key on. */
type Identity = Whoami & { id?: string };

const WHOAMI_STALE = 5 * 60 * 1000;

/** A scope part that names no site or environment: an asterisk, as the server keeps it, or nothing. */
function anyScope(value: string | undefined): boolean {
  return !value || value === "*";
}

/**
 * Two hundred permission names in one cloud are read by nobody. They are
 * named area.
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

export function Profile({ theme, setTheme }: {
  theme: Theme;
  setTheme: (theme: Theme) => void;
}) {
  const t = useT();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Identity>("/api/v1/whoami"),
    staleTime: WHOAMI_STALE,
  });
  const sessions = useQuery({
    queryKey: ["me", "sessions"],
    queryFn: () => api.get<Collection<OwnSession>>("/api/v1/me/sessions"),
    retry: false,
  });
  const tokens = useQuery({
    queryKey: ["me", "tokens"],
    queryFn: () => api.get<Collection<ApiToken>>("/api/v1/me/tokens"),
    retry: false,
  });

  if (whoami.error) return <ErrorBox error={whoami.error} />;
  const me = whoami.data;
  const name = me?.display_name || me?.subject || "";
  const managesAccess = (me?.permissions ?? []).includes("principal.manage");

  return (
    <>
      <PageHeader
        icon="user"
        title={t("Profile")}
        description={t("Who the panel takes you for, what you may do and where, where you are signed in, and how you like the panel.")}
      />

      <div className="widgets">
        <Card className="span-6" title={t("Identity")} description={t("As the trail names you.")}>
          {!me ? (
            <Empty>{t("Loading…")}</Empty>
          ) : (
            <Pairs>
              <Pair label={t("Name")}>{name}</Pair>
              <Pair label={t("Subject")}><span className="mono">{me.subject}</span></Pair>
              <Pair label={t("Kind")}>{me.kind === "service" ? t("service") : t("person")}</Pair>
              {me.id && <Pair label={t("Identifier")}><span className="mono">{me.id}</span></Pair>}
              <Pair label={t("Roles")}>
                {me.roles.length === 0 ? <span className="badge unknown">{t("no roles")}</span> : me.roles.join(", ")}
              </Pair>
            </Pairs>
          )}
          {managesAccess && me?.id && (
            <p className="source">
              <Link to="/access">{t("Manage every identity on the access screen")}</Link>
            </p>
          )}
        </Card>

        <Card
          className="span-6"
          title={t("Bindings")}
          description={t("Each role with the site and the environment it holds in.")}
          flush
        >
          {!me ? (
            <Empty>{t("Loading…")}</Empty>
          ) : me.bindings.length === 0 ? (
            <Empty>{t("No binding: you can read nothing and change nothing until somebody grants a role.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Role")}</th><th>{t("Site")}</th><th>{t("Environment")}</th><th>{t("Valid until")}</th></tr>
              </thead>
              <tbody>
                {me.bindings.map((binding, index) => {
                  const until = (binding as { valid_until?: string }).valid_until;
                  return (
                    <tr key={`${binding.role}-${binding.scope.site}-${binding.scope.environment}-${index}`}>
                      <td>{binding.role}</td>
                      <td>{anyScope(binding.scope.site) ? <span className="source">{t("any site")}</span> : <span className="mono">{binding.scope.site}</span>}</td>
                      <td>{anyScope(binding.scope.environment) ? <span className="source">{t("any environment")}</span> : <span className="mono">{binding.scope.environment}</span>}</td>
                      <td>{until ? <Time value={until} /> : <span className="source">{t("until revoked")}</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-12"
          title={t("Permissions")}
          description={t("Everything your roles allow, in any scope, by the part of the panel it concerns. The screens hide what is not here; the server refuses it either way.")}
          flush
        >
          {!me ? (
            <Empty>{t("Loading…")}</Empty>
          ) : me.permissions.length === 0 ? (
            <Empty>{t("No permission.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th>{t("Area")}</th><th>{t("Allowed")}</th></tr>
              </thead>
              <tbody>
                {groupPermissions(me.permissions).map((group) => (
                  <tr key={group.area}>
                    <td className="fp-nowrap">
                      <div className="fp-host-cell">
                        <span>{t(AREA_NAMES[group.area] ?? group.area)}</span>
                        <span className="source mono">{group.area}.*</span>
                      </div>
                    </td>
                    <td>
                      <div className="fp-chips">
                        {group.actions.map((action) => (
                          <span key={action} className="chip chip-mono" title={`${group.area}.${action}`}>{action}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <PreferencesCard theme={theme} setTheme={setTheme} />

        <Card
          className="span-12"
          title={t("Sessions")}
          description={t("Where you are signed in right now. A session you do not recognise is ended from the access screen by whoever manages the identities, or by signing out of every browser.")}
          flush
        >
          <OwnSessions query={sessions} />
        </Card>

        <Card
          className="span-12"
          title={t("Tokens")}
          description={t("The API tokens issued to your identity. A value is shown once, when the token is issued, and nowhere again.")}
          flush
        >
          <OwnTokens query={tokens} />
        </Card>
      </div>
    </>
  );
}

/**
 * The preferences, edited whole: the zone, the page size, the landing page,
 * and the language and the theme the top bar also switches.
 */
function PreferencesCard({ theme, setTheme }: { theme: Theme; setTheme: (theme: Theme) => void }) {
  const t = useT();
  const toast = useToast();
  const { locale, setLocale } = useLocale();
  const { preferences, loaded, save, saving } = usePreferences();
  const [zone, setZone] = useState(preferences.time_zone);
  const [pageSize, setPageSize] = useState(preferences.page_size ? String(preferences.page_size) : "");
  const [landing, setLanding] = useState(preferences.landing_page);
  const [message, setMessage] = useState("");

  // The form follows the server's copy: it fills in when the answer is
  // in and settles on what was written after every save.
  useEffect(() => {
    if (!loaded) return;
    setZone(preferences.time_zone);
    setPageSize(preferences.page_size ? String(preferences.page_size) : "");
    setLanding(preferences.landing_page);
  }, [loaded, preferences.time_zone, preferences.page_size, preferences.landing_page]);

  const parsedPageSize = pageSize.trim() === "" ? 0 : Number(pageSize);
  const pageSizeValid = Number.isInteger(parsedPageSize) && parsedPageSize >= 0 && parsedPageSize <= 500;
  const zoneValid = validTimeZone(zone.trim());
  const landingValid = landing.trim() === "" || (landing.trim().startsWith("/") && !landing.trim().startsWith("//"));
  const changed = zone.trim() !== preferences.time_zone
    || parsedPageSize !== preferences.page_size
    || landing.trim() !== preferences.landing_page;
  const ready = loaded && changed && pageSizeValid && zoneValid && landingValid;

  const submit = async () => {
    setMessage("");
    try {
      await save({ time_zone: zone.trim(), page_size: parsedPageSize, landing_page: landing.trim() });
      toast.success(t("Preferences saved."));
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error));
    }
  };

  const applyLanguage = (code: (typeof LOCALES)[number]["code"]) => {
    setLocale(code);
    save({ language: code }).catch((error: unknown) => setMessage(error instanceof Error ? error.message : String(error)));
  };
  const applyTheme = (code: Theme) => {
    setTheme(code);
    save({ theme: code }).catch((error: unknown) => setMessage(error instanceof Error ? error.message : String(error)));
  };

  const now = new Date().toISOString();

  return (
    <Card
      className="span-12"
      title={t("Preferences")}
      description={t("How you like the panel. The choices are kept under your identity and follow you to the next browser.")}
      footer={
        <Actions>
          <button onClick={submit} disabled={!ready || saving}>{saving ? t("saving…") : t("Save")}</button>
          {message && <span className="page-error">{message}</span>}
          {preferences.updated_at && (
            <span className="source">{t("Last changed")} <Time value={preferences.updated_at} /></span>
          )}
        </Actions>
      }
    >
      <FieldGrid>
        <Field
          label={t("Time zone")}
          hint={zoneValid
            ? t("The zone every time on the screen is read in; empty for this browser's own. Now: {now}", { now: zone.trim() && zoneValid ? absoluteTimeIn(now, zone.trim()) : absoluteTime(now) })
            : t("This browser does not know the zone.")}
        >
          <input
            value={zone}
            list="profile-time-zones"
            placeholder={t("browser's own")}
            onChange={(e) => setZone(e.target.value)}
            aria-invalid={!zoneValid}
            data-testid="preference-time-zone"
          />
          <datalist id="profile-time-zones">
            {COMMON_TIME_ZONES.map((name) => <option key={name} value={name} />)}
          </datalist>
        </Field>
        <Field label={t("Rows per page")} hint={t("How many rows a list loads at once; empty for the panel's default, at most 500.")}>
          <input
            type="number"
            min={0}
            max={500}
            step={1}
            value={pageSize}
            placeholder={t("default")}
            onChange={(e) => setPageSize(e.target.value)}
            aria-invalid={!pageSizeValid}
            data-testid="preference-page-size"
          />
        </Field>
        <Field label={t("Landing page")} hint={t("The path the panel opens on after signing in, such as /hosts or /jobs; empty for the dashboard.")}>
          <input
            value={landing}
            placeholder="/dashboard"
            className="mono"
            onChange={(e) => setLanding(e.target.value)}
            aria-invalid={!landingValid}
            data-testid="preference-landing-page"
          />
        </Field>
        <Field label={t("Language")} hint={t("Applies at once, here and in the top bar.")}>
          <div className="language-switch" role="group" aria-label={t("Language")}>
            {LOCALES.map((entry) => (
              <button
                key={entry.code}
                type="button"
                className={entry.code === locale ? "active" : ""}
                aria-pressed={entry.code === locale}
                onClick={() => applyLanguage(entry.code)}
              >
                {entry.label}
              </button>
            ))}
          </div>
        </Field>
        <Field label={t("Theme")} hint={t("Applies at once, here and in the top bar.")}>
          <div className="theme-switch" role="group" aria-label={t("Theme")}>
            {THEMES.map((entry) => (
              <button
                key={entry.code}
                type="button"
                className={entry.code === theme ? "active" : ""}
                aria-pressed={entry.code === theme}
                title={t(entry.description)}
                onClick={() => applyTheme(entry.code)}
              >
                <span className={`theme-swatch ${entry.code}`} aria-hidden="true" />
                {t(entry.label)}
              </button>
            ))}
          </div>
        </Field>
      </FieldGrid>
    </Card>
  );
}

function OwnSessions({ query }: { query: { data?: Collection<OwnSession>; error: unknown } }) {
  const t = useT();
  if (query.error) return <ErrorBox error={query.error} />;
  if (!query.data) return <Empty>{t("Loading…")}</Empty>;
  if (query.data.items.length === 0) return <Empty>{t("No live browser session. Tokens are not sessions.")}</Empty>;
  return (
    <table>
      <thead>
        <tr><th>{t("Session")}</th><th>{t("Signed in")}</th><th>{t("Last seen")}</th><th>{t("Ends")}</th><th>{t("From")}</th></tr>
      </thead>
      <tbody>
        {query.data.items.map((session) => (
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
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function OwnTokens({ query }: { query: { data?: Collection<ApiToken>; error: unknown } }) {
  const t = useT();
  if (query.error) return <ErrorBox error={query.error} />;
  if (!query.data) return <Empty>{t("Loading…")}</Empty>;
  if (query.data.items.length === 0) return <Empty>{t("No live token.")}</Empty>;
  return (
    <table>
      <thead>
        <tr><th>{t("Token")}</th><th>{t("Description")}</th><th>{t("Issued")}</th><th>{t("Last used")}</th><th>{t("Expires")}</th></tr>
      </thead>
      <tbody>
        {query.data.items.map((token) => (
          <tr key={token.id}>
            <td className="mono" title={token.id}>{token.id.slice(0, 12)}</td>
            <td>{token.description || "—"}</td>
            <td><Time value={token.created_at} /></td>
            <td><Time value={token.last_used_at} /></td>
            <td>{token.expires_at ? <Time value={token.expires_at} /> : <span className="source">{t("never")}</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
