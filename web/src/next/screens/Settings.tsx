import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { absoluteTime, goDuration, relativeTime } from "../../lib/format";
import type {
  InstallationProfile, Settings as SettingsView, SettingsArea, SettingsFact, Whoami,
} from "../../lib/types";
import type { IconName } from "../../components/icons";
import { useToast } from "../../components/Toast";
import { useT } from "../../i18n";
import { Board } from "../Board";
import { CertificateAuthority, CertificateAuthorityWarning } from "./CertificateAuthority";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Banner, Bones, Card, Check, Empty, Fact, Facts, Field, Fields, Find, Grid, Note, Pill, Problem, Screen, stacked, Tabs,
} from "../kit";

/**
 * Everything this installation is configured with, in one place.
 *
 * Two kinds of value live here and they are never mixed. What the panel
 * stores takes effect without a restart; what the process was started with
 * comes from the deployment and is read once at start. A screen that drew
 * them the same way would be telling somebody they can change a thing they
 * cannot.
 *
 * A tab is drawn only for a sign-in that may read what is inside it. The
 * permission named on a tab is the one the body's own requests need, so a
 * tab is never offered that answers with a refusal.
 */

/** What one configurable resource of the installation is showing. */
export type HubState =
  | { kind: "count"; n: number }
  | { kind: "forbidden" }
  | { kind: "unknown" };

/**
 * A hub that counts keeps the product's first rule: a number nobody could
 * take is not a count of nothing. A viewer who may not read the roles must
 * see that they are not visible to them, not "0 roles" - which would read
 * as an installation with nobody in it.
 */
export function hubState(data: unknown, error: unknown, loading: boolean): HubState {
  if (error instanceof ApiError && error.forbidden) return { kind: "forbidden" };
  if (error) return { kind: "unknown" };
  if (loading || data === undefined || data === null) return { kind: "unknown" };
  const payload = data as { count?: unknown; items?: unknown };
  if (typeof payload.count === "number") return { kind: "count", n: payload.count };
  // Some collections answer with the items alone. Counting them is right
  // only because these are the configuration of one installation and are
  // never paged; a paged collection counted this way would under-report.
  if (Array.isArray(payload.items)) return { kind: "count", n: payload.items.length };
  return { kind: "unknown" };
}

/**
 * One section of the settings area.
 *
 * `to` is the place in the new panel that holds the section's own screen;
 * `href` is the panel as it is, for a section the rewrite has not reached.
 * A section with neither is drawn here, in full.
 */
type Section = {
  key: string;
  label: string;
  /** The permission the section's own requests need; "" is everybody's. */
  permission: string;
  icon: IconName;
  /** One line under the heading of the card. */
  note: string;
  /** What the section decides, in the words of what it changes. */
  body: string;
  to?: string;
  href?: string;
};

export const TABS: Section[] = [
  {
    key: "general",
    label: "General",
    permission: "",
    icon: "settings",
    note: "What the panel stores, and what it was started with.",
    body: "",
  },
  {
    key: "users",
    label: "Users",
    permission: "principal.manage",
    icon: "access",
    note: "Who may sign in to this installation, and what each of them holds.",
    body: "Who may sign in, the identities the panel keeps records of, the roles each of them holds and the scope every role is held over. A role granted by a group of the identity provider cannot be taken away one person at a time: the mapping is where it is edited.",
    to: "/next/access",
  },
  {
    key: "roles",
    label: "Roles",
    permission: "host.read",
    icon: "access",
    note: "The roles of this installation and the permissions each one carries.",
    body: "A role is a set of permissions; a scope says where it applies - the whole fleet, a site, an environment or a team. The catalogue is read beside the people holding the roles, because a permission is only readable against who has it.",
    to: "/next/access",
  },
  {
    key: "mappings",
    label: "Group mappings",
    permission: "principal.manage",
    icon: "directory",
    note: "Which group of the identity provider grants which role.",
    body: "A mapping turns a group of the identity provider into a role at the next sign-in. It is the only place such a grant can be withdrawn: taken away from one person it would come back the next time they signed in.",
    to: "/next/access",
  },
  {
    key: "review",
    label: "Access review",
    permission: "principal.manage",
    icon: "audit",
    note: "Who holds what, read once rather than one record at a time.",
    body: "The whole of the access rules on one page, so that a grant nobody remembers making is visible without opening every identity in turn.",
    href: "/settings?tab=review",
  },
  {
    key: "ca",
    label: "Fleet CA",
    permission: "principal.manage",
    icon: "certificates",
    note: "The authority the fleet's own certificates are signed by.",
    body: "Rotation is four deliberate stages, each an ordinary campaign: distribute the new authority, verify it reached every host, rotate the leaves, withdraw the old one. A withdrawal is refused while any host is unverified or still holds a certificate issued by it.",
    to: "/next/certificates",
  },
  {
    key: "channels",
    label: "Notification channels",
    permission: "notification.read",
    icon: "notifications",
    note: "Where the panel sends what it has to say.",
    body: "A channel is an address the panel delivers to and the events it delivers there. A delivery that failed is kept and retried rather than dropped, so a channel that is quiet is a channel nobody subscribed, not a fleet with nothing to report.",
    href: "/notifications",
  },
  {
    key: "budgets",
    label: "Budgets",
    permission: "budget.read",
    icon: "campaigns",
    note: "How much of the fleet may be changed at once.",
    body: "A budget is the reason a job or a campaign stands in the queue instead of running. It is the fleet's own brake: the number of hosts that may be touched in a window, read against what the operations are asking for.",
    href: "/budgets",
  },
  {
    key: "policies",
    label: "Policies",
    permission: "policy.read",
    icon: "campaigns",
    note: "What is declared to be true, and what is ordered for the rest.",
    body: "A policy is the third model of change, next to the job and the campaign: it states what is to hold across a set of hosts and orders campaigns for the hosts where it does not.",
    href: "/policies",
  },
];

export type TabKey = string;

/**
 * The tab the address names, or the first one for a name that is not a tab.
 *
 * A tab the sign-in may not open is not one either: an address kept in a
 * bookmark from a wider role must land somewhere that exists rather than on
 * an empty screen.
 */
export function settingsTab(value: string | null, permissions: Set<string>): TabKey {
  const open = TABS.filter((tab) => tab.permission === "" || permissions.has(tab.permission));
  const named = open.find((tab) => tab.key === value);
  return (named ?? open[0] ?? TABS[0]).key;
}

export function Settings() {
  const t = useT();
  const [searchParams, setSearchParams] = useSearchParams();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);
  const tab = settingsTab(searchParams.get("tab"), permissions);
  const open = TABS.filter((one) => one.permission === "" || permissions.has(one.permission));
  const here = open.find((one) => one.key === tab) ?? TABS[0];
  const setTab = (next: TabKey) => setSearchParams(next === "general" ? {} : { tab: next });

  return (
    <Screen
      title={t("Settings")}
      lead={t("Everything this installation is configured with.")}
      icon="settings"
      help={
        <>
          <p>{t("What the panel stores is set here and takes effect without a restart: who may sign in and what they hold, the retentions, the address the agents dial, the channels, the budgets and the policies.")}</p>
          <p>{t("Your own preferences - the theme, your sessions and what your sign-in carries - are under your name at the top right.")}</p>
          <p>{t("Under General, below those, are the values the process was started with. They come from the deployment and are read when the panel starts, so a change to them needs a restart.")}</p>
          <p>{t("A tab is here only if this sign-in may read what is inside it.")}</p>
        </>
      }
    >
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={open.map((one) => ({ value: one.key, label: t(one.label) }))}
      />
      {tab === "general"
        ? <General permissions={permissions} />
        : <Elsewhere section={here} />}
    </Screen>
  );
}

/**
 * A section whose screen is its own.
 *
 * It is not a tile with a button: the card says what the section decides
 * and in whose words, which is the part worth having on a settings screen,
 * and then leads to where it is done.
 */
function Elsewhere({ section }: { section: Section }) {
  const t = useT();
  return (
    <Grid>
      <Card span={12} title={t(section.label)} note={t(section.note)}>
        <Note>{t(section.body)}</Note>
        <Empty
          icon={section.icon}
          action={section.to
            ? <Link className="fl-btn" to={section.to} data-testid="settings-open-section">{t("Open {name}", { name: t(section.label) })}</Link>
            : <a className="fl-btn fl-quiet" href={section.href} data-testid="settings-open-section">{t("Open it in the panel as it is")}</a>}
        >
          {section.to
            ? t("This section has a screen of its own in the new panel.")
            : t("This section has not been rewritten yet; it is unchanged in the panel as it is.")}
        </Empty>
      </Card>
    </Grid>
  );
}

/* --------------------------------------------------------------- general */

/**
 * The panel's own settings, and under them the values it was started with.
 *
 * The two are kept apart on purpose and labelled: the first take effect as
 * soon as they are stored, the second need the deployment changed and the
 * process restarted.
 */
function General({ permissions }: { permissions: Set<string> }) {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get<SettingsView>("/api/v1/settings"),
    retry: false,
  });

  // What somebody is looking for. A settings screen is read with a name in
  // mind - "where is the session timeout" - and the way to answer that is a
  // search, not nine open cards to scan.
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const areas = (data?.areas ?? []).map((area) => ({
    area,
    facts: needle === ""
      ? area.facts
      : area.facts.filter((fact) =>
          fact.key.toLowerCase().includes(needle)
          || t(FACT_LABELS[fact.key] ?? fact.key).toLowerCase().includes(needle)),
  })).filter(({ area, facts }) => needle === "" || facts.length > 0 || t(area.title).toLowerCase().includes(needle));

  const mayReadAddress = permissions.has("settings.read") || permissions.has("principal.manage");
  // The fleet CA is the root of trust of the whole installation, so the
  // section is drawn for a sign-in that may read it and the rotation is
  // offered only to one that may change it.
  const mayReadCA = permissions.has("pki.read") || permissions.has("pki.rotate");
  // What a refused change to the trust set said. It is the section's own
  // answer and it is drawn above the board: a banner is not a container
  // somebody arranges.
  const [caWarning, setCaWarning] = useState<ApiError | null>(null);
  // A panel without the monitoring has no such settings, and the card
  // draws nothing at all then. The board is asked here rather than left
  // to find out, because a container that draws nothing still takes a
  // cell of the grid - a hand's width of empty floor across the screen.
  const retention = useMonitoringSettings();

  return (
    <Board
      screen={SETTINGS_SCREEN}
      catalogue={settingsCatalogue(data?.areas ?? [])}
      /* What has to be read before the settings are: the read that
         failed, and the search nothing answered. Neither is a container
         somebody arranges. */
      notices={stacked(
        error ? <Problem>{String(error)}</Problem> : null,
        /* The element is only made when there is something to say: an
           element that renders null is still something to stack, and the
           screen would open with a band of empty floor across it. */
        caWarning
          ? <CertificateAuthorityWarning error={caWarning} close={() => setCaWarning(null)} />
          : null,
        data && areas.length === 0
          ? <Card><Empty icon="search">{t("No setting of that name.")}</Empty></Card>
          : null,
      )}
      drawn={{
        retention: !retention.error && <MonitoringRetention />,

        address: mayReadAddress && (
          <Card
            title={t("Advertised address")}
            note={t("The address the agents dial to reach this panel.")}
          >
            <AdvertisedAddress mayConfirm={permissions.has("settings.advertise.write")} />
          </Card>
        ),

        fleet_ca: mayReadCA && (
          <CertificateAuthority
            mayRotate={permissions.has("pki.rotate")}
            reportError={setCaWarning}
          />
        ),

        started_with: (
          <Card
            title={t("What the process was started with")}
            note={t("Read at start, changed where the deployment is defined.")}
            tools={
              <Find
                value={query}
                onChange={setQuery}
                placeholder={t("Find a setting")}
                testId="settings-search"
              />
            }
          >
            {!data && !error && <Bones rows={2} />}
          </Card>
        ),

        /* One container per area of the configuration, as the screen
           being replaced had: which of them comes first belongs to the
           installation. An area the search narrowed away is not drawn,
           so it keeps no cell either. */
        ...Object.fromEntries(areas.map(({ area, facts }) => [
          areaKey(area.key),
          <Card
            key={area.key}
            title={t(area.title)}
            note={facts.length === 1 ? t("{n} value", { n: facts.length }) : t("{n} values", { n: facts.length })}
          >
            <AreaFacts area={area} facts={facts} />
          </Card>,
        ])),
      }}
    />
  );
}

/** One area of the configuration: the values, as label-and-value pairs. */
function AreaFacts({ area, facts }: { area: SettingsArea; facts: SettingsFact[] }) {
  const t = useT();
  return (
    <Facts>
      {facts.map((fact) => (
        <Fact key={fact.key} label={t(FACT_LABELS[fact.key] ?? fact.key)}>
          <FactValue fact={fact} area={area.key} />
        </Fact>
      ))}
    </Facts>
  );
}

/* A Go duration as the server prints it: hours, minutes and seconds with
   every zero part written out, such as 720h0m0s. */
const GO_DURATION = /^(?:\d+h)?(?:\d+m)?(?:\d+(?:\.\d+)?s)?$/;

function FactValue({ fact, area }: { fact: SettingsFact; area: string }) {
  const t = useT();
  // A secret says only whether it is set. Its value is never read back out
  // of the panel, so there is nothing here that could print one.
  if (fact.secret) {
    return fact.configured
      ? <Pill tone="ok" title={t("The value is set; it is never shown here.")}>{t("set")}</Pill>
      : <Pill tone="unknown">{t("not set")}</Pill>;
  }
  const value = fact.value;
  if (value === null) return <Pill tone="unknown">{t("no snapshot yet")}</Pill>;
  // A retention left unset keeps the record for good; a dash would read as
  // "nothing kept", which is the opposite of what happens.
  if (value === "" && area === "retention") {
    return <span title={t("No limit is set; the records are never swept.")}>{t("forever")}</span>;
  }
  if (value === "" || (Array.isArray(value) && value.length === 0)) return <>—</>;
  if (typeof value === "boolean") {
    return <Pill tone={value ? "ok" : "unknown"}>{value ? t("yes") : t("no")}</Pill>;
  }
  if (Array.isArray(value)) return <span className="fl-mono">{value.join(", ")}</span>;
  // A duration is read in days and hours, with the exact value on hover.
  if (typeof value === "string" && value !== "" && GO_DURATION.test(value)) {
    return <span className="fl-mono" title={value}>{goDuration(value)}</span>;
  }
  return <span className="fl-mono">{String(value)}</span>;
}

/* The English label of each fact, so the catalogue has a sentence to
   translate rather than a key. A key without a label is shown as it is. */
export const FACT_LABELS: Record<string, string> = {
  version: "Version",
  pool_max_conns: "Pool maximum",
  pool_min_conns: "Pool minimum",
  pool_max_conn_lifetime: "Connection lifetime",
  pool_max_conn_idle_time: "Idle limit",
  pool_health_check_period: "Health check period",
  pool_connect_timeout: "Connect timeout",
  auto_migrate: "Migration at start",
  migration_role: "Migration role",
  commit: "Commit",
  build_date: "Build date",
  agent_protocol: "Agent protocol",
  relay_cert_ttl: "Relay certificate lifetime",
  migration_level: "Schema migration",
  gateway_addr: "Agent gateway",
  enrollment_addr: "Enrollment endpoint",
  admin_addr: "REST API",
  advertised: "Advertised names",
  gateway_id: "Gateway identifier",
  public_url: "Public URL",
  package_repository_url: "Package repository",
  web_root: "Web root",
  state_dir: "State directory",
  heartbeat_seconds: "Heartbeat (seconds)",
  heartbeat_jitter: "Heartbeat jitter (seconds)",
  stale_after: "Stale after",
  agent_cert_ttl: "Agent certificate lifetime",
  clone_policy: "Clone policy",
  relay_identity: "Relayed session without the host certificate",
  dispatch_rate: "Dispatch rate (envelopes per second)",
  issuer: "Issuer",
  client_id: "Client identifier",
  client_secret: "Client secret",
  groups_claim: "Groups claim",
  session_idle: "Session idle window",
  session_absolute: "Session absolute lifetime",
  session_group_refresh: "Session group refresh",
  oidc_admin_logout: "Logout at the provider on disable",
  configured: "Configured",
  server: "Server",
  principal: "Service principal",
  keytab: "Keytab",
  ca_certificate: "CA certificate",
  realm: "Realm",
  write_enabled: "Directory changes",
  max_age: "Maximum authentication age",
  acr: "Required level (acr)",
  tokens: "API tokens",
  production_environments: "Production environments",
  url: "URL",
  secret: "Signing secret",
  events: "Event prefixes",
  enabled: "Enabled",
  sync_interval: "Sync interval",
  max_snapshot_age: "Maximum snapshot age",
  debian_url: "Debian tracker",
  debian_snapshot_age: "Debian snapshot age",
  ubuntu_url: "Ubuntu OVAL",
  ubuntu_snapshot_age: "Ubuntu snapshot age",
  redhat_url: "Red Hat CSAF",
  redhat_snapshot_age: "Red Hat snapshot age",
  nvd_url: "NVD API",
  nvd_key: "NVD API key",
  nvd_interval: "NVD interval",
  nvd_snapshot_age: "NVD snapshot age",
  metrics_raw: "Raw resource samples",
  metrics_rollup: "Quarter-hour rollups",
  audit: "Audit trail",
  agent_sessions: "Ended agent sessions",
  jobs: "Finished jobs",
  campaigns: "Finished campaigns",
  outbox_events: "Delivered trail events",
  secrets_key_file: "Secret store key file",
};

/* ---------------------------------------------------------- the retentions */

/** The six values, as the API reads and writes them: Go durations, and a count of days. */
type MonitoringValues = {
  raw_retention: string;
  rollup_retention: string;
  max_lateness: string;
  raw_query_window: string;
  clock_skew_limit: string;
  partitions_ahead: number;
};

/** What a change would remove; counted before anything is written. */
type RetentionImpact = {
  dropped_raw_partitions: string[];
  raw_samples_estimate: number;
  rollup_rows: number;
  gap_rows: number;
  clock_skew_rows: number;
  expired_silence_rows: number;
  destructive: boolean;
};

type MonitoringSettings = {
  effective: MonitoringValues;
  environment: MonitoringValues;
  stored: {
    present: boolean;
    updated_at?: string | null;
    updated_by?: string;
    revision?: number;
    values: Partial<Record<keyof MonitoringValues, string | number>>;
  };
  note: string;
};

type WriteResult = {
  valid?: boolean;
  code?: string;
  effective: MonitoringValues;
  impact: RetentionImpact;
};

/* The order the fields are shown in, with the label and the sentence that
   says what each one costs. */
const DURATION_FIELDS: { key: keyof MonitoringValues; label: string; hint: string }[] = [
  { key: "raw_retention", label: "Raw resource samples", hint: "How long every reading is kept at full resolution. One partition a day; a longer window costs disk, a shorter one drops whole days at the next sweep." },
  { key: "rollup_retention", label: "Quarter-hour rollups", hint: "How long the quarter-hour rollups, the recorded gaps, the clock corrections and the expired silences are kept. This is the window a capacity trend is read over." },
  { key: "max_lateness", label: "Maximum lateness", hint: "How long after it was taken a reading may still arrive. A relay that was cut off for longer has its backlog refused with metric_sample_too_old." },
  { key: "raw_query_window", label: "Raw query window", hint: "How far back full resolution is promised. The raw retention must be at least this plus the maximum lateness." },
  { key: "clock_skew_limit", label: "Clock skew limit", hint: "How far ahead of the panel a host's clock may be before its reading is stamped with the panel's time." },
];

/**
 * How long the panel keeps what the hosts send: the one part of the
 * General tab that writes.
 *
 * Nothing is stored until the change has been counted. The server is asked
 * what the settings would remove, the answer is read on the page, and a
 * change that drops readings still being kept needs that said out loud
 * before the button opens.
 */
/**
 * The monitoring settings, read once for the whole tab.
 *
 * The card below draws them; the board asks the same question to know
 * whether there is a container to place at all, and react-query answers
 * both from one request.
 */
function useMonitoringSettings() {
  return useQuery({
    queryKey: ["settings", "monitoring"],
    queryFn: () => api.get<MonitoringSettings>("/api/v1/settings/monitoring"),
    retry: false,
  });
}

function MonitoringRetention() {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [ahead, setAhead] = useState("");
  const [preview, setPreview] = useState<WriteResult | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [message, setMessage] = useState("");

  const settings = useMonitoringSettings();

  // The form holds what the installation stored; an empty field is not
  // zero, it is one the environment of the control plane still decides.
  const stored = settings.data?.stored?.values ?? {};
  const valueOf = (key: keyof MonitoringValues) =>
    draft[key] ?? (stored[key] === undefined ? "" : String(stored[key]));
  const aheadValue = ahead || (stored.partitions_ahead === undefined ? "" : String(stored.partitions_ahead));

  const body = (acknowledge: boolean) => ({
    raw_retention: valueOf("raw_retention").trim(),
    rollup_retention: valueOf("rollup_retention").trim(),
    max_lateness: valueOf("max_lateness").trim(),
    raw_query_window: valueOf("raw_query_window").trim(),
    clock_skew_limit: valueOf("clock_skew_limit").trim(),
    partitions_ahead: Number(aheadValue.trim() || 0),
    acknowledge_data_loss: acknowledge,
    reason: "changed on the settings screen",
  });

  const check = useMutation({
    mutationFn: () => api.put<WriteResult>("/api/v1/settings/monitoring?dry_run=true", body(false)),
    onSuccess: (result) => {
      setPreview(result);
      setAcknowledged(false);
      setMessage("");
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const save = useMutation({
    mutationFn: () => api.put<WriteResult>("/api/v1/settings/monitoring", body(acknowledged)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      setDraft({});
      setAhead("");
      setPreview(null);
      setAcknowledged(false);
      setMessage("");
      toast.success(t("The monitoring settings are stored and in force; every replica picks them up within half a minute."));
    },
    onError: (error) => {
      if (error instanceof ApiError && error.code === "metrics_retention_too_short") {
        setMessage(t("Refused: {detail}", { detail: error.message }));
        return;
      }
      if (error instanceof ApiError && error.code === "metrics_retention_shrink_unacknowledged") {
        setMessage(t("These settings drop readings that are still kept. Check what goes, then confirm it below."));
        return;
      }
      if (error instanceof ApiError && error.forbidden) {
        setMessage(t("You may not change the monitoring settings; they belong to whoever administers the panel."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  // A panel without the monitoring has no such settings; that is not a
  // fault of this screen, and it says nothing rather than an error.
  if (settings.error) return null;
  if (!settings.data) {
    return (
      <Card title={t("Monitoring retention")} note={t("How long the panel keeps what the hosts send.")}>
        <Bones rows={4} />
      </Card>
    );
  }

  const effective = settings.data.effective;
  const environment = settings.data.environment;
  const invalid = preview?.valid === false;
  const destructive = Boolean(preview?.impact.destructive);
  const ready = preview !== null && !invalid && (!destructive || acknowledged);

  return (
    <Card
      title={t("Monitoring retention")}
      note={t("How long the panel keeps what the hosts send.")}
      foot={
        <Actions>
          <button
            type="button"
            className="fl-quiet"
            onClick={() => check.mutate()}
            disabled={check.isPending || save.isPending}
            data-testid="monitoring-check"
          >
            {check.isPending ? t("checking…") : t("Check what this would change")}
          </button>
          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={!ready || save.isPending}
            data-testid="monitoring-store"
          >
            {save.isPending ? t("storing…") : t("Store these settings")}
          </button>
          {settings.data.stored?.present && settings.data.stored.updated_at && (
            <Note>
              {t("Stored by {who} {when}", {
                who: settings.data.stored.updated_by || "—",
                when: relativeTime(settings.data.stored.updated_at),
              })}
            </Note>
          )}
        </Actions>
      }
    >
      <Fields>
        {DURATION_FIELDS.map((field) => (
          <Field
            key={field.key}
            label={t(field.label)}
            hint={`${t(field.hint)} ${t("In force: {value}. Environment: {fallback}.", {
              value: goDuration(effective[field.key] as string),
              fallback: goDuration(environment[field.key] as string),
            })}`}
          >
            <input
              value={valueOf(field.key)}
              placeholder={String(environment[field.key])}
              onChange={(event) => { setDraft({ ...draft, [field.key]: event.target.value }); setPreview(null); }}
              aria-label={t(field.label)}
              data-testid={`monitoring-${field.key}`}
            />
          </Field>
        ))}
        <Field
          label={t("Partitions ahead (days)")}
          hint={`${t("How many days of raw partitions exist before they are needed. A reading for a day no partition covers cannot be written at all, so this is how long the maintenance may fail to run without a fleet losing samples. At most 60.")} ${t("In force: {value}. Environment: {fallback}.", { value: String(effective.partitions_ahead), fallback: String(environment.partitions_ahead) })}`}
        >
          <input
            type="number"
            min={0}
            max={60}
            step={1}
            value={aheadValue}
            placeholder={String(environment.partitions_ahead)}
            onChange={(event) => { setAhead(event.target.value); setPreview(null); }}
            aria-label={t("Partitions ahead (days)")}
            data-testid="monitoring-partitions-ahead"
          />
        </Field>
      </Fields>

      {message && <Problem><span data-testid="monitoring-refusal">{message}</span></Problem>}

      {invalid && (
        <Problem>
          {t("These settings would delete readings that are still arriving, so they cannot be stored. Raise the raw retention to at least the raw query window plus the maximum lateness.")}
        </Problem>
      )}
      {preview && !invalid && (
        <Impact impact={preview.impact} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />
      )}
    </Card>
  );
}

/**
 * What the change removes. It is said before the change is stored, because
 * afterwards there is nothing left to say it about.
 */
function Impact({ impact, acknowledged, onAcknowledge }: {
  impact: RetentionImpact;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  const t = useT();
  if (!impact.destructive) {
    return <Note><span data-testid="monitoring-impact">{t("Nothing stored is removed by this change.")}</span></Note>;
  }
  return (
    <>
      <Facts>
        {impact.dropped_raw_partitions.length > 0 && (
          <Fact label={t("Days of raw samples dropped")}>
            <span className="fl-mono">{impact.dropped_raw_partitions.join(", ")}</span>
          </Fact>
        )}
        {impact.raw_samples_estimate > 0 && (
          <Fact label={t("Raw readings in them (estimate)")}>{impact.raw_samples_estimate.toLocaleString()}</Fact>
        )}
        {impact.rollup_rows > 0 && (
          <Fact label={t("Quarter-hour rollups removed")}>{impact.rollup_rows.toLocaleString()}</Fact>
        )}
        {impact.gap_rows > 0 && (
          <Fact label={t("Recorded gaps removed")}>{impact.gap_rows.toLocaleString()}</Fact>
        )}
        {impact.clock_skew_rows > 0 && (
          <Fact label={t("Clock corrections removed")}>{impact.clock_skew_rows.toLocaleString()}</Fact>
        )}
        {impact.expired_silence_rows > 0 && (
          <Fact label={t("Expired silences removed")}>{impact.expired_silence_rows.toLocaleString()}</Fact>
        )}
      </Facts>
      <Check checked={acknowledged} onChange={onAcknowledge}>
        <span data-testid="monitoring-acknowledge-text">
          {t("I understand these readings are deleted at the next maintenance pass and cannot be brought back.")}
        </span>
      </Check>
    </>
  );
}

/* ------------------------------------------------------ the dialled address */

/** One address the panel found on this machine. A proposal, never a setting. */
export type AddressCandidate = {
  name: string;
  kind: "address" | "hostname";
  interface?: string;
  loopback: boolean;
};

/** What the panel advertises, where it came from, and what it proposes. */
export type AdvertisedAddressState = {
  in_force: string[];
  source: "environment" | "confirmed" | "default";
  loopback_only: boolean;
  reachable?: string[];
  reserved?: string[];
  environment?: string[];
  environment_in_force: boolean;
  confirmed?: string[];
  confirmed_at?: string;
  confirmed_by?: string;
  superseded?: string[];
  revision?: number;
  mismatch?: string;
  candidates: AddressCandidate[];
  note: string;
};

/** The value of the "something else" choice, which is not a candidate's name. */
export const OWN_ADDRESS = "\u0000own";

/**
 * What the administrator is about to confirm: the picked candidate, or
 * what they typed. A blank choice confirms nothing - the button stays out
 * of reach rather than sending the first proposal.
 */
export function chosenAddress(picked: string, typed: string): string[] {
  const value = (picked === OWN_ADDRESS ? typed : picked).trim();
  return value === "" ? [] : value.split(",").map((part) => part.trim()).filter((part) => part !== "");
}

/**
 * Whether a choice may be sent. It is the panel's own check and not the
 * server's: the server refuses the same things, and a screen that lets the
 * request go out only to show a refusal has made the operator wait for
 * nothing.
 */
export function confirmable(names: string[], environmentInForce: boolean): boolean {
  if (environmentInForce || names.length === 0) return false;
  return names.every((name) => /^[A-Za-z0-9.:_-]+$/.test(name) && !name.includes("/"));
}

/** How a candidate is described in one line, without inventing anything. */
export function candidateNote(
  candidate: AddressCandidate,
  t: (s: string, v?: Record<string, string | number>) => string,
): string {
  if (candidate.kind === "hostname") {
    return candidate.loopback
      ? t("the name this machine answers to, and it resolves to loopback")
      : t("the name this machine answers to");
  }
  const where = candidate.interface
    ? t("on the interface {name}", { name: candidate.interface })
    : t("an address of this machine");
  return candidate.loopback ? t("{where}, reaches only this machine", { where }) : where;
}

/** The badge beside the address in force: where it came from. */
export function sourceTone(source: AdvertisedAddressState["source"], loopbackOnly: boolean): "ok" | "warn" | "error" {
  if (loopbackOnly) return "error";
  return source === "default" ? "warn" : "ok";
}

/**
 * The address the agents dial.
 *
 * The panel cannot tell which of its interfaces the hosts route to, and
 * the wrong one in the certificate is a fleet that enrols and drops out
 * again, so a detected address stays a proposal until somebody says
 * otherwise.
 */
function AdvertisedAddress({ mayConfirm }: { mayConfirm: boolean }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [picked, setPicked] = useState("");
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [refusal, setRefusal] = useState<ApiError | null>(null);

  const address = useQuery({
    queryKey: ["advertised-address"],
    queryFn: () => api.get<AdvertisedAddressState>("/api/v1/settings/advertised"),
    retry: false,
  });

  const confirm = useMutation({
    mutationFn: (names: string[]) =>
      api.put<AdvertisedAddressState>("/api/v1/settings/advertised", { names, reason: reason.trim() }),
    onSuccess: (state) => {
      setRefusal(null);
      toast.success(t("The agents now dial {names}.", { names: state.in_force.join(", ") }));
      void queryClient.invalidateQueries({ queryKey: ["advertised-address"] });
      void queryClient.invalidateQueries({ queryKey: ["setup"] });
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      void queryClient.invalidateQueries({ queryKey: ["installation-profile"] });
    },
    onError: (error) => setRefusal(error instanceof ApiError ? error : null),
  });

  if (address.error) return <Problem>{String(address.error)}</Problem>;
  const state = address.data;
  if (!state) return <Bones rows={3} />;
  // An answer without the address in force is not an address of none: it
  // is an answer this section cannot read, and it says so rather than
  // taking the screen down with it.
  if (!Array.isArray(state.in_force)) {
    return (
      <Note>
        <span data-testid="advertised-address">{t("This panel did not say which address is in force.")}</span>
      </Note>
    );
  }

  const names = chosenAddress(picked, typed);
  const ready = confirmable(names, state.environment_in_force);

  return (
    <div data-testid="advertised-address">
      <Facts>
        <Fact label={t("In force")}>
          <span className="fl-mono">{state.in_force.join(", ")}</span>{" "}
          <Pill tone={sourceTone(state.source, state.loopback_only)}>
            {state.source === "environment" && t("declared in the deployment")}
            {state.source === "confirmed" && t("confirmed")}
            {state.source === "default" && t("not confirmed")}
          </Pill>
        </Fact>
        {state.source === "confirmed" && state.confirmed_by && (
          <Fact label={t("Confirmed by")}>
            {t("{who} on {when}", {
              who: state.confirmed_by,
              when: absoluteTime(state.confirmed_at ?? "") || (state.confirmed_at ?? ""),
            })}
          </Fact>
        )}
      </Facts>

      {state.loopback_only && (
        <Note>{t("This reaches only the machine the panel runs on, so a host elsewhere is turned away at enrolment rather than left to fail a handshake later.")}</Note>
      )}
      {state.mismatch && <Banner tone="warn">{state.mismatch}</Banner>}
      {state.superseded && state.superseded.length > 0 && (
        <Note>
          {t("Held back from any relay as well, because an agent not yet reconfigured still dials it: {names}.", {
            names: state.superseded.join(", "),
          })}
        </Note>
      )}

      {state.environment_in_force ? (
        <Note>
          {t("This installation declares the address in the environment of the control plane ({names}), and that declaration decides. Change it there; a confirmation made here would be refused rather than kept where it does not take effect.", {
            names: (state.environment ?? []).join(", "),
          })}
        </Note>
      ) : !mayConfirm ? (
        <Note>{t("Only a platform administrator names the address the fleet connects to; ask one.")}</Note>
      ) : (
        <>
          <Note>{t("The panel read these off its own interfaces. It cannot tell which of them the hosts route to, so none of them is in use until you pick one and confirm it.")}</Note>
          <Fields>
            {state.candidates.map((candidate) => (
              <Field key={`${candidate.kind}:${candidate.name}`} label={candidate.name} hint={candidateNote(candidate, t)}>
                <input
                  type="radio"
                  name="advertised-candidate"
                  value={candidate.name}
                  checked={picked === candidate.name}
                  onChange={() => setPicked(candidate.name)}
                  data-testid={`advertised-${candidate.name}`}
                />
              </Field>
            ))}
            <Field
              label={t("a name of your own")}
              hint={t("The DNS name the hosts resolve, which is usually not an address of an interface. Several, separated by commas, are tried in order.")}
            >
              <input
                type="radio"
                name="advertised-candidate"
                value={OWN_ADDRESS}
                checked={picked === OWN_ADDRESS}
                onChange={() => setPicked(OWN_ADDRESS)}
                data-testid="advertised-own"
              />
            </Field>
            <Field label={t("The name the hosts resolve")} wide>
              <input
                value={typed}
                placeholder="panel.example.org"
                disabled={picked !== OWN_ADDRESS}
                onChange={(event) => setTyped(event.target.value)}
                data-testid="advertised-typed"
              />
            </Field>
            <Field label={t("Reason")} hint={t("Kept on the audit trail beside the names. Optional.")} wide>
              <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="advertised-reason" />
            </Field>
          </Fields>
          {refusal && (
            <Problem>
              <span data-testid="advertised-refusal">
                {refusal.code === "advertised_address_from_environment"
                  ? t("The deployment declares the address, so it is not confirmed here.")
                  : refusal.message}
              </span>
            </Problem>
          )}
          <Actions>
            <button
              type="button"
              disabled={!ready || confirm.isPending}
              onClick={() => confirm.mutate(names)}
              data-testid="advertised-confirm"
            >
              {confirm.isPending
                ? t("Confirming…")
                : names.length > 0
                  ? t("Confirm {names}", { names: names.join(", ") })
                  : t("Confirm the address")}
            </button>
          </Actions>
          <Note>{state.note}</Note>
        </>
      )}

      {/* What was just confirmed decides this, not the query: the answer to
          the confirmation is the newest word on the address, and the read
          behind it may still be in flight. */}
      {confirm.data && !confirm.data.loopback_only && <AgentConfiguration />}
    </div>
  );
}

/**
 * What a new host is told, now that the address is settled. It is read
 * from the installation profile rather than composed here: that is the
 * same file the operator pastes onto a host, so a screen that rebuilt it
 * could agree with nothing.
 */
function AgentConfiguration() {
  const t = useT();
  const profile = useQuery({
    queryKey: ["installation-profile", "advertised-address"],
    queryFn: () => api.get<InstallationProfile>("/api/v1/installation-profiles?kind=agent"),
    retry: false,
  });
  if (profile.error) return <Problem>{String(profile.error)}</Problem>;
  const data = profile.data;
  if (!data) return <Bones rows={2} />;
  return (
    <>
      <Note>
        {t("This is what the add-host screen hands out from now on; it is written to {path} on the host.", {
          path: data.config.path,
        })}
      </Note>
      <pre className="fl-mono" data-testid="advertised-agent-config">{data.config.content}</pre>
      {(data.warnings ?? []).map((warning) => <Note key={warning}>{warning}</Note>)}
    </>
  );
}

/** The name the General tab's arrangement is stored under. */
export const SETTINGS_SCREEN = "next_settings";

/**
 * The containers of the General tab that are there whatever the server
 * was started with.
 */
export const SETTINGS: BoardEntry[] = [
  // Six fields, each with the sentence that says what it costs, and the
  // count of what a change would remove under them.
  { key: "retention", title: "Monitoring retention", width: 12, height: 4 },
  // What is in force, and the interfaces this panel read off itself with
  // a choice between them.
  { key: "address", title: "Advertised address", width: 12, height: 4 },
  // The trust set, what still hangs on each authority, and the two phases
  // of a rotation. It is the one section on this tab that changes what a
  // thousand machines will accept, so it is given the room to be read.
  { key: "fleet_ca", title: "Fleet CA", width: 12, height: 4 },
  // A heading and the search under it: the areas themselves are below.
  { key: "started_with", title: "What the process was started with", width: 12, height: 1 },
];

/**
 * A container key for an area of the configuration.
 *
 * The areas are named by the server and the containers of this tab are
 * named here, so the two are kept apart: an installation whose settings
 * carry an area called `retention` would otherwise have had it stand
 * where the monitoring retentions do, and one of the two would have been
 * drawn twice and the other not at all.
 */
export function areaKey(area: string): string {
  return `area_${area}`;
}

/**
 * The catalogue with one container per area the server reported.
 *
 * The height is the area's own: a pair of values does not need the room
 * fifteen do, and the count is the whole area's rather than what the
 * search left of it, so the shape a container ships with does not change
 * while somebody types.
 */
export function settingsCatalogue(areas: SettingsArea[]): BoardEntry[] {
  return [
    ...SETTINGS,
    ...areas.map((area) => ({
      key: areaKey(area.key),
      title: area.title,
      width: 4,
      // Two values to a row at this width, and a row is about 50 pixels
      // against the 152 of a cell.
      height: area.facts.length > 10 ? 4 : area.facts.length > 4 ? 3 : 2,
    })),
  ];
}
