import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { goDuration } from "../lib/format";
import type { Settings as SettingsView, SettingsArea, SettingsFact, Whoami } from "../lib/types";
import { Empty, ErrorBox, Pair, Pairs, Time } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { useToast } from "../components/Toast";
import { Board } from "../components/board";
import { AdvertisedAddressSection } from "./AdvertisedAddress";
import { Mappings, Roles } from "./Access";
import { Budgets } from "./Budgets";
import { Notifications } from "./Notifications";
import { Policies } from "./Policies";
import { useT } from "../i18n";

/**
 * What one configurable resource of the installation is showing right now.
 *
 * A hub that counts has to keep the product's first rule: a number nobody
 * could take is not a count of nothing. A viewer who may not read the roles
 * must see that they are not visible to them, not "0 roles" - which would
 * read as an installation with nobody in it.
 */
export type HubState =
  | { kind: "count"; n: number }
  | { kind: "forbidden" }
  | { kind: "unknown" };

export function hubState(data: unknown, error: unknown, loading: boolean): HubState {
  if (error instanceof ApiError && error.forbidden) return { kind: "forbidden" };
  if (error) return { kind: "unknown" };
  if (loading || data === undefined || data === null) return { kind: "unknown" };
  const payload = data as { count?: unknown; items?: unknown };
  if (typeof payload.count === "number") return { kind: "count", n: payload.count };
  // Some collections answer with the items alone. Counting them is right only
  // because these are the configuration of one installation and are never
  // paged; a paged collection counted this way would under-report.
  if (Array.isArray(payload.items)) return { kind: "count", n: payload.items.length };
  return { kind: "unknown" };
}

/**
 * The resources this installation configures that are kept on screens of
 * their own.
 *
 * They were six tiles across the top of this screen for half a day, and the
 * owner read them for what they were: *"setting przypomina przejdz do
 * zakladki X-Y a nie ustawienia"*. A box whose whole content is a sentence
 * and a button to go elsewhere is a menu, and a settings screen whose first
 * third is a menu is not a settings screen.
 *
 * So they are one compact table at the end, under a heading that says what it
 * is. The state each one is in is still here - that is the part worth having
 * on a settings screen, and it is still never a zero somebody could mistake
 * for an answer nobody got.
 */
/**
 * The tabs of the settings area.
 *
 * Everything an installation configures is here, each tab holding the screen
 * that does the work rather than a link to it. The six were pages of their
 * own, reached from the navigation, and the settings screen was a list of
 * places to go - which the owner read for what it was on 15.10: *"setting
 * przypomina przejdz do zakladki X-Y a nie ustawienia"*.
 *
 * A tab is drawn only for somebody who may read what is inside it. The
 * permission named here is the one the body's own requests need, so a tab is
 * never offered that answers with a refusal.
 */
const TABS = [
  { key: "general", label: "General", permission: "" },
  { key: "channels", label: "Notification channels", permission: "notification.read" },
  { key: "roles", label: "Roles", permission: "host.read" },
  { key: "mappings", label: "Group mappings", permission: "principal.manage" },
  { key: "budgets", label: "Budgets", permission: "budget.read" },
  { key: "policies", label: "Policies", permission: "policy.read" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

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

/**
 * The settings area: everything an installation configures, in one place,
 * with the screen that does the work inside each tab.
 */
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
  const setTab = (next: TabKey) => setSearchParams(next === "general" ? {} : { tab: next });

  return (
    <>
      <PageHeader
        icon="settings"
        title={t("Settings")}
        description={t("Everything this installation is configured with.")}
        help={
          <>
            <p>{t("What the panel stores is set here and takes effect without a restart: the retentions, the address the agents dial, the channels, the roles, the mappings of the provider's groups, the budgets and the policies.")}</p>
            <p>{t("Under General, below those, are the values the process was started with. They come from the deployment and are read when the panel starts, so a change to them needs a restart.")}</p>
            <p>{t("A tab is here only if this sign-in may read what is inside it.")}</p>
          </>
        }
      />

      <div className="tabs" data-testid="settings-tabs">
        {TABS.filter((one) => one.permission === "" || permissions.has(one.permission)).map((one) => (
          <button
            key={one.key}
            className={tab === one.key ? "active" : ""}
            onClick={() => setTab(one.key)}
            data-testid={`settings-tab-${one.key}`}
          >
            {t(one.label)}
          </button>
        ))}
      </div>

      {tab === "general" && <GeneralSettings permissions={permissions} />}
      {tab === "channels" && <Notifications />}
      {tab === "roles" && <Roles />}
      {tab === "mappings" && <Mappings />}
      {tab === "budgets" && <Budgets />}
      {tab === "policies" && <Policies />}
    </>
  );
}

/**
 * The panel's own settings, and under them the values it was started with.
 *
 * The two are kept apart on purpose and labelled: the first take effect as
 * soon as they are stored, the second need the deployment changed and the
 * process restarted. A screen that mixed them would be telling somebody they
 * can change a thing they cannot.
 */
function GeneralSettings({ permissions }: { permissions: Set<string> }) {
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

  return (
    <>
      {error && <ErrorBox error={error} />}
      {!error && !data && <Card><Empty>{t("Loading…")}</Empty></Card>}

      {/* What this tab itself stores. Side by side where there is room and
          stacked where there is not: the grid decides that, not a width
          written into either card. */}
      <div className="widgets">
        <MonitoringSettingsCard />
        {(permissions.has("settings.read") || permissions.has("principal.manage")) && (
          <Card
            className="span-5"
            title={t("Advertised address")}
            description={t("The address the agents dial to reach this panel.")}
          >
            <AdvertisedAddressSection mayConfirm={permissions.has("settings.advertise.write")} />
          </Card>
        )}
      </div>

      {data && (
        <>
          {/* The tiles stand on the page, not inside a card: a tile is a
              raised surface, and a raised surface on another one of the same
              colour is a tile nobody can see the edge of. */}
          <div className="parts-head">
            <h2>{t("What the process was started with")}</h2>
            <span className="source">{t("Read at start, changed where the deployment is defined.")}</span>
            <input
              type="search"
              className="settings-search"
              placeholder={t("Find a setting")}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              data-testid="settings-search"
            />
          </div>
          <div data-testid="settings-areas">
            <Board
              screen="settings"
              catalogue={areas.map(({ area }) => ({ key: area.key, title: area.title, width: 4 }))}
              drawn={Object.fromEntries(areas.map(({ area, facts }) => [
                area.key, <AreaTile key={area.key} area={area} facts={facts} />,
              ]))}
            />
            {areas.length === 0 && <Empty>{t("No setting of that name.")}</Empty>}
          </div>
        </>
      )}
    </>
  );
}

/* ---------------------------------------------------------------------- */
/* The monitoring retentions: the one part of this screen that writes.     */
/* ---------------------------------------------------------------------- */

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

function MonitoringSettingsCard() {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [ahead, setAhead] = useState("");
  const [preview, setPreview] = useState<WriteResult | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [message, setMessage] = useState("");

  const settings = useQuery({
    queryKey: ["settings", "monitoring"],
    queryFn: () => api.get<MonitoringSettings>("/api/v1/settings/monitoring"),
    retry: false,
  });

  // The form holds what the installation stored; an empty field is not zero,
  // it is one the environment of the control plane still decides.
  const stored = settings.data?.stored.values ?? {};
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
      queryClient.invalidateQueries({ queryKey: ["settings"] });
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

  if (settings.error) {
    // A panel without the monitoring has no such settings; that is not a fault
    // of this screen.
    return null;
  }
  if (!settings.data) return null;

  const effective = settings.data.effective;
  const environment = settings.data.environment;
  const invalid = preview?.valid === false;
  const destructive = Boolean(preview?.impact.destructive);
  const ready = preview !== null && !invalid && (!destructive || acknowledged);

  return (
    <Card
      className="span-7"
      title={t("Monitoring retention")}
      description={t("How long the panel keeps what the hosts send.")}
      footer={
        <Actions>
          <button className="secondary" onClick={() => check.mutate()} disabled={check.isPending || save.isPending}>
            {check.isPending ? t("checking…") : t("Check what this would change")}
          </button>
          <button onClick={() => save.mutate()} disabled={!ready || save.isPending}>
            {save.isPending ? t("storing…") : t("Store these settings")}
          </button>
          {message && <span className="page-error">{message}</span>}
          {settings.data.stored.present && settings.data.stored.updated_at && (
            <span className="source">
              {t("Stored by {who}", { who: settings.data.stored.updated_by || "—" })}{" "}
              <Time value={settings.data.stored.updated_at} />
            </span>
          )}
        </Actions>
      }
    >
      <FieldGrid>
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
              className="mono"
              value={valueOf(field.key)}
              placeholder={String(environment[field.key])}
              onChange={(e) => { setDraft({ ...draft, [field.key]: e.target.value }); setPreview(null); }}
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
            onChange={(e) => { setAhead(e.target.value); setPreview(null); }}
            aria-label={t("Partitions ahead (days)")}
            data-testid="monitoring-partitions-ahead"
          />
        </Field>
      </FieldGrid>

      {invalid && (
        <p className="page-error">
          {t("These settings would delete readings that are still arriving, so they cannot be stored. Raise the raw retention to at least the raw query window plus the maximum lateness.")}
        </p>
      )}
      {preview && !invalid && <ImpactNote impact={preview.impact} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />}
    </Card>
  );
}

/* What the change removes. It is said before the change is stored, because
   afterwards there is nothing left to say it about. */
function ImpactNote({
  impact,
  acknowledged,
  onAcknowledge,
}: {
  impact: RetentionImpact;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  const t = useT();
  if (!impact.destructive) {
    return <p className="source">{t("Nothing stored is removed by this change.")}</p>;
  }
  return (
    <>
      <Pairs>
        {impact.dropped_raw_partitions.length > 0 && (
          <Pair label={t("Days of raw samples dropped")}>
            <span className="mono wrap">{impact.dropped_raw_partitions.join(", ")}</span>
          </Pair>
        )}
        {impact.raw_samples_estimate > 0 && (
          <Pair label={t("Raw readings in them (estimate)")}>
            <span className="num">{impact.raw_samples_estimate.toLocaleString()}</span>
          </Pair>
        )}
        {impact.rollup_rows > 0 && (
          <Pair label={t("Quarter-hour rollups removed")}>
            <span className="num">{impact.rollup_rows.toLocaleString()}</span>
          </Pair>
        )}
        {impact.gap_rows > 0 && (
          <Pair label={t("Recorded gaps removed")}><span className="num">{impact.gap_rows.toLocaleString()}</span></Pair>
        )}
        {impact.clock_skew_rows > 0 && (
          <Pair label={t("Clock corrections removed")}><span className="num">{impact.clock_skew_rows.toLocaleString()}</span></Pair>
        )}
        {impact.expired_silence_rows > 0 && (
          <Pair label={t("Expired silences removed")}><span className="num">{impact.expired_silence_rows.toLocaleString()}</span></Pair>
        )}
      </Pairs>
      <label>
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(e) => onAcknowledge(e.target.checked)}
          data-testid="monitoring-acknowledge"
        />{" "}
        {t("I understand these readings are deleted at the next maintenance pass and cannot be brought back.")}
      </label>
    </>
  );
}

/* The titles come from the server as English keys; the catalogue turns
   them into the panel's language like every other label. */
/**
 * One area of the configuration: its name and its values, in a tile that
 * fits beside the others.
 *
 * The areas were cards of half the page, and a value with no spaces in it -
 * a commit, a DSN - left the card through its right edge and ran over the
 * card beside it. They are tiles of one grid now, and every value wraps.
 */
function AreaTile({
  area, facts,
}: {
  area: SettingsArea;
  /** The facts to draw: all of them, or what the search left. */
  facts: SettingsFact[];
}) {
  const t = useT();
  return (
    <section className="part">
      <h3 className="part-head">
        <span className="part-name">{t(area.title)}</span>
        <span className="part-summary">
          {facts.length === 1 ? t("{n} value", { n: facts.length }) : t("{n} values", { n: facts.length })}
        </span>
      </h3>
      <div className="part-body">
      <Pairs>
        {facts.map((fact) => (
          <Pair key={fact.key} label={t(FACT_LABELS[fact.key] ?? fact.key)}>
            <FactValue fact={fact} area={area.key} />
          </Pair>
        ))}
      </Pairs>
      </div>
    </section>
  );
}

/* A Go duration as the server prints it: hours, minutes and seconds with
   every zero part written out, such as 720h0m0s. */
const GO_DURATION = /^(?:\d+h)?(?:\d+m)?(?:\d+(?:\.\d+)?s)?$/;

function FactValue({ fact, area }: { fact: SettingsFact; area: string }) {
  const t = useT();
  // A secret says only whether it is set.
  if (fact.secret) {
    return fact.configured
      ? <span className="badge ok" title={t("The value is set; it is never shown here.")}>{t("set")}</span>
      : <span className="badge unknown">{t("not set")}</span>;
  }
  const value = fact.value;
  if (value === null) return <span className="badge unknown">{t("no snapshot yet")}</span>;
  // A retention left unset keeps the record for good; a dash would read
  // as "nothing kept", which is the opposite of what happens.
  if (value === "" && area === "retention") return <span title={t("No limit is set; the records are never swept.")}>{t("forever")}</span>;
  if (value === "" || (Array.isArray(value) && value.length === 0)) return <span className="source">—</span>;
  if (typeof value === "boolean") return <span className={value ? "badge ok" : "badge unknown"}>{value ? t("yes") : t("no")}</span>;
  if (Array.isArray(value)) return <span className="mono wrap">{value.join(", ")}</span>;
  // A duration is read in days and hours, with the exact value on hover.
  if (typeof value === "string" && value !== "" && GO_DURATION.test(value)) {
    return <span className="mono" title={value}>{goDuration(value)}</span>;
  }
  return <span className="mono wrap">{String(value)}</span>;
}

/* The English label of each fact, so the catalogue has a sentence to
   translate rather than a key. A key without a label is shown as it is. */
const FACT_LABELS: Record<string, string> = {
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
