import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, InventoryFragment } from "../../../lib/types";
import { useT } from "../../../i18n";
import {
  Band, Banner, Button, C, Card, Check, Empty, Fact, Facts, Field, Fields, Form, Grid, Kpi, Meter,
  Note, Pill, Readout, Section, Table, Tabs, useTab, type Segment,
} from "../../kit";
import {
  Confirm, freshnessOf, Guard, JobLine, ReadOnlyNotice, orderReady, refusalOf, registryOrder,
  useOrder, type Intent, type RegistryOrder,
} from "./Power";

/**
 * The host's clock and its synchronisation.
 *
 * The clock is what everything else assumes. Kerberos refuses tickets
 * from outside its window, mTLS refuses certificates that are not valid
 * yet, and a journal from a host with a shifted clock sorts into the
 * wrong order - so a drifted machine looks from the outside like a broken
 * directory long before anybody suspects the time.
 */

/* The two changes this module offers go through the operation registry,
   so the host module and the Bulk workspace send one payload and refuse
   one set of values. The test of the sources has no registry entry and
   stays as it is: it reads, it does not change the host. */

/** Where the host is to take its time from, as an order. */
export function timeSourcesOrder(servers: string[], allowStep: boolean, enableDropin: boolean): RegistryOrder {
  // The registry reads a list one entry per line; the field on this module
  // is one comma-separated line, because it also feeds the test above it.
  return registryOrder("time.config.apply", {
    servers: servers.join("\n"), allow_step: allowStep, enable_dropin: enableDropin,
  });
}

/** The host's time zone, as an order. */
export function timeZoneOrder(timezone: string): RegistryOrder {
  return registryOrder("time.timezone.set", { timezone });
}

type Source = {
  address: string;
  mode?: string;
  state?: string;
  stratum?: number | null;
  poll_seconds?: number | null;
  reachability?: string;
  last_rx_seconds?: number | null;
  offset_seconds?: number | null;
  error_seconds?: number | null;
};

type Server = { address: string; source?: string; pool?: boolean; managed: boolean };

type Probe = {
  server: string;
  address?: string;
  reachable: boolean;
  stratum?: number | null;
  offset_seconds?: number | null;
  delay_seconds?: number | null;
  error?: string;
};

type Snapshot = {
  now?: string;
  timezone?: string;
  utc_offset_seconds?: number | null;
  rtc_in_local_time?: boolean | null;
  ntp_enabled?: boolean | null;
  synchronized?: boolean | null;
  service?: string;
  unit?: string;
  service_active?: boolean | null;
  reference_name?: string;
  stratum?: number | null;
  offset_seconds?: number | null;
  root_delay_seconds?: number | null;
  root_dispersion_seconds?: number | null;
  frequency_ppm?: number | null;
  leap_status?: string;
  last_sync_at?: string;
  sources?: Source[];
  configured_servers?: Server[];
  managed_config?: string;
  managed_path?: string;
  config_path?: string;
  can_add_source_dir?: boolean;
  write_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type TimeResult = { kind?: string; message?: string; probes?: Probe[] };

/** The threshold above which an offset stops being measurement noise. */
const STEP_THRESHOLD = 1;

/** The changes this module offers; when every one is refused, it says so once. */
const TIME_CHANGES = ["time.config.apply", "time.timezone.set"];

/** What the daemon makes of a source it will not use. */
const REJECTED = ["not combined", "false ticker", "too variable"];

/**
 * The sub-tabs of this module: what the clock is doing, and what to
 * change about it. The address carries the open one.
 */
const TIME_TABS = ["state", "change"] as const;

export function Time({ host }: { host: Host }) {
  const t = useT();
  const [tab, go] = useTab(TIME_TABS);
  const queryClient = useQueryClient();
  const [intent, setIntent] = useState<Intent | null>(null);
  const [servers, setServers] = useState("");
  const [timezone, setTimezone] = useState("");
  const [allowStep, setAllowStep] = useState(false);
  const [allowDropin, setAllowDropin] = useState(false);
  const [testJob, setTestJob] = useState("");

  const module = useQuery({
    queryKey: ["inventory", host.id, "time"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/time`),
    retry: false,
  });

  const order = useOrder(host, (job, body) => {
    // The test's answer belongs to the job, not to the host state: it is
    // the answer to a question asked at one moment, against servers the
    // host may not use yet.
    if (!job.requires_approval && (body as { action?: string }).action === "time.sync.test") {
      setTestJob(job.id);
    }
    setIntent(null);
    void queryClient.invalidateQueries({ queryKey: ["inventory", host.id, "time"] });
  });

  const test = useQuery({
    queryKey: ["job-attempts", testJob],
    queryFn: () => api.get<{ items: { status?: string; detail?: TimeResult }[] }>(
      `/api/v1/jobs/${testJob}/attempts`),
    enabled: testJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      const last = attempts?.[attempts.length - 1];
      return last?.status ? false : 2000;
    },
  });

  const attempts = test.data?.items ?? [];
  const lastAttempt = attempts[attempts.length - 1];
  const probes = lastAttempt?.detail?.probes ?? [];

  const snapshot = module.data?.payload;
  const offset = snapshot?.offset_seconds;
  const drifted = offset !== undefined && offset !== null && Math.abs(offset) >= STEP_THRESHOLD;
  // An unread clock has nothing to count and shows dashes - and a clock
  // whose reading has not arrived yet is unread, not a clock with no
  // sources.
  const sources = module.data && !snapshot?.unavailable_reason ? snapshot?.sources ?? [] : undefined;
  const serverList = servers.split(",").map((one) => one.trim()).filter(Boolean);
  const sourcesRequest = timeSourcesOrder(serverList, allowStep, allowDropin);
  const zoneRequest = timeZoneOrder(timezone);

  /** A missing measurement is not zero: an empty value stays unknown. */
  const seconds = (value?: number | null, digits = 6) =>
    value === undefined || value === null
      ? <Pill tone="unknown">{t("unknown")}</Pill>
      : `${value.toFixed(digits)} s`;
  const flag = (value?: boolean | null) =>
    value === undefined || value === null
      ? <Pill tone="unknown">{t("unknown")}</Pill>
      : value ? t("yes") : t("no");

  const countWhere = (test_: (one: Source) => boolean) =>
    sources === undefined ? undefined : sources.filter(test_).length;
  const states: Segment[] = [
    { label: t("selected"), value: countWhere((one) => one.state === "selected"), tone: "ok" },
    { label: t("candidate"), value: countWhere((one) => one.state === "candidate"), tone: "info" },
    { label: t("rejected"), value: countWhere((one) => REJECTED.includes(one.state ?? "")), tone: "warn" },
    { label: t("unreachable"), value: countWhere((one) => one.state === "unreachable"), tone: "error" },
    {
      label: t("other"),
      value: countWhere((one) => !["selected", "candidate", "unreachable", ...REJECTED].includes(one.state ?? "")),
      tone: "unknown",
    },
  ];

  if (!module.data && !module.isLoading) {
    return <Empty>{t("This host has not reported its clock yet.")}</Empty>;
  }

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={TIME_CHANGES} />
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">
          {t("Clock state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
        </Banner>
      )}
      {/* The write reason repeats the read reason on a host without a
          daemon; one sentence is enough. */}
      {snapshot?.write_reason && snapshot.write_reason !== snapshot.unavailable_reason && (
        <Banner tone="warn">{snapshot.write_reason}</Banner>
      )}
      {/* A drifted clock looks from the outside like a broken directory or
          broken certificates, so the module names it plainly. */}
      {drifted && (
        <Banner tone="error">
          {t("This host is {offset} away from its time source. Expect Kerberos and mTLS failures before anything else looks wrong.", {
            offset: `${offset!.toFixed(3)} s`,
          })}
        </Banner>
      )}
      {order.message && <Banner tone="error">{order.message}</Banner>}
      {order.job && <JobLine job={order.job} hostID={host.id} />}

      <Grid>
        <C span={4}>
          <Kpi
            icon="time"
            label={t("Synchronized")}
            value={snapshot?.synchronized === undefined || snapshot?.synchronized === null
              ? null
              : snapshot.synchronized ? t("yes") : t("no")}
            tone={snapshot?.synchronized === true ? "ok" : snapshot?.synchronized === false ? "error" : undefined}
            note={snapshot?.service ? snapshot.service : undefined}
          />
        </C>
        <C span={4}>
          <Kpi
            icon="time"
            label={t("Offset")}
            value={offset === undefined || offset === null ? null : offset.toFixed(3)}
            unit="s"
            tone={drifted ? "error" : Math.abs(offset ?? 0) >= STEP_THRESHOLD / 2 ? "warn" : "ok"}
            note={t("a second apart and Kerberos gives up")}
          />
        </C>
        <C span={4}>
          <Kpi icon="time" label={t("Stratum")} value={snapshot?.stratum ?? null} />
        </C>
      </Grid>

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "state", label: t("State") },
          { value: "change", label: t("Change") },
        ]}
      />

      {tab === "state" && (
        <Grid>
          <C span={7}>
            <Card
              title={t("How the sources stand")}
              note={t("What the daemon uses, what it keeps in reserve and what it rejected.")}
            >
              <Band segments={states} testId="time-states" />
            </Card>
          </C>
          <C span={5}>
            <Card title={t("Clock")} foot={freshnessOf(t, module.data)}>
              <Facts>
                <Fact label={t("Synchronized")}>
                  <Pill tone={snapshot?.synchronized === true ? "ok" : snapshot?.synchronized === false ? "error" : "unknown"}>
                    {flag(snapshot?.synchronized)}
                  </Pill>
                </Fact>
                <Fact label={t("Stratum")}>{snapshot?.stratum ?? <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
                <Fact label={t("Daemon")}>
                  {snapshot?.service
                    ? <Pill tone={snapshot.service_active === false ? "error" : "ok"}>{snapshot.service}</Pill>
                    : <Pill tone="unknown">{t("unknown")}</Pill>}
                  {snapshot?.unit ? ` ${snapshot.unit}` : ""}
                  {snapshot?.service_active === false ? ` · ${t("not running")}` : ""}
                </Fact>
                {/* The offset against the step threshold: the bar fills as the
                    clock drifts towards the point where Kerberos gives up. */}
                <Fact label={t("Offset")}>
                  {offset === undefined || offset === null ? <Pill tone="unknown">{t("unknown")}</Pill> : (
                    <Meter
                      share={Math.abs(offset) / STEP_THRESHOLD}
                      tone={drifted ? "error" : Math.abs(offset) >= STEP_THRESHOLD / 2 ? "warn" : "ok"}
                      text={`${offset.toFixed(3)} s`}
                    />
                  )}
                </Fact>
              </Facts>
            </Card>
          </C>
          <C span={12}>
            <Card title={t("Clock details")}>
              <Facts>
                {/* The host's clock as it read at the observation: an absolute
                    value, because "19 minutes ago" is the age of the read and
                    says nothing about the clock. */}
                <Fact label={t("Host time")}>
                  {snapshot?.now ? absoluteTime(snapshot.now) : <Pill tone="unknown">{t("unknown")}</Pill>}
                </Fact>
                <Fact label={t("Timezone")}>{snapshot?.timezone || <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
                <Fact label={t("UTC offset")}>
                  {snapshot?.utc_offset_seconds === undefined || snapshot?.utc_offset_seconds === null
                    ? <Pill tone="unknown">{t("unknown")}</Pill>
                    : `${snapshot.utc_offset_seconds / 3600} h`}
                </Fact>
                {/* A hardware clock in local time breaks the hour at every
                    daylight saving change - and only after a reboot. */}
                <Fact label={t("Hardware clock in local time")}>{flag(snapshot?.rtc_in_local_time)}</Fact>
                <Fact label={t("NTP enabled")}>{flag(snapshot?.ntp_enabled)}</Fact>
                <Fact label={t("Reference")}>{snapshot?.reference_name || <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
                <Fact label={t("Frequency error")}>
                  {snapshot?.frequency_ppm === undefined || snapshot?.frequency_ppm === null
                    ? <Pill tone="unknown">{t("unknown")}</Pill>
                    : `${snapshot.frequency_ppm.toFixed(3)} ppm`}
                </Fact>
                <Fact label={t("Root delay")}>{seconds(snapshot?.root_delay_seconds)}</Fact>
                <Fact label={t("Root dispersion")}>{seconds(snapshot?.root_dispersion_seconds)}</Fact>
                <Fact label={t("Leap status")}>{snapshot?.leap_status || <Pill tone="unknown">{t("unknown")}</Pill>}</Fact>
                <Fact label={t("Last sync")}>
                  {snapshot?.last_sync_at
                    ? <span title={absoluteTime(snapshot.last_sync_at)}>{relativeTime(snapshot.last_sync_at)}</span>
                    : <Pill tone="unknown">{t("unknown")}</Pill>}
                </Fact>
                <Fact label={t("Managed file")}>{snapshot?.managed_path || "—"}</Fact>
                {/* The daemon's main file belongs to the distribution. It is
                    shown so that what the panel's change does not touch is
                    visible. */}
                <Fact label={t("Daemon config")}>{snapshot?.config_path || "—"}</Fact>
              </Facts>
            </Card>
          </C>
          <C span={12}>
            <Card title={t("Sources")} note={t("{n} reported by the daemon.", { n: snapshot?.sources?.length ?? 0 })} flush>
              <Table
                rows={snapshot?.sources ?? []}
                keyOf={(one) => one.address}
                loading={module.isLoading}
                testId="time-sources"
                empty={snapshot?.unavailable_reason
                  ? t("No time daemon answers on this host, so there are no sources to list.")
                  : t("The time daemon reports no sources on this host.")}
                columns={[
                  { key: "address", head: t("Address"), tight: true, cell: (one) => one.address },
                  { key: "mode", head: t("Mode"), minor: true, cell: (one) => one.mode || "—" },
                  { key: "state", head: t("State"), cell: (one) => one.state || "—" },
                  { key: "stratum", head: t("Stratum"), num: true, cell: (one) => (
                    one.stratum ?? <Pill tone="unknown">{t("unknown")}</Pill>
                  ) },
                  { key: "poll", head: t("Poll"), num: true, minor: true, cell: (one) => (
                    one.poll_seconds ? `${one.poll_seconds} s` : <Pill tone="unknown">{t("unknown")}</Pill>
                  ) },
                  { key: "reach", head: t("Reach"), minor: true, tight: true, cell: (one) => one.reachability || "—" },
                  { key: "offset", head: t("Offset"), num: true, cell: (one) => seconds(one.offset_seconds) },
                ]}
              />
            </Card>
          </C>
          <C span={7}>
            <Card
              title={t("Configured servers")}
              note={t("Configuration, not reachability: a server written here that never answers does not show up in the source list at all.")}
              flush
            >
              <Table
                rows={snapshot?.configured_servers ?? []}
                keyOf={(one, index) => `${one.address}-${index}`}
                loading={module.isLoading}
                empty={t("No time servers are configured on this host.")}
                columns={[
                  { key: "address", head: t("Address"), tight: true, cell: (one) => one.address },
                  { key: "from", head: t("From"), minor: true, tight: true, cell: (one) => one.source || "—" },
                  { key: "kind", head: t("Kind"), cell: (one) => (one.pool ? t("pool") : t("server")) },
                  { key: "owner", head: t("Owner"), cell: (one) => (
                    one.managed ? <Pill tone="ok">{t("panel")}</Pill> : <Note>{t("host admin")}</Note>
                  ) },
                ]}
              />
            </Card>
          </C>
          <C span={5}>{snapshot?.managed_config ? (
            <Card title={t("What the panel wrote")} note={snapshot.managed_path}>
              <Readout label={t("What the panel wrote")} value={snapshot.managed_config} testId="time-managed" lines={12} />
            </Card>
          ) : undefined}</C>
        </Grid>
      )}

      {tab === "change" && (
        <Grid>
          <C span={12}>
            <Form
              title={t("Time sources")}
              note={t("The query goes out from the host, not from the panel. Leave the field empty to ask the sources this host already uses.")}
              actions={(
                <>
                  <Guard action="time.sync.test" host={host.id} explain>
                    <Button
                      testId="time-test"
                      disabled={order.request.isPending}
                      onClick={() => order.request.mutate({
                        action: "time.sync.test",
                        payload: { time: { probe: serverList } },
                      })}
                    >
                      {t("Test")}
                    </Button>
                  </Guard>
                  <Guard action="time.config.apply" host={host.id} explain>
                    <Button
                      kind="quiet"
                      testId="time-apply"
                      // The host's own refusal comes first: a daemon whose
                      // configuration reads no directory cannot be written to at
                      // all, whatever the servers say.
                      disabled={!orderReady(sourcesRequest) || (Boolean(snapshot?.write_reason) && !allowDropin)}
                      title={snapshot?.write_reason || refusalOf(t, sourcesRequest)}
                      onClick={() => setIntent({
                        action: "time.config.apply",
                        label: t("Set time servers"),
                        description: t("{host} will use {servers} as its time sources. Each server is queried before the change; if none answers, the host keeps what it has.", {
                          host: host.hostname, servers: serverList.join(", "),
                        })
                          + " "
                          + (allowDropin
                            ? t("One line will be appended to {path} so chrony reads the panel's sources directory.", { path: snapshot?.config_path ?? "" }) + " "
                            : "")
                          + (allowStep
                            ? t("A step of the clock is allowed: databases, tokens and certificates will see time move.")
                            : t("A change that would step the clock by more than a second is refused.")),
                        payload: sourcesRequest.payload,
                      })}
                    >
                      {t("Set as sources")}
                    </Button>
                  </Guard>
                </>
              )}
            >
              <Fields>
                <Field label={t("Servers, comma separated (optional)")} wide>
                  <input
                    value={servers}
                    onChange={(event) => setServers(event.target.value)}
                    placeholder={t("Servers, comma separated (optional)")}
                    data-testid="time-servers"
                  />
                </Field>
              </Fields>
              <Check checked={allowStep} onChange={setAllowStep}>
                {t("allow a step of the clock")}
              </Check>
              {/* A host on which chrony includes no directory can be brought
                  to a writable state with one appended line. It is the only
                  place where the panel touches somebody else's configuration,
                  so it asks for consent separately and says what it appends. */}
              {snapshot?.can_add_source_dir && (
                <Check checked={allowDropin} onChange={setAllowDropin}>
                  {t("append one line to {path} so that chrony reads /etc/chrony/sources.d — a directory that accepts nothing but time servers. Nothing already in that file is changed or removed.", {
                    path: snapshot.config_path ?? "",
                  })}
                </Check>
              )}
            </Form>
            {testJob && (
              <Section
                title={t("What the host measured")}
                note={t("The answer to a question asked at one moment, against servers this host may not use yet.")}
              >
                <Table
                  rows={probes}
                  keyOf={(one) => one.server}
                  loading={!lastAttempt?.status}
                  testId="time-probes"
                  empty={t("No measurements.")}
                  columns={[
                    { key: "server", head: t("Server"), tight: true, cell: (one) => one.server },
                    { key: "from", head: t("Answered from"), tight: true, cell: (one) => (
                      one.reachable
                        ? one.address || "—"
                        : <Pill tone="unknown">{one.error || t("no answer")}</Pill>
                    ) },
                    { key: "stratum", head: t("Stratum"), num: true, cell: (one) => (
                      one.stratum ?? <Pill tone="unknown">{t("unknown")}</Pill>
                    ) },
                    { key: "offset", head: t("Offset"), num: true, cell: (one) => seconds(one.offset_seconds) },
                    { key: "delay", head: t("Round trip"), num: true, cell: (one) => seconds(one.delay_seconds, 3) },
                  ]}
                />
              </Section>
            )}
          </C>
          <C span={12}>
            <Form
              title={t("Timezone")}
              note={t("What the host reports local time as; it does not move the moment the host lives in.")}
              actions={(
                <Guard action="time.timezone.set" host={host.id} explain>
                  <Button
                    testId="zone-set"
                    disabled={!orderReady(zoneRequest)}
                    title={refusalOf(t, zoneRequest)}
                    onClick={() => setIntent({
                      action: "time.timezone.set",
                      label: t("Set timezone"),
                      description: t("{host} will report local time as {zone}. This changes what the host shows people and writes to the journal; it does not move the moment the host lives in.", {
                        host: host.hostname, zone: timezone,
                      }),
                      payload: zoneRequest.payload,
                    })}
                  >
                    {t("Set timezone")}
                  </Button>
                </Guard>
              )}
            >
              <Fields>
                <Field
                  label={t("Timezone")}
                  hint={snapshot?.timezone
                    ? t("A zone from the tz database; the host is on {zone} now.", { zone: snapshot.timezone })
                    : t("A zone from the tz database.")}
                  wide
                >
                  <input
                    value={timezone}
                    onChange={(event) => setTimezone(event.target.value)}
                    placeholder={t("e.g. Europe/Warsaw")}
                    data-testid="time-zone"
                  />
                </Field>
              </Fields>
            </Form>
          </C>
        </Grid>
      )}

      {intent && (
        <Confirm
          key={intent.action}
          host={host}
          intent={intent}
          busy={order.request.isPending}
          onConfirm={(reason, confirmation) => order.request.mutate({
            action: intent.action,
            reason,
            // The target name is needed by irreversible operations; here it
            // changes nothing, but sending it does no harm.
            target_confirmation: confirmation,
            payload: intent.payload,
          })}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}
