import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time as Timestamp, Empty } from "../../components/ui";
import { Meter } from "../../components/widgets";
import {
  Check, Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

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

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The threshold above which an offset stops being measurement noise. */
const STEP_THRESHOLD = 1;

/**
 * The host's clock and its synchronisation.
 *
 * The clock is the assumption everything else stands on: Kerberos rejects
 * tickets outside its window, mTLS - certificates not yet valid, and a
 * journal from a shifted host sorts into the wrong order. That is why the
 * tab measures the offset instead of only showing that the time daemon runs.
 */
export function Time() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "time");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [servers, setServers] = useState("");
  const [timezone, setTimezone] = useState("");
  const [allowStep, setAllowStep] = useState(false);
  const [allowDropin, setAllowDropin] = useState(false);
  const [testJob, setTestJob] = useState("");
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  /** A missing measurement is not zero: an empty value stays a label, not a number. */
  const seconds = (value?: number | null, digits = 6) =>
    value === undefined || value === null ? unknown : `${value.toFixed(digits)} s`;
  const flag = (value?: boolean | null) =>
    value === undefined || value === null ? unknown : value ? t("yes") : t("no");

  // The test result belongs to the job, not to the host state: it is the
  // answer to a question asked at one moment, against servers the host may
  // not use yet.
  const test = useQuery({
    queryKey: ["job-attempts", testJob],
    queryFn: () =>
      api.get<{ items: { status?: string; detail?: TimeResult }[] }>(
        `/api/v1/jobs/${testJob}/attempts`,
      ),
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

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job, body) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      if (!job.requires_approval && (body as { action?: string }).action === "time.sync.test") {
        setTestJob(job.id);
      }
      setIntent(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["inventory", host.id, "time"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its clock yet.")}</Empty>;

  const serverList = servers.split(",").map((entry) => entry.trim()).filter(Boolean);
  const offset = snapshot?.offset_seconds;
  const drifted = offset !== undefined && offset !== null && Math.abs(offset) >= STEP_THRESHOLD;
  // The sources by what the daemon makes of them, in chrony's words. An
  // unread clock has nothing to count and shows dashes.
  const sources = snapshot?.unavailable_reason ? undefined : snapshot?.sources ?? [];
  const rejected = ["not combined", "false ticker", "too variable"];

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Time")}
        description={t("The clock is what everything else assumes. Kerberos refuses tickets from outside its window, mTLS refuses certificates that are not valid yet, and a journal from a host with a shifted clock sorts into the wrong order.")}
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Clock state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}
      {snapshot?.write_reason && (
        <p className="warning">
          <span>{snapshot.write_reason}</span>
        </p>
      )}
      {/* A drifted clock looks from the outside like a broken directory or
          broken certificates, so the tab names it plainly. */}
      {drifted && (
        <p className="warning">
          <span>
            {t("This host is {offset} away from its time source. Expect Kerberos and mTLS failures before anything else looks wrong.", { offset: `${offset.toFixed(3)} s` })}
          </span>
        </p>
      )}

      <Widgets>
      {/* The sources by what the daemon makes of them, and beside them the
          four numbers that say whether the clock can be trusted. */}
      <Summary
        title={t("Sources")}
        description={t("What the daemon uses, what it keeps in reserve and what it rejected.")}
        span={8}
        segments={[
          { label: t("selected"), value: countWhere(sources, (source) => source.state === "selected"), tone: "ok" },
          { label: t("candidate"), value: countWhere(sources, (source) => source.state === "candidate"), tone: "info" },
          { label: t("rejected"), value: countWhere(sources, (source) => rejected.includes(source.state ?? "")), tone: "warn" },
          { label: t("unreachable"), value: countWhere(sources, (source) => source.state === "unreachable"), tone: "error" },
          { label: t("other"), value: countWhere(sources, (source) => !["selected", "candidate", "unreachable", ...rejected].includes(source.state ?? "")), tone: "unknown" },
        ]}
      />
      <Section title={t("Clock")} span={4} flush>
        <Facts>
          <Fact label={t("Synchronized")}>
            <span className={snapshot?.synchronized === true ? "badge ok" : snapshot?.synchronized === false ? "badge error" : "badge unknown"}>
              {flag(snapshot?.synchronized)}
            </span>
          </Fact>
          <Fact label={t("Stratum")}>{snapshot?.stratum ?? unknown}</Fact>
          <Fact label={t("Daemon")}>
            {snapshot?.service
              ? <span className={snapshot.service_active === false ? "badge error" : "badge ok"}>{snapshot.service}</span>
              : unknown}
            {snapshot?.service_active === false && <span className="source"> · {t("not running")}</span>}
          </Fact>
          {/* The offset against the step threshold: the bar fills as the
              clock drifts towards the point where Kerberos gives up. */}
          <Fact label={t("Offset")} wide>
            {offset === undefined || offset === null ? unknown : (
              <Meter
                value={Math.abs(offset)}
                max={STEP_THRESHOLD}
                tone={drifted ? "error" : Math.abs(offset) >= STEP_THRESHOLD / 2 ? "warn" : "ok"}
                text={seconds(offset, 3)}
              />
            )}
          </Fact>
        </Facts>
      </Section>

      <Section title={t("Time")} span={12} flush>
        <Facts>
          <Fact label={t("Host time")}>{snapshot?.now ? <Timestamp value={snapshot.now} /> : unknown}</Fact>
          <Fact label={t("Timezone")}>{snapshot?.timezone || unknown}</Fact>
          <Fact label={t("UTC offset")}>
            {snapshot?.utc_offset_seconds === undefined || snapshot?.utc_offset_seconds === null
              ? unknown
              : `${snapshot.utc_offset_seconds / 3600} h`}
          </Fact>
          {/* A hardware clock in local time breaks the hour at every
              daylight saving change - and only after a reboot. */}
          <Fact label={t("Hardware clock in local time")}>{flag(snapshot?.rtc_in_local_time)}</Fact>
          <Fact label={t("Synchronized")}>{flag(snapshot?.synchronized)}</Fact>
          <Fact label={t("Daemon")}>
            {snapshot?.service || unknown}
            {snapshot?.unit && ` · ${snapshot.unit}`}
            {snapshot?.service_active === false && ` · ${t("not running")}`}
          </Fact>
          <Fact label={t("Reference")}>{snapshot?.reference_name || unknown}</Fact>
          <Fact label={t("Stratum")}>{snapshot?.stratum ?? unknown}</Fact>
          <Fact label={t("Offset")}>{seconds(snapshot?.offset_seconds)}</Fact>
          <Fact label={t("Root delay")}>{seconds(snapshot?.root_delay_seconds)}</Fact>
          <Fact label={t("Root dispersion")}>{seconds(snapshot?.root_dispersion_seconds)}</Fact>
          <Fact label={t("Leap status")}>{snapshot?.leap_status || unknown}</Fact>
          <Fact label={t("Last sync")}>{snapshot?.last_sync_at ? <Timestamp value={snapshot.last_sync_at} /> : unknown}</Fact>
          <Fact label={t("Managed file")}><span className="hm-mono">{snapshot?.managed_path || "—"}</span></Fact>
          {/* The daemon's main file belongs to the distribution. It is shown
              so that it is visible what the panel's change does not touch. */}
          {snapshot?.config_path && (
            <Fact label={t("Daemon config")}><span className="hm-mono">{snapshot.config_path}</span></Fact>
          )}
        </Facts>
      </Section>

      {/* What the daemon uses beside what it was told to use, then the two
          forms: four short blocks in two rows rather than a strip of four. */}
      <Section title={t("Sources")} count={snapshot?.sources?.length} span={7} flush>
        {!snapshot?.sources?.length ? (
          <Empty>{t("The time daemon reports no sources on this host.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Address")}</th><th>{t("Mode")}</th><th>{t("State")}</th><th className="hm-num">{t("Stratum")}</th><th className="hm-num">{t("Poll")}</th><th>{t("Reach")}</th><th className="hm-num">{t("Offset")}</th></tr>
            </thead>
            <tbody>
              {snapshot.sources.map((source) => (
                <tr key={source.address}>
                  <td className="hm-mono hm-primary">{source.address}</td>
                  <td>{source.mode || "—"}</td>
                  <td>{source.state || "—"}</td>
                  <td className="hm-num">{source.stratum ?? unknown}</td>
                  <td className="hm-num">{source.poll_seconds ? `${source.poll_seconds} s` : unknown}</td>
                  <td className="hm-mono">{source.reachability || "—"}</td>
                  <td className="hm-num">{seconds(source.offset_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section
        title={t("Configured servers")}
        count={snapshot?.configured_servers?.length}
        span={5}
        description={t("Configuration, not reachability: a server written here that never answers does not show up in the source list above at all.")}
        flush
      >
        {!snapshot?.configured_servers?.length ? (
          <Empty>{t("No time servers are configured on this host.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Address")}</th><th>{t("From")}</th><th>{t("Kind")}</th><th>{t("Owner")}</th></tr></thead>
            <tbody>
              {snapshot.configured_servers.map((server, i) => (
                <tr key={`${server.address}-${i}`}>
                  <td className="hm-mono hm-primary">{server.address}</td>
                  <td className="hm-mono">{server.source || "—"}</td>
                  <td>{server.pool ? "pool" : "server"}</td>
                  <td>{server.managed ? "Flotestro" : t("host admin")}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section
        title={t("Test time sources")}
        description={t("The query goes out from the host, not from the panel. Leave the field empty to ask the sources this host already uses.")}
        span={7}
        flush
      >
        <div className="hm-section-body">
          <Form>
            <Fields>
              <Field label={t("Servers, comma separated (optional)")} wide>
                <input
                  value={servers}
                  onChange={(e) => setServers(e.target.value)}
                  placeholder={t("Servers, comma separated (optional)")}
                />
              </Field>
            </Fields>
            <Check checked={allowStep} onChange={setAllowStep}>
              {t("allow a step of the clock")}
            </Check>
            {/* A host on which chrony includes no directory can be brought to a
                writable state with one appended line. It is the only place where
                the panel touches somebody else's configuration, so it asks for
                consent separately and says exactly what it will append. */}
            {snapshot?.can_add_source_dir && (
              <Check checked={allowDropin} onChange={setAllowDropin}>
                {t("append one line to {path} so that chrony reads /etc/chrony/sources.d — a directory that accepts nothing but time servers. Nothing already in that file is changed or removed.", { path: snapshot.config_path ?? "" })}
              </Check>
            )}
            <FormActions>
              <button
                onClick={() =>
                  request.mutate({
                    action: "time.sync.test",
                    payload: { time: { probe: serverList } },
                  })
                }
                disabled={request.isPending}
              >
                {t("Test")}
              </button>
              <button
                className="secondary"
                onClick={() =>
                  setIntent({
                    action: "time.config.apply",
                    label: t("Set time servers"),
                    description:
                      t("{host} will use {servers} as its time sources. Each server is queried before the change; if none answers, the host keeps what it has.", {
                        host: host.hostname, servers: serverList.join(", "),
                      }) + " " +
                      (allowDropin
                        ? t("One line will be appended to {path} so chrony reads the panel's sources directory.", { path: snapshot?.config_path ?? "" }) + " "
                        : "") +
                      (allowStep
                        ? t("A step of the clock is allowed: databases, tokens and certificates will see time move.")
                        : t("A change that would step the clock by more than a second is refused.")),
                    payload: {
                      time: {
                        servers: serverList,
                        allow_step: allowStep,
                        enable_dropin: allowDropin,
                      },
                    },
                  })
                }
                disabled={!serverList.length || (Boolean(snapshot?.write_reason) && !allowDropin)}
                title={snapshot?.write_reason}
              >
                {t("Set as sources")}
              </button>
            </FormActions>
          </Form>
        </div>

        {testJob && (
          <Table>
            <thead>
              <tr><th>{t("Server")}</th><th>{t("Answered from")}</th><th className="hm-num">{t("Stratum")}</th><th className="hm-num">{t("Offset")}</th><th className="hm-num">{t("Round trip")}</th></tr>
            </thead>
            <tbody>
              {probes.map((probe) => (
                <tr key={probe.server}>
                  <td className="hm-mono hm-primary">{probe.server}</td>
                  <td className="hm-mono">
                    {probe.reachable
                      ? probe.address || "—"
                      : <span className="badge unknown">{probe.error || t("no answer")}</span>}
                  </td>
                  <td className="hm-num">{probe.stratum ?? unknown}</td>
                  <td className="hm-num">{seconds(probe.offset_seconds)}</td>
                  <td className="hm-num">{seconds(probe.delay_seconds, 3)}</td>
                </tr>
              ))}
              {!probes.length && (
                <tr><td colSpan={5}>{lastAttempt?.status ? t("No measurements.") : t("Running…")}</td></tr>
              )}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title={t("Timezone")} span={5}>
        <Form>
          <Fields>
            <Field label={t("Timezone")}>
              <input
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                placeholder={t("e.g. Europe/Warsaw")}
              />
            </Field>
          </Fields>
          <FormActions>
            <button
              onClick={() =>
                setIntent({
                  action: "time.timezone.set",
                  label: t("Set timezone"),
                  description: t("{host} will report local time as {zone}. This changes what the host shows people and writes to the journal; it does not move the moment the host lives in.", {
                    host: host.hostname, zone: timezone,
                  }),
                  payload: { time: { timezone } },
                })
              }
              disabled={!timezone}
            >
              {t("Set timezone")}
            </button>
          </FormActions>
        </Form>
      </Section>
      </Widgets>

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Clock read")} <Timestamp value={snapshot.observed_at} /></span>
        </p>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: intent.action,
              reason,
              // The target name is needed by irreversible operations; here
              // it changes nothing, but sending it does no harm.
              target_confirmation: confirmation,
              payload: intent.payload,
            })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}
