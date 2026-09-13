import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time as Timestamp, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
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

  return (
    <>
      <p className="subtitle">
        {t("The clock is what everything else assumes. Kerberos refuses tickets from outside its window, mTLS refuses certificates that are not valid yet, and a journal from a host with a shifted clock sorts into the wrong order.")}
      </p>

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

      <table>
        <tbody>
          <tr><th>{t("Host time")}</th><td>{snapshot?.now ? <Timestamp value={snapshot.now} /> : unknown}</td></tr>
          <tr><th>{t("Timezone")}</th><td>{snapshot?.timezone || unknown}</td></tr>
          <tr>
            <th>{t("UTC offset")}</th>
            <td>
              {snapshot?.utc_offset_seconds === undefined || snapshot?.utc_offset_seconds === null
                ? unknown
                : `${snapshot.utc_offset_seconds / 3600} h`}
            </td>
          </tr>
          {/* A hardware clock in local time breaks the hour at every
              daylight saving change - and only after a reboot. */}
          <tr><th>{t("Hardware clock in local time")}</th><td>{flag(snapshot?.rtc_in_local_time)}</td></tr>
          <tr><th>{t("Synchronized")}</th><td>{flag(snapshot?.synchronized)}</td></tr>
          <tr>
            <th>{t("Daemon")}</th>
            <td>
              {snapshot?.service || unknown}
              {snapshot?.unit && ` · ${snapshot.unit}`}
              {snapshot?.service_active === false && ` · ${t("not running")}`}
            </td>
          </tr>
          <tr><th>{t("Reference")}</th><td>{snapshot?.reference_name || unknown}</td></tr>
          <tr><th>{t("Stratum")}</th><td>{snapshot?.stratum ?? unknown}</td></tr>
          <tr><th>{t("Offset")}</th><td>{seconds(snapshot?.offset_seconds)}</td></tr>
          <tr><th>{t("Root delay")}</th><td>{seconds(snapshot?.root_delay_seconds)}</td></tr>
          <tr><th>{t("Root dispersion")}</th><td>{seconds(snapshot?.root_dispersion_seconds)}</td></tr>
          <tr><th>{t("Leap status")}</th><td>{snapshot?.leap_status || unknown}</td></tr>
          <tr>
            <th>{t("Last sync")}</th>
            <td>{snapshot?.last_sync_at ? <Timestamp value={snapshot.last_sync_at} /> : unknown}</td>
          </tr>
          <tr><th>{t("Managed file")}</th><td>{snapshot?.managed_path || "—"}</td></tr>
          {/* The daemon's main file belongs to the distribution. It is shown
              so that it is visible what the panel's change does not touch. */}
          {snapshot?.config_path && (
            <tr><th>{t("Daemon config")}</th><td>{snapshot.config_path}</td></tr>
          )}
        </tbody>
      </table>

      <h2>{t("Sources")}</h2>
      {!snapshot?.sources?.length ? (
        <Empty>{t("The time daemon reports no sources on this host.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Address")}</th><th>{t("Mode")}</th><th>{t("State")}</th><th>{t("Stratum")}</th><th>{t("Poll")}</th><th>{t("Reach")}</th><th>{t("Offset")}</th></tr>
          </thead>
          <tbody>
            {snapshot.sources.map((source) => (
              <tr key={source.address}>
                <td>{source.address}</td>
                <td>{source.mode || "—"}</td>
                <td>{source.state || "—"}</td>
                <td>{source.stratum ?? unknown}</td>
                <td>{source.poll_seconds ? `${source.poll_seconds} s` : unknown}</td>
                <td>{source.reachability || "—"}</td>
                <td>{seconds(source.offset_seconds)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Configured servers")}</h2>
      <p className="subtitle">
        {t("Configuration, not reachability: a server written here that never answers does not show up in the source list above at all.")}
      </p>
      {!snapshot?.configured_servers?.length ? (
        <Empty>{t("No time servers are configured on this host.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Address")}</th><th>{t("From")}</th><th>{t("Kind")}</th><th>{t("Owner")}</th></tr></thead>
          <tbody>
            {snapshot.configured_servers.map((server, i) => (
              <tr key={`${server.address}-${i}`}>
                <td>{server.address}</td>
                <td>{server.source || "—"}</td>
                <td>{server.pool ? "pool" : "server"}</td>
                <td>{server.managed ? "Flotestro" : t("host admin")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Test time sources")}</h2>
      <p className="subtitle">
        {t("The query goes out from the host, not from the panel. Leave the field empty to ask the sources this host already uses.")}
      </p>
      <div className="filters">
        <input
          value={servers}
          onChange={(e) => setServers(e.target.value)}
          placeholder={t("Servers, comma separated (optional)")}
          style={{ minWidth: 320 }}
        />
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
        <label>
          <input type="checkbox" checked={allowStep} onChange={(e) => setAllowStep(e.target.checked)} />
          {" "}{t("allow a step of the clock")}
        </label>
      </div>

      {/* A host on which chrony includes no directory can be brought to a
          writable state with one appended line. It is the only place where
          the panel touches somebody else's configuration, so it asks for
          consent separately and says exactly what it will append. */}
      {snapshot?.can_add_source_dir && (
        <p className="subtitle">
          <label>
            <input
              type="checkbox"
              checked={allowDropin}
              onChange={(e) => setAllowDropin(e.target.checked)}
            />
            {" "}{t("append one line to {path} so that chrony reads /etc/chrony/sources.d — a directory that accepts nothing but time servers. Nothing already in that file is changed or removed.", { path: snapshot.config_path ?? "" })}
          </label>
        </p>
      )}

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {testJob && (
        <table>
          <thead>
            <tr><th>{t("Server")}</th><th>{t("Answered from")}</th><th>{t("Stratum")}</th><th>{t("Offset")}</th><th>{t("Round trip")}</th></tr>
          </thead>
          <tbody>
            {probes.map((probe) => (
              <tr key={probe.server}>
                <td>{probe.server}</td>
                <td>
                  {probe.reachable
                    ? probe.address || "—"
                    : <span className="badge unknown">{probe.error || t("no answer")}</span>}
                </td>
                <td>{probe.stratum ?? unknown}</td>
                <td>{seconds(probe.offset_seconds)}</td>
                <td>{seconds(probe.delay_seconds, 3)}</td>
              </tr>
            ))}
            {!probes.length && (
              <tr><td colSpan={5}>{lastAttempt?.status ? t("No measurements.") : t("Running…")}</td></tr>
            )}
          </tbody>
        </table>
      )}

      <h2>{t("Timezone")}</h2>
      <div className="filters">
        <input
          value={timezone}
          onChange={(e) => setTimezone(e.target.value)}
          placeholder={t("e.g. Europe/Warsaw")}
          style={{ minWidth: 240 }}
        />
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
      </div>

      <ModuleFreshness fragment={module.data} />
      {snapshot?.observed_at && (
        <p className="source">
          {t("Clock read")} <Timestamp value={snapshot.observed_at} />
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
    </>
  );
}
