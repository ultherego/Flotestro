import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Inhibitor = { who: string; user?: string; pid?: number; what?: string; why?: string; mode?: string };

type Boot = { index: number; boot_id: string; first_entry: string; last_entry: string };

type Snapshot = {
  boot_id?: string;
  booted_at?: string;
  uptime_seconds?: number | null;
  running_kernel?: string;
  reboot_required?: boolean | null;
  reboot_reasons?: string[];
  inhibitors?: Inhibitor[];
  inhibitors_known?: boolean;
  last_boots?: Boot[];
  scheduled_shutdown?: { mode: string; at: string };
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The uptime in a form that reads without arithmetic in one's head. */
function uptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/**
 * Power, boot and the maintenance window.
 *
 * A reboot does not end with the command being sent, but when the host
 * comes back with a new boot_id. A shutdown does not end at all: the panel
 * cannot power the machine back on, and the tab says so plainly.
 */
export function Power() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "power");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [shutdownReason, setShutdownReason] = useState("");
  const [ignoreInhibitors, setIgnoreInhibitors] = useState(false);
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its boot state yet.")}</Empty>;

  const blocking = (snapshot?.inhibitors ?? []).filter((inhibitor) => inhibitor.mode === "block");

  return (
    <>
      <p className="subtitle">
        {t("A reboot is not finished when the command is sent — it is finished when the host comes back with a new boot ID. A shutdown never finishes here at all: nothing in this panel can power the machine back on.")}
      </p>

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Boot state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}
      {/* A shutdown scheduled outside the panel is a fact the operator is to
          see before requesting anything here. */}
      {snapshot?.scheduled_shutdown && (
        <p className="warning">
          <span>
            {t("A {mode} is already scheduled on this host for", { mode: snapshot.scheduled_shutdown.mode })}{" "}
            <Time value={snapshot.scheduled_shutdown.at} />.
          </span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>{t("Boot ID")}</th><td className="source">{snapshot?.boot_id || unknown}</td></tr>
          <tr><th>{t("Booted")}</th><td>{snapshot?.booted_at ? <Time value={snapshot.booted_at} /> : unknown}</td></tr>
          <tr><th>{t("Uptime")}</th><td>{snapshot?.uptime_seconds === undefined || snapshot?.uptime_seconds === null ? unknown : uptime(snapshot.uptime_seconds)}</td></tr>
          <tr><th>{t("Running kernel")}</th><td>{snapshot?.running_kernel || unknown}</td></tr>
          <tr>
            <th>{t("Reboot required")}</th>
            <td>
              {snapshot?.reboot_required === undefined || snapshot?.reboot_required === null
                ? unknown
                : snapshot.reboot_required
                  ? t("yes")
                  : t("no")}
              {/* "Why" is the whole answer here: a host that requires a
                  reboot without a reason tells the operator nothing. */}
              {(snapshot?.reboot_reasons ?? []).length > 0 && (
                <span className="source"> · {snapshot!.reboot_reasons!.join(", ")}</span>
              )}
            </td>
          </tr>
        </tbody>
      </table>

      <MaintenanceWindow host={host} />

      <h2>{t("Inhibitors")}</h2>
      <p className="subtitle">
        {t("What logind would hold a shutdown for. A delay is waited out; a block stops the operation until an operator decides otherwise.")}
      </p>
      {!snapshot?.inhibitors_known ? (
        <Empty>{t("This host did not report inhibitors.")}</Empty>
      ) : !snapshot.inhibitors?.length ? (
        <Empty>{t("Nothing is holding a shutdown on this host.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Who")}</th><th>{t("User")}</th><th>{t("What")}</th><th>{t("Why")}</th><th>{t("Mode")}</th></tr></thead>
          <tbody>
            {snapshot.inhibitors.map((inhibitor, i) => (
              <tr key={`${inhibitor.who}-${i}`}>
                <td>{inhibitor.who}</td>
                <td>{inhibitor.user || "—"}</td>
                <td>{inhibitor.what || "—"}</td>
                <td>{inhibitor.why || "—"}</td>
                <td>{inhibitor.mode === "block" ? <span className="badge warn">block</span> : inhibitor.mode}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Last boots")}</h2>
      {!snapshot?.last_boots?.length ? (
        <Empty>{t("The journal on this host lists no earlier boots.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>#</th><th>{t("Boot ID")}</th><th>{t("First entry")}</th><th>{t("Last entry")}</th></tr></thead>
          <tbody>
            {[...snapshot.last_boots].reverse().map((boot) => (
              <tr key={boot.boot_id}>
                <td>{boot.index}</td>
                <td className="source">{boot.boot_id}</td>
                <td><Time value={boot.first_entry} /></td>
                <td><Time value={boot.last_entry} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>{t("Power")}</h2>
      <div className="filters">
        <button
          onClick={() =>
            setIntent({
              action: "system.reboot",
              label: t("Reboot host"),
              description: t("{host} will reboot. The panel treats the operation as finished only when the host comes back with a new boot ID, so a host that does not return shows up as failed, not as done.", { host: host.hostname }),
              payload: { reboot: { delay_seconds: 15, reason: "operator reboot" } },
            })
          }
        >
          {t("Reboot")}
        </button>
        <input
          value={shutdownReason}
          onChange={(e) => setShutdownReason(e.target.value)}
          placeholder={t("Reason for shutting this host down")}
          style={{ minWidth: 320 }}
        />
        <button
          className="secondary"
          onClick={() =>
            setIntent({
              action: "system.shutdown",
              label: t("Shut down host"),
              description:
                t("{host} will power off. Nothing in this panel can turn it back on — that needs physical or out-of-band access to the machine.", { host: host.hostname }) +
                " " +
                (blocking.length
                  ? ignoreInhibitors
                    ? t("{n} blocking inhibitor(s) will be overridden.", { n: blocking.length })
                    : t("{n} inhibitor(s) are blocking shutdown; the host will refuse.", { n: blocking.length })
                  : ""),
              payload: {
                power: {
                  mode: "poweroff",
                  delay_seconds: 15,
                  reason: shutdownReason,
                  ignore_inhibitors: ignoreInhibitors,
                },
              },
            })
          }
          disabled={shutdownReason.trim().length < 10}
          title={t("a shutdown needs a reason: nobody will read the panel to find out why this host is dark")}
        >
          {t("Shut down")}
        </button>
        <label>
          <input type="checkbox" checked={ignoreInhibitors} onChange={(e) => setIgnoreInhibitors(e.target.checked)} />
          {" "}{t("override inhibitors")}
        </label>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      <ModuleFreshness fragment={module.data} />
      {snapshot?.observed_at && (
        <p className="source">
          {t("Boot state read")} <Time value={snapshot.observed_at} />
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
              // A shutdown requires the target name typed out: the panel
              // cannot power this machine back on. The other operations do
              // not need it, but sending it does no harm.
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

/**
 * The maintenance window. It is not an operation on the host and does not
 * go through the job queue: it changes what the panel thinks about the
 * host. Campaigns skip a host in a window, and its alerts do not wake the
 * on-call.
 */
function MaintenanceWindow({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [minutes, setMinutes] = useState(120);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  const set = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Host>(`/api/v1/hosts/${host.id}/maintenance`, body),
    onSuccess: () => {
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const active = host.maintenance && new Date(host.maintenance.until).getTime() > Date.now();

  return (
    <>
      <h2>{t("Maintenance window")}</h2>
      <p className="subtitle">
        {t("A window says somebody is working on this machine: campaigns skip it and its alerts stay quiet. It always has an end — a window without one ends as a host nobody patches and nobody remembers.")}
      </p>
      {active ? (
        <table>
          <tbody>
            <tr><th>{t("Until")}</th><td><Time value={host.maintenance!.until} /></td></tr>
            <tr><th>{t("Reason")}</th><td>{host.maintenance!.reason || "—"}</td></tr>
            <tr><th>{t("Declared by")}</th><td>{host.maintenance!.set_by || "—"}</td></tr>
          </tbody>
        </table>
      ) : (
        <Empty>{t("This host is not in a maintenance window.")}</Empty>
      )}
      <div className="filters">
        <input
          type="number"
          min={1}
          value={minutes}
          onChange={(e) => setMinutes(Number(e.target.value))}
          style={{ width: 100 }}
        />
        <span className="source">{t("minutes")}</span>
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t("Reason")}
          style={{ minWidth: 280 }}
        />
        <button
          onClick={() => set.mutate({ duration_minutes: minutes, reason })}
          disabled={!reason.trim() || set.isPending}
        >
          {active ? t("Extend window") : t("Start window")}
        </button>
        <button className="secondary" onClick={() => set.mutate({ clear: true })} disabled={!active || set.isPending}>
          {t("End window")}
        </button>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}
    </>
  );
}
