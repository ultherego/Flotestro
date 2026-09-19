import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host, Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { absoluteTime } from "../../lib/format";
import {
  Check, Fact, Facts, Field, Fields, Form, FormActions, FormNote, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
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

/**
 * A boot identifier in the dashed form the kernel prints.
 */
export function dashedBootID(id: string): string {
  const bare = id.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(bare)) return id;
  return `${bare.slice(0, 8)}-${bare.slice(8, 12)}-${bare.slice(12, 16)}-${bare.slice(16, 20)}-${bare.slice(20)}`;
}

/**
 * The Logs tab of the host narrowed to one boot.
 */
export function bootLogsPath(hostID: string, bootID: string): string {
  const bare = bootID.replace(/-/g, "").toLowerCase();
  return `/hosts/${encodeURIComponent(hostID)}/logs?boot=${encodeURIComponent(bare)}`;
}

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
 * Power, boot and the maintenance window. A reboot does not end with the
 * command being sent, but when the host comes back with a new boot_id.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const POWER_CHANGES = ["system.reboot", "system.shutdown"];

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
  // Unreported inhibitors are not zero inhibitors; the bar shows a dash.
  const inhibitors = snapshot?.inhibitors_known ? snapshot.inhibitors ?? [] : undefined;
  const known = snapshot?.unavailable_reason ? undefined : snapshot;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Power")}
        description={t("A reboot is not finished when the command is sent — it is finished when the host comes back with a new boot ID. A shutdown never finishes here at all: nothing in this panel can power the machine back on.")}
      />
      <ModuleFreshness fragment={module.data} />
      <ReadOnlyModuleNotice host={host.id} actions={POWER_CHANGES} />
      <Message text={message} />

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

      <Widgets>
      {/* What would hold a shutdown and what asks for one, counted; beside
          them the state of this boot. */}
      <Summary
        title={t("Holds and reasons")}
        description={t("What logind would hold a shutdown for, and what asks for a reboot.")}
        span={8}
        segments={[
          { label: t("blocking"), value: countWhere(inhibitors, (inhibitor) => inhibitor.mode === "block"), tone: "warn" },
          { label: t("delaying"), value: countWhere(inhibitors, (inhibitor) => inhibitor.mode !== "block"), tone: "info" },
          { label: t("reboot reasons"), value: known ? (known.reboot_reasons ?? []).length : undefined, tone: known?.reboot_required ? "error" : "neutral" },
        ]}
      />
      <Section title={t("This boot")} span={4} flush>
        <Facts>
          <Fact label={t("Uptime")}>
            {snapshot?.uptime_seconds === undefined || snapshot?.uptime_seconds === null
              ? unknown
              : <span title={t("as of the last read")}>{uptime(snapshot.uptime_seconds)}</span>}
          </Fact>
          <Fact label={t("Reboot required")}>
            {snapshot?.reboot_required === undefined || snapshot?.reboot_required === null
              ? unknown
              : <span className={snapshot.reboot_required ? "badge warn" : "badge ok"}>{snapshot.reboot_required ? t("yes") : t("no")}</span>}
          </Fact>
          <Fact label={t("Inhibitors")}>
            {!snapshot?.inhibitors_known
              ? unknown
              : <span className={blocking.length > 0 ? "badge warn" : "badge"}>{(snapshot.inhibitors ?? []).length}</span>}
          </Fact>
          <Fact label={t("Scheduled shutdown")}>
            {snapshot?.scheduled_shutdown
              ? <><span className="badge warn">{snapshot.scheduled_shutdown.mode}</span> <Time value={snapshot.scheduled_shutdown.at} /></>
              : t("none")}
          </Fact>
          <Fact label={t("Boots in the journal")}>{known ? (known.last_boots ?? []).length : unknown}</Fact>
        </Facts>
      </Section>

      {/* What the host reports on the left; what the operator can do about
          it on the right. Both are short blocks, and side by side they use
          the width instead of running down the left edge. */}
      <Section title={t("Boot")} span={7} flush>
        <Facts>
          <Fact label={t("Boot ID")}>
            {snapshot?.boot_id
              ? <Link className="hm-mono" to={bootLogsPath(host.id, snapshot.boot_id)} title={t("The journal of this boot")}>{snapshot.boot_id}</Link>
              : <span className="hm-mono">{unknown}</span>}
          </Fact>
          {/* The boot instant absolute beside the relative one, and the
              uptime marked as of the read: the two are read at different
              moments and would otherwise seem to disagree. */}
          <Fact label={t("Booted")}>
            {snapshot?.booted_at
              ? <><Time value={snapshot.booted_at} /> <span className="source">· {absoluteTime(snapshot.booted_at)}</span></>
              : unknown}
          </Fact>
          <Fact label={t("Uptime")}>
            {snapshot?.uptime_seconds === undefined || snapshot?.uptime_seconds === null
              ? unknown
              : <span title={t("as of the last read")}>{uptime(snapshot.uptime_seconds)}</span>}
            {snapshot?.uptime_seconds !== undefined && snapshot?.uptime_seconds !== null && snapshot.observed_at && (
              <span className="source"> · {t("as of")} <Time value={snapshot.observed_at} /></span>
            )}
          </Fact>
          <Fact label={t("Running kernel")}><span className="hm-mono">{snapshot?.running_kernel || unknown}</span></Fact>
          <Fact label={t("Reboot required")}>
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
          </Fact>
        </Facts>
      </Section>

      <MaintenanceWindow host={host} />

      <Section
        title={t("Inhibitors")}
        count={snapshot?.inhibitors_known ? (snapshot.inhibitors ?? []).length : undefined}
        span={7}
        description={t("What logind would hold a shutdown for. A delay is waited out; a block stops the operation until an operator decides otherwise.")}
        flush
      >
        {!snapshot?.inhibitors_known ? (
          <Empty>{t("This host did not report inhibitors.")}</Empty>
        ) : !snapshot.inhibitors?.length ? (
          <Empty>{t("Nothing is holding a shutdown on this host.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th>{t("Who")}</th><th>{t("User")}</th><th>{t("What")}</th><th>{t("Why")}</th><th>{t("Mode")}</th></tr></thead>
            <tbody>
              {snapshot.inhibitors.map((inhibitor, i) => (
                <tr key={`${inhibitor.who}-${i}`}>
                  <td className="hm-primary">{inhibitor.who}</td>
                  <td>{inhibitor.user || "—"}</td>
                  <td className="hm-mono">{inhibitor.what || "—"}</td>
                  <td>{inhibitor.why || "—"}</td>
                  <td>{inhibitor.mode === "block" ? <span className="badge warn">block</span> : inhibitor.mode}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title={t("Power")} span={5}>
        <Form>
          <Fields>
            <Field label={t("Reason for shutting this host down")} wide>
              <input
                value={shutdownReason}
                onChange={(e) => setShutdownReason(e.target.value)}
                placeholder={t("disk replacement, ticket 1234")}
              />
            </Field>
            <FormNote>{t("A reboot asks for its reason at the confirmation. A shutdown needs one here first, at least 10 characters: nobody will read the panel to find out why the host is dark.")}</FormNote>
          </Fields>
          <Check checked={ignoreInhibitors} onChange={setIgnoreInhibitors}>
            {t("override inhibitors")}
          </Check>
          <FormActions>
            <ActionGuard action="system.reboot" host={host.id}>
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
            </ActionGuard>
            <ActionGuard action="system.shutdown" host={host.id}>
            <button
              className="hm-danger"
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
            </ActionGuard>
          </FormActions>
        </Form>
      </Section>

      <Section title={t("Last boots")} count={snapshot?.last_boots?.length} span={12} flush>
        {!snapshot?.last_boots?.length ? (
          <Empty>{t("The journal on this host lists no earlier boots.")}</Empty>
        ) : (
          <Table>
            <thead><tr><th className="hm-num">#</th><th>{t("Boot ID")}</th><th>{t("First entry")}</th><th>{t("Last entry")}</th></tr></thead>
            <tbody>
              {[...snapshot.last_boots].reverse().map((boot) => (
                <tr key={boot.boot_id}>
                  <td className="hm-num">{boot.index}</td>
                  {/* The journal numbers boots back from the current one:
                      0 is this boot, -1 the one before. */}
                  {/* Each boot opens the Logs tab narrowed to it. */}
                  <td className="hm-mono">
                    <Link to={bootLogsPath(host.id, boot.boot_id)} title={t("The journal of this boot")}>{dashedBootID(boot.boot_id)}</Link>
                    {boot.index === 0 && <span className="badge ok"> {t("this boot")}</span>}
                  </td>
                  <td><Time value={boot.first_entry} /> <span className="source">· {absoluteTime(boot.first_entry)}</span></td>
                  <td><Time value={boot.last_entry} /> <span className="source">· {absoluteTime(boot.last_entry)}</span></td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Boot state read")} <Time value={snapshot.observed_at} /></span>
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
              // cannot power this machine back on.
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

/**
 * The maintenance window. It is not an operation on the host and does not go
 * through the job queue: it changes what the panel thinks about the host.
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
    <Section
      title={t("Maintenance window")}
      description={t("A window says somebody is working on this machine: campaigns skip it and its alerts stay quiet. It always has an end — a window without one ends as a host nobody patches and nobody remembers.")}
      span={5}
      flush
    >
      {active ? (
        <Facts>
          <Fact label={t("Until")}><Time value={host.maintenance!.until} /></Fact>
          <Fact label={t("Reason")}>{host.maintenance!.reason || "—"}</Fact>
          <Fact label={t("Declared by")}>{host.maintenance!.set_by || "—"}</Fact>
        </Facts>
      ) : (
        <Empty>{t("This host is not in a maintenance window.")}</Empty>
      )}
      <div className="hm-section-body">
        <Form>
          <Fields>
            <Field label={t("Duration (minutes)")} narrow help={t("Counted from now; the window ends on its own.")}>
              <input
                type="number"
                min={1}
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </Field>
            <Field label={t("Reason")} wide help={t("Shown to whoever finds the host in a window; kept in the audit trail.")}>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder={t("disk swap, ticket 1234")}
              />
            </Field>
          </Fields>
          <FormActions>
            <button
              onClick={() => set.mutate({ duration_minutes: minutes, reason })}
              disabled={!reason.trim() || set.isPending}
            >
              {active ? t("Extend window") : t("Start window")}
            </button>
            <button className="secondary" onClick={() => set.mutate({ clear: true })} disabled={!active || set.isPending}>
              {t("End window")}
            </button>
          </FormActions>
          <Message text={message} error />
        </Form>
      </div>
    </Section>
  );
}
