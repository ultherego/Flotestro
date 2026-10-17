import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import {
  enableOrder, ensureOrder, entryOrder, foundUnderName, kindLabel, previewOf, scheduleKinds,
  type Attempt, type Schedule,
} from "../../../lib/host/schedules";
import { orderReady, refusalOf } from "../../../lib/host/module";
import { useT } from "../../../i18n";
import {
  Band, Banner, Bars, Button, C, Card, Check, Empty, Fact, Facts, Field, Fields, Form, Grid, HeadActions,
  Modal, Note, Pill, Problem, Readout, Table, Tabs, useTab, type Segment,
} from "../../kit";

/** The sub-tabs of this screen, in the order a reader wants them. */
const SCHEDULE_TABS = ["state", "schedules", "new"] as const;

/**
 * The recurring work of one host: cron entries and systemd timers in one
 * list.
 *
 * The distinction the screen is built on is ownership. An entry the panel
 * wrote is the panel's to run, switch off and take away; an entry the host
 * administrator wrote is read and left alone until somebody deliberately
 * adopts it. Confusing the two is how a panel deletes a line nobody told
 * it about.
 */

type Snapshot = {
  schedules?: Schedule[];
  timezone?: string;
  unavailable_reason?: string;
};

/** An operation waiting for its confirmation. */
type Intent = {
  action: string;
  label: string;
  description: string;
  payload: Record<string, unknown>;
};

/** The changes this screen offers; when every one is refused, it says so once. */
export const SCHEDULE_CHANGES = [
  "schedule.ensure", "schedule.run_now", "schedule.disable", "schedule.remove",
];

/**
 * The wall clock of a run as the host wrote it, not converted to the
 * browser's zone: "03:00" is what the entry says, and the operator
 * compares it with the expression and not with their own watch.
 */
export function hostClock(value: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(value);
  return match ? `${match[1]} ${match[2]}` : value;
}

/** The entry's command in the form the host will run it. */
export function commandOf(entry: Schedule): string {
  return entry.command_line || (entry.command ?? []).join(" ");
}

/** A count of what satisfies a test, or nothing at all when the list is unread. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/** A control that exists only where the order it places would be taken. */
function Guard({ action, host, explain, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

export function Schedules({ host }: { host: Host }) {
  const t = useT();
  const [tab, go] = useTab(SCHEDULE_TABS);
  const queryClient = useQueryClient();

  const module = useQuery({
    queryKey: ["inventory", host.id, "schedules"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/schedules`),
    retry: false,
  });

  const [intent, setIntent] = useState<Intent | null>(null);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setProblem("");
      setNotice(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      setIntent(null);
      // An entry that has been ordered is read on the list, not on the
      // form it was typed into.
      go("schedules");
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setProblem(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const entries = snapshot?.schedules ?? [];
  const managed = entries.filter((entry) => entry.source === "managed").length;
  // An unread list is not an empty one: the counts are dashes until then.
  const known = snapshot && !snapshot.unavailable_reason ? entries : undefined;
  const kinds = Object.entries(entries.reduce<Record<string, number>>((into, entry) => {
    into[entry.kind] = (into[entry.kind] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]);

  const shape: Segment[] = [
    { label: t("enabled"), value: countWhere(known, (entry) => entry.enabled), tone: "ok" },
    { label: t("disabled"), value: countWhere(known, (entry) => !entry.enabled), tone: "neutral" },
    { label: "Flotestro", value: known ? managed : undefined, tone: "info" },
    { label: t("host admin"), value: known ? known.length - managed : undefined, tone: "unknown" },
  ];

  const freshness = module.data
    ? t("Source: {source}, revision {revision}, observed {when}", {
        source: module.data.source,
        revision: module.data.revision.slice(0, 12),
        when: relativeTime(module.data.observed_at),
      })
    : undefined;

  return (
    <>
      <HeadActions>
        <Guard action="schedule.ensure" host={host.id}>
          <Button onClick={() => go("new")} testId="new-schedule">
            {t("New schedule")}
          </Button>
        </Guard>
      </HeadActions>

      <ReadOnlyNotice host={host.id} actions={SCHEDULE_CHANGES} />
      {/* No entries and no read are two different things: an empty list
          without an explanation reads as a host with no recurring work. */}
      {snapshot?.unavailable_reason && (
        <Banner tone="warn">
          {t("Schedules could not be read: {reason}", { reason: snapshot.unavailable_reason })}
        </Banner>
      )}
      {notice && <Banner tone="info">{notice}</Banner>}
      {problem && <Problem>{problem}</Problem>}

      {intent && (
        <ConfirmEntry
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onCancel={() => setIntent(null)}
          onConfirm={(reason) => request.mutate({ action: intent.action, reason, payload: intent.payload })}
        />
      )}

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "state", label: t("State") },
          { value: "schedules", label: t("Schedules") },
          { value: "new", label: t("New") },
        ]}
      />

      {tab === "state" && (
        <Grid>
          <C span={12}>
            {/* Not "Schedules" a second time: the list on the next tab
                carries that name, and two containers of one name on one
                screen is what sent the reader hunting. */}
            <Card
              title={t("By state and owner")}
              note={t("Cron entries and timers, by whether they run and who owns them.")}
              foot={freshness}
            >
              <Band segments={shape} testId="schedule-shape" />
            </Card>
          </C>
          <C span={12}>
            <Card title={t("By kind")} note={t("Which mechanism carries the recurring work here.")}>
              <Facts>
                <Fact label={t("Timezone")}>{snapshot?.timezone || "—"}</Fact>
              </Facts>
              {kinds.length > 0
                ? <Bars items={kinds.map(([kind, count]) => ({ label: kind, value: count }))} />
                : <Empty icon="schedules">{t("Nothing recurring has been reported.")}</Empty>}
            </Card>
          </C>
        </Grid>
      )}

      {tab === "schedules" && (
        <Grid>
          <C span={12}>
            <Card
              title={t("Schedules")}
              note={t("Cron entries and systemd timers under one list. Entries created here belong to Flotestro and live in their own files; entries found on the host stay untouched until you adopt them.")}
              foot={snapshot
                ? `${t("{managed} managed · {found} found on the host", {
                    managed, found: entries.length - managed,
                  })}${snapshot.timezone ? ` · ${t("host timezone {zone}", { zone: snapshot.timezone })}` : ""}`
                : undefined}
              flush
            >
              {!module.data
                ? <Empty icon="schedules">{t("This host has not reported its schedules yet.")}</Empty>
                : (
                  <Table
                    rows={entries}
                    keyOf={(entry) => `${entry.path ?? ""}:${entry.line ?? 0}:${entry.id}`}
                    rowTestId={(entry) => `schedule-${entry.id}`}
                    testId="schedules"
                    loading={module.isLoading}
                    empty={t("No cron entries and no timers on this host.")}
                    columns={[
                      { key: "name", head: t("Name"), tight: true, cell: (entry) => entry.id },
                      { key: "kind", head: t("Kind"), cell: (entry) => entry.kind },
                      /* The entry's ownership decides what the panel may do with it. */
                      {
                        key: "owner", head: t("Owner"), cell: (entry) => (
                          entry.source === "managed"
                            ? "Flotestro"
                            : <Pill tone="unknown" title={entry.path}>{t("host admin")}</Pill>
                        ),
                      },
                      /* A timer the panel wrote shows both: the expression
                         the operator typed and what systemd was told, which
                         are the same schedule in two languages. */
                      {
                        key: "schedule", head: t("Schedule"), tight: true, cell: (entry) => (
                          <>
                            {entry.expression || <Pill tone="unknown">{t("event-based")}</Pill>}
                            {entry.calendar && entry.calendar !== entry.expression && (
                              <span title={t("The calendar expression systemd runs it by")}> · {entry.calendar}</span>
                            )}
                            {entry.timezone ? ` · ${entry.timezone}` : ""}
                          </>
                        ),
                      },
                      /* The next run, and the two after it: the rhythm of an
                         entry is read from three dates, not from one. */
                      {
                        key: "next", head: t("Next run"), cell: (entry) => (
                          <>
                            {entry.next_run
                              ? <span title={absoluteTime(entry.next_run)}>{relativeTime(entry.next_run)}</span>
                              : "—"}
                            {(entry.next_runs ?? []).length > 1 && (
                              <span title={t("The following runs, in the host zone")}>
                                {` · ${t("then")} ${(entry.next_runs ?? []).slice(1).map(hostClock).join(", ")}`}
                              </span>
                            )}
                          </>
                        ),
                      },
                      /* A found entry is a shell line, an owned one an
                         argument list; both show what the host will run. */
                      {
                        key: "command", head: t("Command"), tight: true, minor: true,
                        cell: (entry) => <span title={commandOf(entry)}>{commandOf(entry).slice(0, 50) || "—"}</span>,
                      },
                      {
                        key: "state", head: t("State"), cell: (entry) => (
                          entry.enabled
                            ? <Pill tone="ok">{t("enabled")}</Pill>
                            : <Pill tone="neutral">{t("disabled")}</Pill>
                        ),
                      },
                      {
                        key: "actions", head: t("Actions"), actions: true, cell: (entry) => (
                          <>
                            <Guard action="schedule.run_now" host={host.id}>
                              <Button
                                kind="quiet"
                                disabled={entry.source !== "managed"}
                                title={entry.source === "managed"
                                  ? undefined
                                  : t("Only entries owned by Flotestro can be run from the panel.")}
                                onClick={() => setIntent({
                                  action: "schedule.run_now",
                                  label: t("Run now"),
                                  description: t("{command} will run immediately on {host}, outside its schedule.", {
                                    command: commandOf(entry), host: host.hostname,
                                  }),
                                  payload: entryOrder("schedule.run_now", entry.id).payload,
                                })}
                                testId={`run-${entry.id}`}
                              >
                                {t("Run now")}
                              </Button>
                            </Guard>
                            {/* Switching an entry off is reversible with one
                                click and erases nothing, so it is not stopped
                                by a confirmation of its own. */}
                            <Guard action="schedule.disable" host={host.id}>
                              <Button
                                kind="quiet"
                                disabled={entry.source !== "managed"}
                                onClick={() => request.mutate({
                                  action: "schedule.disable",
                                  payload: enableOrder(entry.id, !entry.enabled).payload,
                                })}
                              >
                                {entry.enabled ? t("Disable") : t("Enable")}
                              </Button>
                            </Guard>
                            <Guard action="schedule.remove" host={host.id}>
                              <Button
                                kind="danger"
                                disabled={entry.source !== "managed"}
                                onClick={() => setIntent({
                                  action: "schedule.remove",
                                  label: t("Remove"),
                                  description: t("{id} will be removed from {path}.", {
                                    id: entry.id, path: entry.path || t("the host"),
                                  }),
                                  payload: entryOrder("schedule.remove", entry.id).payload,
                                })}
                                testId={`remove-${entry.id}`}
                              >
                                {t("Remove")}
                              </Button>
                            </Guard>
                          </>
                        ),
                      },
                    ]}
                  />
                )}
            </Card>
          </C>
        </Grid>
      )}

      {tab === "new" && (
        <Grid>
          <C span={12}>
            {/* The tab is there for everybody, so a reader who may not write
                one is told why rather than being shown an empty page. */}
            <Guard action="schedule.ensure" host={host.id} explain>
              <NewEntry
                hostId={host.id}
                online={host.connection_state === "online"}
                kinds={scheduleKinds(host.capabilities)}
                entries={entries}
                busy={request.isPending}
                onRequest={(payload) => request.mutate({ action: "schedule.ensure", payload })}
              />
            </Guard>
          </C>
        </Grid>
      )}
    </>
  );
}

/**
 * The new entry.
 *
 * One expression and two mechanisms: the operator writes cron and the
 * host writes it as a cron entry or as the pair of units of a timer. The
 * next runs are computed on the host, never here - the browser knows
 * neither the host's zone nor its clock, and a preview in the wrong zone
 * shows the entry running at the wrong hour.
 */
function NewEntry({ hostId, online, kinds, entries, busy, onRequest }: {
  hostId: string;
  online: boolean;
  /** The mechanisms this host can carry an entry with, the first preferred. */
  kinds: string[];
  /** What the host already schedules: the names taken and the accounts used. */
  entries: Schedule[];
  busy: boolean;
  onRequest: (payload: Record<string, unknown>) => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [expression, setExpression] = useState("0 3 * * *");
  const [commandLine, setCommandLine] = useState("");
  const [user, setUser] = useState("root");
  const [comment, setComment] = useState("");
  const choices = kinds.length > 1 ? [...kinds, "any"] : kinds;
  const [kind, setKind] = useState(kinds[0] ?? "cron");
  const [previewError, setPreviewError] = useState("");
  // Adoption removes what the host runs under this name, so it is a
  // decision of its own and is not remembered past the name it was for.
  const [adopt, setAdopt] = useState(false);

  const args = commandLine.trim().split(/\s+/).filter(Boolean);
  const accounts = [...new Set(entries.map((entry) => entry.user).filter((name): name is string => Boolean(name)))].sort();
  // A name another entry of ours already carries is not a new entry:
  // ordering it rewrites that one.
  const taken = entries.some((entry) => entry.source === "managed" && entry.id === id.trim());
  // What the host administrator runs under this name; only a cron entry
  // takes such a line over, a timer is written beside it under its own name.
  const found = kind === "timer" ? [] : foundUnderName(entries, id.trim());
  // The host adopts a line by removing the file it is alone in, so a file
  // it shares with other entries it refuses - and so does the form.
  const shared = found.length > 1;
  const entryRequest = ensureOrder({
    id, expression, command: args, user, comment, kind,
    // The consent travels with the order: the host refuses to take over
    // anything it was not given for.
    adopt: found.length > 0 && adopt,
  });

  const preview = useMutation({
    mutationFn: async (spec: string) => {
      const job = await api.post<Job>(`/api/v1/hosts/${hostId}/operations`, {
        action: "schedule.preview",
        payload: { schedule: { expression: spec, kind, id, user, command: args } },
      });
      for (let attempt = 0; attempt < 20; attempt++) {
        await new Promise((done) => setTimeout(done, 1500));
        const attempts = await api.get<{ items: Attempt[] }>(`/api/v1/jobs/${job.id}/attempts`);
        const last = attempts.items[attempts.items.length - 1];
        if (!last?.status) continue;
        if (last.status !== "succeeded") {
          throw new Error(last.message || last.error_code || t("The host refused the read."));
        }
        return previewOf(last);
      }
      throw new Error(t("The host did not answer in time."));
    },
    onSuccess: () => setPreviewError(""),
    onError: (error) => setPreviewError(error instanceof Error ? error.message : String(error)),
  });
  // A preview of another expression than the one in the field is stale.
  const shown = preview.data && preview.data.expression === expression.trim() ? preview.data : undefined;

  return (
    <Form
      title={t("New schedule")}
      note={t("What runs, when, and under which account.")}
      actions={(
        <>
          <Guard action="schedule.preview" host={hostId} explain>
            <Button
              kind="quiet"
              onClick={() => preview.mutate(expression.trim())}
              disabled={!expression.trim() || preview.isPending || !online}
              testId="schedule-preview-ask"
            >
              {preview.isPending ? t("Asking the host…") : t("Preview next runs")}
            </Button>
          </Guard>
          <Button
            onClick={() => onRequest(entryRequest.payload)}
            // What the host already runs under this name is this screen's
            // own refusal: the registry sees the form, not the host.
            disabled={busy || !orderReady(entryRequest) || shared || (found.length > 0 && !adopt)}
            title={refusalOf(t, entryRequest)}
            testId="schedule-create"
          >
            {t("Create")}
          </Button>
          {!orderReady(entryRequest) && <Note>{refusalOf(t, entryRequest)}</Note>}
        </>
      )}
    >
      <Fields>
        <Field
          label={t("Name")}
          hint={taken ? t("An entry of this name is already on the host; ordering this one rewrites it.") : undefined}
        >
          <input
            placeholder={t("A name for this entry, its own on this host")}
            value={id}
            // The consent was given for one name; another name is another entry.
            onChange={(event) => { setId(event.target.value); setAdopt(false); }}
            data-testid="schedule-id"
          />
        </Field>
        <Field label={t("Cron expression")}>
          <input
            placeholder={t("Cron expression")}
            value={expression}
            onChange={(event) => setExpression(event.target.value)}
            data-testid="schedule-expression"
          />
        </Field>
        <Field
          label={t("Written as")}
          hint={t("A cron entry is one file in /etc/cron.d; a timer is a .timer and a .service unit under /etc/systemd/system. The expression is the same either way.")}
        >
          <select value={kind} onChange={(event) => setKind(event.target.value)} data-testid="schedule-kind">
            {choices.map((choice) => (
              <option key={choice} value={choice}>{kindLabel(choice, t)}</option>
            ))}
          </select>
        </Field>
        <Field
          label={t("Run as user")}
          hint={accounts.length > 1 ? t("The accounts this host already schedules work under are on the list.") : undefined}
        >
          <input
            placeholder={t("Run as user")}
            value={user}
            onChange={(event) => setUser(event.target.value)}
            list="next-schedule-user"
            data-testid="schedule-user"
          />
          <datalist id="next-schedule-user">
            {accounts.map((account) => <option key={account} value={account} />)}
          </datalist>
        </Field>
        <Field label={t("Command")} wide>
          <input
            placeholder={t("An absolute path, then one argument at a time")}
            value={commandLine}
            onChange={(event) => setCommandLine(event.target.value)}
            data-testid="schedule-command"
          />
        </Field>
        <Field label={t("Comment (optional)")} wide>
          <input value={comment} onChange={(event) => setComment(event.target.value)} data-testid="schedule-comment" />
        </Field>
      </Fields>

      {/* An entry of the host administrator under this name is taken over
          only on purpose, and the operator reads first what disappears. */}
      {found.length > 0 && (shared ? (
        <Banner tone="warn">
          {t("{path} carries {count} entries of the host administrator, this name among them. The host does not take over a file it shares: remove that line there by hand, or give this entry another name.", {
            path: found[0].path ?? "", count: found.length,
          })}
        </Banner>
      ) : (
        <>
          <Note>
            {t("{path} (line {line}) already runs under this name and belongs to the host administrator.", {
              path: found[0].path ?? "", line: found[0].line ?? 0,
            })}
          </Note>
          <Check checked={adopt} onChange={setAdopt}>
            {t("Take it over: the panel writes its own entry and removes that one. The host refuses the order if that file holds anything besides it.")}
          </Check>
        </>
      ))}

      {/* The arguments shown plainly: the operator is to see that the panel
          runs no shell and that quotes mean nothing here. */}
      {args.length > 0 && (
        <Readout
          label={t("Will run:")}
          value={args.map((argument, index) => `[${index}] ${argument}`).join("  ")}
          testId="schedule-args"
        />
      )}

      {previewError && <Problem>{previewError}</Problem>}
      {shown && (shown.error ? (
        <Problem>{t("The host does not accept the expression: {reason}", { reason: shown.error })}</Problem>
      ) : (
        <Readout
          label={t("Next runs in {zone}:", { zone: shown.timezone || t("the host zone") })}
          value={(shown.next_runs ?? []).map(hostClock).join("\n")}
          testId="schedule-preview"
        />
      ))}
      {/* The plan of a timer: what systemd is told, and the two files that
          would land on the host. Nothing is written until the operator asks
          for it, and they read it first. */}
      {shown?.calendar && <Note>{t("As a timer it runs on {calendar}.", { calendar: shown.calendar })}</Note>}
      {(shown?.units ?? []).map((unit) => (
        <Readout key={unit.path} label={unit.path} value={unit.content} lines={10} />
      ))}

    </Form>
  );
}

/** How long a reason has to be before the trail will take it. */
export const REASON_MIN_LENGTH = 8;

/** Running an entry out of turn, or taking it away, is asked for by name. */
function ConfirmEntry({ host, label, description, busy, onConfirm, onCancel }: {
  host: Host;
  label: string;
  description: string;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= REASON_MIN_LENGTH && confirmation === host.hostname;

  return (
    <Modal
      title={label}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button kind="danger" disabled={!ready || busy} onClick={() => onConfirm(reason.trim())} testId="entry-confirm">
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{description}</Note>
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="entry-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            data-testid="entry-hostname"
          />
        </Field>
      </Fields>
    </Modal>
  );
}
