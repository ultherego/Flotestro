import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Fact, Facts, Field, Fields, Foot, Form, FormActions, FormNote, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Schedule = {
  id: string;
  kind: string;
  source: string;
  enabled: boolean;
  expression: string;
  command?: string[];
  command_line?: string;
  user?: string;
  path?: string;
  line?: number;
  next_run?: string;
  // The coming runs, the first of them next_run again: three show the
  // rhythm of an entry the way a single date cannot.
  next_runs?: string[];
  timezone?: string;
  last_result?: string;
  comment?: string;
};

/** The answer of schedule.preview: the next runs computed on the host. */
type Preview = {
  expression?: string;
  timezone?: string;
  next_runs?: string[];
  error?: string;
};

type Attempt = { status?: string; error_code?: string; message?: string; stdout?: string };

type Snapshot = {
  schedules?: Schedule[];
  timezone?: string;
  unavailable_reason?: string;
};

/** An operation waiting for the target confirmation. */
type Intent = {
  action: string;
  label: string;
  description: string;
  payload: Record<string, unknown>;
};

/**
 * The host's recurring jobs.
 *
 * The panel tells its own entries from the pre-existing ones. A pre-existing
 * entry belongs to the host administrator; for the panel to manage it, it
 * has to be adopted explicitly - otherwise the first operation from the
 * panel would erase somebody else's work.
 */
export function Schedules() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "schedules");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState(false);

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
      setForm(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  const entries = snapshot?.schedules ?? [];
  const managed = entries.filter((entry) => entry.source === "managed").length;
  // An unread list is not an empty one: the counts are dashes until then.
  const known = snapshot && !snapshot.unavailable_reason ? entries : undefined;
  const kinds = Object.entries(entries.reduce<Record<string, number>>((acc, entry) => {
    acc[entry.kind] = (acc[entry.kind] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Schedules")}
        description={t("Cron entries and systemd timers under one list. Entries created here belong to Flotestro and live in their own files; entries found on the host stay untouched until you adopt them.")}
        actions={
          <button onClick={() => setForm((open) => !open)}>
            {form ? t("Cancel") : t("New schedule")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {/* No entries and no read are two different things: an empty list
          without an explanation would look like a host with no recurring
          jobs. */}
      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Schedules could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <Widgets>
      {/* The entries by state and owner: what runs, what is switched off,
          and how much of it is ours to change. */}
      <Summary
        title={t("Schedules")}
        description={t("Cron entries and timers, by whether they run and who owns them.")}
        span={8}
        segments={[
          { label: t("enabled"), value: countWhere(known, (entry) => entry.enabled), tone: "ok" },
          { label: t("disabled"), value: countWhere(known, (entry) => !entry.enabled), tone: "neutral" },
          { label: "Flotestro", value: known ? managed : undefined, tone: "info" },
          { label: t("host admin"), value: known ? known.length - managed : undefined, tone: "unknown" },
        ]}
      />
      <Section title={t("By kind")} span={4} flush>
        <Facts>
          <Fact label={t("Timezone")}>{snapshot?.timezone || "—"}</Fact>
          <Fact label={t("Kinds")} wide>
            {kinds.length ? <Breakdown items={kinds.map(([kind, count]) => ({ label: kind, value: count }))} /> : "—"}
          </Fact>
        </Facts>
      </Section>

      {form && (
        <NewEntry
          hostId={host.id}
          online={host.connection_state === "online"}
          onRequest={(payload) =>
            request.mutate({ action: "schedule.ensure", payload: { schedule: payload } })
          }
        />
      )}

      <Section title={t("Schedules")} count={module.data ? entries.length : undefined} span={12} flush>
        {!module.data ? (
          <Empty>{t("This host has not reported its schedules yet.")}</Empty>
        ) : !entries.length ? (
          <Empty>{t("No cron entries and no timers on this host.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Owner")}</th><th>{t("Schedule")}</th>
                <th>{t("Next run")}</th><th>{t("Command")}</th><th>{t("State")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={`${entry.path ?? ""}:${entry.line ?? 0}:${entry.id}`}>
                  <td className="hm-mono hm-primary">{entry.id}</td>
                  <td>{entry.kind}</td>
                  {/* The entry's ownership decides what the panel may do with it. */}
                  <td>
                    {entry.source === "managed" ? (
                      "Flotestro"
                    ) : (
                      <span className="badge unknown" title={entry.path}>
                        {t("host admin")}
                      </span>
                    )}
                  </td>
                  <td className="hm-mono">
                    {entry.expression || <span className="badge unknown">{t("event-based")}</span>}
                    {entry.timezone && <span className="source"> · {entry.timezone}</span>}
                  </td>
                  {/* The next run, and the two after it: the rhythm of the
                      entry is read from three dates, not from one. */}
                  <td>
                    {entry.next_run ? <Time value={entry.next_run} /> : "—"}
                    {(entry.next_runs ?? []).length > 1 && (
                      <span className="source" title={t("The following runs, in the host zone")}>
                        {" "}· {t("then")} {(entry.next_runs ?? []).slice(1).map((run) => hostClock(run)).join(", ")}
                      </span>
                    )}
                  </td>
                  {/* A pre-existing entry is a shell line, an owned one - an
                      argument list. We show what the host will really run. */}
                  <td className="hm-mono" title={command(entry)}>{command(entry).slice(0, 50)}</td>
                  <td>{entry.enabled ? <span className="badge ok">{t("enabled")}</span> : <span className="badge">{t("disabled")}</span>}</td>
                  <td>
                    <div className="operations">
                      <button
                        onClick={() =>
                          setIntent({
                            action: "schedule.run_now",
                            label: t("Run now"),
                            description: t("{command} will run immediately on {host}, outside its schedule.", { command: command(entry), host: host.hostname }),
                            payload: { schedule: { id: entry.id } },
                          })
                        }
                        disabled={entry.source !== "managed"}
                        title={
                          entry.source === "managed"
                            ? ""
                            : t("Only entries owned by Flotestro can be run from the panel.")
                        }
                      >
                        {t("Run now")}
                      </button>
                      {/* Enabling and disabling are reversible with one click
                          and do not erase the entry's content, so the operator
                          is not stopped by a separate confirmation. */}
                      <button
                        className="secondary"
                        onClick={() =>
                          request.mutate({
                            action: "schedule.disable",
                            payload: { schedule: { id: entry.id, enabled: !entry.enabled } },
                          })
                        }
                        disabled={entry.source !== "managed"}
                      >
                        {entry.enabled ? t("Disable") : t("Enable")}
                      </button>
                      <button
                        className="hm-danger"
                        onClick={() =>
                          setIntent({
                            action: "schedule.remove",
                            label: t("Remove"),
                            description: t("{id} will be removed from {path}.", { id: entry.id, path: entry.path || t("the host") }),
                            payload: { schedule: { id: entry.id } },
                          })
                        }
                        disabled={entry.source !== "managed"}
                      >
                        {t("Remove")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {snapshot && (
          <Foot>
            <span>
              {t("{managed} managed · {found} found on the host", {
                managed,
                found: entries.length - managed,
              })}
              {snapshot.timezone && ` · ${t("host timezone {zone}", { zone: snapshot.timezone })}`}
            </span>
          </Foot>
        )}
      </Section>
      </Widgets>

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ action: intent.action, reason, payload: intent.payload })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}

/**
 * The wall clock of a run as the host wrote it, not converted to the
 * browser's zone: "03:00" is what the entry says, and the operator compares
 * it with the expression, not with their own watch.
 */
function hostClock(value: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(value);
  return match ? `${match[1]} ${match[2]}` : value;
}

/** The entry's command in the form the host will run it. */
function command(entry: Schedule): string {
  return entry.command_line || (entry.command ?? []).join(" ");
}

/**
 * The new entry form. The command is an argument list, not a shell line: we
 * split it on whitespace and show the operator what really lands on the
 * host.
 */
function NewEntry({
  hostId, online, onRequest,
}: {
  hostId: string;
  online: boolean;
  onRequest: (payload: Record<string, unknown>) => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [expression, setExpression] = useState("0 3 * * *");
  const [commandLine, setCommandLine] = useState("");
  const [user, setUser] = useState("root");
  const [comment, setComment] = useState("");
  const [previewError, setPreviewError] = useState("");
  const args = commandLine.trim().split(/\s+/).filter(Boolean);

  // The next runs come from the host, not from the browser: the browser
  // knows neither the host's zone nor its clock, and a preview in the
  // wrong zone would show the entry running at the wrong hour.
  const preview = useMutation({
    mutationFn: async (spec: string) => {
      const job = await api.post<Job>(`/api/v1/hosts/${hostId}/operations`, {
        action: "schedule.preview",
        payload: { schedule: { expression: spec } },
      });
      for (let attempt = 0; attempt < 20; attempt++) {
        await new Promise((done) => setTimeout(done, 1500));
        const attempts = await api.get<{ items: Attempt[] }>(`/api/v1/jobs/${job.id}/attempts`);
        const last = attempts.items[attempts.items.length - 1];
        if (!last?.status) continue;
        if (last.status !== "succeeded") {
          throw new Error(last.message || last.error_code || t("The host refused the read."));
        }
        return JSON.parse(last.stdout ?? "{}") as Preview;
      }
      throw new Error(t("The host did not answer in time."));
    },
    onSuccess: () => setPreviewError(""),
    onError: (error) => setPreviewError(error instanceof Error ? error.message : String(error)),
  });
  // A preview of another expression than the one in the field is stale.
  const shown = preview.data && preview.data.expression === expression.trim() ? preview.data : undefined;

  return (
    <Section title={t("New schedule")} span={12}>
      <Form>
        <Fields>
          <Field label={t("Name")}>
            <input placeholder={t("Name, e.g. nightly-backup")} value={id} onChange={(e) => setId(e.target.value)} />
          </Field>
          <Field label={t("Cron expression")} narrow>
            <input placeholder={t("Cron expression")} value={expression} onChange={(e) => setExpression(e.target.value)} />
          </Field>
          <Field label={t("Run as user")} narrow>
            <input placeholder={t("Run as user")} value={user} onChange={(e) => setUser(e.target.value)} />
          </Field>
          <Field label={t("Command")} wide>
            <input
              placeholder={t("Command with an absolute path, e.g. /usr/bin/systemctl restart nginx")}
              value={commandLine}
              onChange={(e) => setCommandLine(e.target.value)}
            />
          </Field>
          <Field label={t("Comment (optional)")} wide>
            <input value={comment} onChange={(e) => setComment(e.target.value)} />
          </Field>
        </Fields>
        {/* The arguments shown plainly: the operator is to see that the panel
            runs no shell and that quotes mean nothing here. */}
        {args.length > 0 && (
          <FormNote>
            {t("Will run:")} <span className="hm-mono">{args.map((argument, i) => `[${i}] ${argument}`).join("  ")}</span>
          </FormNote>
        )}
        {previewError && <Message text={previewError} error />}
        {shown && (
          <FormNote>
            {shown.error
              ? t("The host does not accept the expression: {reason}", { reason: shown.error })
              : t("Next runs in {zone}:", { zone: shown.timezone || t("the host zone") })}{" "}
            {!shown.error && (
              <span className="hm-mono">{(shown.next_runs ?? []).map((run) => hostClock(run)).join(", ")}</span>
            )}
          </FormNote>
        )}
        <FormActions>
          <button
            className="secondary"
            onClick={() => preview.mutate(expression.trim())}
            disabled={!expression.trim() || preview.isPending || !online}
          >
            {preview.isPending ? t("Asking the host…") : t("Preview next runs")}
          </button>
          <button
            onClick={() =>
              onRequest({
                id,
                expression,
                command: args,
                user,
                comment,
                enabled: true,
              })
            }
            disabled={!id || !expression || args.length === 0}
          >
            {t("Create")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
