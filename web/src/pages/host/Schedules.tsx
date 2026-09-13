import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
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
  timezone?: string;
  last_result?: string;
  comment?: string;
};

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

  return (
    <>
      <p className="subtitle">
        {t("Cron entries and systemd timers under one list. Entries created here belong to Flotestro and live in their own files; entries found on the host stay untouched until you adopt them.")}
      </p>

      <div className="filters">
        <button onClick={() => setForm((open) => !open)}>
          {form ? t("Cancel") : t("New schedule")}
        </button>
      </div>

      {form && (
        <NewEntry
          onRequest={(payload) =>
            request.mutate({ action: "schedule.ensure", payload: { schedule: payload } })
          }
        />
      )}

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {/* No entries and no read are two different things: an empty list
          without an explanation would look like a host with no recurring
          jobs. */}
      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Schedules could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      {!module.data ? (
        <Empty>{t("This host has not reported its schedules yet.")}</Empty>
      ) : !entries.length ? (
        <Empty>{t("No cron entries and no timers on this host.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Owner")}</th><th>{t("Schedule")}</th>
              <th>{t("Next run")}</th><th>{t("Command")}</th><th>{t("State")}</th><th>{t("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={`${entry.path ?? ""}:${entry.line ?? 0}:${entry.id}`}>
                <td>{entry.id}</td>
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
                <td>
                  {entry.expression || <span className="badge unknown">{t("event-based")}</span>}
                  {entry.timezone && <span className="source"> · {entry.timezone}</span>}
                </td>
                <td>{entry.next_run ? <Time value={entry.next_run} /> : "—"}</td>
                {/* A pre-existing entry is a shell line, an owned one - an
                    argument list. We show what the host will really run. */}
                <td title={command(entry)}>{command(entry).slice(0, 50)}</td>
                <td>{entry.enabled ? t("enabled") : t("disabled")}</td>
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
                      className="secondary"
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
        </table>
      )}

      {snapshot && (
        <p className="source" style={{ marginTop: 12 }}>
          {t("{managed} managed · {found} found on the host", {
            managed: entries.filter((entry) => entry.source === "managed").length,
            found: entries.filter((entry) => entry.source !== "managed").length,
          })}
          {snapshot.timezone && ` · ${t("host timezone {zone}", { zone: snapshot.timezone })}`}
        </p>
      )}
      <ModuleFreshness fragment={module.data} />

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
    </>
  );
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
  onRequest,
}: {
  onRequest: (payload: Record<string, unknown>) => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [expression, setExpression] = useState("0 3 * * *");
  const [commandLine, setCommandLine] = useState("");
  const [user, setUser] = useState("root");
  const [comment, setComment] = useState("");
  const args = commandLine.trim().split(/\s+/).filter(Boolean);

  return (
    <div className="form" style={{ marginBottom: 16 }}>
      <div className="filters">
        <input placeholder={t("Name, e.g. nightly-backup")} value={id} onChange={(e) => setId(e.target.value)} />
        <input placeholder={t("Cron expression")} value={expression} onChange={(e) => setExpression(e.target.value)} />
        <input placeholder={t("Run as user")} value={user} onChange={(e) => setUser(e.target.value)} />
      </div>
      <div className="filters">
        <input
          placeholder={t("Command with an absolute path, e.g. /usr/bin/systemctl restart nginx")}
          value={commandLine}
          onChange={(e) => setCommandLine(e.target.value)}
          style={{ minWidth: 420 }}
        />
        <input placeholder={t("Comment (optional)")} value={comment} onChange={(e) => setComment(e.target.value)} />
      </div>
      {/* The arguments shown plainly: the operator is to see that the panel
          runs no shell and that quotes mean nothing here. */}
      {args.length > 0 && (
        <p className="source">
          {t("Will run:")} {args.map((argument, i) => `[${i}] ${argument}`).join("  ")}
        </p>
      )}
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
    </div>
  );
}
