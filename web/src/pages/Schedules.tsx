import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign } from "../lib/types";
import { ErrorBox, Empty, JobState, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { useConfirm } from "../components/Modal";
import { absoluteTime, toInstant } from "../lib/format";
import { useT } from "../i18n";

/**
 * Scheduled campaigns and the maintenance calendar.
 *
 * A schedule keeps a campaign order for a moment or for a rule of
 * moments; the panel places the order when the moment comes, through the
 * same door the Bulk workspace uses, and the campaign then waits for its
 * approval like any other. The calendar draws, month by month, what the
 * fleet has ahead: hosts in maintenance, campaign windows and the moments
 * the schedules will fire at - one picture, so a window nobody remembers
 * setting is seen before the change that collides with it is ordered.
 */

/** The schedule record as the API serves it. */
export type Schedule = {
  id: string;
  name: string;
  order: Record<string, unknown>;
  start_at?: string | null;
  recurrence?: string;
  timezone: string;
  next_run_at?: string | null;
  last_run_at?: string | null;
  last_campaign_id?: string;
  last_error?: string;
  created_by: string;
  enabled: boolean;
  reason: string;
  created_at: string;
  updated_at: string;
};

/** One entry of the calendar, whatever its source. */
export type CalendarEntry = {
  kind: "host_window" | "campaign_window" | "schedule";
  id: string;
  name: string;
  start?: string | null;
  end?: string | null;
  state?: string;
  reason?: string;
  set_by?: string;
};

/** The recurrence as the form holds it; freq "" means one moment. */
export type RecurrenceForm = {
  freq: "" | "MONTHLY" | "WEEKLY";
  monthDay: number;
  weekdays: string[];
  hour: number;
  minute: number;
};

/** The weekday codes of RRULE, Monday first as the calendar reads them. */
export const WEEKDAYS = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

export function emptyRecurrence(): RecurrenceForm {
  return { freq: "", monthDay: 1, weekdays: ["MO"], hour: 2, minute: 0 };
}

/**
 * The rule text the API reads, or an empty string for one moment. The
 * weekdays go in the calendar's order whatever order they were ticked
 * in, so the same rule always reads the same.
 */
export function recurrenceText(form: RecurrenceForm): string {
  if (!form.freq) return "";
  const at = `BYHOUR=${form.hour};BYMINUTE=${form.minute}`;
  if (form.freq === "MONTHLY") return `FREQ=MONTHLY;BYMONTHDAY=${form.monthDay};${at}`;
  const days = WEEKDAYS.filter((day) => form.weekdays.includes(day));
  return `FREQ=WEEKLY;BYDAY=${days.join(",")};${at}`;
}

/**
 * The form of a stored rule, or null when the text is not one the form
 * can hold - the server accepts the same subset, so a stored rule always
 * parses, and null only ever means an empty or foreign text.
 */
export function parseRecurrence(text: string | undefined): RecurrenceForm | null {
  if (!text) return null;
  const form = emptyRecurrence();
  const parts: Record<string, string> = {};
  for (const part of text.split(";")) {
    const [key, value] = part.split("=");
    if (key && value !== undefined) parts[key.trim().toUpperCase()] = value.trim().toUpperCase();
  }
  if (parts.FREQ !== "MONTHLY" && parts.FREQ !== "WEEKLY") return null;
  form.freq = parts.FREQ;
  if (parts.BYHOUR !== undefined) form.hour = Number(parts.BYHOUR);
  if (parts.BYMINUTE !== undefined) form.minute = Number(parts.BYMINUTE);
  if (form.freq === "MONTHLY") {
    const day = Number(parts.BYMONTHDAY);
    if (!Number.isInteger(day) || day < 1 || day > 31) return null;
    form.monthDay = day;
  } else {
    const days = (parts.BYDAY ?? "").split(",").map((day) => day.trim()).filter((day) => WEEKDAYS.includes(day));
    if (days.length === 0) return null;
    form.weekdays = WEEKDAYS.filter((day) => days.includes(day));
  }
  if (!Number.isInteger(form.hour) || form.hour < 0 || form.hour > 23) return null;
  if (!Number.isInteger(form.minute) || form.minute < 0 || form.minute > 59) return null;
  return form;
}

/** What is wrong with a recurrence form, or null when nothing is. */
export function recurrenceProblem(form: RecurrenceForm): "no_weekday" | "bad_day" | "bad_time" | null {
  if (!form.freq) return null;
  if (!Number.isInteger(form.hour) || form.hour < 0 || form.hour > 23) return "bad_time";
  if (!Number.isInteger(form.minute) || form.minute < 0 || form.minute > 59) return "bad_time";
  if (form.freq === "MONTHLY" && (!Number.isInteger(form.monthDay) || form.monthDay < 1 || form.monthDay > 31)) return "bad_day";
  if (form.freq === "WEEKLY" && !form.weekdays.some((day) => WEEKDAYS.includes(day))) return "no_weekday";
  return null;
}

const pad = (value: number) => String(value).padStart(2, "0");

/**
 * The rule in words: "monthly on day 15 at 02:30", "weekly on MO, TH at
 * 22:00", or "once" for a single moment. The weekday codes stay as the
 * rule writes them; a name per language would read the same list twice.
 */
export function describeRecurrence(t: (text: string, params?: Record<string, string | number>) => string, text: string | undefined): string {
  const form = parseRecurrence(text);
  if (!form) return t("once");
  const at = `${pad(form.hour)}:${pad(form.minute)}`;
  if (form.freq === "MONTHLY") return t("monthly on day {day} at {time}", { day: form.monthDay, time: at });
  return t("weekly on {days} at {time}", { days: form.weekdays.join(", "), time: at });
}

/**
 * The next moment of a schedule in words, read against the clock: how
 * far ahead it is and when exactly, "disabled" for a schedule that will
 * not fire, and "nothing more to place" for a single moment that has
 * passed. A moment the loop is late for reads as due, not as a time in
 * the past - the loop places it within seconds, and a negative distance
 * would read as a failure.
 */
export function nextRunWords(
  t: (text: string, params?: Record<string, string | number>) => string,
  schedule: Pick<Schedule, "enabled" | "next_run_at">,
  now: Date,
): string {
  if (!schedule.enabled) return t("disabled");
  if (!schedule.next_run_at) return t("nothing more to place");
  const at = new Date(schedule.next_run_at);
  const seconds = Math.floor((at.getTime() - now.getTime()) / 1000);
  const when = absoluteTime(schedule.next_run_at);
  if (seconds <= 0) return t("due now ({when})", { when });
  if (seconds < 3600) return t("in {n} min ({when})", { n: Math.max(1, Math.floor(seconds / 60)), when });
  if (seconds < 86400) return t("in {n} h ({when})", { n: Math.floor(seconds / 3600), when });
  return t("in {n} days ({when})", { n: Math.floor(seconds / 86400), when });
}

/**
 * The weeks of a month as rows of seven dates, Monday first, padded with
 * the neighbouring months' days so every row is full. The month is
 * zero-based as the Date API counts it.
 */
export function monthGrid(year: number, month: number): Date[][] {
  const first = new Date(year, month, 1);
  // Monday is column 0; JavaScript's Sunday is 0, so it moves to the end.
  const lead = (first.getDay() + 6) % 7;
  const start = new Date(year, month, 1 - lead);
  const weeks: Date[][] = [];
  const cursor = new Date(start);
  do {
    const week: Date[] = [];
    for (let i = 0; i < 7; i++) {
      week.push(new Date(cursor));
      cursor.setDate(cursor.getDate() + 1);
    }
    weeks.push(week);
  } while (cursor.getMonth() === month && cursor.getFullYear() === year);
  return weeks;
}

/** The key of a day in the browser's zone, for grouping the entries. */
export function dayKey(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/**
 * The entries of every day: a moment on its day, a window on every day it
 * covers, so a host in maintenance for a week is seen on each of the
 * seven. A window without a start is drawn from the range's first day;
 * one without an end, on its start day only.
 */
export function entriesByDay(entries: CalendarEntry[], from: Date, to: Date): Map<string, CalendarEntry[]> {
  const byDay = new Map<string, CalendarEntry[]>();
  const add = (date: Date, entry: CalendarEntry) => {
    const key = dayKey(date);
    const list = byDay.get(key) ?? [];
    list.push(entry);
    byDay.set(key, list);
  };
  for (const entry of entries) {
    const start = entry.start ? new Date(entry.start) : from;
    const end = entry.end ? new Date(entry.end) : start;
    const cursor = new Date(Math.max(start.getTime(), from.getTime()));
    cursor.setHours(0, 0, 0, 0);
    const last = new Date(Math.min(end.getTime(), to.getTime() - 1));
    if (cursor.getTime() > last.getTime()) {
      add(start, entry);
      continue;
    }
    while (cursor.getTime() <= last.getTime()) {
      add(cursor, entry);
      cursor.setDate(cursor.getDate() + 1);
    }
  }
  return byDay;
}

/** The browser's zone, the zone an operator writes the schedule's hours in. */
export function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** The form of a schedule as it is edited. */
export type ScheduleForm = {
  name: string;
  orderText: string;
  startAt: string;
  recurrence: RecurrenceForm;
  timezone: string;
  enabled: boolean;
  reason: string;
};

function emptyForm(): ScheduleForm {
  return {
    name: "",
    orderText: JSON.stringify({
      name: "", action: "unit.restart", payload: { unit: { unit: "" } },
      selector: { host_ids: [] }, canary_size: 1, wave_size: 10, max_concurrent: 5,
      failure_threshold_percent: 20, reboot_policy: "never",
    }, null, 2),
    startAt: "",
    recurrence: emptyRecurrence(),
    timezone: browserZone(),
    enabled: true,
    reason: "",
  };
}

/** The value a datetime-local input shows for an instant, in the browser's zone. */
function localInput(value?: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return `${dayKey(date)}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formOf(schedule: Schedule): ScheduleForm {
  return {
    name: schedule.name,
    orderText: JSON.stringify(schedule.order, null, 2),
    startAt: localInput(schedule.start_at),
    recurrence: parseRecurrence(schedule.recurrence) ?? emptyRecurrence(),
    timezone: schedule.timezone,
    enabled: schedule.enabled,
    reason: schedule.reason,
  };
}

/** The body the API takes, or a sentence about what stops it. */
export function scheduleBody(form: ScheduleForm): { body?: Record<string, unknown>; problem?: string } {
  let order: unknown;
  try {
    order = JSON.parse(form.orderText);
  } catch {
    return { problem: "order_json" };
  }
  if (!order || typeof order !== "object" || Array.isArray(order)) return { problem: "order_json" };
  if (form.name.trim() === "") return { problem: "name" };
  if (form.reason.trim().length < 8) return { problem: "reason" };
  const rule = recurrenceText(form.recurrence);
  const startAt = toInstant(form.startAt);
  if (form.startAt && !startAt) return { problem: "start" };
  if (!rule && !startAt) return { problem: "moment" };
  if (!rule && new Date(startAt).getTime() <= Date.now()) return { problem: "start_past" };
  if (recurrenceProblem(form.recurrence)) return { problem: "recurrence" };
  return {
    body: {
      name: form.name.trim(),
      order,
      start_at: startAt || undefined,
      recurrence: rule || undefined,
      timezone: form.timezone.trim() || "UTC",
      enabled: form.enabled,
      reason: form.reason.trim(),
    },
  };
}

function problemWords(t: (text: string, params?: Record<string, string | number>) => string, problem: string | undefined): string {
  switch (problem) {
    case "order_json": return t("the order is not a JSON object");
    case "name": return t("the schedule needs a name");
    case "reason": return t("the reason needs at least 8 characters");
    case "start": return t("the first run is not a valid date and time");
    case "moment": return t("give the schedule a first run or a recurrence");
    case "start_past": return t("a single run has to lie ahead");
    case "recurrence": return t("the recurrence is incomplete: a day, an hour and a minute");
  }
  return "";
}

export function Schedules() {
  const t = useT();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<ScheduleForm | null>(null);
  const [editingID, setEditingID] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [runOutcome, setRunOutcome] = useState<{ id: string; campaign: Campaign } | null>(null);
  const [month, setMonth] = useState(() => {
    const now = new Date();
    return { year: now.getFullYear(), month: now.getMonth() };
  });

  const schedules = useQuery({
    queryKey: ["campaign-schedules"],
    queryFn: () => api.get<Collection<Schedule>>("/api/v1/campaign-schedules"),
    refetchInterval: 15000,
  });
  const from = new Date(month.year, month.month, 1);
  const to = new Date(month.year, month.month + 1, 1);
  const calendar = useQuery({
    queryKey: ["maintenance-calendar", from.toISOString(), to.toISOString()],
    queryFn: () => api.get<Collection<CalendarEntry>>(
      `/api/v1/maintenance/calendar?from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`),
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["campaign-schedules"] });
    queryClient.invalidateQueries({ queryKey: ["maintenance-calendar"] });
  };
  const failed = (error: unknown) => setErrorMessage(error instanceof Error ? error.message : String(error));

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => editingID
      ? api.put<Schedule>(`/api/v1/campaign-schedules/${editingID}`, body)
      : api.post<Schedule>("/api/v1/campaign-schedules", body),
    onSuccess: () => { setEditing(null); setEditingID(""); setErrorMessage(""); refresh(); },
    onError: failed,
  });
  // Disabling and enabling rewrite the record with the flag flipped: the
  // API has one write, and the reason of the toggle goes on the record.
  const toggle = useMutation({
    mutationFn: ({ schedule, reason }: { schedule: Schedule; reason: string }) =>
      api.put<Schedule>(`/api/v1/campaign-schedules/${schedule.id}`, {
        name: schedule.name, order: schedule.order, start_at: schedule.start_at ?? undefined,
        recurrence: schedule.recurrence || undefined, timezone: schedule.timezone,
        enabled: !schedule.enabled, reason,
      }),
    onSuccess: refresh,
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del<void>(`/api/v1/campaign-schedules/${id}`, { reason }),
    onSuccess: refresh,
    onError: failed,
  });
  const runNow = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<Campaign>(`/api/v1/campaign-schedules/${id}/run-now`, { reason }),
    onSuccess: (campaign, { id }) => { setRunOutcome({ id, campaign }); refresh(); },
    onError: failed,
  });

  const askToggle = async (schedule: Schedule) => {
    const { ok, reason } = await confirm({
      title: schedule.enabled ? t("Disable the schedule {name}?", { name: schedule.name }) : t("Enable the schedule {name}?", { name: schedule.name }),
      body: <p>{schedule.enabled
        ? t("No order is placed until it is enabled again; the campaigns it already placed are not touched.")
        : t("The next moment is computed from now; a single run whose moment has passed places nothing.")}</p>,
      confirmLabel: schedule.enabled ? t("Disable") : t("Enable"),
      reason: { required: true },
    });
    if (ok && reason) toggle.mutate({ schedule, reason });
  };
  const askRemove = async (schedule: Schedule) => {
    const { ok, reason } = await confirm({
      title: t("Delete the schedule {name}?", { name: schedule.name }),
      body: <p>{t("The campaigns it placed stay; only the moments ahead are gone.")}</p>,
      confirmLabel: t("Delete"),
      danger: true,
      reason: { required: true },
    });
    if (ok && reason) remove.mutate({ id: schedule.id, reason });
  };
  const askRunNow = async (schedule: Schedule) => {
    const { ok, reason } = await confirm({
      title: t("Place the order of {name} now?", { name: schedule.name }),
      body: <p>{t("The campaign is created at once under the schedule's name and waits for its approval; the schedule's next moment stays where it is.")}</p>,
      confirmLabel: t("Run now"),
      reason: { required: true },
    });
    if (ok && reason) runNow.mutate({ id: schedule.id, reason });
  };

  if (schedules.error) return <ErrorBox error={schedules.error} />;
  const items = schedules.data?.items ?? [];
  const now = new Date();
  const check = editing ? scheduleBody(editing) : undefined;

  return (
    <>
      <PageHeader
        title={t("Scheduled campaigns")}
        description={t("A schedule places a campaign order at its moment; the campaign then waits for its approval like any other. The calendar shows what the fleet has ahead.")}
        breadcrumb={[{ label: t("Campaigns"), to: "/campaigns" }]}
        actions={
          <button onClick={() => { setEditing(emptyForm()); setEditingID(""); setErrorMessage(""); }} disabled={Boolean(editing)}>
            {t("New schedule")}
          </button>
        }
      />

      {errorMessage && <p className="page-error">{errorMessage}</p>}
      {runOutcome && (
        <p>
          {t("The order was placed:")}{" "}
          <Link to={`/campaigns/${runOutcome.campaign.id}`}>{runOutcome.campaign.name}</Link>
          {" "}<JobState state={runOutcome.campaign.state} />
        </p>
      )}

      {editing && (
        <Card
          title={editingID ? t("Edit the schedule") : t("New schedule")}
          description={t("The order is the body of a campaign as the Bulk workspace sends it. It is checked now for what can never be placed, and at every moment for everything else - the hosts, the rights, the window - with the refusal kept on the schedule.")}
        >
          <FieldGrid>
            <Field label={t("Name")}>
              <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
            </Field>
            <Field label={t("Timezone")} hint={t("The IANA zone the hours of the recurrence are read in; the first run is typed in the browser's zone.")}>
              <input value={editing.timezone} onChange={(e) => setEditing({ ...editing, timezone: e.target.value })} className="mono" />
            </Field>
            <Field label={t("First run")}
              hint={editing.recurrence.freq
                ? t("Optional with a recurrence: the earliest moment the rule may name.")
                : t("The one moment the order is placed at, in the browser's zone.")}>
              <input type="datetime-local" value={editing.startAt} onChange={(e) => setEditing({ ...editing, startAt: e.target.value })} />
            </Field>
            <RecurrenceFields value={editing.recurrence} onChange={(recurrence) => setEditing({ ...editing, recurrence })} />
            <Field label={t("Order (JSON)")} wide
              hint={t("What POST /api/v1/campaigns takes: name, action, payload, selector and the rollout policy. The reason below is carried into it when it names none.")}>
              <textarea rows={12} className="mono" spellCheck={false} value={editing.orderText}
                onChange={(e) => setEditing({ ...editing, orderText: e.target.value })} />
            </Field>
            <Field label={t("Reason or change reference")} wide
              hint={t("Kept in the audit trail with the schedule and shown to the approver of every campaign it places.")}>
              <input value={editing.reason} onChange={(e) => setEditing({ ...editing, reason: e.target.value })} />
            </Field>
            <div className="field">
              <label className="toggle">
                <input type="checkbox" checked={editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />{" "}
                {t("enabled")}
              </label>
            </div>
          </FieldGrid>
          <Actions>
            <button onClick={() => check?.body && save.mutate(check.body)} disabled={save.isPending || !check?.body}>
              {save.isPending ? t("Saving…") : editingID ? t("Save the schedule") : t("Create the schedule")}
            </button>
            <button className="secondary" onClick={() => { setEditing(null); setEditingID(""); }}>{t("Cancel")}</button>
            {check?.problem && <span className="source">{problemWords(t, check.problem)}</span>}
          </Actions>
        </Card>
      )}

      <div className="widgets">
        <Card className="span-12" title={t("Schedules")} flush
          description={t("The next to fire first. A schedule places orders under the rights of whoever last wrote it, read again at every moment.")}>
          {!schedules.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : items.length === 0 ? (
            <EmptyState action={<Link className="button primary" to="/bulk">{t("Schedule one from the Bulk workspace")}</Link>}>
              {t("No schedules.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Name")}</th><th>{t("Operation")}</th><th>{t("Rule")}</th><th>{t("Next run")}</th>
                  <th>{t("Last run")}</th><th>{t("Author")}</th><th>{t("Actions")}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((schedule) => (
                  <tr key={schedule.id}>
                    <td>
                      {schedule.name}
                      {!schedule.enabled && <> <span className="badge unknown">{t("disabled")}</span></>}
                    </td>
                    <td className="mono">{String(schedule.order.action ?? "")}</td>
                    <td>
                      {describeRecurrence(t, schedule.recurrence)}
                      {schedule.recurrence && <span className="source"> · {schedule.timezone}</span>}
                    </td>
                    <td>{nextRunWords(t, schedule, now)}</td>
                    <td>
                      {schedule.last_run_at ? <Time value={schedule.last_run_at} /> : "—"}
                      {schedule.last_campaign_id && (
                        <> · <Link to={`/campaigns/${schedule.last_campaign_id}`}>{t("campaign")}</Link></>
                      )}
                      {schedule.last_error && (
                        <span className="badge error" title={schedule.last_error}> {t("refused")}</span>
                      )}
                    </td>
                    <td>{schedule.created_by}</td>
                    <td>
                      <Toolbar>
                        <button className="secondary" onClick={() => askRunNow(schedule)} disabled={runNow.isPending}>{t("Run now")}</button>
                        <button className="secondary" onClick={() => { setEditing(formOf(schedule)); setEditingID(schedule.id); setErrorMessage(""); }}>{t("Edit")}</button>
                        <button className="secondary" onClick={() => askToggle(schedule)} disabled={toggle.isPending}>
                          {schedule.enabled ? t("Disable") : t("Enable")}
                        </button>
                        <button className="danger" onClick={() => askRemove(schedule)} disabled={remove.isPending}>{t("Delete")}</button>
                      </Toolbar>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card className="span-12" title={t("Maintenance calendar")}
          description={t("Hosts in maintenance, campaign windows and the moments of the schedules, in the browser's zone.")}
          actions={
            <Toolbar>
              <button className="secondary" onClick={() => setMonth(shiftMonth(month, -1))}>{t("Previous month")}</button>
              <span className="mono">{month.year}-{pad(month.month + 1)}</span>
              <button className="secondary" onClick={() => setMonth(shiftMonth(month, 1))}>{t("Next month")}</button>
            </Toolbar>
          }>
          {calendar.error ? (
            <ErrorBox error={calendar.error} />
          ) : (
            <MonthView year={month.year} month={month.month} entries={calendar.data?.items ?? []} loading={!calendar.data} />
          )}
        </Card>
      </div>
    </>
  );
}

function shiftMonth(current: { year: number; month: number }, by: number): { year: number; month: number } {
  const date = new Date(current.year, current.month + by, 1);
  return { year: date.getFullYear(), month: date.getMonth() };
}

/** The fields of a recurrence: none, monthly by day, weekly by weekdays. */
export function RecurrenceFields({ value, onChange }: { value: RecurrenceForm; onChange: (next: RecurrenceForm) => void }) {
  const t = useT();
  return (
    <>
      <Field label={t("Repeats")}>
        <select value={value.freq} onChange={(e) => onChange({ ...value, freq: e.target.value as RecurrenceForm["freq"] })}>
          <option value="">{t("does not repeat")}</option>
          <option value="MONTHLY">{t("monthly")}</option>
          <option value="WEEKLY">{t("weekly")}</option>
        </select>
      </Field>
      {value.freq === "MONTHLY" && (
        <Field label={t("Day of the month")} hint={t("A month without that day is skipped: the 31st names nothing in April.")}>
          <input type="number" min={1} max={31} value={value.monthDay} onChange={(e) => onChange({ ...value, monthDay: +e.target.value })} />
        </Field>
      )}
      {value.freq === "WEEKLY" && (
        <div className="field">
          <span className="field-label">{t("Weekdays")}</span>
          <Toolbar>
            {WEEKDAYS.map((day) => (
              <label key={day} className="toggle">
                <input type="checkbox" checked={value.weekdays.includes(day)}
                  onChange={(e) => onChange({
                    ...value,
                    weekdays: e.target.checked ? [...value.weekdays, day] : value.weekdays.filter((present) => present !== day),
                  })} />{" "}
                {day}
              </label>
            ))}
          </Toolbar>
        </div>
      )}
      {value.freq && (
        <Field label={t("At (hour and minute)")}>
          <Toolbar>
            <input type="number" min={0} max={23} value={value.hour} onChange={(e) => onChange({ ...value, hour: +e.target.value })} style={{ width: "5em" }} />
            <span>:</span>
            <input type="number" min={0} max={59} value={value.minute} onChange={(e) => onChange({ ...value, minute: +e.target.value })} style={{ width: "5em" }} />
          </Toolbar>
        </Field>
      )}
    </>
  );
}

/** The tone of an entry: a host window warns, a campaign window informs, a schedule is what is planned. */
function entryTone(entry: CalendarEntry): string {
  switch (entry.kind) {
    case "host_window": return "warn";
    case "campaign_window": return entry.state && ["failed", "canceled", "expired"].includes(entry.state) ? "unknown" : "";
    default: return "ok";
  }
}

/**
 * The month as a grid of seven columns, every day with its entries. No
 * library: the grid is a list of weeks, and a day cell is a list of
 * badges linking to what they name.
 */
function MonthView({ year, month, entries, loading }: { year: number; month: number; entries: CalendarEntry[]; loading: boolean }) {
  const t = useT();
  const weeks = monthGrid(year, month);
  const from = new Date(year, month, 1);
  const to = new Date(year, month + 1, 1);
  const byDay = entriesByDay(entries, from, to);
  const today = dayKey(new Date());
  const labels = [t("Mon"), t("Tue"), t("Wed"), t("Thu"), t("Fri"), t("Sat"), t("Sun")];
  const time = (value?: string | null) => value ? absoluteTime(value).slice(11, 16) : "";
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(7, minmax(0, 1fr))", gap: 4 }}>
      {labels.map((label) => <div key={label} className="source" style={{ textAlign: "center" }}>{label}</div>)}
      {weeks.flat().map((date) => {
        const key = dayKey(date);
        const inMonth = date.getMonth() === month;
        const list = byDay.get(key) ?? [];
        return (
          <div key={key} style={{
            minHeight: 84, padding: 6, border: "1px solid var(--border)", borderRadius: 6,
            opacity: inMonth ? 1 : 0.45, background: key === today ? "color-mix(in srgb, var(--text) 6%, transparent)" : undefined,
          }}>
            <div className="source" style={{ marginBottom: 4 }}>{date.getDate()}</div>
            {loading && inMonth && list.length === 0 && <span className="source">…</span>}
            {list.map((entry, index) => (
              <div key={`${entry.kind}-${entry.id}-${index}`} style={{ marginBottom: 2, fontSize: 11, lineHeight: "16px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                title={entryTitle(t, entry)}>
                <span className={`badge ${entryTone(entry)}`}>{kindWord(t, entry.kind)}</span>{" "}
                {entry.kind === "campaign_window"
                  ? <Link to={`/campaigns/${entry.id}`}>{entry.name}</Link>
                  : entry.kind === "host_window"
                    ? <Link to={`/hosts/${entry.id}`}>{entry.name}</Link>
                    : <span>{time(entry.start)} {entry.name}</span>}
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

function kindWord(t: (text: string) => string, kind: CalendarEntry["kind"]): string {
  switch (kind) {
    case "host_window": return t("maintenance");
    case "campaign_window": return t("window");
    default: return t("schedule");
  }
}

function entryTitle(t: (text: string, params?: Record<string, string | number>) => string, entry: CalendarEntry): string {
  const span = [entry.start ? absoluteTime(entry.start) : "", entry.end ? absoluteTime(entry.end) : ""].filter(Boolean).join(" → ");
  switch (entry.kind) {
    case "host_window":
      return t("{name} in maintenance {span}: {reason} (set by {by})", { name: entry.name, span, reason: entry.reason ?? "", by: entry.set_by ?? "" });
    case "campaign_window":
      return t("campaign {name} ({state}), window {span}", { name: entry.name, state: entry.state ?? "", span });
    default:
      return t("schedule {name} places its order at {span}", { name: entry.name, span });
  }
}
