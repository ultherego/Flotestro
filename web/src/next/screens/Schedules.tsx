import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import { absoluteTime, relativeTime, toInstant } from "../../lib/format";
import type { Campaign } from "../../lib/types";
import { stateName } from "../../lib/states";
import {
  browserZone, describeRecurrence, emptyRecurrence, parseRecurrence, recurrenceProblem,
  recurrenceText, WEEKDAYS, type RecurrenceForm,
} from "../../lib/recurrence";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Banner, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Form, Kpi, Kpis,
  Modal, Note, Pill, Presets, Problem, Row, Stack, Table, Toolbar, TwoLine, type Tone,
} from "../kit";
import { campaignTone } from "./Campaigns";

/**
 * The campaigns that run on a clock.
 *
 * A schedule is an order kept until its moment: at that moment the panel
 * places the campaign and it waits for its approval like any other. So
 * the one thing the screen has to say about each is what it is waiting
 * for - a moment ahead, a switch somebody turned off, or a refusal the
 * last moment came back with - and that is the column nothing else may
 * push off the row.
 *
 * Every write here is recorded: running one early, turning one off and
 * deleting one all ask first and all carry a reason, because the next
 * person to read the trail is the one who has to explain the gap.
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

/* The recurrence of a schedule lives in lib/recurrence: the bulk wizard
   keeps one beside an order, and a rule written on one screen is the rule
   the other reads back. Re-exported under the names this screen uses. */
export {
  describeRecurrence, emptyRecurrence, parseRecurrence, recurrenceProblem, recurrenceText,
  WEEKDAYS, type RecurrenceForm,
};

/** Two digits, for the clock and the calendar. */
const pad = (value: number) => String(value).padStart(2, "0");

/** How short a reason the audit trail will take. */
export const SCHEDULE_REASON_MIN_LENGTH = 8;

/**
 * The next moment of a schedule in words, read against the clock: how far
 * ahead it is and when exactly, "disabled" for a schedule that will not
 * fire, and "nothing more to place" for a single moment that has passed.
 */
export function nextRunWords(
  t: Translate,
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
 * How a schedule's next moment reads as a state: a schedule that was
 * refused the last time it fired is a fault whatever its clock says, and
 * one nobody has switched on is not waiting for anything.
 */
export function scheduleTone(schedule: Pick<Schedule, "enabled" | "next_run_at" | "last_error">): Tone {
  if (schedule.last_error) return "error";
  if (!schedule.enabled) return "unknown";
  return schedule.next_run_at ? "ok" : "warn";
}

/**
 * The weeks of a month as rows of seven dates, Monday first, padded with the
 * neighbouring months' days so every row is full.
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
 * covers, so a host in maintenance for a week is seen on each of the seven.
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

export { browserZone };

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

export function emptyForm(): ScheduleForm {
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

export function formOf(schedule: Schedule): ScheduleForm {
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
  if (form.reason.trim().length < SCHEDULE_REASON_MIN_LENGTH) return { problem: "reason" };
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

export function problemWords(t: Translate, problem: string | undefined): string {
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

function shiftMonth(current: { year: number; month: number }, by: number): { year: number; month: number } {
  const date = new Date(current.year, current.month + by, 1);
  return { year: date.getFullYear(), month: date.getMonth() };
}

/** The tone of an entry: a host window warns, a campaign window informs, a schedule is what is planned. */
export function entryTone(entry: CalendarEntry): Tone {
  switch (entry.kind) {
    case "host_window": return "warn";
    case "campaign_window":
      return entry.state && ["failed", "canceled", "expired"].includes(entry.state) ? "unknown" : "info";
    default: return "ok";
  }
}

export function kindWord(t: Translate, kind: CalendarEntry["kind"]): string {
  switch (kind) {
    case "host_window": return t("maintenance");
    case "campaign_window": return t("window");
    default: return t("schedule");
  }
}

export function entryTitle(t: Translate, entry: CalendarEntry): string {
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

/** Whether the entry's start falls on the day drawn, in the browser's zone. */
export function startsOn(entry: CalendarEntry, day: string): boolean {
  return Boolean(entry.start) && dayKey(new Date(entry.start as string)) === day;
}

/** Where an entry of the calendar leads inside the new panel. */
export function entryLink(entry: CalendarEntry): string | undefined {
  if (entry.kind === "campaign_window") return `/campaigns/${entry.id}`;
  if (entry.kind === "host_window") return `/hosts/${entry.id}`;
  return undefined;
}

/**
 * One day of the month with one entry on it: the calendar flattened into
 * rows, because the kit draws one table for the whole panel and a month
 * of seven columns is not one of its pieces.
 */
export type CalendarRow = { day: string; date: Date; entry: CalendarEntry; index: number };

/**
 * Every day of the month that has something on it, in order, with its
 * entries under it. A day nobody planned anything on is not a row: an
 * empty row says the same as no row and costs thirty of them.
 */
export function calendarRows(entries: CalendarEntry[], year: number, month: number): CalendarRow[] {
  const from = new Date(year, month, 1);
  const to = new Date(year, month + 1, 1);
  const byDay = entriesByDay(entries, from, to);
  const out: CalendarRow[] = [];
  for (const date of monthGrid(year, month).flat()) {
    if (date.getMonth() !== month) continue;
    const day = dayKey(date);
    const list = byDay.get(day);
    if (!list) continue;
    list.forEach((entry, index) => out.push({ day, date, entry, index }));
  }
  return out;
}

/** One square of the month: the date, whether it belongs to it, and what stands on it. */
export type CalendarDay = { date: Date; day: string; inMonth: boolean; entries: CalendarEntry[] };

/**
 * The month as weeks of seven days, Monday first, every day carrying what
 * stands on it.
 *
 * The days of the neighbouring months are drawn to fill the week out and
 * carry nothing: the server was asked about this month, so an entry on
 * one of them would be an entry nobody asked about.
 */
export function monthDays(entries: CalendarEntry[], year: number, month: number): CalendarDay[][] {
  const from = new Date(year, month, 1);
  const to = new Date(year, month + 1, 1);
  const byDay = entriesByDay(entries, from, to);
  return monthGrid(year, month).map((week) => week.map((date) => {
    const day = dayKey(date);
    const inMonth = date.getMonth() === month && date.getFullYear() === year;
    return { date, day, inMonth, entries: inMonth ? byDay.get(day) ?? [] : [] };
  }));
}

/** What a destructive answer is being asked about. */
type Ask =
  | { what: "toggle"; schedule: Schedule }
  | { what: "delete"; schedule: Schedule }
  | { what: "run"; schedule: Schedule };

export function Schedules() {
  const t = useT();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<ScheduleForm | null>(null);
  const [editingID, setEditingID] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [runOutcome, setRunOutcome] = useState<{ id: string; campaign: Campaign } | null>(null);
  const [ask, setAsk] = useState<Ask | null>(null);
  const [reason, setReason] = useState("");
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
    void queryClient.invalidateQueries({ queryKey: ["campaign-schedules"] });
    void queryClient.invalidateQueries({ queryKey: ["maintenance-calendar"] });
  };
  const failed = (error: unknown) => setErrorMessage(error instanceof Error ? error.message : String(error));
  const close = () => { setAsk(null); setReason(""); };

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
    mutationFn: ({ schedule, why }: { schedule: Schedule; why: string }) =>
      api.put<Schedule>(`/api/v1/campaign-schedules/${schedule.id}`, {
        name: schedule.name, order: schedule.order, start_at: schedule.start_at ?? undefined,
        recurrence: schedule.recurrence || undefined, timezone: schedule.timezone,
        enabled: !schedule.enabled, reason: why,
      }),
    onSuccess: () => { close(); refresh(); },
    onError: (error) => { close(); failed(error); },
  });
  const remove = useMutation({
    mutationFn: ({ id, why }: { id: string; why: string }) =>
      api.del<void>(`/api/v1/campaign-schedules/${id}`, { reason: why }),
    onSuccess: () => { close(); refresh(); },
    onError: (error) => { close(); failed(error); },
  });
  const runNow = useMutation({
    mutationFn: ({ id, why }: { id: string; why: string }) =>
      api.post<Campaign>(`/api/v1/campaign-schedules/${id}/run-now`, { reason: why }),
    onSuccess: (campaign, { id }) => { setRunOutcome({ id, campaign }); close(); refresh(); },
    onError: (error) => { close(); failed(error); },
  });

  const working = toggle.isPending || remove.isPending || runNow.isPending;
  const reasonGiven = reason.trim().length >= SCHEDULE_REASON_MIN_LENGTH;
  const answer = () => {
    if (!ask || !reasonGiven) return;
    const why = reason.trim();
    if (ask.what === "toggle") toggle.mutate({ schedule: ask.schedule, why });
    if (ask.what === "delete") remove.mutate({ id: ask.schedule.id, why });
    if (ask.what === "run") runNow.mutate({ id: ask.schedule.id, why });
  };

  if (schedules.error) return <Problem>{String(schedules.error)}</Problem>;

  // A list still in flight is not a list of none: every count stays
  // unknown until the answer lands, and the tiles draw an em dash.
  const items = schedules.data?.items;
  const now = new Date();
  const soon = now.getTime() + 24 * 3600 * 1000;
  const waiting = items?.filter((one) => one.enabled && !!one.next_run_at).length;
  const dueSoon = items?.filter(
    (one) => one.enabled && one.next_run_at && new Date(one.next_run_at).getTime() <= soon,
  ).length;
  const refused = items?.filter((one) => !!one.last_error).length;
  const check = editing ? scheduleBody(editing) : undefined;
  const rows = items ?? [];
  const entries = calendar.data?.items;

  const edit = (schedule?: Schedule) => {
    setEditing(schedule ? formOf(schedule) : emptyForm());
    setEditingID(schedule?.id ?? "");
    setErrorMessage("");
  };

  return (
    <>
      {errorMessage && <Problem>{errorMessage}</Problem>}
      {runOutcome && (
        <Banner tone="ok">
          {t("The order was placed:")}{" "}
          <Link to={`/campaigns/${runOutcome.campaign.id}`}>{runOutcome.campaign.name}</Link>{" "}
          <Pill tone={campaignTone(runOutcome.campaign.state)}>{t(stateName(runOutcome.campaign.state))}</Pill>
        </Banner>
      )}

      {editing && (
      <Form
        title={editingID ? t("Edit the schedule") : t("New schedule")}
        note={t("The order is the body of a campaign as the Bulk workspace sends it. It is checked now for what can never be placed, and at every moment for everything else - the hosts, the rights, the window - with the refusal kept on the schedule.")}
        actions={
          <Actions>
            <Button
              onClick={() => { if (check?.body) save.mutate(check.body); }}
              disabled={save.isPending || !check?.body}
              testId="schedule-save"
            >
              {save.isPending ? t("Saving…") : editingID ? t("Save the schedule") : t("Create the schedule")}
            </Button>
            <Button kind="quiet" onClick={() => { setEditing(null); setEditingID(""); }} testId="schedule-cancel">
              {t("Cancel")}
            </Button>
            {check?.problem && <Note>{problemWords(t, check.problem)}</Note>}
          </Actions>
        }
      >
        <Stack>
          <Fields>
            <Field label={t("Name")}>
              <input
                value={editing.name}
                onChange={(event) => setEditing({ ...editing, name: event.target.value })}
                data-testid="schedule-name"
              />
            </Field>
            <Field
              label={t("Timezone")}
              hint={t("The IANA zone the hours of the recurrence are read in; the first run is typed in the browser's zone.")}
            >
              <input
                className="fl-mono"
                value={editing.timezone}
                onChange={(event) => setEditing({ ...editing, timezone: event.target.value })}
                data-testid="schedule-timezone"
              />
            </Field>
            <Field
              label={t("First run")}
              hint={editing.recurrence.freq
                ? t("Optional with a recurrence: the earliest moment the rule may name.")
                : t("The one moment the order is placed at, in the browser's zone.")}
            >
              <input
                type="datetime-local"
                value={editing.startAt}
                onChange={(event) => setEditing({ ...editing, startAt: event.target.value })}
                data-testid="schedule-start"
              />
            </Field>
            <Field label={t("Repeats")}>
              <select
                value={editing.recurrence.freq}
                onChange={(event) => setEditing({
                  ...editing,
                  recurrence: { ...editing.recurrence, freq: event.target.value as RecurrenceForm["freq"] },
                })}
                data-testid="schedule-freq"
              >
                <option value="">{t("does not repeat")}</option>
                <option value="MONTHLY">{t("monthly")}</option>
                <option value="WEEKLY">{t("weekly")}</option>
              </select>
            </Field>
            {editing.recurrence.freq === "MONTHLY" && (
              <Field
                label={t("Day of the month")}
                hint={t("A month without that day is skipped: the 31st names nothing in April.")}
              >
                <input
                  type="number"
                  min={1}
                  max={31}
                  value={editing.recurrence.monthDay}
                  onChange={(event) => setEditing({
                    ...editing,
                    recurrence: { ...editing.recurrence, monthDay: Number(event.target.value) },
                  })}
                  data-testid="schedule-monthday"
                />
              </Field>
            )}
            {editing.recurrence.freq && (
              <>
                <Field label={t("Hour")}>
                  <input
                    type="number"
                    min={0}
                    max={23}
                    value={editing.recurrence.hour}
                    onChange={(event) => setEditing({
                      ...editing,
                      recurrence: { ...editing.recurrence, hour: Number(event.target.value) },
                    })}
                    data-testid="schedule-hour"
                  />
                </Field>
                <Field label={t("Minute")}>
                  <input
                    type="number"
                    min={0}
                    max={59}
                    value={editing.recurrence.minute}
                    onChange={(event) => setEditing({
                      ...editing,
                      recurrence: { ...editing.recurrence, minute: Number(event.target.value) },
                    })}
                    data-testid="schedule-minute"
                  />
                </Field>
              </>
            )}
          </Fields>

          {/* The weekdays are a set and not a choice of one, so they are
              seven switches rather than a Seg. Each carries its own
              label; a label inside a Field's label would name the field
              twice and neither of them well. */}
          {editing.recurrence.freq === "WEEKLY" && (
            <Stack>
              <Note>{t("Weekdays")}</Note>
              <Row>
                {WEEKDAYS.map((day) => (
                  <Check
                    key={day}
                    checked={editing.recurrence.weekdays.includes(day)}
                    onChange={(on) => setEditing({
                      ...editing,
                      recurrence: {
                        ...editing.recurrence,
                        weekdays: on
                          ? [...editing.recurrence.weekdays, day]
                          : editing.recurrence.weekdays.filter((present) => present !== day),
                      },
                    })}
                  >
                    {day}
                  </Check>
                ))}
              </Row>
            </Stack>
          )}

          <Fields>
            <Field
              label={t("Order (JSON)")}
              wide
              hint={t("What POST /api/v1/campaigns takes: name, action, payload, selector and the rollout policy. The reason below is carried into it when it names none.")}
            >
              <textarea
                rows={12}
                className="fl-mono"
                spellCheck={false}
                value={editing.orderText}
                onChange={(event) => setEditing({ ...editing, orderText: event.target.value })}
                data-testid="schedule-order"
              />
            </Field>
            <Field
              label={t("Reason or change reference")}
              wide
              hint={t("Kept in the audit trail with the schedule and shown to the approver of every campaign it places.")}
            >
              <input
                value={editing.reason}
                onChange={(event) => setEditing({ ...editing, reason: event.target.value })}
                data-testid="schedule-reason"
              />
            </Field>
          </Fields>

          <Check
            checked={editing.enabled}
            onChange={(on) => setEditing({ ...editing, enabled: on })}
          >
            {t("enabled")}
          </Check>
        </Stack>
      </Form>
      )}

      <Board screen={SCHEDULES_SCREEN} catalogue={SCHEDULES} drawn={{
        counts: (
          <Kpis>
            <Kpi
              label={t("Schedules")}
              value={items?.length}
              icon="schedules"
              hero
              testId="kpi-schedules"
              note={t("campaigns that run on a clock")}
            />
            <Kpi
              label={t("Waiting on a moment")}
              value={waiting}
              tone="ok"
              testId="kpi-waiting"
            />
            <Kpi
              label={t("Due within a day")}
              value={dueSoon}
              tone={dueSoon ? "warn" : "neutral"}
              testId="kpi-due"
            />
            <Kpi
              label={t("Refused last time")}
              value={refused}
              tone={refused ? "error" : "ok"}
              testId="kpi-refused"
              note={t("the moment came and the order was turned down")}
            />
          </Kpis>
        ),

        schedules: (
          <Card
            title={t("Schedules")}
            flush
            note={t("The next to fire first. A schedule places orders under the rights of whoever last wrote it, read again at every moment.")}
          >
            <Toolbar
              end={
                <Button onClick={() => edit()} disabled={Boolean(editing)} testId="schedule-new">
                  {t("New schedule")}
                </Button>
              }
            />
            {items !== undefined && rows.length === 0 ? (
              <Empty
                icon="schedules"
                action={<Link to="/bulk">{t("Schedule one from the Bulk workspace")}</Link>}
              >
                {t("No campaign runs on a clock here yet.")}
              </Empty>
            ) : (
            <Table
              rows={rows}
              keyOf={(one) => one.id}
              rowTestId={(one) => `schedule-${one.name}`}
              loading={items === undefined}
              testId="schedules"
              columns={[
                {
                  key: "name",
                  head: t("Name"),
                  cell: (one) => (
                    <>
                      {one.name}
                      {!one.enabled && <> <Pill tone="unknown">{t("disabled")}</Pill></>}
                    </>
                  ),
                },
                {
                  key: "action",
                  head: t("Operation"),
                  tight: true,
                  cell: (one) => <code>{String(one.order.action ?? "")}</code>,
                },
                {
                  key: "rule",
                  head: t("Rule"),
                  cell: (one) => (
                    <>
                      {describeRecurrence(t, one.recurrence)}
                      {one.recurrence && <span className="fl-note"> · {one.timezone}</span>}
                    </>
                  ),
                },
                {
                  key: "next",
                  head: t("Waiting for"),
                  cell: (one) => (
                    <Pill tone={scheduleTone(one)}>{nextRunWords(t, one, now)}</Pill>
                  ),
                },
                {
                  key: "last",
                  head: t("Last run"),
                  minor: true,
                  cell: (one) => (
                    <>
                      {one.last_run_at
                        ? <span title={absoluteTime(one.last_run_at)}>{relativeTime(one.last_run_at)}</span>
                        : <span className="fl-faint">—</span>}
                      {one.last_campaign_id && (
                        <> · <Link to={`/campaigns/${one.last_campaign_id}`}>{t("campaign")}</Link></>
                      )}
                      {one.last_error && (
                        <> <Pill tone="error" title={one.last_error}>{t("refused")}</Pill></>
                      )}
                    </>
                  ),
                },
                { key: "by", head: t("Author"), minor: true, tight: true, cell: (one) => one.created_by },
                {
                  key: "do",
                  head: t("Actions"),
                  actions: true,
                  cell: (one) => (
                    <Row>
                      <Button
                        kind="quiet"
                        onClick={() => { setReason(""); setAsk({ what: "run", schedule: one }); }}
                        disabled={working}
                        testId={`run-${one.name}`}
                      >
                        {t("Run now")}
                      </Button>
                      <Button kind="quiet" onClick={() => edit(one)} testId={`edit-${one.name}`}>
                        {t("Edit")}
                      </Button>
                      <Button
                        kind="quiet"
                        onClick={() => { setReason(""); setAsk({ what: "toggle", schedule: one }); }}
                        disabled={working}
                        testId={`toggle-${one.name}`}
                      >
                        {one.enabled ? t("Disable") : t("Enable")}
                      </Button>
                      <Button
                        kind="danger"
                        onClick={() => { setReason(""); setAsk({ what: "delete", schedule: one }); }}
                        disabled={working}
                        testId={`delete-${one.name}`}
                      >
                        {t("Delete")}
                      </Button>
                    </Row>
                  ),
                },
              ]}
            />
            )}
          </Card>
        ),

        calendar: (
          <Card
            title={t("Maintenance calendar")}
            flush
            note={t("Hosts in maintenance, campaign windows and the moments of the schedules, in the browser's zone.")}
            foot={entries !== undefined && calendarRows(entries, month.year, month.month).length === 0
              ? t("Nothing is planned in this month.")
              : undefined}
          >
            <Toolbar
              end={
                <Presets
                  label={t("Which month")}
                  options={[
                    { label: t("Previous month"), onPick: () => setMonth(shiftMonth(month, -1)) },
                    { label: t("This month"), onPick: () => setMonth({ year: now.getFullYear(), month: now.getMonth() }) },
                    { label: t("Next month"), onPick: () => setMonth(shiftMonth(month, 1)) },
                  ]}
                />
              }
            >
              <span className="fl-mono" data-testid="calendar-month">{`${month.year}-${pad(month.month + 1)}`}</span>
            </Toolbar>
            {calendar.error ? (
              <Problem>{String(calendar.error)}</Problem>
            ) : (
              <MonthView year={month.year} month={month.month} entries={entries} />
            )}
          </Card>
        ),
      }} />

      {/* Running one early, turning one off and deleting one all change what
          the fleet does without anybody watching, so each is asked first and
          each carries the reason the trail keeps. */}
      {ask && (
        <Modal
          title={
            ask.what === "delete"
              ? t("Delete the schedule {name}?", { name: ask.schedule.name })
              : ask.what === "run"
                ? t("Place the order of {name} now?", { name: ask.schedule.name })
                : ask.schedule.enabled
                  ? t("Disable the schedule {name}?", { name: ask.schedule.name })
                  : t("Enable the schedule {name}?", { name: ask.schedule.name })
          }
          onClose={close}
          actions={
            <>
              <Button kind="quiet" onClick={close} disabled={working} testId="ask-cancel">{t("Cancel")}</Button>
              <Button
                kind={ask.what === "delete" ? "danger" : "do"}
                onClick={answer}
                disabled={!reasonGiven || working}
                testId="ask-confirm"
              >
                {ask.what === "delete"
                  ? t("Delete")
                  : ask.what === "run"
                    ? t("Run now")
                    : ask.schedule.enabled ? t("Disable") : t("Enable")}
              </Button>
            </>
          }
        >
          <Stack>
            <Note>
              {ask.what === "delete"
                ? t("The campaigns it placed stay; only the moments ahead are gone.")
                : ask.what === "run"
                  ? t("The campaign is created at once under the schedule's name and waits for its approval; the schedule's next moment stays where it is.")
                  : ask.schedule.enabled
                    ? t("No order is placed until it is enabled again; the campaigns it already placed are not touched.")
                    : t("The next moment is computed from now; a single run whose moment has passed places nothing.")}
            </Note>
            <Facts>
              <Fact label={t("Operation")} mono>{String(ask.schedule.order.action ?? "")}</Fact>
              <Fact label={t("Rule")}>{describeRecurrence(t, ask.schedule.recurrence)}</Fact>
              <Fact label={t("Waiting for")}>{nextRunWords(t, ask.schedule, now)}</Fact>
            </Facts>
            <Fields>
              <Field
                label={t("Reason (kept in the audit trail)")}
                wide
                hint={t("At least {n} characters.", { n: SCHEDULE_REASON_MIN_LENGTH })}
              >
                <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="ask-reason" />
              </Field>
            </Fields>
          </Stack>
        </Modal>
      )}
    </>
  );
}

/**
 * The month, read across: seven columns of weekdays and a row per week.
 *
 * A list of days is not a month - the owner reads this one the way a
 * calendar is read, and the shape of the month is half of what it says.
 * It is still only kit pieces: the panel's one `Table`, seven columns
 * wide, with a day of the month in each cell. Nothing here writes a
 * grid, a width or a colour of its own.
 */
function MonthView({ year, month, entries }: { year: number; month: number; entries?: CalendarEntry[] }) {
  const t = useT();
  const today = dayKey(new Date());
  const names = [t("Mon"), t("Tue"), t("Wed"), t("Thu"), t("Fri"), t("Sat"), t("Sun")];
  // The month has not arrived: the shape of it, not the word "Loading…",
  // and not a month of empty squares that reads as a month with nothing on.
  if (entries === undefined) return <Bones rows={6} height={64} />;
  const weeks = monthDays(entries, year, month);
  return (
    <Table
      rows={weeks}
      keyOf={(week) => `week-${week[0].day}`}
      testId="calendar"
      rowTestId={(week) => `week-${week[0].day}`}
      columns={names.map((name, column) => ({
        // No weekday is `minor`: a month missing its Saturday on a narrow
        // screen is not a month.
        key: WEEKDAYS[column],
        head: name,
        cell: (week: CalendarDay[]) => <DayCell day={week[column]} today={today} />,
      }))}
    />
  );
}

/** One square of the month: its number, and everything standing on it. */
function DayCell({ day, today }: { day: CalendarDay; today: string }) {
  const t = useT();
  // A day of the neighbouring month fills the week out and says nothing:
  // the server was asked about this month only.
  if (!day.inMonth) return null;
  return (
    <div data-testid={`day-${day.day}`}>
      <Stack>
        <span className="fl-nowrap">
          {day.date.getDate()}
          {day.day === today && <> <Pill tone="accent">{t("today")}</Pill></>}
        </span>
        {day.entries.map((entry, index) => (
          <DayEntry key={`${entry.kind}-${entry.id}-${index}`} entry={entry} day={day.day} />
        ))}
      </Stack>
    </div>
  );
}

/**
 * One thing standing on one day: what kind it is, when, what it is called
 * and where it leads.
 *
 * Every word the flattened list carried is here - the kind, the hour, the
 * name, the link and the whole of it in the title - because the month was
 * not meant to cost the reader any of them.
 */
function DayEntry({ entry, day }: { entry: CalendarEntry; day: string }) {
  const t = useT();
  const title = entryTitle(t, entry);
  const to = entryLink(entry);
  // A window that began before this day has no hour on it: the hour it
  // opened belongs to the day it opened on.
  const opens = startsOn(entry, day) || entry.kind === "schedule";
  const at = entry.start ? absoluteTime(entry.start).slice(11, 16) : "";
  const detail = entry.kind === "host_window"
    ? [entry.reason, entry.set_by].filter(Boolean).join(" · ")
    : entry.state ?? "";
  return (
    <TwoLine sub={detail || undefined}>
      <Pill tone={entryTone(entry)} title={title}>{kindWord(t, entry.kind)}</Pill>
      {" "}
      {opens
        ? <span className="fl-nowrap">{at}</span>
        : <span className="fl-faint">{t("runs through")}</span>}
      {" "}
      {to
        ? <Link to={to} title={title}>{entry.name}</Link>
        : <span title={title}>{entry.name}</span>}
    </TwoLine>
  );
}

export const SCHEDULES_SCREEN = "next_schedules";

export const SCHEDULES: BoardEntry[] = [
  { key: "counts", title: "Schedules at a glance", width: 12, height: 2 },
  { key: "schedules", title: "Schedules", width: 12, height: 7 },
  { key: "calendar", title: "Maintenance calendar", width: 12, height: 7 },
];
