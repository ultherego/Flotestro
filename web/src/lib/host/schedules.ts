import { registryOrder, type RegistryOrder } from "./module";
import type { Capabilities } from "../types";

/**
 * The recurring jobs of one host: what the agent reports about an entry,
 * what a preview of the next runs amounts to, and the four changes the
 * panel may order.
 *
 * The orders go through the operation registry, so a host page and the
 * Bulk workspace send one payload and refuse one set of values.
 */

export type Schedule = {
  id: string;
  kind: string;
  source: string;
  enabled: boolean;
  expression: string;
  // The OnCalendar expression a timer really runs by.
  calendar?: string;
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

/** One unit file of a timer's plan: where it goes and what is in it. */
export type UnitFile = { path: string; content: string };

/** The answer of schedule.preview: the next runs computed on the host. */
export type Preview = {
  expression?: string;
  timezone?: string;
  next_runs?: string[];
  error?: string;
  // The plan of a timer: the calendar expression the cron line becomes and
  // the two units that would be written.
  calendar?: string;
  units?: UnitFile[];
};

/** The preview as the panel types it from the result of the agent. */
export type PreviewDetail = {
  kind?: string;
  expression?: string;
  timezone?: string;
  runs?: string[];
  error?: string;
  calendar?: string;
  units?: UnitFile[];
};

export type Attempt = { status?: string; error_code?: string; message?: string; stdout?: string; detail?: PreviewDetail };

/**
 * The preview of an attempt: typed from the result when the panel has read
 * it, otherwise the document the agent prints on stdout.
 */
export function previewOf(attempt: Attempt): Preview {
  const printed = readDocument(attempt.stdout);
  const detail = attempt.detail;
  if (detail?.kind === "schedule_preview") {
    return {
      expression: detail.expression,
      timezone: detail.timezone,
      next_runs: detail.runs,
      error: detail.error,
      calendar: detail.calendar ?? printed.calendar,
      units: detail.units ?? printed.units,
    };
  }
  return printed;
}

/** The preview document of the agent, or nothing readable. */
function readDocument(stdout?: string): Preview {
  try {
    return JSON.parse(stdout ?? "{}") as Preview;
  } catch {
    return {};
  }
}

/**
 * The mechanisms this host can carry a managed entry with.
 */
export function scheduleKinds(capabilities: Capabilities | undefined): string[] {
  const adapter = (capabilities ?? []).find((capability) => capability.name === "schedules");
  if (!adapter?.available) return [];
  const kinds: string[] = [];
  if (adapter.features?.cron !== false) kinds.push("cron");
  if (adapter.features?.managed_timers === true) kinds.push("timer");
  return kinds;
}


/** A new or rewritten entry, as an order. */
export function ensureOrder(fields: {
  id: string; expression: string; command: string[]; user: string;
  comment: string; kind: string; adopt: boolean;
}): RegistryOrder {
  // The registry reads a list one entry per line; the command on this page
  // is typed as one line and split on the spaces in it.
  return registryOrder("schedule.ensure", { ...fields, command: fields.command.join("\n") });
}

/** Running an entry now, or taking it away, as an order. */
export function entryOrder(action: string, id: string): RegistryOrder {
  return registryOrder(action, { id });
}

/** Switching an entry off or on, as an order. */
export function enableOrder(id: string, enabled: boolean): RegistryOrder {
  return registryOrder("schedule.disable", { id, enabled });
}


export function entryFile(entry: Schedule): string {
  const path = entry.path ?? "";
  return path.slice(path.lastIndexOf("/") + 1);
}

/**
 * What the host already runs under a name a new entry would take. A found
 * entry is named "<file>:<line>", so the name is compared with its file.
 */
export function foundUnderName(entries: Schedule[], name: string): Schedule[] {
  if (!name) return [];
  return entries.filter(
    (entry) => entry.source !== "managed" && entry.kind === "cron" && entryFile(entry) === name,
  );
}

/** What a mechanism is called on screen. */
export function kindLabel(kind: string, t: (text: string) => string): string {
  switch (kind) {
    case "cron":
      return t("a cron entry");
    case "timer":
      return t("a systemd timer");
    case "any":
      return t("whichever the host has");
  }
  return kind;
}

/**
 * The new entry form.
 */
