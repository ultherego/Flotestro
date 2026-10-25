import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "./api";
import type { FleetActivity, OperationContract, SelectorExpression } from "./types";
import { operationForm, readPayloadText, startingForm, type FormValue } from "./operations";
import { REBOOT_TIMEOUT } from "./targets";
import { buildExpression, type Rule } from "./selectors";
import {
  browserZone, emptyRecurrence, recurrenceProblem, recurrenceText, type RecurrenceForm,
} from "./recurrence";
import type { PlanGroup } from "../components/plan";

/**
 * The order a campaign is placed from: what it does, where it runs, how
 * fast, when, and what the panel carries back from the preview it was
 * placed on.
 *
 * None of this draws anything. It sits beside the wizard rather than inside
 * it because the campaign page, the job list, the policy editor and the read
 * form all compose or read part of the same order, and a second copy of
 * `campaignBody` would be a second idea of what was ordered.
 */

/** The order as the wizard starts it, before anything is typed. */
export function emptyOrder(): Order {
  return {
    name: "",
    action: "",
    unit: "",
    securityOnly: true,
    form: {},
    payloadText: "",
    mapping: {},
    pretty: "",
    compensates: "",
    hostIDs: [],
    site: "",
    environment: "",
    osFamily: "",
    targetMode: "filters",
    group: "",
    rules: [{ field: "tag", value: "", negated: false }],
    combine: "all",
    exclude: [],
    excludeReason: "",
    canary: 1,
    wave: 10,
    concurrent: 5,
    thresholdPercent: 20,
    thresholdCount: 0,
    rebootPolicy: "never",
    rebootTimeoutSeconds: REBOOT_TIMEOUT.default,
    offlinePolicy: "",
    deadlineMinutes: 24 * 60,
    manualGate: false,
    connectivityLost: 0,
    reason: "",
    maintenanceStart: "",
    maintenanceEnd: "",
    healthCheckUnits: "",
    jobTimeoutSeconds: 0,
    schedule: { enabled: false, startAt: "", recurrence: emptyRecurrence() },
  };
}

/**
 * The order another screen handed over in the address, or null when the
 * address carries no order.
 */
export function prefilledOrder(params: URLSearchParams): Draft | null {
  if (!params.has("action") && !params.has("name") && !params.has("reason")
    && !params.has("group") && !params.has("host_id")) return null;
  // A group page hands its name over: the order then opens on the group's
  // selector, the way a host list opens on its identifiers.
  const group = params.get("group") ?? "";
  const action = params.get("action") ?? "";
  const payloadText = params.get("payload") ?? "";
  // A payload another screen composed opens in the fields when the registry
  // can show it: the operator follows a link and lands in a form, not in a
  // box of JSON they have to read before they may change one value.
  const entry = operationForm(action);
  const form = entry && payloadText ? readPayloadText(entry, payloadText) : null;
  return {
    order: {
      ...emptyOrder(),
      name: params.get("name") ?? "",
      action,
      form: form ?? startingForm(action),
      payloadText: form ? "" : payloadText,
      compensates: params.get("compensates") ?? "",
      hostIDs: params.getAll("host_id"),
      reason: params.get("reason") ?? "",
      group,
      // The way the targets are named follows what the address carries:
      // a host list from a campaign row, a group from the group page.
      targetMode: params.has("host_id") ? "hosts" : group ? "expression" : "filters",
    },
    step: 0,
  };
}

/** What the browser keeps between reloads: the order and the step it was on. */
export type Draft = { order: Order; step: number };

/** The key the draft is kept under in the browser's session storage. */
export const DRAFT_KEY = "flotestro.bulk.draft";

/** The steps a draft may reopen on: anything before the campaign exists. */
const LAST_DRAFT_STEP = 5;

/**
 * The draft the browser kept, laid over an empty order so a field this
 * release added and an older draft does not know starts from its default
 * instead of from nothing.
 */
export function loadDraft(storage: Storage | null): Draft | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Draft> | null;
    if (!parsed || typeof parsed !== "object" || !parsed.order || typeof parsed.order !== "object") return null;
    const step = typeof parsed.step === "number" ? Math.min(Math.max(0, Math.floor(parsed.step)), LAST_DRAFT_STEP) : 0;
    return { order: { ...emptyOrder(), ...parsed.order }, step };
  } catch {
    return null;
  }
}

export function saveDraft(storage: Storage | null, draft: Draft): void {
  if (!storage) return;
  try {
    storage.setItem(DRAFT_KEY, JSON.stringify({ order: draft.order, step: Math.min(draft.step, LAST_DRAFT_STEP) }));
  } catch {
    // A draft that cannot be kept is a reload that starts over - the
    // wizard itself keeps working.
  }
}

export function clearDraft(storage: Storage | null): void {
  if (!storage) return;
  try {
    storage.removeItem(DRAFT_KEY);
  } catch {
    // Nothing to clear where nothing could be kept.
  }
}

/**
 * The number of hosts the order is placed on: the hosts the address named,
 * or what the preview counted as eligible, or what it matched.
 */
export function orderTargets(order: Pick<Order, "hostIDs">, preview?: Pick<Preview, "count" | "eligible">): number {
  if (order.hostIDs.length > 0) return order.hostIDs.length;
  return preview?.eligible ?? preview?.count ?? 0;
}

/** The fewest characters a reason has to have to count as one. */
export const MIN_REASON = 8;

/** Whether the reason says something: at least MIN_REASON characters after trimming. */
export function reasonValid(reason: string): boolean {
  return reason.trim().length >= MIN_REASON;
}

/** What is wrong with the maintenance window, or null when nothing is. */
export type WindowProblem = "start_invalid" | "end_invalid" | "start_past" | "end_past" | "end_before_start";

/**
 * The maintenance window as typed, checked against the clock: both ends are
 * optional, a given end has to lie ahead of the start and of now, and a
 * given start ahead of now - a window that already closed would create a.
 */
export function windowProblem(start: string, end: string, now: Date): WindowProblem | null {
  const from = start ? new Date(start) : null;
  const to = end ? new Date(end) : null;
  if (from && Number.isNaN(from.getTime())) return "start_invalid";
  if (to && Number.isNaN(to.getTime())) return "end_invalid";
  if (from && from.getTime() <= now.getTime()) return "start_past";
  if (to && to.getTime() <= now.getTime()) return "end_past";
  if (from && to && to.getTime() <= from.getTime()) return "end_before_start";
  return null;
}

/** The unit names typed one per line or separated by commas, trimmed and deduplicated. */
export function parseUnits(text: string): string[] {
  const units: string[] = [];
  for (const part of text.split(/[\n,;]/)) {
    const unit = part.trim();
    if (unit && !units.includes(unit)) units.push(unit);
  }
  return units;
}

/** The bounds of a job timeout the wizard accepts, in seconds. Zero means the operation's own default. */
export const JOB_TIMEOUT = { min: 30, max: 24 * 3600 };

export function jobTimeoutValid(seconds: number): boolean {
  return seconds === 0 || (Number.isInteger(seconds) && seconds >= JOB_TIMEOUT.min && seconds <= JOB_TIMEOUT.max);
}

/**
 * The instant of a datetime-local value as the API reads it: an RFC 3339
 * timestamp in UTC.
 */
export function windowInstant(value: string): string | undefined {
  if (!value) return undefined;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

/**
 * The body of the order as the API takes it.
 */
export function campaignBody(order: Order, token?: PreviewToken): Record<string, unknown> {
  const expression = expressionOf(order);
  const units = parseUnits(order.healthCheckUnits);
  return {
    name: order.name,
    action: order.action,
    reason: order.reason.trim(),
    payload: orderPayload(order) ?? {},
    selector: {
      site: expression ? undefined : order.site || undefined,
      environment: expression ? undefined : order.environment || undefined,
      os_family: expression ? undefined : order.osFamily || undefined,
      // A typed expression would decide over the host list on the
      // server; the named hosts are the order, so it is not sent.
      expression: order.hostIDs.length > 0 ? undefined : expression ?? undefined,
      host_ids: order.hostIDs.length > 0 ? order.hostIDs : undefined,
      exclude: order.exclude.length > 0 ? order.exclude : undefined,
      exclude_reason: order.exclude.length > 0 ? order.excludeReason.trim() : undefined,
    },
    canary_size: order.canary,
    wave_size: order.wave,
    max_concurrent: order.concurrent,
    failure_threshold_percent: order.thresholdPercent,
    failure_threshold_absolute: order.thresholdCount,
    reboot_policy: order.rebootPolicy,
    // Sent only when it differs from the default, so an order with the
    // default reads like one that said nothing about it.
    reboot_timeout_seconds: order.rebootTimeoutSeconds !== REBOOT_TIMEOUT.default
      ? order.rebootTimeoutSeconds : undefined,
    offline_policy: order.offlinePolicy || undefined,
    deadline_minutes: order.deadlineMinutes,
    manual_gate: order.manualGate && order.canary > 0,
    connectivity_lost_absolute: order.connectivityLost,
    maintenance_start: windowInstant(order.maintenanceStart),
    maintenance_end: windowInstant(order.maintenanceEnd),
    health_check_units: units.length > 0 ? units : undefined,
    job_timeout_seconds: order.jobTimeoutSeconds > 0 ? order.jobTimeoutSeconds : undefined,
    // Every campaign carries the gate: the server forces it whatever a
    // client says, and the body says the same thing.
    requires_approval: true,
    compensates_campaign_id: order.compensates || undefined,
    // The order says which preview it was placed from. A stored order - a
    // schedule - carries none: it is placed at a moment nobody previewed.
    preview_id: token?.preview_id,
    preview_digest: token?.preview_digest,
  };
}

export type Order = {
  name: string;
  action: string;
  // The unit and the security-only choice of the orders this wizard carried
  // before the registry existed.
  unit: string;
  securityOnly: boolean;
  // The fields of the operation, as the registry describes them. Empty until
  // something is typed; the registry's own starting value lies underneath.
  form: FormValue;
  // The payload of an operation the registry cannot show, as JSON text the
  // operator edits; it starts from the template the server gives.
  payloadText: string;
  // A rename in bulk: the new name of every host, by host identifier.
  mapping: Record<string, string>;
  // The pretty name a rename sets everywhere; empty leaves it alone.
  pretty: string;
  // The campaign this order undoes, when it came from "Plan the rollback" on
  // a finished campaign.
  compensates: string;
  // Hosts named by identifier: picked one by one from the host list, or
  // handed over in the address as a compensation of one host from the
  // campaign page.
  hostIDs: string[];
  site: string;
  environment: string;
  osFamily: string;
  // How the targets are named: by the flat filters, by a group and tag rules
  // compiled into one expression, or by a list of hosts picked by hand.
  targetMode: TargetMode;
  group: string;
  rules: Rule[];
  combine: "all" | "any";
  // Hosts left out by name, with the reason the approver will read next
  // to them; the server refuses an exclusion without one.
  exclude: string[];
  excludeReason: string;
  canary: number;
  wave: number;
  concurrent: number;
  thresholdPercent: number;
  thresholdCount: number;
  rebootPolicy: string;
  // How long a rebooted host is waited for before it fails, in seconds.
  rebootTimeoutSeconds: number;
  // What happens to a host that is not connected when its turn comes.
  offlinePolicy: string;
  // How long the campaign waits for offline hosts, counted from creation.
  deadlineMinutes: number;
  // Whether the campaign stops after the canary for a decision.
  manualGate: boolean;
  // How many lost sessions mid-task pause the campaign; zero disables it.
  connectivityLost: number;
  // Why the change is made, or the change reference it answers to: the
  // sentence the audit trail keeps next to the order.
  reason: string;
  // The maintenance window, as datetime-local values in the browser's
  // zone; either end may be empty. No host is started outside it.
  maintenanceStart: string;
  maintenanceEnd: string;
  // The units checked on every host once its change is done - after the
  // reboot when one follows, right after the change when none does.
  healthCheckUnits: string;
  // How long one host's task may run, in seconds; zero takes the
  // operation's own default from the catalogue.
  jobTimeoutSeconds: number;
  // Whether the campaign waits for a consent before anything runs. A
  // critical operation cannot turn it off.
  schedule: ScheduleChoice;
};

/** The three ways of naming the targets of an order. */
export type TargetMode = "filters" | "expression" | "hosts";

/** The moment an order is kept for, and the rule of the moments after it. */
export type ScheduleChoice = { enabled: boolean; startAt: string; recurrence: RecurrenceForm };

/**
 * What is wrong with the schedule of an order, or null when nothing is or
 * nothing is scheduled: a single run needs a moment ahead, a recurring one a
 * complete rule.
 */
export function scheduleProblem(choice: ScheduleChoice, now: Date): "start_invalid" | "start_past" | "moment_required" | "recurrence" | null {
  if (!choice.enabled) return null;
  const rule = recurrenceText(choice.recurrence);
  const start = choice.startAt ? new Date(choice.startAt) : null;
  if (start && Number.isNaN(start.getTime())) return "start_invalid";
  if (!rule && !start) return "moment_required";
  if (!rule && start && start.getTime() <= now.getTime()) return "start_past";
  if (rule && recurrenceProblem(choice.recurrence)) return "recurrence";
  return null;
}

/**
 * The body of a schedule as the API takes it: the order as it would be
 * placed now, kept for the moment, with the reason on the schedule as well -
 * it is what the trail keeps next to the schedule and what every campaign
 */
export function scheduleBody(order: Order): Record<string, unknown> {
  const rule = recurrenceText(order.schedule.recurrence);
  return {
    name: order.name,
    order: campaignBody(order),
    start_at: windowInstant(order.schedule.startAt),
    recurrence: rule || undefined,
    timezone: browserZone(),
    reason: order.reason.trim(),
  };
}

/**
 * Whether the order narrows the fleet at all. The server refuses a campaign
 * whose selector names nobody - an empty selector is not an order on
 * everything - so the wizard never builds one. It is read off the body the
 * order really sends, so the wizard and the server agree on what was named.
 */
export function selectorNames(order: Order): boolean {
  // A compensation may name nobody of its own: it takes the hosts the
  // campaign it undoes changed, and the server writes them in.
  if (order.compensates) return true;
  const chosen = campaignBody(order).selector as Record<string, unknown>;
  return Boolean(chosen.site || chosen.environment || chosen.os_family || chosen.expression
    || (chosen.host_ids as string[] | undefined)?.length);
}

/**
 * The expression the order carries: the chosen group and the tag rules
 * joined by "all". Null means the flat filters decide.
 */
export function expressionOf(order: Order): SelectorExpression | null {
  if (order.targetMode !== "expression") return null;
  const parts: SelectorExpression[] = [];
  if (order.group) parts.push({ group: order.group });
  const rules = buildExpression(order.rules, order.combine);
  if (rules) parts.push(rules);
  if (parts.length === 0) return null;
  return parts.length === 1 ? parts[0] : { all: parts };
}

export type Operation = OperationContract & {
  action: string;
  campaign_refusal?: string;
  mutating: boolean;
  campaign_mode: string;
  campaign_ready: boolean;
  offline_policy?: string;
  risk?: string;
  // How long one task of the operation may run when the order says
  // nothing; the wizard shows it next to the timeout field.
  default_timeout_seconds?: number;
  payload_template?: Record<string, unknown>;
  needs_material?: boolean;
  // What the payload has to carry, for the operations a template does not
  // cover. The panel builds a skeleton from these rather than offering an
  // empty object: the group is the key, and the fields are what goes inside.
  payload_group?: string;
  payload_fields?: { name: string; kind: string }[];
};

/**
 * What the payload field opens on for an operation the wizard draws no form
 * for: the example if the operation has one, the skeleton the registry
 * describes if it has not, and nothing at all for an operation that reads no
 * payload - an empty box is the honest offer there.
 */
export function startingPayloadText(operation: Operation | undefined, hasForm: boolean): string {
  if (hasForm) return "";
  const skeleton = payloadSkeleton(operation);
  const starting = operation?.payload_template
    ?? (Object.keys(skeleton).length > 0 ? skeleton : undefined);
  return starting ? JSON.stringify(starting, null, 2) : "";
}

/**
 * The skeleton of a payload, from what the registry says the operation reads.
 *
 * Every fan-out read lacked a hand-written template, so the form offered "{}"
 * and the operator had to know which group and which fields the operation
 * takes - or order it, read the refusal and try again. An empty group is a
 * complete answer for the operations that accept one: {"docker_read":{}} is a
 * payload docker.read takes as it stands.
 */
export function payloadSkeleton(operation: Operation | undefined): Record<string, unknown> {
  if (!operation?.payload_group) return {};
  const body: Record<string, unknown> = {};
  for (const field of operation.payload_fields ?? []) {
    body[field.name] = field.kind === "number" ? 0
      : field.kind === "boolean" ? false
      : field.kind === "array" ? []
      : field.kind === "object" ? {}
      : "";
  }
  return { [operation.payload_group]: body };
}

/**
 * The operation catalogue under /api/v1/actions, read once and shared by
 * every screen that draws something from an operation's contract: the
 * wizard, the campaign page and the job list.
 */
export function useOperations() {
  return useQuery({
    queryKey: ["actions"],
    queryFn: () => api.get<Collection<Operation>>("/api/v1/actions"),
    staleTime: 10 * 60_000,
  });
}

/** The catalogue entry of one operation, once the catalogue is in. */
export function useOperation(action: string | undefined): Operation | undefined {
  const operations = useOperations();
  return action ? operations.data?.items.find((item) => item.action === action) : undefined;
}

/**
 * The facets of the visible fleet - sites, environments, OS families with
 * their host counts - counted in the database, under the same key the host
 * list and the dashboard read them by, so one screen does not fetch what.
 */
export function useFleetFacets() {
  return useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    staleTime: 60_000,
  });
}


/**
 * The reverse of a change, where a true one exists: an operation that puts
 * back what the forward one changed, as a new plan the operator approves.
 */
export const REVERSE_OPERATION: Record<string, string> = {
  "file.ensure": "file.rollback",
};

/**
 * The payload the reverse operation starts from: the same file. The
 * version is per host and is left for the operator to fill in.
 */
export function reversePayload(action: string, payload: unknown): Record<string, unknown> {
  const source = payload && typeof payload === "object"
    ? payload as Record<string, Record<string, unknown> | undefined>
    : {};
  const text = (section: string, field: string): string => {
    const value = source[section]?.[field];
    return typeof value === "string" ? value : "";
  };
  switch (action) {
    case "file.ensure":
      return { file: { path: text("file", "path"), version_sha256: "" } };
  }
  return {};
}

/**
 * The address of the wizard with an order half written.
 */
export function bulkPrefill(action: string, name: string, payload: unknown, compensates?: string, hostIDs: string[] = []): string {
  let address = `/bulk?action=${encodeURIComponent(action)}&name=${encodeURIComponent(name)}&payload=${encodeURIComponent(JSON.stringify(payload, null, 2))}`;
  if (compensates) address += `&compensates=${encodeURIComponent(compensates)}`;
  // One host of the original, when the rollback is ordered from its row;
  // the parameter repeats, one host per value.
  for (const hostID of hostIDs) address += `&host_id=${encodeURIComponent(hostID)}`;
  return address;
}

/**
 * The words for every class of the contract: a short label for the chip and
 * one sentence for the tooltip.
 */
const CONTRACT_WORDS: Record<string, Record<string, [label: string, meaning: string]>> = {
  cancel: {
    safe: ["any time", "Can be cancelled at any moment; the host is left in a consistent state."],
    checkpoint_only: ["between steps", "A cancel is honoured only between steps: the step under way finishes, the next one does not start."],
    impossible_after_start: ["not after start", "Once the host reported a start, a cancel is only information: the operation runs to its end."],
    local_watchdog_owned: ["host watchdog", "The host's own watchdog decides: the panel only requests, and never stops a rollback timer that guards the management channel."],
  },
  retry: {
    never: ["never", "Repeating the same order fails the same way; a decision is needed first."],
    automatic: ["automatic", "Idempotent: the system may repeat it on its own."],
    after_change: ["after a fix", "Repeat only after fixing what the result names on the host."],
    after_replan: ["after a new plan", "The plan has to be computed and approved again before a repeat."],
    read_state: ["after reading the host", "Read the state of the host before repeating; never repeat blind."],
  },
  rollback: {
    automatic_local: ["automatic on the host", "The host reverts itself when the connectivity check fails, with no help from the panel."],
    exact_restore: ["exact restore", "The previous version is kept and can be put back exactly as it was."],
    compensating: ["compensating plan", "A new plan neutralises the effect; the history stays."],
    best_effort: ["best effort", "An attempt to limit the damage, with no guarantee of the initial state."],
    none: ["none", "Irreversible: there is no way back."],
  },
  verification: {
    none: ["none", "Nothing is checked after the change."],
    unit_health: ["unit health", "After the change the unit is checked for the expected state and health."],
    connectivity: ["connectivity", "After the change the host has to answer on the management channel."],
    plan_recheck: ["plan recheck", "After the change the plan is computed again and has to show no difference."],
    custom: ["module check", "The module runs its own check: a probe, a new boot ID, a version reported back."],
  },
};

/** The label and the meaning of one contract value, translated. */
export function contractWords(t: (text: string) => string, field: string, value: string | undefined): [string, string] {
  const words = value ? CONTRACT_WORDS[field]?.[value] : undefined;
  if (!words) return [value ?? "—", t("The registry declares a value this panel does not describe yet.")];
  return [t(words[0]), t(words[1])];
}

export function orderForm(order: Order): FormValue {
  const legacy: FormValue = {};
  if (UNIT_OPERATIONS.includes(order.action) && order.unit !== "") legacy.unit = order.unit;
  if (order.action === "packages.upgrade") legacy.security_only = order.securityOnly;
  return { ...startingForm(order.action), ...legacy, ...order.form };
}

/**
 * The payload of the order.
 */
export function orderPayload(order: Order): Record<string, unknown> | null {
  if (order.action === RENAME_OPERATION) {
    // A rename across the fleet carries one name per host and nothing
    // shared, so it keeps its own editor: the registry's form describes a
    // rename of one host and would give every host the same name - the one.
    const mapping = Object.fromEntries(
      Object.entries(order.mapping).map(([id, name]) => [id, name.trim()] as const).filter(([, name]) => name !== ""),
    );
    if (Object.keys(mapping).length === 0) return null;
    return { hostname: { pretty: order.pretty.trim() || undefined, mapping } };
  }
  const entry = operationForm(order.action);
  if (entry && !order.payloadText) {
    // A form with a problem in it is not a payload: the wizard holds the
    // order at the first step and says what is missing, rather than sending
    // something the server would refuse.
    if (entry.validate(orderForm(order)).length > 0) return null;
    return entry.toPayload(orderForm(order));
  }
  try {
    const parsed = JSON.parse(order.payloadText);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

export type Group = { reason: string; count: number; sample: string[] };

/**
 * What the last full reads of the hosts say of a container the order names. The capability
 * says a host can run the operation and nothing of whether the container is there; the
 * rest is settled on each host when the order arrives.
 */
export type ContainerEvidence = {
  name: string;
  present: { count: number; sample: string[] };
  absent: { count: number; sample: string[] };
  unknown: { count: number; sample: string[] };
  evidence_max_age_seconds: number;
  oldest_read_at?: string;
};

export type Preview = {
  count: number;
  limit: number;
  eligible?: number;
  sample?: string[];
  excluded?: Group[];
  notes?: Group[];
  campaign_mode?: string;
  requires_plan?: boolean;
  // Present when the order names a container and not its identifier.
  container?: ContainerEvidence;
  // Every ready host by identifier, for an operation whose order names
  // each host by itself; absent for every other operation.
  hosts?: { id: string; hostname: string }[];
  // The distribution of the snapshot: thirty hosts from one site are a
  // different change than thirty spread over three.
  distribution?: Record<string, Group[]>;
  // The campaign the order would undo, as the server checked it, with the
  // number of hosts it changed - the only hosts the order may name.
  compensates?: { id: string; name: string; state: string; changed: number };
  // The binding between this answer and the order placed from it: the server
  // records what it showed, the order names it, and the creation refuses
  // when the fleet or the operator's rights moved in between.
  preview_id?: string;
  preview_digest?: string;
  expires_at?: string;
};

/** What the order carries back from the preview it was placed from. */
export type PreviewToken = { preview_id: string; preview_digest: string };

/**
 * The token of a preview, when it has one.
 */
export function previewTokenOf(preview?: Preview): PreviewToken | undefined {
  if (!preview?.preview_id || !preview.preview_digest) return undefined;
  return { preview_id: preview.preview_id, preview_digest: preview.preview_digest };
}

/**
 * The operations whose payload an earlier release of this wizard built from
 * a field of its own.
 */
export const UNIT_OPERATIONS = ["unit.start", "unit.stop", "unit.restart", "unit.reload", "unit.reset_failed"];

/** A rename in bulk: the payload is a mapping the wizard builds host by host. */
export const RENAME_OPERATION = "system.hostname.set";

/**
 * The operations the wizard can build a payload for: those the catalogue
 * opens to the fleet and the registry has a form for, plus the rename, whose
 * per-host mapping this wizard builds itself.
 */
export function wizardOperations(bulk: Operation[]): string[] {
  return bulk
    .filter((item) => item.action === RENAME_OPERATION || Boolean(operationForm(item.action)))
    .map((item) => item.action);
}

/**
 * What the screen can honestly say about how many hosts the selector matches.
 *
 * Four states and not three, because "nobody answered yet" is not "the
 * selector matches nobody". The screen said the second over the first until
 * 15.10 - the count was `preview?.count ?? 0` - so an operator who narrowed
 * the fleet and looked while the answer was in flight read that their
 * selector hits no host. Unknown is not zero, here as everywhere.
 */
export type MatchedState =
  | { kind: "unnarrowed" }
  | { kind: "counting" }
  | { kind: "unknown" }
  | { kind: "counted"; n: number };

export function matchedState(
  names: boolean,
  count: number | undefined,
  checking: boolean | undefined,
): MatchedState {
  if (!names) return { kind: "unnarrowed" };
  if (count === undefined) return checking ? { kind: "counting" } : { kind: "unknown" };
  return { kind: "counted", n: count };
}

/** The plans of a campaign grouped by fingerprint, as the panel serves them. */
export type PlanGroups = {
  items: PlanGroup[];
  plan_set_hash?: string;
  plan_ttl_seconds?: number;
};
