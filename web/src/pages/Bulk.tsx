import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type {
  Campaign, CampaignTarget, Facet, FleetActivity, OperationContract, ResourceClaim, SelectorExpression,
} from "../lib/types";
import { ErrorBox, Empty, JobState, Time } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { OPERATIONS_INTERVAL } from "../lib/stream";
import { useCapabilities } from "../lib/capabilities";
import { PlanGroupView, type PlanGroup } from "../components/plan";
import { VirtualRows } from "../components/virtual";
import { loadedTargets, REBOOT_TIMEOUT, useTargets } from "../lib/targets";
import { moduleForAction } from "./host/modules";
import { buildExpression, describeExpression, HostChooser, SelectorBuilder, type Rule } from "./Groups";
import { browserZone, emptyRecurrence, RecurrenceFields, recurrenceProblem, recurrenceText, type RecurrenceForm } from "./Schedules";
import { useT } from "../i18n";

/**
 * Bulk Workspace: the second, equal path of work next to the host tabs.
 *
 * The Host Workspace serves precise work on one machine. Here one picks the
 * target, reads the refusals and drives a change across the whole fleet. A
 * campaign cannot be one button hidden on the host list: it is the main
 * mechanism of change, not a shortcut.
 */
export function Bulk() {
  const t = useT();
  // Another screen may open the workspace with an order half written - the
  // certificate view hands over a rotation stage this way. The address
  // carries the operation, a name and a payload; everything else is
  // decided here. An address with nothing in it reopens the draft the
  // browser kept, so a reload halfway through does not start over.
  const [prefill] = useSearchParams();
  const [draft] = useState(() => prefilledOrder(prefill) ?? loadDraft(sessionStorageOrNull()));
  const [step, setStep] = useState(draft?.step ?? 0);
  // The campaign comes into being halfway through. Until then we work on an
  // order, afterwards - on a campaign that computes its plans itself and
  // waits for consent.
  const [campaignID, setCampaignID] = useState("");
  const [order, setOrder] = useState<Order>(draft?.order ?? emptyOrder());

  const change = (delta: Partial<Order>) =>
    setOrder((previous) => ({ ...previous, ...delta }));

  // The draft follows every change until the campaign exists: after that
  // the record on the server is the truth, and a stale draft reopening on
  // the next visit would look like a second order waiting to be placed.
  useEffect(() => {
    if (campaignID) return;
    saveDraft(sessionStorageOrNull(), { order, step });
  }, [order, step, campaignID]);

  const capabilities = useCapabilities();
  const operations = useOperations();
  const bulk = (operations.data?.items ?? []).filter((item) => item.campaign_ready);
  const chosenOperation = bulk.find((item) => item.action === order.action);
  // An operation that arrived in the address may be one the catalogue
  // refuses in bulk - a rollback family, a specialised sequence. The
  // catalogue's reason closes the first gate; the server would refuse the
  // order anyway, and later.
  const unready = order.action && operations.data && !chosenOperation
    ? operations.data.items.find((item) => item.action === order.action)
    : undefined;
  const refusal = unready
    ? unready.campaign_refusal ?? t("the catalogue does not open it to the fleet")
    : undefined;
  // A prefilled operation without a payload takes the template once the
  // catalogue is in, exactly as choosing it by hand would.
  const prefilledTemplate = order.action && !order.payloadText && !WIZARD_OPERATIONS.includes(order.action)
    ? bulk.find((item) => item.action === order.action)?.payload_template
    : undefined;
  useEffect(() => {
    if (prefilledTemplate) {
      setOrder((previous) => ({ ...previous, payloadText: JSON.stringify(prefilledTemplate, null, 2) }));
    }
  }, [prefilledTemplate]);
  // Refusals are shown together with the reason. An operation missing from
  // the list without a word of explanation looks like a missing feature -
  // while it may be a boundary drawn on purpose, e.g. restoring a backup.
  const refusals = (operations.data?.items ?? []).filter(
    (item) => item.mutating && !item.campaign_ready && item.campaign_refusal,
  );

  const params = new URLSearchParams();
  const expression = expressionOf(order);
  if (expression) {
    // The typed selector decides alone; the flat filters are not sent
    // next to it, so the preview asks exactly what the order will.
    params.set("expression", JSON.stringify(expression));
  } else {
    if (order.site) params.set("site", order.site);
    if (order.environment) params.set("environment", order.environment);
    if (order.osFamily) params.set("os_family", order.osFamily);
  }
  for (const hostID of order.exclude) params.append("exclude", hostID);
  if (order.excludeReason.trim()) params.set("exclude_reason", order.excludeReason.trim());
  if (order.action) params.set("action", order.action);
  // A compensation previews against its original: the server names the
  // hosts that changed and refuses the rest, before anything is created.
  if (order.compensates) params.set("compensates", order.compensates);
  const preview = useQuery({
    queryKey: ["campaign-preview", params.toString()],
    queryFn: () => api.get<Preview>(`/api/v1/campaigns/preview?${params}`),
    enabled: Boolean(order.action),
  });

  const campaign = useQuery({
    queryKey: ["campaign", campaignID],
    queryFn: () => api.get<Campaign>(`/api/v1/campaigns/${campaignID}`),
    enabled: Boolean(campaignID),
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // A host list from the address is not a filter the preview can count:
  // the preview reads the selector fields, and a compensation narrowed to
  // one host previews the whole set the original changed. The named hosts
  // are what the order carries, so they are what the count says.
  const eligible = orderTargets(order, preview.data);
  const gates = stepGates(t, order, preview.data, campaign.data, refusal);

  // A backend without a planning phase will not drive any of these changes.
  // A wizard that ends in an error after the form is filled in is worse than
  // its absence together with the reason.
  if (!capabilities.campaign_v2) {
    return (
      <>
        <PageHeader title={t("Bulk Workspace")} />
        <Card>
          <Empty>
            {t("This installation runs operations host by host: the backend has no campaign engine, so there is no set of per-host plans to approve.")}
          </Empty>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title={t("Bulk Workspace")}
        description={t("Choose the target, read the refusals, run the change. One host at a time lives in the host workspace; this is where the fleet is changed.")}
      />

      <ScopeBar order={order} preview={preview.data} campaign={campaign.data}
        targets={eligible} risk={chosenOperation?.risk} />

      <ol className="bulk-steps">
        {STEPS.map((title, index) => (
          <li key={title}>
            <button
              className={index === step ? "step active" : "step"}
              onClick={() => setStep(index)}
              disabled={index > 0 && !gates[index - 1].open}
            >
              <span className="number">{index + 1}</span>
              <span className="title">{t(title)}</span>
              {/* A closed gate says what is missing. A step greyed out
                  without a reason looks like an interface defect. */}
              {index > 0 && !gates[index - 1].open && (
                <span className="reason">{gates[index - 1].reason}</span>
              )}
            </button>
          </li>
        ))}
      </ol>

      {step === 0 && (
        <ScopeStep
          order={order}
          change={change}
          bulk={bulk}
          refusals={refusals}
          preview={preview.data}
          refusal={refusal}
        />
      )}
      {step === 1 && <TargetsStep order={order} change={change} preview={preview.data} refusal={preview.error} />}
      {step === 2 && <EligibilityStep order={order} preview={preview.data} checking={preview.isLoading} />}
      {step === 3 && (
        <RolloutStep
          order={order}
          change={change}
          targets={eligible}
          declaredPolicy={chosenOperation?.offline_policy}
        />
      )}
      {step === 4 && <WindowStep order={order} change={change} operation={chosenOperation} />}
      {step === 5 && (
        <CreateStep
          order={order}
          change={change}
          targets={eligible}
          compensates={preview.data?.compensates}
          campaignID={campaignID}
          onCreated={(id) => {
            // The order is placed: the draft would only reopen an order
            // that already became a campaign.
            clearDraft(sessionStorageOrNull());
            setCampaignID(id);
            setStep(6);
          }}
        />
      )}
      {step === 6 && <PlansStep campaignID={campaignID} campaign={campaign.data} />}
      {step === 7 && <ApprovalStep campaignID={campaignID} campaign={campaign.data} />}
    </>
  );
}

/** The order as the wizard starts it, before anything is typed. */
export function emptyOrder(): Order {
  return {
    name: "",
    action: "",
    unit: "",
    securityOnly: true,
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
    requiresApproval: true,
    schedule: { enabled: false, startAt: "", recurrence: emptyRecurrence() },
  };
}

/**
 * The order another screen handed over in the address, or null when the
 * address carries no order. A link with an operation in it is a new order
 * and wins over a draft: the operator followed it on purpose.
 */
export function prefilledOrder(params: URLSearchParams): Draft | null {
  if (!params.has("action") && !params.has("name") && !params.has("reason")
    && !params.has("group") && !params.has("host_id")) return null;
  // A group page hands its name over: the order then opens on the group's
  // selector, the way a host list opens on its identifiers.
  const group = params.get("group") ?? "";
  return {
    order: {
      ...emptyOrder(),
      name: params.get("name") ?? "",
      action: params.get("action") ?? "",
      payloadText: params.get("payload") ?? "",
      compensates: params.get("compensates") ?? "",
      hostIDs: params.getAll("host_id"),
      reason: params.get("reason") ?? "",
      group,
      targetMode: group ? "expression" : "filters",
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
 * The session storage of this tab, or null where there is none: a private
 * window or blocked site data leave the wizard working without a draft
 * rather than failing on the first keystroke.
 */
function sessionStorageOrNull(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

/**
 * The draft the browser kept, laid over an empty order so a field this
 * release added and an older draft does not know starts from its default
 * instead of from nothing. A draft that is not an object is ignored.
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
 * or what the preview counted as eligible, or what it matched. A host list
 * from the campaign page is not a filter the preview can count, so the
 * list itself is the number.
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

/**
 * The risk classes whose campaigns cannot skip the approval gate: an
 * operation that can cut a host off or destroy what it holds is never one
 * decision short of running on the fleet.
 */
export function approvalForced(risk: string | undefined): boolean {
  return risk === "critical" || risk === "destructive";
}

/** What is wrong with the maintenance window, or null when nothing is. */
export type WindowProblem = "start_invalid" | "end_invalid" | "start_past" | "end_past" | "end_before_start";

/**
 * The maintenance window as typed, checked against the clock: both ends
 * are optional, a given end has to lie ahead of the start and of now, and
 * a given start ahead of now - a window that already closed would create
 * a campaign that waits forever, with nothing on screen to say so.
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
 * timestamp in UTC. The input gives local wall time without a zone, and
 * the Date constructor reads it in the browser's zone, which is the zone
 * the operator meant.
 */
export function windowInstant(value: string): string | undefined {
  if (!value) return undefined;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

/**
 * The body of the order as the API takes it. A field the operator left at
 * its default is not sent, so an order that said nothing about it reads
 * like one on the server as well.
 */
export function campaignBody(order: Order, risk: string | undefined): Record<string, unknown> {
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
    // A critical operation carries the gate whatever the box says; the
    // box is disabled for it, and the body says the same thing.
    requires_approval: approvalForced(risk) ? true : order.requiresApproval,
    compensates_campaign_id: order.compensates || undefined,
  };
}

type Order = {
  name: string;
  action: string;
  unit: string;
  securityOnly: boolean;
  // The payload of an operation without a form of its own, as JSON text
  // the operator edits; it starts from the template the server gives.
  payloadText: string;
  // A rename in bulk: the new name of every host, by host identifier. The
  // server splits it host by host and a host it does not name is
  // ineligible - there is no shared name, on purpose.
  mapping: Record<string, string>;
  // The pretty name a rename sets everywhere; empty leaves it alone.
  pretty: string;
  // The campaign this order undoes, when it came from "Plan the rollback"
  // on a finished campaign. Empty for an ordinary campaign. The server
  // holds the rules: the reverse operation, the hosts that changed.
  compensates: string;
  // Hosts named by identifier in the address - a compensation of one host
  // from the campaign page. When present they are the order's targets and
  // the filters below are not sent; the server checks them against the
  // original the way it checks any selector.
  hostIDs: string[];
  site: string;
  environment: string;
  osFamily: string;
  // How the targets are named: by the flat filters of the next step, or
  // by a group and tag rules compiled into one expression. The expression,
  // when present, decides alone.
  targetMode: "filters" | "expression";
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
  // What happens to a host that is not connected when its turn comes. An
  // empty value keeps the operation's own policy; a chosen one may only
  // tighten it.
  offlinePolicy: string;
  // How long the campaign waits for offline hosts, counted from creation.
  deadlineMinutes: number;
  // Whether the campaign stops after the canary for a decision.
  manualGate: boolean;
  // How many lost sessions mid-task pause the campaign; zero disables it.
  connectivityLost: number;
  // Why the change is made, or the change reference it answers to: the
  // sentence the audit trail keeps next to the order. Required, so the
  // trail does not fill with the operation name repeated.
  reason: string;
  // The maintenance window, as datetime-local values in the browser's
  // zone; either end may be empty. No host is started outside it.
  maintenanceStart: string;
  maintenanceEnd: string;
  // The units checked on every host once its change is done - after the
  // reboot when one follows, right after the change when none does. One
  // per line or comma-separated; empty means nothing is verified.
  healthCheckUnits: string;
  // How long one host's task may run, in seconds; zero takes the
  // operation's own default from the catalogue.
  jobTimeoutSeconds: number;
  // Whether the campaign waits for a consent before anything runs. A
  // critical operation cannot turn it off.
  requiresApproval: boolean;
  // Whether the order is kept for a moment instead of placed now: the
  // first run as a datetime-local value in the browser's zone, and the
  // rule of the moments after it. The schedule places the same order
  // through the same door at its moments; each campaign then waits for
  // its approval like any other.
  schedule: ScheduleChoice;
};

/** The moment an order is kept for, and the rule of the moments after it. */
export type ScheduleChoice = { enabled: boolean; startAt: string; recurrence: RecurrenceForm };

/**
 * What is wrong with the schedule of an order, or null when nothing is
 * or nothing is scheduled: a single run needs a moment ahead, a recurring
 * one a complete rule.
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
 * placed now, kept for the moment, with the reason on the schedule as
 * well - it is what the trail keeps next to the schedule and what every
 * campaign it places carries.
 */
export function scheduleBody(order: Order, risk: string | undefined): Record<string, unknown> {
  const rule = recurrenceText(order.schedule.recurrence);
  return {
    name: order.name,
    order: campaignBody(order, risk),
    start_at: windowInstant(order.schedule.startAt),
    recurrence: rule || undefined,
    timezone: browserZone(),
    reason: order.reason.trim(),
  };
}

/**
 * The expression the order carries: the chosen group and the tag rules
 * joined by "all". Null means the flat filters decide.
 */
function expressionOf(order: Order): SelectorExpression | null {
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
};

/**
 * The operation catalogue under /api/v1/actions, read once and shared by
 * every screen that draws something from an operation's contract: the
 * wizard, the campaign page and the job list. The registry changes only
 * with a release of the control plane, so the copy stays fresh for a good
 * while and one screen does not fetch what another just did.
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
 * their host counts - counted in the database, under the same key the
 * host list and the dashboard read them by, so one screen does not fetch
 * what another just did.
 */
export function useFleetFacets() {
  return useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    staleTime: 60_000,
  });
}

/**
 * The values a target field may take, offered under an input that still
 * takes free text: the sites the fleet really has are a hint, not a
 * boundary - a site with no host yet is a valid selector that matches
 * nobody, and the preview says so.
 */
export function FacetList({ id, facets }: { id: string; facets?: Facet[] }) {
  return (
    <datalist id={id}>
      {(facets ?? []).map((facet) => (
        <option key={facet.key} value={facet.key} label={`${facet.count}`} />
      ))}
    </datalist>
  );
}

/**
 * The reverse of a change, where a true one exists: an operation that puts
 * back what the forward one changed, as a new plan the operator approves.
 * A restart or a signal has no reverse, and the list says so by leaving
 * it out.
 *
 * A network profile and a firewall rule set have a reverse on one host -
 * the rollback plan the host kept under the identifier the change
 * reported - but not as a campaign: the identifier is minted on each host
 * from its own clock, and the plan leaves the host the moment the change
 * is confirmed. One payload could name one host's plan at most, and a
 * settled campaign has already confirmed every host. The families are
 * left out here on purpose, so the campaign page says there is no reverse
 * to plan rather than offering an order the engine refuses.
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
 * The address of the wizard with an order half written. A rollback link
 * names the campaign it undoes as well, so the order is created as its
 * compensation and the two campaigns are linked rather than merely named
 * alike.
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
 * The words for every class of the contract: a short label for the chip
 * and one sentence for the tooltip. The values are the registry's; the
 * words are the panel's, so a class the panel does not know yet shows as
 * it came instead of as nothing.
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

function describeClaim(t: (text: string) => string, claim: ResourceClaim): string {
  const mode = claim.mode === "exclusive" ? t("exclusive") : t("shared");
  return claim.weight > 1 ? `${claim.class} (${mode} ×${claim.weight})` : `${claim.class} (${mode})`;
}

/**
 * The contract of an operation as small chips, each with its sentence on
 * hover: what a cancel does, whether a repeat is safe, what way back
 * exists, what is verified and which host resources the operation takes.
 */
export function ContractChips({ contract }: { contract: OperationContract }) {
  const t = useT();
  const chips: [string, string, string][] = [];
  for (const [field, value, label] of [
    ["cancel", contract.cancel_mode, t("cancel")],
    ["retry", contract.retry_class, t("retry")],
    ["rollback", contract.rollback, t("rollback")],
    ["verification", contract.verification, t("verification")],
  ] as const) {
    if (!value) continue;
    const [word, meaning] = contractWords(t, field, value);
    chips.push([`${label}: ${word}`, meaning, field === "rollback" && value === "none" ? "warn" : ""]);
  }
  const claims = contract.resource_claims ?? [];
  if (claims.length > 0) {
    chips.push([
      `${t("claims")}: ${claims.map((claim) => describeClaim(t, claim)).join(", ")}`,
      t("The host resources the operation holds while it runs. An exclusive claim keeps every other change off that resource; shared claims coexist and their weight is what they cost the host."),
      "",
    ]);
  }
  if (chips.length === 0) return null;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {chips.map(([label, meaning, kind]) => (
        <span key={label} className={`badge ${kind}`} title={meaning}>{label}</span>
      ))}
    </div>
  );
}

/**
 * The payload of the order. The few operations with a form build it from
 * the fields; every other one takes the JSON the operator edited, starting
 * from the server's template. The server validates it the same way as an
 * order typed by hand and names what is wrong.
 */
function orderPayload(order: Order): Record<string, unknown> | null {
  if (UNIT_OPERATIONS.includes(order.action)) return { unit: { unit: order.unit } };
  if (order.action === "packages.upgrade") return { package_upgrade: { security_only: order.securityOnly } };
  if (order.action === RENAME_OPERATION) {
    // Only the hosts given a name travel; an order that names nobody is
    // no order, and the server refuses an empty mapping the same way.
    const mapping = Object.fromEntries(
      Object.entries(order.mapping).map(([id, name]) => [id, name.trim()] as const).filter(([, name]) => name !== ""),
    );
    if (Object.keys(mapping).length === 0) return null;
    return { hostname: { pretty: order.pretty.trim() || undefined, mapping } };
  }
  try {
    const parsed = JSON.parse(order.payloadText);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

type Group = { reason: string; count: number; sample: string[] };

type Preview = {
  count: number;
  limit: number;
  eligible?: number;
  sample?: string[];
  excluded?: Group[];
  notes?: Group[];
  campaign_mode?: string;
  requires_plan?: boolean;
  // Every ready host by identifier, for an operation whose order names
  // each host by itself; absent for every other operation.
  hosts?: { id: string; hostname: string }[];
  // The distribution of the snapshot: thirty hosts from one site are a
  // different change than thirty spread over three.
  distribution?: Record<string, Group[]>;
  // The campaign the order would undo, as the server checked it, with the
  // number of hosts it changed - the only hosts the order may name.
  compensates?: { id: string; name: string; state: string; changed: number };
};

/**
 * The steps go in the order the system really works in.
 *
 * The document puts the plans before the rollout policy. Here the plan is
 * computed as the first phase of the campaign - and the campaign must already
 * know its policy, because it enters the approval fingerprint. The order is
 * therefore different, and it is better to show it plainly than to pretend a
 * plan can be computed before the order.
 */
const STEPS = [
  "Scope",
  "Targets",
  "Eligibility",
  "Rollout",
  "Window & verification",
  "Create",
  "Plans",
  "Approval & run",
];

/** A transition gate: the next step opens only when there is a reason to. */
type Gate = { open: boolean; reason: string };

/**
 * The sentence for what is wrong with the window, or an empty string when
 * nothing is; the words live here so the gate and the field say the same.
 */
function windowWords(t: (text: string) => string, problem: WindowProblem | null): string {
  switch (problem) {
    case "start_invalid":
    case "end_invalid":
      return t("the maintenance window is not a valid date and time");
    case "start_past":
      return t("the maintenance window starts in the past");
    case "end_past":
      return t("the maintenance window has already ended");
    case "end_before_start":
      return t("the maintenance window ends before it starts");
  }
  return "";
}

/** The sentence for what is wrong with the schedule, or an empty string when nothing is. */
function scheduleWords(t: (text: string) => string, problem: ReturnType<typeof scheduleProblem>): string {
  switch (problem) {
    case "start_invalid":
      return t("the first run is not a valid date and time");
    case "start_past":
      return t("a single run has to lie ahead");
    case "moment_required":
      return t("give the schedule a first run or a recurrence");
    case "recurrence":
      return t("the recurrence is incomplete: a day, an hour and a minute");
  }
  return "";
}

function stepGates(
  t: (text: string, params?: Record<string, string | number>) => string,
  order: Order,
  preview?: Preview,
  campaign?: Campaign,
  refusal?: string,
): Gate[] {
  const hasAction = Boolean(order.action && order.name) &&
    (!UNIT_OPERATIONS.includes(order.action) || order.unit !== "") &&
    orderPayload(order) !== null;
  const hasTargets = (preview?.count ?? 0) > 0;
  const hasEligible = (preview?.eligible ?? 0) > 0;
  const exclusionsExplained = order.exclude.length === 0 || order.excludeReason.trim() !== "";
  const window = windowWords(t, windowProblem(order.maintenanceStart, order.maintenanceEnd, new Date()));
  const schedule = scheduleWords(t, scheduleProblem(order.schedule, new Date()));
  const timeoutFits = jobTimeoutValid(order.jobTimeoutSeconds);
  return [
    { open: hasAction && exclusionsExplained && !refusal, reason: refusal
      ? t("the catalogue refuses this operation in bulk: {reason}", { reason: refusal })
      : exclusionsExplained
        ? order.action === RENAME_OPERATION
          ? t("pick an operation, name the campaign and give at least one host its new name")
          : t("pick an operation, name the campaign and give it a valid payload")
        : t("give the exclusions a reason") },
    { open: hasAction && hasTargets, reason: t("the selector matches no host") },
    { open: hasEligible, reason: t("no matched host can run this operation") },
    { open: hasEligible, reason: t("no matched host can run this operation") },
    { open: window === "" && schedule === "" && timeoutFits, reason: window || schedule || t("the job timeout is out of bounds") },
    { open: Boolean(campaign), reason: t("the campaign does not exist yet") },
    { open: Boolean(campaign && campaign.state !== "planning"), reason: t("hosts are still planning") },
  ];
}

/**
 * ScopeBar: the name, the operation, the target count and the snapshot
 * fingerprint, pinned for the whole wizard.
 *
 * The operator is to see all the time what the thing they are setting up
 * applies to. A host count hidden two steps earlier is worth as much as its
 * absence.
 */
function ScopeBar({
  order,
  preview,
  campaign,
  targets,
  risk,
}: {
  order: Order;
  preview?: Preview;
  campaign?: Campaign;
  // The number the order is placed on: the named hosts when the address
  // carries them, the preview's count otherwise.
  targets: number;
  risk?: string;
}) {
  const t = useT();
  return (
    <div className="scope-bar">
      <div className="identity">
        <span className="name">{order.name || t("unnamed campaign")}</span>
        <span className="action">
          {order.action || t("no operation")}
          {/* The risk class of the operation decides the approvals and the
              step-up; it stays in view for the whole wizard. */}
          {risk && <span className={`badge ${risk === "critical" ? "error" : risk === "high" ? "warn" : ""}`}>{risk}</span>}
        </span>
      </div>
      <div className="facts">
        <span>
          {t("targets")}: <strong>{targets}</strong>
          {order.hostIDs.length > 0
            ? <> {t("named by identifier")}</>
            : preview && preview.eligible !== undefined && preview.eligible !== preview.count && (
              <> {t("of {n} matched", { n: preview.count })}</>
            )}
        </span>
        {preview?.campaign_mode && <span>{t("mode")}: {preview.campaign_mode}</span>}
        {/* What the order undoes stays in view for the whole wizard: a
            rollback approved without its original in sight is a change
            like any other. */}
        {preview?.compensates && (
          <span>
            {t("compensates")}: <Link to={`/campaigns/${preview.compensates.id}`}>{preview.compensates.name}</Link>
          </span>
        )}
        {campaign && (
          <>
            <span>
              {t("state")}: <JobState state={campaign.state} />
            </span>
            {/* The fingerprint is what the consent applies to. Without it
                "approved" does not say what was approved; the snapshot time
                says which fleet it was taken of. */}
            <span className="source">
              {t("fingerprint")} {campaign.approval_fingerprint.slice(0, 12)} · {t("snapshot")} <Time value={campaign.created_at} />
            </span>
          </>
        )}
      </div>
    </div>
  );
}

/** The operations the wizard can build a payload for. */
const UNIT_OPERATIONS = ["unit.start", "unit.stop", "unit.restart", "unit.reload", "unit.reset_failed"];
/** A rename in bulk: the payload is a mapping the wizard builds host by host. */
const RENAME_OPERATION = "system.hostname.set";
const WIZARD_OPERATIONS = [...UNIT_OPERATIONS, "packages.upgrade", RENAME_OPERATION];

function ScopeStep({
  order,
  change,
  bulk,
  refusals,
  preview,
  refusal,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  bulk: Operation[];
  refusals: Operation[];
  preview?: Preview;
  // Why the catalogue refuses the operation the address named in bulk,
  // so the refusal is read here and not from the server after the form
  // is filled in.
  refusal?: string;
}) {
  const t = useT();
  const needsUnit = UNIT_OPERATIONS.includes(order.action);
  const chosen = bulk.find((item) => item.action === order.action);
  const generic = Boolean(order.action) && !WIZARD_OPERATIONS.includes(order.action);
  const payloadValid = orderPayload(order) !== null;
  return (
    <Card
      title={`1. ${t("Scope")}`}
      description={t("The registry decides what may run on many hosts at once. An operation with no bulk mode is a deliberate refusal, not a missing screen.")}
    >
      {refusal && (
        <p className="page-error">
          {t("{action} does not run as a campaign: {reason}", { action: order.action, reason: refusal })}
        </p>
      )}
      <FieldGrid>
        <Field label={t("Name")}>
          <input
            placeholder={t("campaign name")}
            value={order.name}
            onChange={(e) => change({ name: e.target.value })}
          />
        </Field>
        <Field label={t("Operation")}>
          <select
            value={order.action}
            onChange={(e) => {
              // Choosing an operation loads its template: the operator edits
              // a shape the server already accepts, not a blank field.
              const next = bulk.find((item) => item.action === e.target.value);
              change({
                action: e.target.value,
                payloadText: next?.payload_template ? JSON.stringify(next.payload_template, null, 2) : "",
              });
            }}
          >
            <option value="">{t("pick an operation…")}</option>
            {bulk.map((item) => (
              <option key={item.action} value={item.action}>
                {item.action}{item.risk ? ` · ${item.risk}` : ""}
              </option>
            ))}
          </select>
        </Field>
        {chosen && (
          <Field
            label={t("Contract")}
            hint={t("What the panel may promise about this operation once it is on the host; hover a chip for the meaning.")}
            wide
          >
            <ContractChips contract={chosen} />
          </Field>
        )}
        {needsUnit && (
          <Field label={t("Unit")}>
            <input
              placeholder={t("unit, e.g. cron.service")}
              value={order.unit}
              onChange={(e) => change({ unit: e.target.value })}
            />
          </Field>
        )}
        {order.action === "packages.upgrade" && (
          <label className="toggle">
            <input
              type="checkbox"
              checked={order.securityOnly}
              onChange={(e) => change({ securityOnly: e.target.checked })}
            />{" "}
            {t("security updates only")}
          </label>
        )}
        {order.action === RENAME_OPERATION && (
          <MappingEditor order={order} change={change} hosts={preview?.hosts} />
        )}
        {generic && (
          <Field
            label={t("Payload (JSON, the same shape as a single-host operation)")}
            hint={!payloadValid
              ? t("This is not valid JSON.")
              : chosen?.needs_material
                ? t("The template carries a placeholder for certificate material; replace it with the real PEM before the order.")
                : t("The server validates the payload when the campaign is created and names what is wrong.")}
            wide
          >
            <textarea
              rows={Math.min(18, Math.max(6, order.payloadText.split("\n").length + 1))}
              value={order.payloadText}
              onChange={(e) => change({ payloadText: e.target.value })}
              spellCheck={false}
            />
          </Field>
        )}
      </FieldGrid>
      <TargetChoice order={order} change={change} />
      {preview?.requires_plan && (
        <p className="subtitle">
          {order.action === RENAME_OPERATION
            ? t("The mapping is split host by host: every host's plan is its own new name, and you approve the set of names, not one payload.")
            : t("Every host computes its own plan first. You approve the set of plans, not one payload, and a host whose plan changed in the meantime refuses the change.")}
        </p>
      )}
      {refusals.length > 0 && (
        <details>
          <summary className="subtitle">
            {t("{n} operations change hosts but cannot run as a campaign — with reasons", { n: refusals.length })}
          </summary>
          <table>
            <thead><tr><th>{t("Operation")}</th><th>{t("Why not")}</th></tr></thead>
            <tbody>
              {refusals.map((item) => (
                <tr key={item.action}>
                  <td className="mono">{item.action}</td>
                  <td className="source">{item.campaign_refusal}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </Card>
  );
}

/**
 * The mapping of a rename in bulk: one row per host the selector matches,
 * current name on the left, the new name typed on the right. A paste box
 * takes the same thing as CSV, "hostname,fqdn" per line, for a list kept
 * somewhere else. There is no shared name and no default: a host left
 * without a name is shown as ineligible here and settles so on the server.
 */
function MappingEditor({
  order,
  change,
  hosts,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  hosts?: { id: string; hostname: string }[];
}) {
  const t = useT();
  const [pasted, setPasted] = useState("");
  const rows = hosts ?? [];
  const named = rows.filter((host) => (order.mapping[host.id] ?? "").trim() !== "").length;
  const setName = (id: string, name: string) => change({ mapping: { ...order.mapping, [id]: name } });
  // The paste matches by the current name, full or short: the list the
  // operator keeps elsewhere rarely spells the names the way the
  // inventory does. A line that names no matched host is reported, not
  // dropped: silence would look like a host that was renamed.
  const applyPaste = () => {
    const byName = new Map<string, string>();
    for (const host of rows) {
      byName.set(host.hostname.toLowerCase(), host.id);
      byName.set(host.hostname.toLowerCase().split(".")[0], host.id);
    }
    const next = { ...order.mapping };
    const unmatched: string[] = [];
    for (const line of pasted.split("\n")) {
      const [current, fqdn] = line.split(/[,;\t]/).map((part) => part.trim());
      if (!current || !fqdn) continue;
      const id = byName.get(current.toLowerCase()) ?? byName.get(current.toLowerCase().split(".")[0]);
      if (!id) {
        unmatched.push(current);
        continue;
      }
      next[id] = fqdn;
    }
    change({ mapping: next });
    setPasted(unmatched.length ? unmatched.map((name) => `${name},`).join("\n") : "");
  };
  return (
    <>
      <Field label={t("Pretty name")} hint={t("Optional; set on every host the same. The static name comes from the mapping below.")}>
        <input value={order.pretty} onChange={(e) => change({ pretty: e.target.value })} placeholder={t("e.g. Web node")} />
      </Field>
      {/* A table of inputs is not one field: a label around it would
          send every click to the first input, so the frame is drawn by
          hand with the field classes. */}
      <div className="field wide">
        <span className="field-label">{t("New names, one host at a time")}</span>
        <table>
          <thead><tr><th>{t("Current hostname")}</th><th>{t("New FQDN")}</th><th></th></tr></thead>
          <tbody>
            {rows.map((host) => {
              const name = order.mapping[host.id] ?? "";
              return (
                <tr key={host.id}>
                  <td className="mono">{host.hostname}</td>
                  <td>
                    <input
                      className="mono"
                      value={name}
                      placeholder={t("new.fqdn.example")}
                      onChange={(e) => setName(host.id, e.target.value)}
                      spellCheck={false}
                    />
                  </td>
                  <td>
                    {name.trim() === ""
                      ? <span className="badge error">{t("no new name")}</span>
                      : name.trim().toLowerCase() === host.hostname.toLowerCase()
                        ? <span className="badge">{t("unchanged")}</span>
                        : <span className="badge ok">{t("renames")}</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <span className="field-hint">
          {rows.length === 0
            ? t("Pick the targets first: the rows come from the hosts the selector matches.")
            : t("{named} of {n} matched hosts have a new name. A host without one stays in the snapshot as ineligible; nothing is renamed to a default.", { named, n: rows.length })}
        </span>
      </div>
      <div className="field wide">
        <span className="field-label">{t("Paste as CSV")}</span>
        <textarea
          rows={4}
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          placeholder={"web01.old.example,web01.new.example\nweb02,web02.new.example"}
          spellCheck={false}
        />
        <span className="field-hint">
          {t("One host per line: hostname,fqdn. The hostname is matched to the rows above, full or short; a line that matches no host stays in the box.")}
        </span>
        <Actions>
          <button type="button" className="secondary" onClick={applyPaste} disabled={!pasted.trim()}>
            {t("Apply the pasted names")}
          </button>
        </Actions>
      </div>
    </>
  );
}

/**
 * How the targets are named: by the flat filters of the next step, or by
 * a saved group and tag rules. The second way builds the typed expression
 * the server compiles into the host query - it is shown here as the
 * campaign will carry it, so what the approver reads is what was sent.
 * Under it, the hosts left out by name, with the reason that goes into
 * the snapshot next to each of them.
 */
function TargetChoice({ order, change }: { order: Order; change: (delta: Partial<Order>) => void }) {
  const t = useT();
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<{ id: string; name: string; kind: string }>>("/api/v1/host-groups"),
    enabled: order.targetMode === "expression",
    staleTime: 60 * 1000,
  });
  const [excluding, setExcluding] = useState(false);
  const expression = expressionOf(order);
  return (
    <>
      <h4 className="widget-subhead">{t("Targets")}</h4>
      <FieldGrid>
        <Field label={t("Named by")} hint={order.targetMode === "expression"
          ? t("The expression decides alone; the site, environment and OS filters of the next step do not apply.")
          : t("Site, environment and OS family, set in the next step.")}>
          <select value={order.targetMode} onChange={(e) => change({ targetMode: e.target.value as Order["targetMode"] })}>
            <option value="filters">{t("site, environment and OS")}</option>
            <option value="expression">{t("groups and tags")}</option>
          </select>
        </Field>
        {order.targetMode === "expression" && (
          <Field label={t("Group")} hint={t("Optional; the rules below narrow it further.")}>
            <select value={order.group} onChange={(e) => change({ group: e.target.value })}>
              <option value="">{t("no group")}</option>
              {(groups.data?.items ?? []).map((group) => (
                <option key={group.id} value={group.name}>{group.name} · {group.kind}</option>
              ))}
            </select>
          </Field>
        )}
      </FieldGrid>
      {order.targetMode === "expression" && (
        <>
          <SelectorBuilder
            rules={order.rules}
            combine={order.combine}
            onRules={(rules) => change({ rules })}
            onCombine={(combine) => change({ combine })}
          />
          {/* The expression as the campaign will carry it: the structure
              the server compiles, not a sentence the panel made up. */}
          <p className="source">
            {expression
              ? <>{t("the campaign will carry")} <span className="mono">{describeExpression(expression)}</span></>
              : t("pick a group or give a rule a value; until then the selector names nobody")}
          </p>
        </>
      )}

      <h4 className="widget-subhead">{t("Exclude")}</h4>
      <p className="subtitle">
        {order.exclude.length === 0
          ? t("No host is left out by name. An excluded host stays in the snapshot as excluded, with the reason and your name next to it.")
          : t("{n} hosts left out by name; each stays in the snapshot as excluded, with the reason and your name next to it.", { n: order.exclude.length })}
      </p>
      {order.exclude.length > 0 && (
        <FieldGrid>
          <Field label={t("Reason for the exclusions")} hint={t("Required; it is what the approver reads next to every excluded host.")} wide>
            <input
              placeholder={t("e.g. the database primary; failing over first")}
              value={order.excludeReason}
              onChange={(e) => change({ excludeReason: e.target.value })}
            />
          </Field>
        </FieldGrid>
      )}
      {excluding ? (
        <>
          <HostChooser selected={new Set(order.exclude)} onChange={(next) => change({ exclude: [...next] })} />
          <Actions>
            <button type="button" className="secondary" onClick={() => setExcluding(false)}>{t("Done choosing")}</button>
          </Actions>
        </>
      ) : (
        <Actions>
          <button type="button" className="secondary" onClick={() => setExcluding(true)}>
            {order.exclude.length === 0 ? t("Exclude hosts by name") : t("Change the excluded hosts")}
          </button>
          {order.exclude.length > 0 && (
            <button type="button" className="secondary" onClick={() => change({ exclude: [], excludeReason: "" })}>{t("Clear the exclusions")}</button>
          )}
        </Actions>
      )}
    </>
  );
}

function TargetsStep({
  order,
  change,
  preview,
  refusal,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  preview?: Preview;
  // The server's refusal of the selector, when there is one: a
  // compensation narrowed to a host the original did not change is
  // refused here, with the host named, rather than at the creation.
  refusal?: unknown;
}) {
  const t = useT();
  // The values the fleet really has, offered under each field; free text
  // still goes through, and the count below says what it matched.
  const facets = useFleetFacets();
  return (
    <Card
      title={`2. ${t("Targets")}`}
      description={t("The count comes from the database, not from the first page of a list. The snapshot is frozen when the campaign is created; hosts added later do not join it.")}
      footer={
        <div>
          {refusal ? <ErrorBox error={refusal} /> : null}
          {/* A compensation may only name hosts the original changed; with
              the filters empty it takes all of them, and the operator is
              told so instead of reading it off an empty form. */}
          {order.compensates && preview?.compensates && (
            <p>
              {t("This campaign compensates {name}: only the {changed} hosts that campaign changed can be its targets. Leave the filters empty to take all of them, or narrow them to a part.", {
                name: preview.compensates.name, changed: preview.compensates.changed,
              })}
            </p>
          )}
          {/* The preview cannot count a host list, so the operator is told
              which number binds: the hosts the address named. */}
          {order.hostIDs.length > 0 && (
            <p>
              {t("The order names {n} hosts by identifier, from the campaign page; the campaign is created on those alone, whatever the filters below match.", { n: order.hostIDs.length })}
            </p>
          )}
          <p>
            {t("The selector matches {n} hosts", { n: preview?.count ?? 0 })}
            {preview && preview.count > preview.limit && (
              <> — {t("more than the {n} one campaign may carry", { n: preview.limit })}</>
            )}
            .
          </p>
          <div className="source">{(preview?.sample ?? []).join(", ")}</div>
          <Distribution preview={preview} />
        </div>
      }
    >
      <FieldGrid>
        <Field label={t("Site")} hint={t("Pick one the fleet has, or type any.")}>
          <input
            placeholder={t("site")}
            value={order.site}
            list="bulk-sites"
            onChange={(e) => change({ site: e.target.value })}
          />
          <FacetList id="bulk-sites" facets={facets.data?.by_site} />
        </Field>
        <Field label={t("Environment")} hint={t("Pick one the fleet has, or type any.")}>
          <input
            placeholder={t("environment")}
            value={order.environment}
            list="bulk-environments"
            onChange={(e) => change({ environment: e.target.value })}
          />
          <FacetList id="bulk-environments" facets={facets.data?.by_environment} />
        </Field>
        <Field label={t("OS family")} hint={t("Pick one the fleet has, or type any.")}>
          <input
            placeholder={t("os family")}
            value={order.osFamily}
            list="bulk-os-families"
            onChange={(e) => change({ osFamily: e.target.value })}
          />
          <FacetList id="bulk-os-families" facets={facets.data?.by_os_family} />
        </Field>
      </FieldGrid>
    </Card>
  );
}

/**
 * The distribution of the frozen snapshot by site, environment, OS family
 * and the required capability.
 *
 * The bare count of eligible hosts does not say what is about to happen:
 * thirty hosts from one site are a different change than thirty spread over
 * three.
 */
function Distribution({ preview }: { preview?: Preview }) {
  const t = useT();
  const dimensions = Object.entries(preview?.distribution ?? {}).filter(
    ([, groups]) => groups.length > 0,
  );
  if (!dimensions.length) return null;
  const names: Record<string, string> = {
    site: t("site"),
    environment: t("environment"),
    os_family: t("os family"),
    capability: t("capability"),
  };
  return (
    <div className="distribution">
      {dimensions.map(([dimension, groups]) => (
        <div key={dimension} className="source">
          {names[dimension] ?? dimension}:{" "}
          {groups.map((group) => `${group.reason} ${group.count}`).join(", ")}
        </div>
      ))}
    </div>
  );
}

function EligibilityStep({ order, preview, checking }: { order: Order; preview?: Preview; checking: boolean }) {
  const t = useT();
  if (checking) return <Empty>{t("Checking every matched host…")}</Empty>;
  // A rename names every host in its mapping; a matched host the mapping
  // leaves out will settle as ineligible on the server, and is listed so
  // here, before the order, under the code the server will give it.
  const unnamed = order.action === RENAME_OPERATION
    ? (preview?.hosts ?? []).filter((host) => (order.mapping[host.id] ?? "").trim() === "")
    : [];
  const excluded = [...(preview?.excluded ?? [])];
  if (unnamed.length > 0) {
    excluded.push({ reason: "no_hostname_for_host", count: unnamed.length, sample: unnamed.slice(0, 12).map((host) => host.hostname) });
  }
  const notes = preview?.notes ?? [];
  const eligible = Math.max(0, (preview?.eligible ?? 0) - unnamed.length);
  const sample = unnamed.length > 0
    ? (preview?.hosts ?? []).filter((host) => (order.mapping[host.id] ?? "").trim() !== "").slice(0, 12).map((host) => host.hostname)
    : preview?.sample ?? [];
  return (
    <Card
      title={`3. ${t("Eligibility")}`}
      description={t("A host that cannot run this operation stays in the snapshot with its reason. Dropping it quietly would hide a decision nobody made.")}
      footer={!excluded.length && !notes.length && (
        <p>{t("Every matched host can run this operation.")}</p>
      )}
      flush
    >
      <table>
        <thead>
          <tr><th>{t("Bucket")}</th><th className="num">{t("Hosts")}</th><th>{t("Which")}</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><span className="badge ok">{t("eligible")}</span></td>
            <td className="num">{eligible}</td>
            <td className="source">{sample.join(", ")}</td>
          </tr>
          {excluded.map((group) => (
            <tr key={group.reason}>
              <td><span className="badge error">{reasonName(t, group.reason)}</span></td>
              <td className="num">{group.count}</td>
              <td className="source">{group.sample.join(", ")}</td>
            </tr>
          ))}
          {/* A note does not exclude the host. An offline host comes back
              and does its part; a host in a conflict waits for somebody
              else's lock. */}
          {notes.map((group) => (
            <tr key={group.reason}>
              <td><span className="badge warn">{reasonName(t, group.reason)}</span></td>
              <td className="num">{group.count}</td>
              <td className="source">{group.sample.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function reasonName(t: (text: string) => string, reason: string): string {
  const names: Record<string, string> = {
    capability_missing: t("no adapter"),
    capability_unknown: t("adapter unknown"),
    maintenance: t("in maintenance"),
    quarantined: t("quarantined"),
    out_of_scope: t("out of your scope"),
    conflict: t("in another campaign"),
    offline: t("offline"),
    no_hostname_for_host: t("no new name in the mapping"),
  };
  return names[reason] ?? reason;
}

/**
 * The offline policies, from the one that does the most with an offline host
 * to the one that does the least. A campaign may move down this list and
 * never up: the operation's own policy is the boundary its module drew, and
 * the server refuses a request that loosens it.
 */
const OFFLINE_POLICIES = ["wait_until_deadline", "replan_on_reconnect", "skip_if_offline", "require_online"];

function RolloutStep({
  order,
  change,
  targets,
  declaredPolicy,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  targets: number;
  declaredPolicy?: string;
}) {
  const t = useT();
  const policyNames: Record<string, string> = {
    wait_until_deadline: t("wait for the host until the deadline"),
    replan_on_reconnect: t("wait, then compute the plan again when the host is back"),
    skip_if_offline: t("leave the host out, not a failure"),
    require_online: t("skip the host and say it was offline"),
  };
  // Only the policies at least as strict as the operation's own are offered;
  // the rest would be refused anyway, and a refusal after the form is filled
  // in is worse than a shorter list with the reason next to it.
  const declaredIndex = declaredPolicy ? OFFLINE_POLICIES.indexOf(declaredPolicy) : -1;
  const offered = OFFLINE_POLICIES.filter((policy, index) =>
    index >= declaredIndex && (policy !== "replan_on_reconnect" || declaredPolicy === "replan_on_reconnect"));
  return (
    <Card
      title={`4. ${t("Rollout")}`}
      description={
        <>
          {t("Canary is wave zero. The concurrency limit says how many hosts move at once in this change; fleet and site budgets say how much the system carries in total, and a host waiting for capacity says so instead of standing still.")}
          {" "}
          <Link to="/budgets">{t("See the budgets.")}</Link>
        </>
      }
      footer={
        <p>
          {t("{targets} hosts, canary {canary}, then waves of {wave} with at most {concurrent} at a time.", {
            targets, canary: order.canary, wave: order.wave, concurrent: order.concurrent,
          })}
        </p>
      }
    >
      <FieldGrid>
        <Field label={t("Canary")}>
          <input type="number" min={0} value={order.canary}
            onChange={(e) => change({ canary: +e.target.value })} />
        </Field>
        <Field label={t("Wave")}>
          <input type="number" min={1} value={order.wave}
            onChange={(e) => change({ wave: +e.target.value })} />
        </Field>
        <Field label={t("Concurrent hosts")}>
          <input type="number" min={1} value={order.concurrent}
            onChange={(e) => change({ concurrent: +e.target.value })} />
        </Field>
        <Field label={t("threshold %")}>
          <input type="number" min={0} max={100} value={order.thresholdPercent}
            onChange={(e) => change({ thresholdPercent: +e.target.value })} />
        </Field>
        <Field label={t("threshold count")}>
          <input type="number" min={0} value={order.thresholdCount}
            onChange={(e) => change({ thresholdCount: +e.target.value })} />
        </Field>
        <Field label={t("Reboot policy")}>
          <select value={order.rebootPolicy}
            onChange={(e) => change({ rebootPolicy: e.target.value })}>
            <option value="never">{t("reboot: never")}</option>
            <option value="if_required">{t("reboot: when required")}</option>
            <option value="always">{t("reboot: always")}</option>
          </select>
        </Field>
        <Field label={t("Reboot timeout (seconds)")}
          hint={t("How long a rebooted host is waited for before it fails; a host still away when the maintenance window ends fails at once and pauses the campaign.")}>
          <input type="number" min={REBOOT_TIMEOUT.min} max={REBOOT_TIMEOUT.max} step={60}
            value={order.rebootTimeoutSeconds}
            disabled={order.rebootPolicy === "never"}
            onChange={(e) => change({ rebootTimeoutSeconds: +e.target.value })} />
        </Field>
        <Field label={t("connectivity loss threshold")}
          hint={t("Pause once this many hosts lose their session mid-task; 0 turns the check off. A change that cuts hosts off shows up here, not among the failures.")}>
          <input type="number" min={0} value={order.connectivityLost}
            onChange={(e) => change({ connectivityLost: +e.target.value })} />
        </Field>
        <Field label={t("Offline policy")}
          hint={declaredPolicy
            ? t("The operation declares {policy}; a campaign may only tighten it.", { policy: declaredPolicy })
            : t("What happens to a host that is not connected when its turn comes.")}>
          <select value={order.offlinePolicy}
            onChange={(e) => change({ offlinePolicy: e.target.value })}>
            <option value="">{t("as the operation declares")}</option>
            {offered.map((policy) => (
              <option key={policy} value={policy}>{policy}: {policyNames[policy]}</option>
            ))}
          </select>
        </Field>
        <Field label={t("Deadline for offline hosts (minutes)")}
          hint={t("Counted from the creation; a host still offline by then is left out with a reason.")}>
          <input type="number" min={1} value={order.deadlineMinutes}
            onChange={(e) => change({ deadlineMinutes: +e.target.value })} />
        </Field>
        {/* A gate after the canary needs a canary to gate on: with none the
            box is off, and the hint says why rather than leaving a control
            that does nothing. */}
        <div className="field">
          <label className="toggle">
            <input
              type="checkbox"
              checked={order.manualGate && order.canary > 0}
              disabled={order.canary <= 0}
              onChange={(e) => change({ manualGate: e.target.checked })}
            />{" "}
            {t("stop after the canary until somebody advances the campaign")}
          </label>
          {order.canary <= 0 && (
            <span className="field-hint">{t("A manual gate needs a canary: set the canary above 0 to stop after it.")}</span>
          )}
        </div>
      </FieldGrid>
    </Card>
  );
}

/**
 * The window the change may run in, and what is checked afterwards. Both
 * live in the campaign record and enter the approval fingerprint, so they
 * are settled before the campaign exists - the approver reads them as
 * part of what is approved.
 */
function WindowStep({
  order,
  change,
  operation,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  operation?: Operation;
}) {
  const t = useT();
  const problem = windowProblem(order.maintenanceStart, order.maintenanceEnd, new Date());
  const units = parseUnits(order.healthCheckUnits);
  const forced = approvalForced(operation?.risk);
  const timeoutFits = jobTimeoutValid(order.jobTimeoutSeconds);
  const schedule = order.schedule;
  const scheduleFault = scheduleWords(t, scheduleProblem(schedule, new Date()));
  const changeSchedule = (delta: Partial<ScheduleChoice>) => change({ schedule: { ...schedule, ...delta } });
  return (
    <Card
      title={`5. ${t("Window and verification")}`}
      description={t("No host is started outside the maintenance window, and every host is checked once its change is done. Both go into the fingerprint the approver signs.")}
    >
      <FieldGrid>
        <Field label={t("Window opens")}
          hint={problem === "start_past" || problem === "start_invalid"
            ? windowWords(t, problem)
            : t("Optional; hosts wait until then. Local time.")}>
          <input type="datetime-local" value={order.maintenanceStart}
            onChange={(e) => change({ maintenanceStart: e.target.value })} />
        </Field>
        <Field label={t("Window closes")}
          hint={problem === "end_past" || problem === "end_before_start" || problem === "end_invalid"
            ? windowWords(t, problem)
            : t("Optional; no host is started once it closes - a host still waiting stays held back, and a host still rebooting fails and pauses the campaign.")}>
          <input type="datetime-local" value={order.maintenanceEnd} min={order.maintenanceStart || undefined}
            onChange={(e) => change({ maintenanceEnd: e.target.value })} />
        </Field>
        <Field label={t("Units to check afterwards")}
          hint={units.length === 0
            ? t("One unit per line or comma-separated, e.g. nginx.service. Checked on every host right after the change, or after the reboot when one follows; empty means nothing is verified.")
            : t("{n} units will be checked on every host once its change is done.", { n: units.length })}
          wide>
          <textarea rows={3} className="mono" value={order.healthCheckUnits}
            placeholder={"nginx.service\nphp-fpm.service"}
            onChange={(e) => change({ healthCheckUnits: e.target.value })} spellCheck={false} />
        </Field>
        <Field label={t("Job timeout (seconds)")}
          hint={!timeoutFits
            ? t("Between {min} and {max} seconds, or 0 for the operation's default.", { min: JOB_TIMEOUT.min, max: JOB_TIMEOUT.max })
            : operation?.default_timeout_seconds
              ? t("How long one host's task may run; 0 keeps the operation's default of {n} seconds.", { n: operation.default_timeout_seconds })
              : t("How long one host's task may run; 0 keeps the operation's default.")}>
          <input type="number" min={0} max={JOB_TIMEOUT.max} step={30} value={order.jobTimeoutSeconds}
            onChange={(e) => change({ jobTimeoutSeconds: +e.target.value })} />
        </Field>
        <div className="field">
          <label className="toggle">
            <input
              type="checkbox"
              checked={forced || order.requiresApproval}
              disabled={forced}
              onChange={(e) => change({ requiresApproval: e.target.checked })}
            />{" "}
            {t("requires an approval before anything runs")}
          </label>
          <span className="field-hint">
            {forced
              ? t("A {risk} operation cannot skip the approval: the consent is what binds the fingerprint of what runs on the fleet.", { risk: operation?.risk ?? "critical" })
              : t("The approver signs the operation, the payload, the host list, the rollout policy and the set of plans as one fingerprint.")}
          </span>
        </div>
      </FieldGrid>
      {/* The order kept for a moment instead of placed now. The schedule
          places this same order through the same door at its moments, so
          everything above still applies to each campaign it places - the
          window, the checks, the approval. */}
      <FieldGrid>
        <div className="field wide">
          <label className="toggle">
            <input type="checkbox" checked={schedule.enabled} onChange={(e) => changeSchedule({ enabled: e.target.checked })} />{" "}
            {t("Schedule instead of ordering now")}
          </label>
          <span className="field-hint">
            {schedule.enabled
              ? scheduleFault || t("The order is kept and placed at its moments under your rights as they stand then; each campaign waits for its approval. Listed under Campaigns › Schedules.")
              : t("Keep the order for a moment ahead, once or on a monthly or weekly rule, instead of creating the campaign now.")}
          </span>
        </div>
        {schedule.enabled && (
          <>
            <Field label={t("First run")}
              hint={schedule.recurrence.freq
                ? t("Optional with a recurrence: the earliest moment the rule may name.")
                : t("The one moment the order is placed at. Local time.")}>
              <input type="datetime-local" value={schedule.startAt} onChange={(e) => changeSchedule({ startAt: e.target.value })} />
            </Field>
            <RecurrenceFields value={schedule.recurrence} onChange={(recurrence) => changeSchedule({ recurrence })} />
          </>
        )}
      </FieldGrid>
    </Card>
  );
}

function CreateStep({
  order,
  change,
  targets,
  compensates,
  campaignID,
  onCreated,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  targets: number;
  compensates?: Preview["compensates"];
  campaignID: string;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  const queryClient = useQueryClient();
  const operation = useOperation(order.action || undefined);
  const reasonOK = reasonValid(order.reason);

  const create = useMutation({
    mutationFn: () => api.post<Campaign>("/api/v1/campaigns", campaignBody(order, operation?.risk)),
    onSuccess: (campaign) => {
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onCreated(campaign.id);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });
  // A scheduled order creates no campaign now: the schedule is the
  // record, and the wizard ends here with a link to it.
  const [scheduled, setScheduled] = useState("");
  const schedule = useMutation({
    mutationFn: () => api.post<{ id: string }>("/api/v1/campaign-schedules", scheduleBody(order, operation?.risk)),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["campaign-schedules"] });
      clearDraft(sessionStorageOrNull());
      setScheduled(created.id);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });
  const scheduling = order.schedule.enabled;

  return (
    <Card
      title={`6. ${t("Create")}`}
      description={t("Creating the campaign freezes the snapshot. Nothing changes on any host yet.")}
    >
      {/* The link is part of what is created: the operator is to read
          which campaign this one undoes before pressing the button, not
          find out from the campaign page afterwards. */}
      {order.compensates && (
        <p>
          {t("Compensates campaign")}{" "}
          {compensates
            ? <Link to={`/campaigns/${compensates.id}`}>{compensates.name}</Link>
            : <span className="mono">{order.compensates}</span>}
          {" · "}
          {t("The original is linked, never rewritten; its hosts get a compensate step as the reverse change runs on them.")}
        </p>
      )}
      <FieldGrid>
        {/* The reason is the one sentence the audit trail keeps next to
            the order; the operation name repeated there would say nothing
            the record does not already say. */}
        <Field label={t("Reason or change reference")}
          hint={reasonOK
            ? t("Kept in the audit trail next to the order, and shown to the approver.")
            : t("Required: at least {n} characters, e.g. the change ticket and what it fixes.", { n: MIN_REASON })}
          wide>
          <input
            value={order.reason}
            placeholder={t("e.g. CHG-1234: rotate the web tier onto the patched kernel")}
            onChange={(e) => change({ reason: e.target.value })}
            disabled={Boolean(campaignID)}
          />
        </Field>
      </FieldGrid>
      <Actions>
        {scheduling ? (
          <button onClick={() => schedule.mutate()} disabled={schedule.isPending || Boolean(scheduled) || !reasonOK}>
            {schedule.isPending ? t("Scheduling…") : t("Schedule a campaign on {n} hosts", { n: targets })}
          </button>
        ) : (
          <button onClick={() => create.mutate()} disabled={create.isPending || Boolean(campaignID) || !reasonOK}>
            {create.isPending ? t("Creating…") : t("Create a campaign on {n} hosts", { n: targets })}
          </button>
        )}
        {scheduled && (
          <span className="source">
            {t("The schedule is recorded; the campaign is created at its moment.")}{" "}
            <Link to="/campaigns/schedules">{t("Open the schedules")}</Link>
          </span>
        )}
        {errorMessage && <p className="page-error">{errorMessage}</p>}
      </Actions>
    </Card>
  );
}

function PlansStep({ campaignID, campaign }: { campaignID: string; campaign?: Campaign }) {
  const t = useT();
  const targets = useTargets(campaignID, {});
  // The consent covers the set of plans, so the operator is to see that set
  // - grouped, because a hundred hosts with an identical diff are one
  // change, not a hundred.
  const plans = useQuery({
    queryKey: ["campaign-plans", campaignID],
    queryFn: () => api.get<PlanGroups>(`/api/v1/campaigns/${campaignID}/plans`),
    enabled: Boolean(campaignID),
    refetchInterval: OPERATIONS_INTERVAL,
  });
  if (targets.error) return <ErrorBox error={targets.error} />;

  const planning = campaign?.state === "planning";
  const groups = plans.data?.items ?? [];
  return (
    <Card
      title={`7. ${t("Plans")}`}
      description={planning
        ? t("Each host is computing its own diff. Nothing is applied while this runs.")
        : t("Every host has its plan. The fingerprint below covers the whole set: a host whose plan changed refuses the change.")}
      flush
    >
      {/* One group is one shape of the change: its hosts, fingerprint and
          expiry in a header line, then the change itself as a table the
          operator can read package by package. */}
      {groups.length > 0 && (
        <div className="plan-groups">
          {groups.map((group) => (
            <PlanGroupView key={group.plan_hash} group={group} action={campaign?.action_type} />
          ))}
        </div>
      )}
      <TargetTable targets={targets} action={campaign?.action_type ?? ""} />
    </Card>
  );
}

/** The plans of a campaign grouped by fingerprint, as the panel serves them. */
export type PlanGroups = {
  items: PlanGroup[];
  plan_set_hash?: string;
  plan_ttl_seconds?: number;
};

function ApprovalStep({ campaignID, campaign }: { campaignID: string; campaign?: Campaign }) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  // The reason and the change ticket go into the approval record next to
  // the fingerprint; a critical operation cannot be approved without the
  // reason.
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const queryClient = useQueryClient();
  const targets = useTargets(campaignID, {});
  const approve = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/campaigns/${campaignID}/approve`, {
        reason: reason.trim(),
        change_ticket: ticket.trim(),
        // The consent carries the fingerprint of what is on screen. A
        // campaign changed since it was loaded ends in a refusal, not in the
        // consent being transferred.
        approval_fingerprint: campaign?.approval_fingerprint,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["campaign", campaignID] }),
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  if (!campaign) return <Empty>{t("No campaign yet.")}</Empty>;
  return (
    <Card
      title={`8. ${t("Approval and run")}`}
      description={t("You are approving this operation, this payload, this list of hosts, this rollout policy and this set of plans - together, as one fingerprint.")}
      flush
    >
      <p className="source mono">{t("fingerprint")} {campaign.approval_fingerprint}</p>
      {errorMessage && <p className="page-error">{errorMessage}</p>}
      {campaign.state === "awaiting_approval" ? (
        <>
          <FieldGrid>
            {/* The consent is what the audit record keeps next to the
                fingerprint; a consent without a reason is noise there, so
                the button waits for one whatever the risk class. */}
            <Field label={t("Reason (kept in the audit trail)")}
              hint={reasonValid(reason)
                ? t("Recorded with the fingerprint; a critical operation asks for fresh authentication as well.")
                : t("Required: at least {n} characters.", { n: MIN_REASON })}
              wide>
              <input value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
            <Field label={t("Change ticket")} hint={t("Optional: the identifier or address of the change request.")}>
              <input value={ticket} onChange={(e) => setTicket(e.target.value)} placeholder="CHG-1234" />
            </Field>
          </FieldGrid>
          <p>
            <button onClick={() => approve.mutate()} disabled={approve.isPending || !reasonValid(reason)}>
              {approve.isPending ? t("Approving…") : t("Approve and start")}
            </button>
          </p>
        </>
      ) : (
        <p>
          {t("This campaign is")} <JobState state={campaign.state} />.{" "}
          {/* Pausing and cancelling belong to the campaign screen: the
              consequences are described there, and this wizard does not
              repeat them. */}
          <Link to={`/campaigns/${campaign.id}`}>{t("Pause, cancel or read the report")}</Link>.
        </p>
      )}
      <TargetTable targets={targets} action={campaign.action_type} />
    </Card>
  );
}

/**
 * The target table with the blocker. A host that stands still is to say
 * what it waits for: a budget, somebody else's resource lock, or coming back
 * online.
 */
function TargetTable({ targets, action }: { targets: ReturnType<typeof useTargets>; action: string }) {
  const t = useT();
  const rows = loadedTargets(targets.data);
  const total = targets.data?.pages[0]?.total ?? 0;
  if (!rows.length) return <Empty>{t("No targets.")}</Empty>;
  return (
    <>
    {/* The rows are windowed and the next page is fetched as the operator
        nears the end: the loaded pages do not become that many elements. */}
    <VirtualRows
      items={rows}
      rowHeight={40}
      height={480}
      columns={5}
      rowKey={(target) => target.host_id}
      head={<tr><th>{t("Host")}</th><th>{t("Wave")}</th><th>{t("State")}</th><th>{t("Blocker")}</th><th>{t("Message")}</th></tr>}
      onNearEnd={targets.hasNextPage && !targets.isFetchingNextPage ? () => targets.fetchNextPage() : undefined}
      loading={targets.isFetchingNextPage}
      render={(target) => (
        <>
          <td>
            <Link to={`/hosts/${target.host_id}/${moduleForAction(action)}?campaign=${target.campaign_id}`}>
              {target.hostname || target.host_id.slice(0, 8)}
            </Link>
          </td>
          <td>{target.wave}{target.wave === 0 && ` (${t("canary")})`}</td>
          <td><JobState state={target.state} /></td>
          <td>{blockerName(t, target)}</td>
          <td title={target.message}>{target.message || "—"}</td>
        </>
      )}
    />
    {/* The rows come page by page: a campaign on the whole fleet must not
        become the whole fleet in the browser. The button stays next to the
        automatic fetch, so a page that failed to arrive can be asked for by
        hand. */}
    <p className="source">
      {t("{shown} of {total} shown", { shown: rows.length, total })}
      {targets.hasNextPage && (
        <>
          {" "}
          <button className="secondary" onClick={() => targets.fetchNextPage()} disabled={targets.isFetchingNextPage}>
            {t("Load more ({n} left)", { n: total - rows.length })}
          </button>
        </>
      )}
    </p>
    </>
  );
}

/** blockerName names the kind of obstacle, not the bare error code. */
function blockerName(t: (text: string) => string, target: CampaignTarget): string {
  if (!target.error_code) return "—";
  if (target.error_code.startsWith("budget_")) return t("budget");
  if (target.error_code === "resource_busy") return t("resource lock");
  if (target.error_code === "capability_missing") return t("capability");
  if (target.error_code === "maintenance") return t("maintenance");
  if (target.error_code === "no_hostname_for_host") return t("no new name in the mapping");
  return target.error_code;
}
