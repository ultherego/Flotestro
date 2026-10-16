import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, loadedItems, LIST_PAGE, type Collection, type Page } from "../../lib/api";
import { useDebounced } from "../../lib/debounce";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import { OPERATIONS_INTERVAL } from "../../lib/stream";
import { useCapabilities } from "../../lib/capabilities";
import { loadedTargets, REBOOT_TIMEOUT, useTargets } from "../../lib/targets";
import { moduleForAction } from "../../lib/modules";
import {
  body, count, flag, operationForm, payloadTextOf, readPayloadText, startingForm, text,
  type FieldValue, type FormValue, type OperationEntry, type OperationField,
} from "../../lib/operations";
import type {
  Campaign, CampaignTarget, Host, OperationContract, ResourceClaim, SelectorExpression,
} from "../../lib/types";
import { stateName } from "../../lib/states";
import {
  changeAction, isPackageChange, planStatus, planWords, ACTION_WORDS,
  type HostPlan, type PackagePlanFacts, type PlanGroup,
} from "../../components/plan";
import { buildExpression, describeExpression, RULE_FIELDS, type Rule, type RuleField } from "../../pages/Groups";
import { WEEKDAYS, type RecurrenceForm } from "../../pages/Schedules";
import {
  campaignBody, clearDraft, contractWords, emptyOrder, FacetList, JOB_TIMEOUT, jobTimeoutValid,
  loadDraft, matchedState, MIN_REASON, orderForm, orderTargets, parseUnits, prefilledOrder,
  previewTokenOf, reasonValid, saveDraft, scheduleBody, scheduleProblem, selectorNames,
  startingPayloadText, useFleetFacets, useOperations, windowProblem, wizardOperations,
  type Operation, type PreviewToken, type ScheduleChoice, type TargetMode, type WindowProblem,
} from "../../pages/Bulk";
import { useT, type Translate } from "../../i18n";
import {
  Actions, Banner, Bones, Card, Check, Dot, Empty, Fact, Facts, Field, Fields, Find, Grid,
  Note, Pill, Problem, Screen, Seg, Stack, Table, Tabs, Tag, Tags, type Tone, Toolbar, TwoLine,
} from "../kit";

/**
 * The bulk workspace: the second, equal path of work beside the host
 * screens. One machine at a time is the host workspace; this is where the
 * fleet is changed.
 *
 * It is a wizard because the order is a wizard: what runs, where it runs,
 * which of those hosts can run it, how fast, when it may run, and only
 * then the campaign itself, its plans and the consent. Nothing leaves this
 * screen until that consent, and the consent covers exactly what the
 * screen showed - one fingerprint over the operation, the payload, the
 * host list, the rollout policy and the set of plans.
 *
 * A step opens when the one before it has a reason to be done with; the
 * reason a step is shut is written next to it rather than left as a
 * button that does nothing.
 */

/** The order as the wizard keeps it, from the one place that defines it. */
type Order = ReturnType<typeof emptyOrder>;

/** The answer of the preview endpoint. */
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
  // The binding between this answer and the order placed from it.
  preview_id?: string;
  preview_digest?: string;
  expires_at?: string;
};

/** The plans of a campaign grouped by fingerprint, as the panel serves them. */
type PlanGroups = { items: PlanGroup[]; plan_set_hash?: string; plan_ttl_seconds?: number };

/**
 * The steps, in the order the system really works in: the plans come
 * before the consent, because the consent is over the plans.
 */
const STEPS = [
  "Scope",
  "Targets",
  "Eligibility",
  "Rollout",
  "Window and verification",
  "Create",
  "Plans",
  "Approval and run",
];

/** The operations whose payload an earlier release built from its own field. */
const UNIT_OPERATIONS = ["unit.start", "unit.stop", "unit.restart", "unit.reload", "unit.reset_failed"];

/** A rename in bulk: the payload is a mapping the wizard builds host by host. */
const RENAME_OPERATION = "system.hostname.set";

/** The offline policies, from the one that does the most to the one that does the least. */
const OFFLINE_POLICIES = ["wait_until_deadline", "replan_on_reconnect", "skip_if_offline", "require_online"];

/** A transition gate: the next step opens only when there is a reason to. */
type Gate = { open: boolean; reason: string };

export function Bulk() {
  const t = useT();
  // Another screen may open the workspace with an order half written - the
  // certificate view hands over a rotation stage this way.
  const [prefill] = useSearchParams();
  const [draft] = useState(() => prefilledOrder(prefill) ?? loadDraft(sessionStorageOrNull()));
  const [step, setStep] = useState(draft?.step ?? 0);
  // The campaign comes into being halfway through.
  const [campaignID, setCampaignID] = useState("");
  const [order, setOrder] = useState<Order>(draft?.order ?? emptyOrder());

  const change = (delta: Partial<Order>) => setOrder((previous) => ({ ...previous, ...delta }));

  // The draft follows every change until the campaign exists: after that the
  // record on the server is the truth, and a stale draft reopening on the
  // next visit would look like a second order waiting to be placed.
  useEffect(() => {
    if (campaignID) return;
    saveDraft(sessionStorageOrNull(), { order, step });
  }, [order, step, campaignID]);

  const capabilities = useCapabilities();
  const operations = useOperations();
  const bulk = (operations.data?.items ?? []).filter((item) => item.campaign_ready);
  const chosenOperation = bulk.find((item) => item.action === order.action);
  // An operation that arrived in the address may be one the catalogue
  // refuses in bulk - a rollback family, a specialised sequence.
  const unready = order.action && operations.data && !chosenOperation
    ? operations.data.items.find((item) => item.action === order.action)
    : undefined;
  const refusal = unready
    ? unready.campaign_refusal ?? t("the catalogue does not open it to the fleet")
    : undefined;
  // A prefilled operation without a payload takes the template once the
  // catalogue is in, exactly as choosing it by hand would.
  const prefilledTemplate = order.action && !order.payloadText && !operationForm(order.action)
    ? bulk.find((item) => item.action === order.action)?.payload_template
    : undefined;
  useEffect(() => {
    if (prefilledTemplate) {
      setOrder((previous) => ({ ...previous, payloadText: JSON.stringify(prefilledTemplate, null, 2) }));
    }
  }, [prefilledTemplate]);
  // Refusals are shown together with the reason.
  const refusals = (operations.data?.items ?? []).filter(
    (item) => item.mutating && !item.campaign_ready && item.campaign_refusal,
  );

  const params = new URLSearchParams();
  const expression = expressionOf(order);
  if (order.hostIDs.length > 0) {
    // A list of hosts is the order itself: the preview resolves the same
    // identifiers the creation will, and nothing else is sent next to them -
    // a filter beside a list would be ignored on the server.
    for (const hostID of order.hostIDs) params.append("host_id", hostID);
  } else if (expression) {
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
  // A host list with nobody on it yet is not previewed: without the
  // identifiers the query would count the whole fleet.
  const listEmpty = order.targetMode === "hosts" && order.hostIDs.length === 0;
  const preview = useQuery({
    queryKey: ["campaign-preview", params.toString()],
    queryFn: () => api.get<Preview>(`/api/v1/campaigns/preview?${params}`),
    // Nor is an order that narrows nothing: the endpoint would answer with
    // the fleet, and that count is one the order will be refused for.
    enabled: Boolean(order.action) && !listEmpty && selectorNames(order),
  });

  const campaign = useQuery({
    queryKey: ["campaign", campaignID],
    queryFn: () => api.get<Campaign>(`/api/v1/campaigns/${campaignID}`),
    enabled: Boolean(campaignID),
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // A host list from the address is not a filter the preview can count: the
  // preview reads the selector fields, and a compensation narrowed to one
  // host previews the whole set the original changed.
  const eligible = orderTargets(order, preview.data);
  const gates = stepGates(t, order, preview.data, campaign.data, refusal);
  // A step opens once every gate before it is open; the first shut one is
  // the reason the rest are out of reach.
  const shutBefore = (index: number) => gates.slice(0, index).find((gate) => !gate.open);
  const goTo = (index: number) => { if (!shutBefore(index)) setStep(index); };
  const shutHere = shutBefore(step + 1);

  const help = (
    <p>
      {t("A campaign built in steps: what runs, where it runs, which of those hosts can run it, how fast it rolls out, when it may run and what is checked afterwards. Nothing leaves this screen until the consent at the end, and the consent covers exactly what the screen shows - one fingerprint over the operation, the payload, the host list, the rollout policy and the set of plans. One host at a time belongs in the host workspace; this is where the fleet is changed.")}
    </p>
  );

  // A backend without a planning phase will not drive any of these changes.
  if (!capabilities.campaign_v2) {
    return (
      <Screen title={t("Bulk")} lead={t("Choose the target, read the refusals, run the change.")} icon="bulk" help={help}>
        <Grid>
          <Card span={12}>
            <Empty icon="help">
              {t("This installation runs operations host by host: the backend has no campaign engine, so there is no set of per-host plans to approve.")}
            </Empty>
          </Card>
        </Grid>
      </Screen>
    );
  }

  const nav = <StepNav step={step} setStep={setStep} gates={gates} />;

  return (
    <Screen
      title={t("Bulk")}
      lead={t("Choose the target, read the refusals, run the change.")}
      icon="bulk"
      help={help}
      banner={refusal ? (
        <Banner tone="error">
          {t("{action} does not run as a campaign: {reason}", { action: order.action, reason: refusal })}
        </Banner>
      ) : undefined}
    >
      <Grid>
        <ScopeBar order={order} preview={preview.data} campaign={campaign.data}
                  targets={eligible} risk={chosenOperation?.risk} />

        <Card span={12} title={t("The steps")} note={t("A step opens once the one before it has what it needs.")}>
          <Stack>
            <Tabs
              value={String(step)}
              onChange={(value) => goTo(Number(value))}
              tabs={STEPS.map((title, index) => ({
                value: String(index),
                label: `${index + 1}. ${t(title)}`,
              }))}
            />
            {shutHere && <Note>{t("Before going on: {reason}.", { reason: shutHere.reason })}</Note>}
          </Stack>
        </Card>

        {step === 0 && (
          <ScopeStep order={order} change={change} bulk={bulk} refusals={refusals}
                     preview={preview.data} refusal={refusal} nav={nav} />
        )}
        {step === 1 && (
          <TargetsStep order={order} change={change} preview={preview.data}
                       checking={preview.isLoading} refusal={preview.error} nav={nav} />
        )}
        {step === 2 && (
          <EligibilityStep order={order} preview={preview.data} checking={preview.isLoading} nav={nav} />
        )}
        {step === 3 && (
          <RolloutStep order={order} change={change} targets={eligible}
                       declaredPolicy={chosenOperation?.offline_policy} nav={nav} />
        )}
        {step === 4 && <WindowStep order={order} change={change} operation={chosenOperation} nav={nav} />}
        {step === 5 && (
          <CreateStep
            order={order}
            change={change}
            targets={eligible}
            compensates={preview.data?.compensates}
            token={previewTokenOf(preview.data)}
            campaignID={campaignID}
            onCreated={(id) => {
              // The order is placed: the draft would only reopen an order
              // that already became a campaign.
              clearDraft(sessionStorageOrNull());
              setCampaignID(id);
              setStep(6);
            }}
            nav={nav}
          />
        )}
        {step === 6 && <PlansStep campaignID={campaignID} campaign={campaign.data} nav={nav} />}
        {step === 7 && <ApprovalStep campaignID={campaignID} campaign={campaign.data} nav={nav} />}
      </Grid>
    </Screen>
  );
}

/* ------------------------------------------------------------ the frame */

/** The buttons at the end of a step: back, and on to the next by its name. */
function StepNav({ step, setStep, gates }: { step: number; setStep: (step: number) => void; gates: Gate[] }) {
  const t = useT();
  const gate = gates[step];
  const last = step >= STEPS.length - 1;
  return (
    <Actions>
      <button type="button" className="fl-quiet" onClick={() => setStep(step - 1)} disabled={step === 0}
              title={step === 0 ? t("This is the first step.") : undefined} data-testid="step-back">
        {t("Back")}
      </button>
      {!last && (
        <button type="button" onClick={() => setStep(step + 1)} disabled={!gate.open}
                title={gate.open ? undefined : gate.reason} data-testid="step-next">
          {t("Next: {step}", { step: t(STEPS[step + 1]) })}
        </button>
      )}
      {!last && !gate.open && (
        <span className="fl-note">{t("Before going on: {reason}.", { reason: gate.reason })}</span>
      )}
    </Actions>
  );
}

/**
 * What the order is, pinned above every step: its name, its operation and
 * its risk class, how many hosts it is placed on, what it undoes, and -
 * once the campaign exists - the fingerprint the consent will cover.
 */
function ScopeBar({ order, preview, campaign, targets, risk }: {
  order: Order;
  preview?: Preview;
  campaign?: Campaign;
  /** The number the order is placed on. */
  targets: number;
  risk?: string;
}) {
  const t = useT();
  return (
    <Card span={12} title={order.name || t("unnamed campaign")}
          note={t("What is being ordered, in view for the whole wizard.")}>
      <Facts>
        <Fact label={t("Operation")}>
          {order.action
            ? (
              <Tags>
                <Tag>{order.action}</Tag>
                {/* The risk class decides the approvals and the step-up; it
                    stays in view for the whole wizard. */}
                {risk && (
                  <Pill tone={risk === "critical" ? "error" : risk === "high" ? "warn" : "neutral"}>{risk}</Pill>
                )}
              </Tags>
            )
            : <span className="fl-faint">{t("no operation")}</span>}
        </Fact>
        <Fact label={t("Targets")}>
          <span data-testid="scope-targets">{targets}</span>
          {order.hostIDs.length > 0
            ? ` ${t("picked by name")}`
            : preview && preview.eligible !== undefined && preview.eligible !== preview.count
              ? ` ${t("of {n} matched", { n: preview.count })}`
              : ""}
        </Fact>
        {preview?.campaign_mode && <Fact label={t("Mode")}>{preview.campaign_mode}</Fact>}
        {/* What the order undoes stays in view: a rollback approved without
            its original in sight is a change like any other. */}
        {preview?.compensates && (
          <Fact label={t("Compensates")}>
            <Link to={`/campaigns/${preview.compensates.id}`}>{preview.compensates.name}</Link>
          </Fact>
        )}
        {campaign && (
          <>
            <Fact label={t("State")}>
              <Pill tone={campaignTone(campaign.state)}>{t(stateName(campaign.state))}</Pill>
            </Fact>
            {/* The fingerprint is what the consent applies to. Without it
                "approved" does not say what was approved; the snapshot time
                says which fleet it was taken of. */}
            <Fact label={t("Fingerprint")}>
              <span className="fl-mono">{campaign.approval_fingerprint.slice(0, 12)}</span>
            </Fact>
            <Fact label={t("Snapshot")}>
              <span title={absoluteTime(campaign.created_at)}>{relativeTime(campaign.created_at)}</span>
            </Fact>
          </>
        )}
      </Facts>
    </Card>
  );
}

/** How a campaign's state reads as a colour. */
export function campaignTone(state: string): Tone {
  if (["completed", "succeeded"].includes(state)) return "ok";
  if (["failed", "plan_failed"].includes(state)) return "error";
  if (["completed_with_issues", "paused", "pausing", "awaiting_approval", "manual_gate"].includes(state)) return "warn";
  if (["canceled", "cancelled", "expired"].includes(state)) return "neutral";
  if (["planning", "canary", "running", "active"].includes(state)) return "info";
  return "unknown";
}

/* ------------------------------------------------------------- the order */

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

/**
 * The payload of the order, or null when it is not one yet: the wizard
 * holds the order at the first step rather than sending something the
 * server would refuse.
 */
function orderPayload(order: Order): Record<string, unknown> | null {
  if (order.action === RENAME_OPERATION) {
    // A rename across the fleet carries one name per host and nothing
    // shared, so it keeps its own editor.
    const mapping = Object.fromEntries(
      Object.entries(order.mapping)
        .map(([id, name]) => [id, String(name).trim()] as const)
        .filter(([, name]) => name !== ""),
    );
    if (Object.keys(mapping).length === 0) return null;
    return { hostname: { pretty: order.pretty.trim() || undefined, mapping } };
  }
  const entry = operationForm(order.action);
  if (entry && !order.payloadText) {
    if (entry.validate(orderForm(order)).length > 0) return null;
    return entry.toPayload(orderForm(order));
  }
  try {
    const parsed: unknown = JSON.parse(order.payloadText);
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/** The sentence for what is wrong with the window, empty when nothing is. */
function windowWords(t: Translate, problem: WindowProblem | null): string {
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

/** The sentence for what is wrong with the schedule, empty when nothing is. */
function scheduleWords(t: Translate, problem: ReturnType<typeof scheduleProblem>): string {
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

/**
 * The sentence a refused order is shown with: the wizard's own words where
 * it has them, and the server's own sentence for everything else.
 */
function refusalWords(t: Translate, error: unknown): string {
  if (error instanceof ApiError && error.code === "selector_required") {
    return t("The order was refused: its selector names nobody, and an empty selector is not an order on everything. Go back to the targets and name a site, an environment, a group, a tag rule or a list of hosts.");
  }
  return error instanceof Error ? error.message : String(error);
}

function stepGates(t: Translate, order: Order, preview?: Preview, campaign?: Campaign, refusal?: string): Gate[] {
  // A valid payload is the whole test of the first step: the registry's form
  // reports what is missing field by field, and an operation without one is
  // judged by whether its JSON parses.
  const hasAction = Boolean(order.action && order.name) && orderPayload(order) !== null;
  const hasTargets = order.targetMode === "hosts"
    ? order.hostIDs.length > 0
    : (preview?.count ?? 0) > 0;
  const names = selectorNames(order);
  const hasEligible = (preview?.eligible ?? 0) > 0;
  const exclusionsExplained = order.exclude.length === 0 || order.excludeReason.trim() !== "";
  const window = windowWords(t, windowProblem(order.maintenanceStart, order.maintenanceEnd, new Date()));
  const schedule = scheduleWords(t, scheduleProblem(order.schedule, new Date()));
  const timeoutFits = jobTimeoutValid(order.jobTimeoutSeconds);
  // Where the registry draws the form, the gate says the same thing the
  // field does: one reason, in one place.
  const formEntry = order.action === RENAME_OPERATION || order.payloadText
    ? undefined : operationForm(order.action);
  const formProblem = formEntry ? formEntry.validate(orderForm(order))[0] : undefined;
  return [
    {
      open: hasAction && !refusal,
      reason: refusal
        ? t("the catalogue refuses this operation in bulk: {reason}", { reason: refusal })
        : !order.action
          ? t("pick an operation and name the campaign")
          : !order.name
            ? t("name the campaign")
            : order.action === RENAME_OPERATION
              ? t("give at least one host its new name")
              : formProblem
                ? t(formProblem.message, formProblem.params)
                : t("give the operation a valid payload"),
    },
    {
      open: hasAction && hasTargets && exclusionsExplained && names,
      reason: !exclusionsExplained
        ? t("give the exclusions a reason")
        : order.targetMode === "hosts" && order.hostIDs.length === 0
          ? t("pick at least one host from the list")
          : !names
            ? t("narrow the fleet first: a site, an environment, a group, a tag rule or a list of hosts; an empty selector is not an order on everything")
            : t("the selector matches no host"),
    },
    { open: hasEligible, reason: t("no matched host can run this operation") },
    { open: hasEligible, reason: t("no matched host can run this operation") },
    { open: window === "" && schedule === "" && timeoutFits, reason: window || schedule || t("the job timeout is out of bounds") },
    { open: Boolean(campaign), reason: t("the campaign does not exist yet") },
    { open: Boolean(campaign && campaign.state !== "planning"), reason: t("hosts are still planning") },
  ];
}

/* ------------------------------------------------------------- 1. Scope */

function ScopeStep({ order, change, bulk, refusals, preview, refusal, nav }: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  bulk: Operation[];
  refusals: Operation[];
  preview?: Preview;
  /** Why the catalogue refuses the operation the address named in bulk. */
  refusal?: string;
  nav: ReactNode;
}) {
  const t = useT();
  const [showRefusals, setShowRefusals] = useState(false);
  const chosen = bulk.find((item) => item.action === order.action);
  // The registry draws the fields of every operation it knows.
  const entry = order.action === RENAME_OPERATION ? undefined : operationForm(order.action);
  const generic = Boolean(order.action) && !entry && order.action !== RENAME_OPERATION;
  const formed = wizardOperations(bulk);
  const payloadValid = orderPayload(order) !== null;
  return (
    <Card
      span={12}
      title={`1. ${t("Scope")}`}
      note={t("Name the campaign and pick what it does on every host; the next step chooses the hosts. Only operations the registry opens to the fleet are listed - an operation missing here is a deliberate refusal, not a missing screen.")}
      foot={nav}
    >
      <Stack>
        {refusal && (
          <Problem>
            {t("{action} does not run as a campaign: {reason}", { action: order.action, reason: refusal })}
          </Problem>
        )}
        <Fields>
          <Field label={t("Name")} hint={t("How the campaign is listed and searched for, e.g. September security updates, web tier.")}>
            <input
              placeholder={t("campaign name")}
              value={order.name}
              data-testid="order-name"
              onChange={(event) => change({ name: event.target.value })}
            />
          </Field>
          <Field
            label={t("Operation")}
            hint={chosen
              ? t("The same operation the host page runs one host at a time; the word after the dot is its risk class.")
              : t("Named as on the host page and in the job list, e.g. packages.upgrade for the pending updates or unit.restart for a service; the word after the dot is the risk class.")}
          >
            <select
              value={order.action}
              data-testid="order-action"
              onChange={(event) => {
                // An operation the registry knows opens on its own fields,
                // at their own starting values.
                const action = event.target.value;
                const next = bulk.find((item) => item.action === action);
                change({
                  action,
                  form: startingForm(action),
                  payloadText: startingPayloadText(next, Boolean(operationForm(action))),
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
              <Contract contract={chosen} />
            </Field>
          )}
          {generic && (
            <Field
              label={t("Payload (JSON, the same shape as a single-host operation)")}
              hint={!payloadValid
                ? t("This is not valid JSON.")
                : chosen?.needs_material
                  ? t("The template carries a placeholder for certificate material; replace it with the real PEM before the order.")
                  : t("The registry has no form for this operation yet, so its payload is typed here. The server validates it when the campaign is created and names what is wrong.")}
              wide
            >
              <textarea
                className="fl-mono"
                rows={Math.min(18, Math.max(6, order.payloadText.split("\n").length + 1))}
                value={order.payloadText}
                data-testid="order-payload"
                onChange={(event) => change({ payloadText: event.target.value })}
                spellCheck={false}
              />
            </Field>
          )}
        </Fields>

        {order.action === RENAME_OPERATION && (
          <MappingEditor order={order} change={change} hosts={preview?.hosts} />
        )}

        {/* The operation's own fields come from the registry, so the wizard
            and the host page ask for the same things in the same words. The
            key resets the advanced view when another operation is picked. */}
        {entry && (
          <OperationFields
            key={entry.action}
            entry={entry}
            value={orderForm(order)}
            onChange={(form) => change({ form })}
            json={order.payloadText}
            onJson={(payloadText) => change({ payloadText })}
          />
        )}

        {/* How far the forms reach is said plainly: an operation ordered as
            JSON is one the registry has not reached yet. */}
        {bulk.length > 0 && formed.length < bulk.length && (
          <Note>
            {t("{formed} of the {n} operations open to the fleet have a form here; the rest are ordered by typing their payload.",
              { formed: formed.length, n: bulk.length })}
          </Note>
        )}

        {preview?.requires_plan && (
          <Note>
            {order.action === RENAME_OPERATION
              ? t("The mapping is split host by host: every host's plan is its own new name, and you approve the set of names, not one payload.")
              : t("Every host computes its own plan first. You approve the set of plans, not one payload, and a host whose plan changed in the meantime refuses the change.")}
          </Note>
        )}

        {refusals.length > 0 && (
          <Stack>
            <Actions>
              <button type="button" className="fl-quiet fl-small" data-testid="show-refusals"
                      onClick={() => setShowRefusals(!showRefusals)}>
                {showRefusals
                  ? t("Hide the operations that cannot run as a campaign")
                  : t("{n} operations change hosts but cannot run as a campaign — with reasons", { n: refusals.length })}
              </button>
            </Actions>
            {showRefusals && (
              <Table
                rows={refusals}
                keyOf={(one) => one.action}
                testId="bulk-refusals"
                columns={[
                  { key: "action", head: t("Operation"), tight: true, cell: (one) => <code>{one.action}</code> },
                  { key: "why", head: t("Why not"), cell: (one) => one.campaign_refusal },
                ]}
              />
            )}
          </Stack>
        )}
      </Stack>
    </Card>
  );
}

/**
 * The contract of an operation as small chips, each with its sentence on
 * hover: what a cancel does, whether a repeat is safe, what way back
 * exists, what is verified and which host resources it takes.
 */
function Contract({ contract }: { contract: OperationContract }) {
  const t = useT();
  const chips: { label: string; meaning: string; tone?: Tone }[] = [];
  for (const [field, value, label] of [
    ["cancel", contract.cancel_mode, t("cancel")],
    ["retry", contract.retry_class, t("retry")],
    ["rollback", contract.rollback, t("rollback")],
    ["verification", contract.verification, t("verification")],
  ] as const) {
    if (!value) continue;
    const [word, meaning] = contractWords(t, field, value);
    chips.push({
      label: `${label}: ${word}`,
      meaning,
      tone: field === "rollback" && value === "none" ? "warn" : undefined,
    });
  }
  const claims = contract.resource_claims ?? [];
  if (claims.length > 0) {
    chips.push({
      label: `${t("claims")}: ${claims.map((claim) => describeClaim(t, claim)).join(", ")}`,
      meaning: t("The host resources the operation holds while it runs. An exclusive claim keeps every other change off that resource; shared claims coexist and their weight is what they cost the host."),
    });
  }
  if (chips.length === 0) return null;
  return (
    <Tags>
      {chips.map((chip) => (
        <Pill key={chip.label} tone={chip.tone} title={chip.meaning} dot={false}>{chip.label}</Pill>
      ))}
    </Tags>
  );
}

function describeClaim(t: Translate, claim: ResourceClaim): string {
  const mode = claim.mode === "exclusive" ? t("exclusive") : t("shared");
  return claim.weight > 1 ? `${claim.class} (${mode} ×${claim.weight})` : `${claim.class} (${mode})`;
}

/**
 * The form of one operation, drawn from the registry, with the hand-written
 * payload behind a switch for what the fields cannot show.
 */
function OperationFields({ entry, value, onChange, json, onJson }: {
  entry: OperationEntry;
  value: FormValue;
  onChange: (value: FormValue) => void;
  /** The payload as hand-written JSON; empty means the fields are the order. */
  json: string;
  onJson: (json: string) => void;
}) {
  const t = useT();
  const [advanced, setAdvanced] = useState(json !== "");
  // The text of the advanced view lives here rather than in the order: a
  // value that reformats itself on every keystroke cannot be typed into.
  const [draft, setDraft] = useState(() => json || payloadTextOf(entry, value));
  const problems = entry.validate(value);
  const problemOf = (name: string) => problems.find((problem) => problem.field === name);

  const set = (field: OperationField, next: FieldValue) => onChange({ ...value, [field.name]: next });

  const editJson = (next: string) => {
    setDraft(next);
    const read = readPayloadText(entry, next);
    if (read) {
      // The fields can carry this payload, so they take it back.
      onChange(read);
      onJson("");
      return;
    }
    onJson(next);
  };

  return (
    <Stack>
      <Toolbar end={<span className="fl-note">{t(entry.title)}</span>}>
        <Check
          checked={advanced}
          onChange={(on) => {
            if (on) { setDraft(payloadTextOf(entry, value)); setAdvanced(true); return; }
            setAdvanced(false);
            onJson("");
          }}
        >
          {t("Advanced (JSON)")}
        </Check>
      </Toolbar>

      {entry.note && <Note>{t(entry.note)}</Note>}
      {entry.plan && <Note>{t(entry.plan)}</Note>}

      {advanced ? (
        <Fields>
          <Field
            label={t("Payload (JSON, the same shape as a single-host operation)")}
            hint={advancedWords(t, entry, draft)}
            wide
          >
            <textarea
              className="fl-mono"
              rows={Math.min(24, Math.max(6, draft.split("\n").length + 1))}
              value={draft}
              data-testid="operation-json"
              onChange={(event) => editJson(event.target.value)}
              spellCheck={false}
            />
          </Field>
        </Fields>
      ) : (
        <>
          <Fields>
            {entry.fields.map((field) => (
              <OneField key={field.name} field={field} value={value} problem={problemOf(field.name)} set={set} />
            ))}
          </Fields>
          {entry.fields.length === 0 && <Note>{t("This operation takes no settings.")}</Note>}
          {problems.length > 0 && (
            // Not a problem box: a form that has not been filled in yet is
            // not a page that broke.
            <Note>{problems.map((problem) => t(problem.message, problem.params)).join(" ")}</Note>
          )}
        </>
      )}
    </Stack>
  );
}

/** What the advanced view is holding right now. */
function advancedWords(t: Translate, entry: OperationEntry, draft: string): string {
  if (readPayloadText(entry, draft)) {
    return t("The fields can show this payload, so they are what the order carries; close the advanced view and they are filled in with it.");
  }
  try {
    const parsed: unknown = JSON.parse(draft);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return t("The fields cannot show this payload, so it travels exactly as typed. The server checks it and names what is wrong.");
    }
  } catch {
    // Not JSON at all; said below.
  }
  return t("This is not valid JSON.");
}

/** One field of an operation's form. */
function OneField({ field, value, problem, set }: {
  field: OperationField;
  value: FormValue;
  problem?: { message: string; params?: Record<string, string | number> };
  set: (field: OperationField, next: FieldValue) => void;
}) {
  const t = useT();
  // A field that is wrong says so where its explanation stood: one place to
  // look, and the explanation is no use until the value is right.
  const hint = problem ? t(problem.message, problem.params) : field.hint ? t(field.hint) : undefined;

  if (field.kind === "boolean") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <Check checked={flag(value, field.name)} onChange={(on) => set(field, on)}>{t(field.label)}</Check>
      </Field>
    );
  }

  if (field.kind === "select") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <select value={text(value, field.name)} onChange={(event) => set(field, event.target.value)}>
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>{t(option.label)}</option>
          ))}
        </select>
      </Field>
    );
  }

  if (field.kind === "number" || field.kind === "duration") {
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <input
          type="number"
          min={field.min}
          max={field.max}
          value={String(count(value, field.name))}
          onChange={(event) => set(field, event.target.value === "" ? 0 : Number(event.target.value))}
        />
      </Field>
    );
  }

  if (["textarea", "list", "packages", "pairs"].includes(field.kind)) {
    const written = body(value, field.name);
    return (
      <Field label={t(field.label)} hint={hint} wide={field.wide}>
        <textarea
          className="fl-mono"
          rows={Math.min(16, Math.max(field.kind === "textarea" ? 6 : 3, written.split("\n").length + 1))}
          value={written}
          placeholder={field.placeholder}
          onChange={(event) => set(field, event.target.value)}
          spellCheck={false}
        />
      </Field>
    );
  }

  return (
    <Field label={t(field.label)} hint={hint} wide={field.wide}>
      <input
        type="text"
        value={body(value, field.name)}
        placeholder={field.placeholder}
        onChange={(event) => set(field, event.target.value)}
        spellCheck={field.kind === "text"}
      />
    </Field>
  );
}

/**
 * The mapping of a rename in bulk: one row per host the selector matches,
 * the current name on the left and the new one typed on the right.
 */
function MappingEditor({ order, change, hosts }: {
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
  // operator keeps elsewhere rarely spells the names the way the inventory
  // does.
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
      if (!id) { unmatched.push(current); continue; }
      next[id] = fqdn;
    }
    change({ mapping: next });
    setPasted(unmatched.length ? unmatched.map((name) => `${name},`).join("\n") : "");
  };
  return (
    <Stack>
      <Fields>
        <Field label={t("Pretty name")} hint={t("Optional; set on every host the same. The static name comes from the mapping below.")}>
          <input value={order.pretty} onChange={(event) => change({ pretty: event.target.value })}
                 placeholder={t("e.g. Web node")} />
        </Field>
      </Fields>

      <h3 className="fl-subhead">{t("New names, one host at a time")}</h3>
      <Table
        rows={rows}
        keyOf={(one) => one.id}
        rowTestId={(one) => `rename-${one.hostname}`}
        testId="rename-mapping"
        empty={t("No host matched yet: the rows come from the hosts the Targets step names.")}
        columns={[
          { key: "current", head: t("Current hostname"), tight: true, cell: (one) => one.hostname },
          {
            key: "new",
            head: t("New FQDN"),
            cell: (one) => (
              <input
                className="fl-mono"
                value={order.mapping[one.id] ?? ""}
                placeholder={t("new.fqdn.example")}
                aria-label={t("New name of {host}", { host: one.hostname })}
                onChange={(event) => setName(one.id, event.target.value)}
                spellCheck={false}
              />
            ),
          },
          {
            key: "verdict",
            head: t("Verdict"),
            cell: (one) => {
              const name = (order.mapping[one.id] ?? "").trim();
              if (name === "") return <Pill tone="error">{t("no new name")}</Pill>;
              if (name.toLowerCase() === one.hostname.toLowerCase()) return <Pill tone="neutral">{t("unchanged")}</Pill>;
              return <Pill tone="ok">{t("renames")}</Pill>;
            },
          },
        ]}
      />
      <Note>
        {rows.length === 0
          ? t("No host matched yet: the rows come from the hosts the Targets step names, and with nothing set there, from the whole fleet.")
          : t("{named} of {n} matched hosts have a new name. A host without one stays in the snapshot as ineligible; nothing is renamed to a default.", { named, n: rows.length })}
      </Note>

      <Fields>
        <Field
          label={t("Paste as CSV")}
          hint={t("One host per line: hostname,fqdn. The hostname is matched to the rows above, full or short; a line that matches no host stays in the box.")}
          wide
        >
          <textarea
            className="fl-mono"
            rows={4}
            value={pasted}
            data-testid="rename-paste"
            onChange={(event) => setPasted(event.target.value)}
            placeholder={"web01.old.example,web01.new.example\nweb02,web02.new.example"}
            spellCheck={false}
          />
        </Field>
      </Fields>
      <Actions>
        <button type="button" className="fl-quiet" onClick={applyPaste} disabled={!pasted.trim()}
                title={pasted.trim() ? undefined : t("Paste at least one line first.")} data-testid="rename-apply">
          {t("Apply the pasted names")}
        </button>
      </Actions>
    </Stack>
  );
}

/* ----------------------------------------------------------- 2. Targets */

/**
 * The words for each way of naming the targets: a short label for the
 * choice and one sentence for what it means.
 */
const TARGET_WAYS: [mode: TargetMode, label: string, meaning: string][] = [
  ["filters", "by site, environment and OS", "Every host that matches the fields; leave a field empty to match any value. Hosts added later do not join: the list is frozen when the campaign is created."],
  ["expression", "by groups and tags", "A saved group, tag rules, or both; the expression is resolved on the server the moment the campaign is created."],
  ["hosts", "a list of hosts picked by hand", "Tick the hosts one by one; nothing else decides. The right way for a handful of named machines."],
];

function TargetsStep({ order, change, preview, checking, refusal, nav }: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  preview?: Preview;
  /** Whether an answer is on its way: "nobody has answered yet" is not
      "the selector matches nobody", and the screen must not say the one
      while the other is true. */
  checking?: boolean;
  /** The server's refusal of the selector, when there is one. */
  refusal?: unknown;
  nav: ReactNode;
}) {
  const t = useT();
  // The values the fleet really has, offered under each field; free text
  // still goes through, and the count below says what it matched.
  const facets = useFleetFacets();
  const groups = useQuery({
    queryKey: ["host-groups"],
    queryFn: () => api.get<Collection<{ id: string; name: string; kind: string }>>("/api/v1/host-groups"),
    enabled: order.targetMode === "expression",
    staleTime: 60 * 1000,
  });
  const [excluding, setExcluding] = useState(false);
  const expression = expressionOf(order);
  // Changing the way clears what the other ways typed: a host list kept from
  // an earlier choice would win over the filters on the server without a
  // word on screen.
  const chooseMode = (mode: TargetMode) => change({
    targetMode: mode,
    hostIDs: mode === "hosts" ? order.hostIDs : [],
  });
  // No "?? 0" here, and that is the whole point: a count nobody has taken is
  // not a count of nothing.
  const count = preview?.count;
  const names = selectorNames(order);
  const matched = matchedState(Boolean(names), count, checking);
  const way = TARGET_WAYS.find(([mode]) => mode === order.targetMode);
  return (
    <Card
      span={12}
      title={`2. ${t("Targets")}`}
      note={t("Choose the hosts one of three ways: by site, environment and OS; by groups and tags; or by picking them from a list. The count below is the server's answer; the next step says which of those hosts can run the operation.")}
      tools={
        <Seg
          value={order.targetMode}
          label={t("How the hosts are named")}
          onChange={chooseMode}
          options={TARGET_WAYS.map(([mode, label]) => ({ value: mode, label: t(label) }))}
        />
      }
      foot={nav}
    >
      <Stack>
        {way && <Note>{t(way[2])}</Note>}
        {refusal ? <Problem>{refusalWords(t, refusal)}</Problem> : null}

        {order.targetMode === "filters" && (
          <Fields>
            <Field label={t("Site")} hint={t("Pick one the fleet has, or type any; empty means every site.")}>
              <input placeholder={t("any site")} value={order.site} list="next-bulk-sites" data-testid="target-site"
                     onChange={(event) => change({ site: event.target.value })} />
              <FacetList id="next-bulk-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")} hint={t("Pick one the fleet has, or type any; empty means every environment.")}>
              <input placeholder={t("any environment")} value={order.environment} list="next-bulk-environments"
                     data-testid="target-environment"
                     onChange={(event) => change({ environment: event.target.value })} />
              <FacetList id="next-bulk-environments" facets={facets.data?.by_environment} />
            </Field>
            <Field label={t("OS family")} hint={t("Pick one the fleet has, or type any; empty means every family.")}>
              <input placeholder={t("any OS family")} value={order.osFamily} list="next-bulk-os-families"
                     data-testid="target-os-family"
                     onChange={(event) => change({ osFamily: event.target.value })} />
              <FacetList id="next-bulk-os-families" facets={facets.data?.by_os_family} />
            </Field>
          </Fields>
        )}

        {order.targetMode === "expression" && (
          <Stack>
            <Fields>
              <Field label={t("Group")} hint={t("Optional; the rules below narrow it further.")}>
                <select value={order.group} data-testid="target-group"
                        onChange={(event) => change({ group: event.target.value })}>
                  <option value="">{t("no group")}</option>
                  {(groups.data?.items ?? []).map((group) => (
                    <option key={group.id} value={group.name}>{group.name} · {group.kind}</option>
                  ))}
                </select>
              </Field>
            </Fields>
            <Rules
              rules={order.rules}
              combine={order.combine}
              onRules={(rules) => change({ rules })}
              onCombine={(combine) => change({ combine })}
            />
            {/* The expression as the campaign will carry it: the structure
                the server compiles, not a sentence the panel made up. */}
            <Note>
              {expression
                ? `${t("the campaign will carry")} ${describeExpression(expression)}`
                : t("pick a group or give a rule a value; until then the selector names nobody")}
            </Note>
          </Stack>
        )}

        {order.targetMode === "hosts" && (
          <HostPicker
            title={t("Hosts")}
            chosen={new Set(order.hostIDs)}
            onChange={(next) => change({ hostIDs: [...next] })}
            testId="targets"
          />
        )}

        {/* A host list has nothing to exclude from: a host not wanted is
            simply not ticked. The two selectors may match a host the change
            must not touch, and that host is left out by name, with a reason. */}
        {order.targetMode !== "hosts" && (
          <Stack>
            <h3 className="fl-subhead">{t("Exclude")}</h3>
            <Note>
              {order.exclude.length === 0
                ? t("Optional. A host the selector matches but the change must not touch is left out here by name; it stays in the snapshot as excluded, with the reason and your name next to it.")
                : t("{n} hosts left out by name; each stays in the snapshot as excluded, with the reason and your name next to it.", { n: order.exclude.length })}
            </Note>
            {order.exclude.length > 0 && (
              <Fields>
                <Field label={t("Reason for the exclusions")}
                       hint={t("Required; it is what the approver reads next to every excluded host.")} wide>
                  <input
                    placeholder={t("e.g. the database primary; failing over first")}
                    value={order.excludeReason}
                    data-testid="exclude-reason"
                    onChange={(event) => change({ excludeReason: event.target.value })}
                  />
                </Field>
              </Fields>
            )}
            {excluding ? (
              <Stack>
                <HostPicker
                  title={t("Hosts to leave out")}
                  chosen={new Set(order.exclude)}
                  onChange={(next) => change({ exclude: [...next] })}
                  testId="excluded"
                />
                <Actions>
                  <button type="button" className="fl-quiet" onClick={() => setExcluding(false)}>
                    {t("Done choosing")}
                  </button>
                </Actions>
              </Stack>
            ) : (
              <Actions>
                <button type="button" className="fl-quiet" data-testid="exclude-open" onClick={() => setExcluding(true)}>
                  {order.exclude.length === 0 ? t("Exclude hosts by name") : t("Change the excluded hosts")}
                </button>
                {order.exclude.length > 0 && (
                  <button type="button" className="fl-quiet"
                          onClick={() => change({ exclude: [], excludeReason: "" })}>
                    {t("Clear the exclusions")}
                  </button>
                )}
              </Actions>
            )}
          </Stack>
        )}

        {/* A compensation may only name hosts the original changed; with the
            filters empty it takes all of them, and the operator is told so
            instead of reading it off an empty form. */}
        {order.compensates && preview?.compensates && (
          <Note>
            {t("This campaign compensates {name}: only the {changed} hosts that campaign changed can be its targets. Leave the filters empty to take all of them, or narrow them to a part.", {
              name: preview.compensates.name, changed: preview.compensates.changed,
            })}
          </Note>
        )}

        <Note>
          <span data-testid="matched">
            {order.targetMode === "hosts"
              ? order.hostIDs.length === 0
                ? t("No host is picked yet; tick at least one in the list above.")
                : t("{n} hosts picked by hand; the campaign is created on those alone.", { n: order.hostIDs.length })
              : matched.kind === "unnarrowed"
                ? t("The fleet is not narrowed yet: name a site, an environment or an OS family above, or a group and tag rules. An empty selector is not an order on everything")
                : matched.kind === "counting"
                  ? t("Counting the hosts the selector matches…")
                  : matched.kind === "unknown"
                    ? t("How many hosts the selector matches is not known yet.")
                    : t("The selector matches {n} hosts", { n: matched.n })}
            {order.targetMode !== "hosts" && names && preview && preview.count > preview.limit
              ? ` — ${t("more than the {n} one campaign may carry", { n: preview.limit })}`
              : ""}
            {order.targetMode !== "hosts" ? "." : ""}
          </span>
        </Note>
        {(preview?.sample ?? []).length > 0 && (
          <Note>{(preview?.sample ?? []).join(", ")}</Note>
        )}
        <Distribution preview={preview} />
      </Stack>
    </Card>
  );
}

/**
 * The selector as rows of fact and value, joined by all or any. The
 * expression is the panel's own model - the same one the group page builds.
 */
function Rules({ rules, combine, onRules, onCombine }: {
  rules: Rule[];
  combine: "all" | "any";
  onRules: (rules: Rule[]) => void;
  onCombine: (combine: "all" | "any") => void;
}) {
  const t = useT();
  const update = (index: number, delta: Partial<Rule>) =>
    onRules(rules.map((rule, i) => (i === index ? { ...rule, ...delta } : rule)));
  const names: Record<RuleField, string> = {
    tag: t("tag"), group: t("group"), site: t("site"), environment: t("environment"),
    os_family: t("os family"), os_version: t("os version"), capability: t("capability"),
    connection_state: t("connection state"), lifecycle_state: t("lifecycle state"), owner: t("owner"),
    channel: t("release channel"), security_updates: t("security updates waiting"),
    reboot_required: t("reboot required"), failed_units: t("failed units"),
    agent_version: t("agent version"), relay: t("relay"), failure_domain: t("failure domain"),
  };
  return (
    <Stack>
      <Toolbar>
        <span className="fl-note">{t("the host has to match")}</span>
        <select value={combine} aria-label={t("the host has to match")}
                onChange={(event) => onCombine(event.target.value as "all" | "any")}>
          <option value="all">{t("every rule")}</option>
          <option value="any">{t("any rule")}</option>
        </select>
      </Toolbar>
      {rules.map((rule, index) => (
        <Toolbar
          key={index}
          end={
            <button type="button" className="fl-quiet fl-small" disabled={rules.length === 1}
                    onClick={() => onRules(rules.filter((_, i) => i !== index))}>
              {t("Remove")}
            </button>
          }
        >
          <Check checked={rule.negated} onChange={(on) => update(index, { negated: on })}>{t("not")}</Check>
          <select
            value={rule.field}
            aria-label={t("Rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { field: event.target.value as RuleField, value: "" })}
          >
            {RULE_FIELDS.map((field) => <option key={field} value={field}>{names[field]}</option>)}
          </select>
          <input
            value={rule.value}
            placeholder={t("value")}
            aria-label={t("Value of rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { value: event.target.value })}
          />
        </Toolbar>
      ))}
      <Actions>
        <button type="button" className="fl-quiet fl-small"
                onClick={() => onRules([...rules, { field: "tag", value: "", negated: false }])}>
          {t("Add a rule")}
        </button>
      </Actions>
    </Stack>
  );
}

/** Hosts picked one by one, from the list the server pages. */
function HostPicker({ chosen, onChange, title, testId }: {
  chosen: Set<string>;
  onChange: (next: Set<string>) => void;
  title: string;
  testId: string;
}) {
  const t = useT();
  const [search, setSearch] = useState("");
  const settled = useDebounced(search.trim());
  const params = new URLSearchParams({ limit: String(LIST_PAGE) });
  if (settled) params.set("q", settled);
  const hosts = useInfiniteQuery({
    queryKey: ["hosts", params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Host>>(`/api/v1/hosts?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const rows = loadedItems(hosts.data);
  const total = hosts.data?.pages[0]?.total ?? rows.length;
  const toggle = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id); else next.add(id);
    onChange(next);
  };
  return (
    <Stack>
      <h3 className="fl-subhead">{title}</h3>
      <Toolbar end={<span className="fl-note">{t("{n} chosen", { n: chosen.size })}</span>}>
        <Find value={search} onChange={setSearch}
              placeholder={t("Search hostname, address, machine ID or owner")} testId={`${testId}-search`} />
        <button type="button" className="fl-quiet fl-small"
                onClick={() => onChange(new Set([...chosen, ...rows.map((one) => one.id)]))}>
          {t("Choose every listed host")}
        </button>
        <button type="button" className="fl-quiet fl-small" disabled={chosen.size === 0}
                onClick={() => onChange(new Set())}>
          {t("Clear")}
        </button>
      </Toolbar>
      {hosts.error ? <Problem>{String(hosts.error)}</Problem> : (
        <Table
          rows={rows}
          keyOf={(one) => one.id}
          rowTestId={(one) => `${testId}-${one.hostname}`}
          testId={`${testId}-hosts`}
          loading={hosts.isLoading} empty={t("No host matches this.")}
          columns={[
            {
              key: "chosen",
              head: t("Chosen"),
              cell: (one) => (
                <Check checked={chosen.has(one.id)} onChange={() => toggle(one.id)}>{one.hostname}</Check>
              ),
            },
            {
              key: "state",
              head: t("State"),
              cell: (one) => <><Dot state={one.connection_state} /> {t(stateName(one.connection_state))}</>,
            },
            { key: "site", head: t("Site"), minor: true, cell: (one) => one.site || <span className="fl-faint">—</span> },
            { key: "environment", head: t("Environment"), minor: true, cell: (one) => one.environment || <span className="fl-faint">—</span> },
            {
              key: "tags",
              head: t("Tags"),
              minor: true,
              cell: (one) => one.tags.length > 0
                ? <Tags>{one.tags.map((tag) => <Tag key={tag}>{tag}</Tag>)}</Tags>
                : <span className="fl-faint">—</span>,
            },
          ]}
        />
      )}
      {hosts.hasNextPage && (
        <Actions>
          <button type="button" className="fl-quiet fl-small" onClick={() => hosts.fetchNextPage()}
                  disabled={hosts.isFetchingNextPage}>
            {t("Load more ({n} left)", { n: total - rows.length })}
          </button>
        </Actions>
      )}
    </Stack>
  );
}

/**
 * The distribution of the frozen snapshot by site, environment, OS family
 * and the required capability.
 */
function Distribution({ preview }: { preview?: Preview }) {
  const t = useT();
  const dimensions = Object.entries(preview?.distribution ?? {}).filter(([, groups]) => groups.length > 0);
  if (!dimensions.length) return null;
  const names: Record<string, string> = {
    site: t("site"),
    environment: t("environment"),
    os_family: t("os family"),
    capability: t("capability"),
  };
  return (
    <Facts>
      {dimensions.map(([dimension, groups]) => (
        <Fact key={dimension} label={names[dimension] ?? dimension}>
          {groups.map((group) => `${group.reason} ${group.count}`).join(", ")}
        </Fact>
      ))}
    </Facts>
  );
}

/* ------------------------------------------------------- 3. Eligibility */

type Bucket = { key: string; mark: ReactNode; count: number; sample: string[] };

function EligibilityStep({ order, preview, checking, nav }: {
  order: Order; preview?: Preview; checking: boolean; nav: ReactNode;
}) {
  const t = useT();
  // A rename names every host in its mapping; a matched host the mapping
  // leaves out will settle as ineligible on the server, and is listed so
  // here, before the order, under the code the server will give it.
  const unnamed = order.action === RENAME_OPERATION
    ? (preview?.hosts ?? []).filter((host) => (order.mapping[host.id] ?? "").trim() === "")
    : [];
  const excluded = [...(preview?.excluded ?? [])];
  if (unnamed.length > 0) {
    excluded.push({
      reason: "no_hostname_for_host",
      count: unnamed.length,
      sample: unnamed.slice(0, 12).map((host) => host.hostname),
    });
  }
  const notes = preview?.notes ?? [];
  const eligible = Math.max(0, (preview?.eligible ?? 0) - unnamed.length);
  const sample = unnamed.length > 0
    ? (preview?.hosts ?? []).filter((host) => (order.mapping[host.id] ?? "").trim() !== "")
      .slice(0, 12).map((host) => host.hostname)
    : preview?.sample ?? [];
  const buckets: Bucket[] = [
    { key: "eligible", mark: <Pill tone="ok">{t("eligible")}</Pill>, count: eligible, sample },
    ...excluded.map((group): Bucket => ({
      key: `excluded:${group.reason}`,
      mark: <Pill tone="error">{reasonName(t, group.reason)}</Pill>,
      count: group.count,
      sample: group.sample,
    })),
    // A note does not exclude the host. An offline host comes back and does
    // its part; a host in a conflict waits for somebody else's lock.
    ...notes.map((group): Bucket => ({
      key: `note:${group.reason}`,
      mark: <Pill tone="warn">{reasonName(t, group.reason)}</Pill>,
      count: group.count,
      sample: group.sample,
    })),
  ];
  return (
    <Card
      span={12}
      title={`3. ${t("Eligibility")}`}
      note={t("Nothing to fill in here: read which of the matched hosts can run the operation and why the rest cannot, then go on to the rollout. A host that cannot run it stays in the snapshot with its reason; dropping it quietly would hide a decision nobody made.")}
      foot={
        <Stack>
          {!excluded.length && !notes.length && <Note>{t("Every matched host can run this operation.")}</Note>}
          {nav}
        </Stack>
      }
    >
      {checking ? <Bones rows={4} /> : (
        <Table
          rows={buckets}
          keyOf={(one) => one.key}
          testId="eligibility"
          columns={[
            { key: "bucket", head: t("Bucket"), cell: (one) => one.mark },
            { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.count },
            {
              key: "which",
              head: t("Which"),
              cell: (one) => one.sample.length > 0
                ? <span className="fl-faint">{one.sample.join(", ")}</span>
                : <span className="fl-faint">—</span>,
            },
          ]}
        />
      )}
    </Card>
  );
}

/** The kind of obstacle in words, not the bare code. */
function reasonName(t: Translate, reason: string): string {
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

/* ----------------------------------------------------------- 4. Rollout */

function RolloutStep({ order, change, targets, declaredPolicy, nav }: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  targets: number;
  declaredPolicy?: string;
  nav: ReactNode;
}) {
  const t = useT();
  const policyNames: Record<string, string> = {
    wait_until_deadline: t("wait for the host until the deadline"),
    replan_on_reconnect: t("wait, then compute the plan again when the host is back"),
    skip_if_offline: t("leave the host out, not a failure"),
    require_online: t("skip the host and say it was offline"),
  };
  // Only the policies at least as strict as the operation's own are offered;
  // the rest would be refused anyway.
  const declaredIndex = declaredPolicy ? OFFLINE_POLICIES.indexOf(declaredPolicy) : -1;
  const offered = OFFLINE_POLICIES.filter((policy, index) =>
    index >= declaredIndex && (policy !== "replan_on_reconnect" || declaredPolicy === "replan_on_reconnect"));
  return (
    <Card
      span={12}
      title={`4. ${t("Rollout")}`}
      note={t("Decide how many hosts change at once and when the campaign stops itself; the defaults suit a first campaign. A canary goes first as wave zero, the rest follow in waves, and a host waiting for capacity says so instead of standing still.")}
      tools={<Link to="/budgets" className="fl-quiet fl-small">{t("See the budgets.")}</Link>}
      foot={
        <Stack>
          <Note>
            {t("{targets} hosts, canary {canary}, then waves of {wave} with at most {concurrent} at a time.", {
              targets, canary: order.canary, wave: order.wave, concurrent: order.concurrent,
            })}
          </Note>
          {nav}
        </Stack>
      }
    >
      <Fields>
        <Field label={t("Canary hosts")} hint={t("How many hosts go first, alone, before any wave; 0 skips the canary.")}>
          <input type="number" min={0} value={order.canary} data-testid="canary"
                 onChange={(event) => change({ canary: +event.target.value })} />
        </Field>
        <Field label={t("Wave size")} hint={t("How many hosts each wave after the canary holds; the next wave starts when the previous one is done.")}>
          <input type="number" min={1} value={order.wave} data-testid="wave"
                 onChange={(event) => change({ wave: +event.target.value })} />
        </Field>
        <Field label={t("Concurrent hosts")} hint={t("How many hosts of a wave change at the same moment.")}>
          <input type="number" min={1} value={order.concurrent} data-testid="concurrent"
                 onChange={(event) => change({ concurrent: +event.target.value })} />
        </Field>
        <Field label={t("Failure threshold (%)")} hint={t("Pause the campaign once this share of the finished hosts failed; 0 turns the share off.")}>
          <input type="number" min={0} max={100} value={order.thresholdPercent}
                 onChange={(event) => change({ thresholdPercent: +event.target.value })} />
        </Field>
        <Field label={t("Failure threshold (hosts)")} hint={t("Pause the campaign once this many hosts failed, whatever the share; 0 turns the count off.")}>
          <input type="number" min={0} value={order.thresholdCount}
                 onChange={(event) => change({ thresholdCount: +event.target.value })} />
        </Field>
        <Field label={t("Reboot policy")} hint={t("Whether a host is rebooted after its change: never, only when the host reports a reboot is required, or always.")}>
          <select value={order.rebootPolicy} data-testid="reboot-policy"
                  onChange={(event) => change({ rebootPolicy: event.target.value })}>
            <option value="never">{t("reboot: never")}</option>
            <option value="if_required">{t("reboot: when required")}</option>
            <option value="always">{t("reboot: always")}</option>
          </select>
        </Field>
        <Field
          label={t("Reboot timeout (seconds)")}
          hint={order.rebootPolicy === "never"
            ? t("Not used: the reboot policy is never.")
            : t("How long a rebooted host is waited for before it fails; a host still away when the maintenance window ends fails at once and pauses the campaign.")}
        >
          <input type="number" min={REBOOT_TIMEOUT.min} max={REBOOT_TIMEOUT.max} step={60}
                 value={order.rebootTimeoutSeconds} disabled={order.rebootPolicy === "never"}
                 onChange={(event) => change({ rebootTimeoutSeconds: +event.target.value })} />
        </Field>
        <Field
          label={t("Connectivity loss threshold (hosts)")}
          hint={t("Pause once this many hosts lose their session mid-task; 0 turns the check off. A change that cuts hosts off shows up here, not among the failures.")}
        >
          <input type="number" min={0} value={order.connectivityLost}
                 onChange={(event) => change({ connectivityLost: +event.target.value })} />
        </Field>
        <Field
          label={t("Offline policy")}
          hint={declaredPolicy
            ? t("The operation declares {policy}; a campaign may only tighten it.", { policy: declaredPolicy })
            : t("What happens to a host that is not connected when its turn comes.")}
        >
          <select value={order.offlinePolicy} data-testid="offline-policy"
                  onChange={(event) => change({ offlinePolicy: event.target.value })}>
            <option value="">{t("as the operation declares")}</option>
            {offered.map((policy) => (
              <option key={policy} value={policy}>{policy}: {policyNames[policy]}</option>
            ))}
          </select>
        </Field>
        <Field label={t("Deadline for offline hosts (minutes)")}
               hint={t("Counted from the creation; a host still offline by then is left out with a reason.")}>
          <input type="number" min={1} value={order.deadlineMinutes}
                 onChange={(event) => change({ deadlineMinutes: +event.target.value })} />
        </Field>
        {/* A gate after the canary needs a canary to gate on: with none the
            box is off, and the hint says why rather than leaving a control
            that does nothing. */}
        <Field
          label={t("Manual gate")}
          hint={order.canary <= 0
            ? t("A manual gate needs a canary: set the canary above 0 to stop after it.")
            : t("The campaign holds after the canary until somebody advances it.")}
          wide
        >
          <Check
            checked={order.manualGate && order.canary > 0}
            disabled={order.canary <= 0}
            onChange={(on) => change({ manualGate: on })}
          >
            {t("stop after the canary until somebody advances the campaign")}
          </Check>
        </Field>
      </Fields>
    </Card>
  );
}

/* -------------------------------------------- 5. Window and verification */

function WindowStep({ order, change, operation, nav }: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  operation?: Operation;
  nav: ReactNode;
}) {
  const t = useT();
  const problem = windowProblem(order.maintenanceStart, order.maintenanceEnd, new Date());
  const units = parseUnits(order.healthCheckUnits);
  const timeoutFits = jobTimeoutValid(order.jobTimeoutSeconds);
  const schedule = order.schedule;
  const scheduleFault = scheduleWords(t, scheduleProblem(schedule, new Date()));
  const changeSchedule = (delta: Partial<ScheduleChoice>) => change({ schedule: { ...schedule, ...delta } });
  return (
    <Card
      span={12}
      title={`5. ${t("Window and verification")}`}
      note={t("Say when the change may run and what is checked afterwards; everything here is optional, and left empty the campaign runs as soon as it is approved and verifies nothing. Both go into the fingerprint the approver signs; the next step creates the campaign.")}
      foot={nav}
    >
      <Stack>
        <Fields>
          <Field
            label={t("Window opens")}
            hint={problem === "start_past" || problem === "start_invalid"
              ? windowWords(t, problem)
              : t("Optional; hosts wait until then. Local time.")}
          >
            <input type="datetime-local" value={order.maintenanceStart} data-testid="window-start"
                   onChange={(event) => change({ maintenanceStart: event.target.value })} />
          </Field>
          <Field
            label={t("Window closes")}
            hint={problem === "end_past" || problem === "end_before_start" || problem === "end_invalid"
              ? windowWords(t, problem)
              : t("Optional; no host is started once it closes - a host still waiting stays held back, and a host still rebooting fails and pauses the campaign.")}
          >
            <input type="datetime-local" value={order.maintenanceEnd} min={order.maintenanceStart || undefined}
                   data-testid="window-end"
                   onChange={(event) => change({ maintenanceEnd: event.target.value })} />
          </Field>
          <Field
            label={t("Units to check afterwards")}
            hint={units.length === 0
              ? t("One unit per line or comma-separated, named as the hosts name them - the same service is called differently on different distributions. Checked on every host right after the change, or after the reboot when one follows; empty means nothing is verified.")
              : t("{n} units will be checked on every host once its change is done.", { n: units.length })}
            wide
          >
            <textarea rows={3} className="fl-mono" value={order.healthCheckUnits} data-testid="health-units"
                      placeholder={t("A unit of these hosts, one per line")}
                      onChange={(event) => change({ healthCheckUnits: event.target.value })} spellCheck={false} />
          </Field>
          <Field
            label={t("Job timeout (seconds)")}
            hint={!timeoutFits
              ? t("Between {min} and {max} seconds, or 0 for the operation's default.", { min: JOB_TIMEOUT.min, max: JOB_TIMEOUT.max })
              : operation?.default_timeout_seconds
                ? t("How long one host's task may run; 0 keeps the operation's default of {n} seconds.", { n: operation.default_timeout_seconds })
                : t("How long one host's task may run; 0 keeps the operation's default.")}
          >
            <input type="number" min={0} max={JOB_TIMEOUT.max} step={30} value={order.jobTimeoutSeconds}
                   data-testid="job-timeout"
                   onChange={(event) => change({ jobTimeoutSeconds: +event.target.value })} />
          </Field>
        </Fields>

        <Note>
          {t("Every campaign waits for an approval before anything runs: the approver signs the operation, the payload, the host list, the rollout policy and the set of plans as one fingerprint.")}
        </Note>

        {/* The order kept for a moment instead of placed now. The schedule
            places this same order through the same door at its moments, so
            everything above still applies to each campaign it places. */}
        <h3 className="fl-subhead">{t("Schedule")}</h3>
        <Check checked={schedule.enabled} onChange={(on) => changeSchedule({ enabled: on })}>
          {t("Schedule instead of ordering now")}
        </Check>
        <Note>
          {schedule.enabled
            ? scheduleFault || t("The order is kept and placed at its moments under your rights as they stand then; each campaign waits for its approval. Listed under Campaigns › Schedules.")
            : t("Keep the order for a moment ahead, once or on a monthly or weekly rule, instead of creating the campaign now.")}
        </Note>
        {schedule.enabled && (
          <Stack>
            <Fields>
              <Field
                label={t("First run")}
                hint={schedule.recurrence.freq
                  ? t("Optional with a recurrence: the earliest moment the rule may name.")
                  : t("The one moment the order is placed at. Local time.")}
              >
                <input type="datetime-local" value={schedule.startAt} data-testid="schedule-start"
                       onChange={(event) => changeSchedule({ startAt: event.target.value })} />
              </Field>
            </Fields>
            <Recurrence value={schedule.recurrence} onChange={(recurrence) => changeSchedule({ recurrence })} />
          </Stack>
        )}
      </Stack>
    </Card>
  );
}

/** The rule of the moments after the first one. */
function Recurrence({ value, onChange }: { value: RecurrenceForm; onChange: (next: RecurrenceForm) => void }) {
  const t = useT();
  return (
    <Stack>
      <Fields>
        <Field label={t("Repeats")}>
          <select value={value.freq} data-testid="recurrence-freq"
                  onChange={(event) => onChange({ ...value, freq: event.target.value as RecurrenceForm["freq"] })}>
            <option value="">{t("does not repeat")}</option>
            <option value="MONTHLY">{t("monthly")}</option>
            <option value="WEEKLY">{t("weekly")}</option>
          </select>
        </Field>
        {value.freq === "MONTHLY" && (
          <Field label={t("Day of the month")} hint={t("A month without that day is skipped: the 31st names nothing in April.")}>
            <input type="number" min={1} max={31} value={value.monthDay}
                   onChange={(event) => onChange({ ...value, monthDay: +event.target.value })} />
          </Field>
        )}
        {value.freq && (
          <>
            <Field label={t("Hour")}>
              <input type="number" min={0} max={23} value={value.hour}
                     onChange={(event) => onChange({ ...value, hour: +event.target.value })} />
            </Field>
            <Field label={t("Minute")}>
              <input type="number" min={0} max={59} value={value.minute}
                     onChange={(event) => onChange({ ...value, minute: +event.target.value })} />
            </Field>
          </>
        )}
      </Fields>
      {value.freq === "WEEKLY" && (
        <>
          <h3 className="fl-subhead">{t("Weekdays")}</h3>
          <Toolbar>
            {WEEKDAYS.map((day) => (
              <Check
                key={day}
                checked={value.weekdays.includes(day)}
                onChange={(on) => onChange({
                  ...value,
                  weekdays: on ? [...value.weekdays, day] : value.weekdays.filter((present) => present !== day),
                })}
              >
                {day}
              </Check>
            ))}
          </Toolbar>
        </>
      )}
    </Stack>
  );
}

/* ------------------------------------------------------------ 6. Create */

function CreateStep({ order, change, targets, compensates, token, campaignID, onCreated, nav }: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  targets: number;
  compensates?: Preview["compensates"];
  /** The preview this order is placed from. */
  token?: PreviewToken;
  campaignID: string;
  onCreated: (id: string) => void;
  nav: ReactNode;
}) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  const queryClient = useQueryClient();
  const reasonOK = reasonValid(order.reason);

  const create = useMutation({
    mutationFn: () => api.post<Campaign>("/api/v1/campaigns", campaignBody(order, token)),
    onSuccess: (campaign) => {
      void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onCreated(campaign.id);
    },
    onError: (error) => {
      setErrorMessage(refusalWords(t, error));
      // A refused order has spent its preview, whatever the reason: the next
      // attempt is placed from a fresh one.
      void queryClient.invalidateQueries({ queryKey: ["campaign-preview"] });
    },
  });
  // A scheduled order creates no campaign now: the schedule is the record,
  // and the wizard ends here with a link to it.
  const [scheduled, setScheduled] = useState("");
  const schedule = useMutation({
    mutationFn: () => api.post<{ id: string }>("/api/v1/campaign-schedules", scheduleBody(order)),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: ["campaign-schedules"] });
      clearDraft(sessionStorageOrNull());
      setScheduled(created.id);
    },
    onError: (error) => setErrorMessage(refusalWords(t, error)),
  });
  const scheduling = order.schedule.enabled;

  return (
    <Card
      span={12}
      title={`6. ${t("Create")}`}
      note={scheduling
        ? t("Give the reason and record the schedule: the order is placed at its moments, and each campaign it places waits for its approval. Nothing changes on any host now.")
        : t("Give the reason and create the campaign: this freezes the host list and every host starts computing its plan. Nothing changes on any host yet; that takes the approval two steps on.")}
      foot={nav}
    >
      <Stack>
        {/* The link is part of what is created: the operator is to read which
            campaign this one undoes before pressing the button. */}
        {order.compensates && (
          <Note>
            {t("Compensates campaign")}{" "}
            {compensates
              ? <Link to={`/campaigns/${compensates.id}`}>{compensates.name}</Link>
              : <span className="fl-mono">{order.compensates}</span>}
            {" · "}
            {t("The original is linked, never rewritten; its hosts get a compensate step as the reverse change runs on them.")}
          </Note>
        )}
        <Fields>
          {/* The reason is the one sentence the audit trail keeps next to the
              order; the operation name repeated there would say nothing. */}
          <Field
            label={t("Reason or change reference")}
            hint={reasonOK
              ? t("Kept in the audit trail next to the order, and shown to the approver.")
              : t("Required: at least {n} characters, e.g. the change ticket and what it fixes.", { n: MIN_REASON })}
            wide
          >
            <input
              value={order.reason}
              data-testid="order-reason"
              placeholder={t("e.g. CHG-1234: rotate the web tier onto the patched kernel")}
              onChange={(event) => change({ reason: event.target.value })}
              disabled={Boolean(campaignID)}
            />
          </Field>
        </Fields>
        <Actions>
          {scheduling ? (
            <button type="button" onClick={() => schedule.mutate()} data-testid="schedule-order"
                    disabled={schedule.isPending || Boolean(scheduled) || !reasonOK}
                    title={scheduled
                      ? t("The schedule is already recorded.")
                      : !reasonOK ? t("Give a reason of at least {n} characters first.", { n: MIN_REASON }) : undefined}>
              {schedule.isPending ? t("Scheduling…") : t("Schedule a campaign on {n} hosts", { n: targets })}
            </button>
          ) : (
            <button type="button" onClick={() => create.mutate()} data-testid="create-campaign"
                    disabled={create.isPending || Boolean(campaignID) || !reasonOK}
                    title={campaignID
                      ? t("The campaign is already created.")
                      : !reasonOK ? t("Give a reason of at least {n} characters first.", { n: MIN_REASON }) : undefined}>
              {create.isPending ? t("Creating…") : t("Create a campaign on {n} hosts", { n: targets })}
            </button>
          )}
          {!reasonOK && !campaignID && !scheduled && (
            <span className="fl-note">{t("The button waits for a reason of at least {n} characters.", { n: MIN_REASON })}</span>
          )}
        </Actions>
        {scheduled && (
          <Note>
            {t("The schedule is recorded; the campaign is created at its moment.")}{" "}
            <Link to="/campaigns/schedules">{t("Open the schedules")}</Link>
          </Note>
        )}
        {errorMessage && <Problem>{errorMessage}</Problem>}
      </Stack>
    </Card>
  );
}

/* ------------------------------------------------------------- 7. Plans */

function PlansStep({ campaignID, campaign, nav }: { campaignID: string; campaign?: Campaign; nav: ReactNode }) {
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
  const planning = campaign?.state === "planning";
  const groups = plans.data?.items ?? [];
  return (
    <Card
      span={12}
      title={`7. ${t("Plans")}`}
      note={planning
        ? t("Wait: each host is computing what it would change, and the page refreshes by itself. Nothing is applied while this runs; the approval opens once every plan is in.")
        : t("Read what every host would change - hosts with the same change are shown as one group - then go on to approve. The fingerprint covers the whole set: a host whose plan changed refuses the change.")}
      foot={nav}
    >
      {targets.error ? <Problem>{String(targets.error)}</Problem> : (
        <Stack>
          {planning && groups.length === 0 && <Bones rows={4} />}
          {/* One group is one shape of the change: its hosts, fingerprint and
              expiry in a line, then the change itself. */}
          {groups.map((group) => (
            <PlanGroupView key={group.plan_hash} group={group} action={campaign?.action_type} />
          ))}
          {!planning && groups.length === 0 && (
            <Empty icon="help">{t("This campaign has no per-host plan: the operation is applied as it was ordered.")}</Empty>
          )}
          <TargetTable targets={targets} action={campaign?.action_type ?? ""} />
        </Stack>
      )}
    </Card>
  );
}

/** How many host names the header of a group spells out before it counts the rest. */
const HOSTS_SHOWN = 12;

/**
 * One group of identical plans: who it is for, what binds it, and what it
 * would change.
 */
function PlanGroupView({ group, action }: { group: PlanGroup; action?: string }) {
  const t = useT();
  const plan = (group.plan?.plan ?? group.plan ?? {}) as HostPlan & PackagePlanFacts;
  const named = group.hosts.slice(0, HOSTS_SHOWN);
  const more = group.hosts.length - named.length;
  const trouble = Boolean(plan.refusal || plan.validator_failed);
  const status = planStatus(group);
  const planner = group.planner_version ?? plan.planner_version;
  return (
    <Stack>
      <Facts>
        <Fact label={t("Hosts")}>
          <span title={group.hosts.join("\n")}>
            {t("{n} hosts", { n: group.count })} {named.join(", ")}{more > 0 ? ` +${more}` : ""}
          </span>
        </Fact>
        <Fact label={t("Plan fingerprint")}>
          <span className="fl-mono" title={group.plan_hash}>{group.plan_hash.slice(0, 16)}</span>
        </Fact>
        {/* The planner that made the plan: two plans of different planners
            are different plans even over the same packages. */}
        <Fact label={t("Planner")}>
          {planner ? <span className="fl-mono">{planner}</span> : <span className="fl-faint">—</span>}
        </Fact>
        {/* A plan is bound in time as well as by its digest. */}
        <Fact label={t("Valid until")}>
          <span title={absoluteTime(group.expires_at)}>{relativeTime(group.expires_at)}</span>
        </Fact>
        <Fact label={t("Plan")}>
          {status === "expired"
            ? <Pill tone="error">{t("expired")}</Pill>
            : status === "unknown"
              ? (
                <Pill tone="error" title={t("The panel cannot read this plan as a declaration of its effects; exclude these hosts with a reason or plan again.")}>
                  {t("unknown plan")}
                </Pill>
              )
              : <Pill tone="ok">{t("read")}</Pill>}
        </Fact>
      </Facts>

      {status === "unknown" ? (
        <Banner tone="error">
          {t("The host gave a plan the panel cannot read. Nothing here is approved: exclude the hosts with a reason, or plan the campaign again once the agent is upgraded.")}
        </Banner>
      ) : trouble ? (
        <PlanTrouble plan={plan} />
      ) : (
        <Stack>
          <Note>
            {action ? `${action} · ` : ""}{planWords(plan, t)}
            {/* The source resolved to a UUID is what goes to the host. */}
            {plan.resolved_source && plan.resolved_source !== plan.requested_source
              ? ` · ${plan.requested_source} → ${plan.resolved_source}`
              : ""}
          </Note>
          {(plan.warnings ?? []).length > 0 && (
            <Tags>
              {(plan.warnings ?? []).map((warning) => <Pill key={warning} tone="warn">{warning}</Pill>)}
            </Tags>
          )}
          <PlanFacts plan={plan} />
          <PlanBlocked plan={plan} />
          <PlanChanges changes={plan.changes} />
          <PlanVerbatim plan={plan} />
        </Stack>
      )}
    </Stack>
  );
}

/** A plan that refused, or whose validator did. */
function PlanTrouble({ plan }: { plan: HostPlan }) {
  const t = useT();
  if (plan.refusal) return <Problem>{t("refused: {reason}", { reason: plan.refusal })}</Problem>;
  return (
    <Problem>
      {t("validator failed")}{plan.validator_output ? `: ${plan.validator_output.slice(0, 200)}` : ""}
    </Problem>
  );
}

/**
 * What a package plan says besides its packages: whether a reboot follows,
 * how much comes down the wire, and whether every file system has room.
 */
function PlanFacts({ plan }: { plan: PackagePlanFacts }) {
  const t = useT();
  const purposes: Record<string, string> = {
    download: t("download cache"), install: t("installed files"), boot: t("boot files"),
  };
  const facts: { key: string; text: string; warn?: boolean }[] = [];
  if (plan.reboot_predicted) facts.push({ key: "reboot", text: t("reboot predicted"), warn: true });
  if (plan.download_bytes) facts.push({ key: "download", text: t("download {size}", { size: bytes(plan.download_bytes) }) });
  for (const fact of plan.space ?? []) {
    const known = Boolean(fact.basis) && fact.basis !== "unknown";
    const short = known && (fact.needed_bytes ?? 0) > (fact.available_bytes ?? 0);
    const purpose = purposes[fact.purpose ?? ""] ?? fact.purpose ?? "";
    facts.push({
      key: `${fact.purpose}:${fact.path}`,
      warn: short,
      text: known
        ? t("{path} ({purpose}): needs {needed}, {available} free", {
          path: fact.path, purpose, needed: bytes(fact.needed_bytes), available: bytes(fact.available_bytes),
        })
        : t("{path} ({purpose}): need unknown, {available} free", {
          path: fact.path, purpose, available: bytes(fact.available_bytes),
        }),
    });
  }
  // The rollback answer is a fact of the plan too.
  if (plan.rollback?.mechanism) {
    facts.push(plan.rollback.available
      ? { key: "rollback", text: t("rollback: {mechanism}", { mechanism: plan.rollback.mechanism }) }
      : {
        key: "rollback",
        text: t("no rollback: {reason}", { reason: plan.rollback.reason ?? plan.rollback.mechanism }),
        warn: true,
      });
  }
  if (facts.length === 0) return null;
  return (
    <Tags>
      {facts.map((fact) => (
        <Pill key={fact.key} tone={fact.warn ? "warn" : "neutral"} dot={false}>{fact.text}</Pill>
      ))}
    </Tags>
  );
}

/**
 * What the plan leaves out. An update no advisory classifies is not a fault
 * of the host, so it reads as a note; a broken package database is.
 */
function PlanBlocked({ plan }: { plan: PackagePlanFacts }) {
  const t = useT();
  const blocked = plan.blocked ?? [];
  if (blocked.length === 0) return null;
  const database = blocked.filter((entry) => (entry.kind ?? "database") === "database");
  const held = blocked.filter((entry) => entry.kind === "held");
  const unknown = blocked.filter((entry) => entry.kind === "unknown");
  const advisory = blocked.length - database.length - held.length - unknown.length;
  return (
    <Stack>
      {database.length > 0 && (
        <Banner tone="error">
          {t("{n} packages block the package operations of this host; a repair has to run before the plan is applied.", { n: database.length })}
        </Banner>
      )}
      {held.length > 0 && (
        <Note>{t("{n} updates are held back on the host itself and stay out of this plan.", { n: held.length })}</Note>
      )}
      {unknown.length > 0 && (
        <Banner tone="warn">
          {t("{n} entries of this transaction could not be named; what they stand for is not in the plan.", { n: unknown.length })}
        </Banner>
      )}
      {advisory > 0 && (
        <Note>
          {t("{n} packages stay out of this plan: no advisory of this host says whether their update closes a vulnerability.", { n: advisory })}
        </Note>
      )}
      <Table
        rows={blocked}
        keyOf={(one) => `${one.kind ?? "database"}:${one.name}`}
        testId="plan-blocked"
        columns={[
          { key: "name", head: t("Package"), tight: true, cell: (one) => <code>{one.name}</code> },
          { key: "status", head: t("Status"), cell: (one) => one.status || <span className="fl-faint">—</span> },
        ]}
      />
    </Stack>
  );
}

/** How many package rows a plan shows before the operator asks for the rest. */
const ROWS_SHOWN = 8;

/**
 * The changes of a plan: a package plan is one row per package with the
 * version it has now and the one it gets, folded to the first few rows.
 */
function PlanChanges({ changes }: { changes?: (string | { name: string })[] }) {
  const t = useT();
  const [all, setAll] = useState(false);
  if (!changes || changes.length === 0) return null;
  const packages = changes.filter(isPackageChange).sort((a, b) => a.name.localeCompare(b.name));
  const sentences = changes.filter((change): change is string => typeof change === "string");
  if (packages.length === 0) {
    return (
      <Stack>
        {sentences.map((change, index) => <Note key={`${index}:${change}`}>{change}</Note>)}
      </Stack>
    );
  }
  const rows = all ? packages : packages.slice(0, ROWS_SHOWN);
  const security = packages.filter((change) => change.security).length;
  const removals = packages.filter((change) => changeAction(change) === "remove").length;
  const downgrades = packages.filter((change) => changeAction(change) === "downgrade").length;
  return (
    <Stack>
      <Table
        rows={rows}
        keyOf={(one) => one.name}
        testId="plan-changes"
        columns={[
          { key: "package", head: t("Package"), tight: true, cell: (one) => <code>{one.name}</code> },
          {
            key: "change",
            head: t("Change"),
            // The direction is what the host said; a dash is a host that did
            // not say, never an upgrade by default.
            cell: (one) => {
              const action = changeAction(one);
              if (!action) {
                return (
                  <span className="fl-faint" title={t("The plan does not name the direction of this change.")}>—</span>
                );
              }
              const word = t(ACTION_WORDS[action] ?? action);
              return action === "remove" || action === "downgrade"
                ? <Pill tone="warn">{word}</Pill>
                : <>{word}</>;
            },
          },
          // A package without a current version is new on the host; one
          // without a candidate goes away.
          { key: "now", head: t("Now"), tight: true, cell: (one) => one.current_version || <span className="fl-faint">—</span> },
          { key: "after", head: t("After"), tight: true, cell: (one) => one.candidate_version || <span className="fl-faint">—</span> },
          {
            key: "note",
            head: t("Note"),
            cell: (one) => {
              const delta = one.installed_delta_known ? one.installed_delta_bytes ?? 0 : undefined;
              return (
                <Tags>
                  {one.security && <Pill tone="warn">{t("security")}</Pill>}
                  {one.protected && <Pill tone="error">{t("protected")}</Pill>}
                  {one.blocked && <Pill tone="error">{t("blocked")}</Pill>}
                  {one.origin && <Tag>{one.origin}</Tag>}
                  {one.architecture && <Tag>{one.architecture}</Tag>}
                  {one.reason && one.reason !== "requested" && <Tag>{t(one.reason)}</Tag>}
                  {delta !== undefined && delta !== 0 && (
                    <Tag>{`${delta > 0 ? "+" : "−"}${bytes(Math.abs(delta))}`}</Tag>
                  )}
                </Tags>
              );
            },
          },
        ]}
      />
      <Toolbar
        end={packages.length > ROWS_SHOWN ? (
          <button type="button" className="fl-quiet fl-small" onClick={() => setAll(!all)} data-testid="plan-fold">
            {all ? t("Show fewer") : t("Show all {n}", { n: packages.length })}
          </button>
        ) : undefined}
      >
        <span className="fl-note">
          {t("{n} packages", { n: packages.length })}
          {security > 0 ? ` · ${t("{n} security", { n: security })}` : ""}
          {removals > 0 ? ` · ${t("{n} removed", { n: removals })}` : ""}
          {downgrades > 0 ? ` · ${t("{n} downgraded", { n: downgrades })}` : ""}
        </span>
      </Toolbar>
      {sentences.map((change, index) => <Note key={`${index}:${change}`}>{change}</Note>)}
    </Stack>
  );
}

/** The text the plan applies, exactly as the host would see it. */
function PlanVerbatim({ plan }: { plan: HostPlan }) {
  const t = useT();
  const verbatim = plan.document
    ? { label: t("Document"), text: plan.document }
    : plan.commands?.length
      ? { label: t("Commands"), text: plan.commands.join("\n") }
      : null;
  if (!verbatim) return null;
  return (
    <>
      <h3 className="fl-subhead">{verbatim.label}</h3>
      <pre className="fl-mono">{verbatim.text}</pre>
    </>
  );
}

/* -------------------------------------------------- 8. Approval and run */

function ApprovalStep({ campaignID, campaign, nav }: { campaignID: string; campaign?: Campaign; nav: ReactNode }) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  // The reason and the change ticket go into the approval record next to the
  // fingerprint.
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState("");
  const queryClient = useQueryClient();
  const targets = useTargets(campaignID, {});
  const approve = useMutation({
    mutationFn: () => api.post(`/api/v1/campaigns/${campaignID}/approve`, {
      reason: reason.trim(),
      change_ticket: ticket.trim(),
      // The consent carries the fingerprint of what is on screen.
      approval_fingerprint: campaign?.approval_fingerprint,
    }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["campaign", campaignID] }),
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  if (!campaign) {
    return (
      <Card span={12} title={`8. ${t("Approval and run")}`} foot={nav}>
        <Empty icon="help">{t("No campaign yet.")}</Empty>
      </Card>
    );
  }
  return (
    <Card
      span={12}
      title={`8. ${t("Approval and run")}`}
      note={t("Give the reason and approve: the campaign starts at once, canary first, and its progress is followed on the campaign page. You are approving this operation, this payload, this list of hosts, this rollout policy and this set of plans - together, as one fingerprint.")}
      foot={nav}
    >
      <Stack>
        <Facts>
          <Fact label={t("Fingerprint")}>
            <span className="fl-mono" data-testid="approval-fingerprint">{campaign.approval_fingerprint}</span>
          </Fact>
        </Facts>
        {errorMessage && <Problem>{errorMessage}</Problem>}
        {campaign.state === "awaiting_approval" ? (
          <Stack>
            <Fields>
              {/* The consent is what the audit record keeps next to the
                  fingerprint; a consent without a reason is noise there. */}
              <Field
                label={t("Reason (kept in the audit trail)")}
                hint={reasonValid(reason)
                  ? t("Recorded with the fingerprint; a critical operation asks for fresh authentication as well.")
                  : t("Required: at least {n} characters.", { n: MIN_REASON })}
                wide
              >
                <input value={reason} data-testid="approve-reason" onChange={(event) => setReason(event.target.value)} />
              </Field>
              <Field label={t("Change ticket")} hint={t("Optional: the identifier or address of the change request.")}>
                <input value={ticket} data-testid="approve-ticket" placeholder="CHG-1234"
                       onChange={(event) => setTicket(event.target.value)} />
              </Field>
            </Fields>
            <Actions>
              <button type="button" onClick={() => approve.mutate()} data-testid="approve"
                      disabled={approve.isPending || !reasonValid(reason)}
                      title={reasonValid(reason) ? undefined : t("Give a reason of at least {n} characters first.", { n: MIN_REASON })}>
                {approve.isPending ? t("Approving…") : t("Approve and start")}
              </button>
              {!reasonValid(reason) && (
                <span className="fl-note">{t("The button waits for a reason of at least {n} characters.", { n: MIN_REASON })}</span>
              )}
            </Actions>
          </Stack>
        ) : (
          <Note>
            {t("This campaign is")}{" "}
            <Pill tone={campaignTone(campaign.state)}>{t(stateName(campaign.state))}</Pill>.{" "}
            {/* Pausing and cancelling belong to the campaign screen: the
                consequences are described there. */}
            <Link to={`/campaigns/${campaign.id}`}>{t("Pause, cancel or read the report")}</Link>.
          </Note>
        )}
        <TargetTable targets={targets} action={campaign.action_type} />
      </Stack>
    </Card>
  );
}

/** The hosts of the campaign, with what is holding each of them up. */
function TargetTable({ targets, action }: { targets: ReturnType<typeof useTargets>; action: string }) {
  const t = useT();
  const rows = loadedTargets(targets.data);
  const total = targets.data?.pages[0]?.total ?? 0;
  if (!rows.length) {
    return <Empty icon="hosts">{t("No targets.")}</Empty>;
  }
  return (
    <Stack>
      <Table
        rows={rows}
        keyOf={(one) => one.host_id}
        rowTestId={(one) => `target-${one.hostname || one.host_id}`}
        testId="campaign-targets"
        columns={[
          {
            key: "host",
            head: t("Host"),
            cell: (one) => (
              <Link to={`/hosts/${one.host_id}/${moduleForAction(action)}?campaign=${one.campaign_id}`}>
                {one.hostname || one.host_id.slice(0, 8)}
              </Link>
            ),
          },
          { key: "wave", head: t("Wave"), num: true, cell: (one) => one.wave === 0 ? `0 (${t("canary")})` : one.wave },
          {
            key: "state",
            head: t("State"),
            cell: (one) => <Pill tone={campaignTone(one.state)}>{t(stateName(one.state))}</Pill>,
          },
          { key: "blocker", head: t("Blocker"), cell: (one) => blockerName(t, one) },
          {
            key: "message",
            head: t("Message"),
            minor: true,
            cell: (one) => one.message
              ? <TwoLine>{one.message}</TwoLine>
              : <span className="fl-faint">—</span>,
          },
        ]}
      />
      {/* The rows come page by page: a campaign on the whole fleet must not
          become the whole fleet in the browser. */}
      <Toolbar
        end={targets.hasNextPage ? (
          <button type="button" className="fl-quiet fl-small" onClick={() => targets.fetchNextPage()}
                  disabled={targets.isFetchingNextPage} data-testid="targets-more">
            {t("Load more ({n} left)", { n: total - rows.length })}
          </button>
        ) : undefined}
      >
        <span className="fl-note">{t("{shown} of {total} shown", { shown: rows.length, total })}</span>
      </Toolbar>
    </Stack>
  );
}

/** The kind of obstacle a target hit, not the bare error code. */
function blockerName(t: Translate, target: CampaignTarget): ReactNode {
  if (!target.error_code) return <span className="fl-faint">—</span>;
  if (target.error_code.startsWith("budget_")) return t("budget");
  if (target.error_code === "resource_busy") return t("resource lock");
  if (target.error_code === "capability_missing") return t("capability");
  if (target.error_code === "maintenance") return t("maintenance");
  if (target.error_code === "no_hostname_for_host") return t("no new name in the mapping");
  return target.error_code;
}

/** The operations an earlier release built a payload for by hand. */
export { UNIT_OPERATIONS, RENAME_OPERATION };
