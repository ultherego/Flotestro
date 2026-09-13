import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign, CampaignTarget } from "../lib/types";
import { ErrorBox, Empty, JobState, Time } from "../components/ui";
import { OPERATIONS_INTERVAL } from "../lib/stream";
import { useCapabilities } from "../lib/capabilities";
import { PlanSummary } from "../components/plan";
import { loadedTargets, useTargets } from "../lib/targets";
import { moduleForAction } from "./host/modules";
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
  const [step, setStep] = useState(0);
  // The campaign comes into being halfway through. Until then we work on an
  // order, afterwards - on a campaign that computes its plans itself and
  // waits for consent.
  const [campaignID, setCampaignID] = useState("");
  const [order, setOrder] = useState<Order>({
    name: "",
    action: "",
    unit: "",
    securityOnly: true,
    payloadText: "",
    site: "",
    environment: "",
    osFamily: "",
    canary: 1,
    wave: 10,
    concurrent: 5,
    thresholdPercent: 20,
    thresholdCount: 0,
    rebootPolicy: "never",
  });

  const change = (delta: Partial<Order>) =>
    setOrder((previous) => ({ ...previous, ...delta }));

  const capabilities = useCapabilities();
  const operations = useQuery({
    queryKey: ["actions"],
    // The operation catalogue lives under /api/v1/actions. The wizard used
    // to ask an address that did not exist, so the list was empty from the
    // start.
    queryFn: () => api.get<Collection<Operation>>("/api/v1/actions"),
  });
  const bulk = (operations.data?.items ?? []).filter((item) => item.campaign_ready);
  // Refusals are shown together with the reason. An operation missing from
  // the list without a word of explanation looks like a missing feature -
  // while it may be a boundary drawn on purpose, e.g. restoring a backup.
  const refusals = (operations.data?.items ?? []).filter(
    (item) => item.mutating && !item.campaign_ready && item.campaign_refusal,
  );

  const params = new URLSearchParams();
  if (order.site) params.set("site", order.site);
  if (order.environment) params.set("environment", order.environment);
  if (order.osFamily) params.set("os_family", order.osFamily);
  if (order.action) params.set("action", order.action);
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

  const eligible = preview.data?.eligible ?? 0;
  const gates = stepGates(t, order, preview.data, campaign.data);

  // A backend without a planning phase will not drive any of these changes.
  // A wizard that ends in an error after the form is filled in is worse than
  // its absence together with the reason.
  if (!capabilities.campaign_v2) {
    return (
      <>
        <h1>{t("Bulk Workspace")}</h1>
        <Empty>
          {t("This installation runs operations host by host: the backend has no campaign engine, so there is no set of per-host plans to approve.")}
        </Empty>
      </>
    );
  }

  return (
    <>
      <h1>{t("Bulk Workspace")}</h1>
      <p className="subtitle">
        {t("Choose the target, read the refusals, run the change. One host at a time lives in the host workspace; this is where the fleet is changed.")}
      </p>

      <ScopeBar order={order} preview={preview.data} campaign={campaign.data}
        risk={bulk.find((item) => item.action === order.action)?.risk} />

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
        />
      )}
      {step === 1 && <TargetsStep order={order} change={change} preview={preview.data} />}
      {step === 2 && <EligibilityStep preview={preview.data} checking={preview.isLoading} />}
      {step === 3 && <RolloutStep order={order} change={change} targets={eligible} />}
      {step === 4 && (
        <CreateStep
          order={order}
          targets={eligible}
          campaignID={campaignID}
          onCreated={(id) => {
            setCampaignID(id);
            setStep(5);
          }}
        />
      )}
      {step === 5 && <PlansStep campaignID={campaignID} campaign={campaign.data} />}
      {step === 6 && <ApprovalStep campaignID={campaignID} campaign={campaign.data} />}
    </>
  );
}

type Order = {
  name: string;
  action: string;
  unit: string;
  securityOnly: boolean;
  // The payload of an operation without a form of its own, as JSON text
  // the operator edits; it starts from the template the server gives.
  payloadText: string;
  site: string;
  environment: string;
  osFamily: string;
  canary: number;
  wave: number;
  concurrent: number;
  thresholdPercent: number;
  thresholdCount: number;
  rebootPolicy: string;
};

type Operation = {
  action: string;
  campaign_refusal?: string;
  mutating: boolean;
  campaign_mode: string;
  campaign_ready: boolean;
  risk?: string;
  payload_template?: Record<string, unknown>;
  needs_material?: boolean;
};

/**
 * The payload of the order. The few operations with a form build it from
 * the fields; every other one takes the JSON the operator edited, starting
 * from the server's template. The server validates it the same way as an
 * order typed by hand and names what is wrong.
 */
function orderPayload(order: Order): Record<string, unknown> | null {
  if (UNIT_OPERATIONS.includes(order.action)) return { unit: { unit: order.unit } };
  if (order.action === "packages.upgrade") return { package_upgrade: { security_only: order.securityOnly } };
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
  // The distribution of the snapshot: thirty hosts from one site are a
  // different change than thirty spread over three.
  distribution?: Record<string, Group[]>;
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
  "Create",
  "Plans",
  "Approval & run",
];

/** A transition gate: the next step opens only when there is a reason to. */
type Gate = { open: boolean; reason: string };

function stepGates(
  t: (text: string, params?: Record<string, string | number>) => string,
  order: Order,
  preview?: Preview,
  campaign?: Campaign,
): Gate[] {
  const hasAction = Boolean(order.action && order.name) &&
    (!UNIT_OPERATIONS.includes(order.action) || order.unit !== "") &&
    orderPayload(order) !== null;
  const hasTargets = (preview?.count ?? 0) > 0;
  const hasEligible = (preview?.eligible ?? 0) > 0;
  return [
    { open: hasAction, reason: t("pick an operation, name the campaign and give it a valid payload") },
    { open: hasAction && hasTargets, reason: t("the selector matches no host") },
    { open: hasEligible, reason: t("no matched host can run this operation") },
    { open: hasEligible, reason: t("no matched host can run this operation") },
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
  risk,
}: {
  order: Order;
  preview?: Preview;
  campaign?: Campaign;
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
          {risk && <span className={`badge ${risk === "critical" ? "error" : risk === "high" ? "warn" : ""}`} style={{ marginLeft: 8 }}>{risk}</span>}
        </span>
      </div>
      <div className="facts">
        <span>
          {t("targets")}: <strong>{preview?.eligible ?? preview?.count ?? 0}</strong>
          {preview && preview.eligible !== undefined && preview.eligible !== preview.count && (
            <> {t("of {n} matched", { n: preview.count })}</>
          )}
        </span>
        {preview?.campaign_mode && <span>{t("mode")}: {preview.campaign_mode}</span>}
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
const UNIT_OPERATIONS = ["unit.start", "unit.stop", "unit.restart", "unit.reload"];
const WIZARD_OPERATIONS = [...UNIT_OPERATIONS, "packages.upgrade"];

function ScopeStep({
  order,
  change,
  bulk,
  refusals,
  preview,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  bulk: Operation[];
  refusals: Operation[];
  preview?: Preview;
}) {
  const t = useT();
  const needsUnit = UNIT_OPERATIONS.includes(order.action);
  const chosen = bulk.find((item) => item.action === order.action);
  const generic = Boolean(order.action) && !WIZARD_OPERATIONS.includes(order.action);
  const payloadValid = orderPayload(order) !== null;
  return (
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>1. {t("Scope")}</h2>
      <p className="subtitle">
        {t("The registry decides what may run on many hosts at once. An operation with no bulk mode is a deliberate refusal, not a missing screen.")}
      </p>
      <div className="filters">
        <input
          placeholder={t("campaign name")}
          value={order.name}
          onChange={(e) => change({ name: e.target.value })}
          style={{ minWidth: 240 }}
        />
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
        {needsUnit && (
          <input
            placeholder={t("unit, e.g. cron.service")}
            value={order.unit}
            onChange={(e) => change({ unit: e.target.value })}
          />
        )}
        {order.action === "packages.upgrade" && (
          <label>
            <input
              type="checkbox"
              checked={order.securityOnly}
              onChange={(e) => change({ securityOnly: e.target.checked })}
            />{" "}
            {t("security updates only")}
          </label>
        )}
      </div>
      {generic && (
        <div className="form" style={{ marginTop: 12 }}>
          <label>
            {t("Payload (JSON, the same shape as a single-host operation)")}
            <textarea
              rows={Math.min(18, Math.max(6, order.payloadText.split("\n").length + 1))}
              value={order.payloadText}
              onChange={(e) => change({ payloadText: e.target.value })}
              spellCheck={false}
            />
          </label>
          <p className="source" style={{ margin: 0 }}>
            {!payloadValid
              ? t("This is not valid JSON.")
              : chosen?.needs_material
                ? t("The template carries a placeholder for certificate material; replace it with the real PEM before the order.")
                : t("The server validates the payload when the campaign is created and names what is wrong.")}
          </p>
        </div>
      )}
      {preview?.requires_plan && (
        <p className="subtitle">
          {t("Every host computes its own plan first. You approve the set of plans, not one payload, and a host whose plan changed in the meantime refuses the change.")}
        </p>
      )}
      {refusals.length > 0 && (
        <details style={{ marginTop: 12 }}>
          <summary className="subtitle">
            {t("{n} operations change hosts but cannot run as a campaign — with reasons", { n: refusals.length })}
          </summary>
          <table>
            <thead><tr><th>{t("Operation")}</th><th>{t("Why not")}</th></tr></thead>
            <tbody>
              {refusals.map((item) => (
                <tr key={item.action}>
                  <td>{item.action}</td>
                  <td className="source">{item.campaign_refusal}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  );
}

function TargetsStep({
  order,
  change,
  preview,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  preview?: Preview;
}) {
  const t = useT();
  return (
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>2. {t("Targets")}</h2>
      <p className="subtitle">
        {t("The count comes from the database, not from the first page of a list. The snapshot is frozen when the campaign is created; hosts added later do not join it.")}
      </p>
      <div className="filters">
        <input
          placeholder={t("site")}
          value={order.site}
          onChange={(e) => change({ site: e.target.value })}
        />
        <input
          placeholder={t("environment")}
          value={order.environment}
          onChange={(e) => change({ environment: e.target.value })}
        />
        <input
          placeholder={t("os family")}
          value={order.osFamily}
          onChange={(e) => change({ osFamily: e.target.value })}
        />
      </div>
      <p>
        {t("The selector matches {n} hosts", { n: preview?.count ?? 0 })}
        {preview && preview.count > preview.limit && (
          <> — {t("more than the {n} one campaign may carry", { n: preview.limit })}</>
        )}
        .
      </p>
      <div className="source">{(preview?.sample ?? []).join(", ")}</div>
      <Distribution preview={preview} />
    </section>
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
    <div style={{ marginTop: 12 }}>
      {dimensions.map(([dimension, groups]) => (
        <div key={dimension} className="source">
          {names[dimension] ?? dimension}:{" "}
          {groups.map((group) => `${group.reason} ${group.count}`).join(", ")}
        </div>
      ))}
    </div>
  );
}

function EligibilityStep({ preview, checking }: { preview?: Preview; checking: boolean }) {
  const t = useT();
  if (checking) return <Empty>{t("Checking every matched host…")}</Empty>;
  const excluded = preview?.excluded ?? [];
  const notes = preview?.notes ?? [];
  return (
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>3. {t("Eligibility")}</h2>
      <p className="subtitle">
        {t("A host that cannot run this operation stays in the snapshot with its reason. Dropping it quietly would hide a decision nobody made.")}
      </p>
      <table>
        <thead>
          <tr><th>{t("Bucket")}</th><th>{t("Hosts")}</th><th>{t("Which")}</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><span className="badge ok">{t("eligible")}</span></td>
            <td>{preview?.eligible ?? 0}</td>
            <td className="source">{(preview?.sample ?? []).join(", ")}</td>
          </tr>
          {excluded.map((group) => (
            <tr key={group.reason}>
              <td><span className="badge error">{reasonName(t, group.reason)}</span></td>
              <td>{group.count}</td>
              <td className="source">{group.sample.join(", ")}</td>
            </tr>
          ))}
          {/* A note does not exclude the host. An offline host comes back
              and does its part; a host in a conflict waits for somebody
              else's lock. */}
          {notes.map((group) => (
            <tr key={group.reason}>
              <td><span className="badge warn">{reasonName(t, group.reason)}</span></td>
              <td>{group.count}</td>
              <td className="source">{group.sample.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!excluded.length && !notes.length && (
        <p className="subtitle">{t("Every matched host can run this operation.")}</p>
      )}
    </section>
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
  };
  return names[reason] ?? reason;
}

function RolloutStep({
  order,
  change,
  targets,
}: {
  order: Order;
  change: (delta: Partial<Order>) => void;
  targets: number;
}) {
  const t = useT();
  return (
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>4. {t("Rollout")}</h2>
      <p className="subtitle">
        {t("Canary is wave zero. The concurrency limit says how many hosts move at once in this change; fleet and site budgets say how much the system carries in total, and a host waiting for capacity says so instead of standing still.")}
      </p>
      <div className="filters">
        <label>
          {t("canary")}{" "}
          <input type="number" min={0} value={order.canary}
            onChange={(e) => change({ canary: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          {t("wave")}{" "}
          <input type="number" min={1} value={order.wave}
            onChange={(e) => change({ wave: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          {t("concurrent")}{" "}
          <input type="number" min={1} value={order.concurrent}
            onChange={(e) => change({ concurrent: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          {t("threshold %")}{" "}
          <input type="number" min={0} max={100} value={order.thresholdPercent}
            onChange={(e) => change({ thresholdPercent: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          {t("threshold count")}{" "}
          <input type="number" min={0} value={order.thresholdCount}
            onChange={(e) => change({ thresholdCount: +e.target.value })} style={{ width: 70 }} />
        </label>
        <select value={order.rebootPolicy}
          onChange={(e) => change({ rebootPolicy: e.target.value })}>
          <option value="never">{t("reboot: never")}</option>
          <option value="if_required">{t("reboot: when required")}</option>
          <option value="always">{t("reboot: always")}</option>
        </select>
      </div>
      <p className="subtitle">
        {t("{targets} hosts, canary {canary}, then waves of {wave} with at most {concurrent} at a time.", {
          targets, canary: order.canary, wave: order.wave, concurrent: order.concurrent,
        })}
      </p>
    </section>
  );
}

function CreateStep({
  order,
  targets,
  campaignID,
  onCreated,
}: {
  order: Order;
  targets: number;
  campaignID: string;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  const queryClient = useQueryClient();

  const create = useMutation({
    mutationFn: () =>
      api.post<Campaign>("/api/v1/campaigns", {
        name: order.name,
        action: order.action,
        reason: `bulk workspace: ${order.action}`,
        payload: orderPayload(order) ?? {},
        selector: {
          site: order.site || undefined,
          environment: order.environment || undefined,
          os_family: order.osFamily || undefined,
        },
        canary_size: order.canary,
        wave_size: order.wave,
        max_concurrent: order.concurrent,
        failure_threshold_percent: order.thresholdPercent,
        failure_threshold_absolute: order.thresholdCount,
        reboot_policy: order.rebootPolicy,
      }),
    onSuccess: (campaign) => {
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onCreated(campaign.id);
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  return (
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>5. {t("Create")}</h2>
      <p className="subtitle">
        {t("Creating the campaign freezes the snapshot. Nothing changes on any host yet.")}
      </p>
      {errorMessage && <p className="page-error">{errorMessage}</p>}
      <button onClick={() => create.mutate()} disabled={create.isPending || Boolean(campaignID)}>
        {create.isPending ? t("Creating…") : t("Create a campaign on {n} hosts", { n: targets })}
      </button>
    </section>
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
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>6. {t("Plans")}</h2>
      <p className="subtitle">
        {planning
          ? t("Each host is computing its own diff. Nothing is applied while this runs.")
          : t("Every host has its plan. The fingerprint below covers the whole set: a host whose plan changed refuses the change.")}
      </p>
      {groups.length > 0 && (
        <table>
          <thead>
            <tr><th>{t("Change")}</th><th>{t("Hosts")}</th><th>{t("Plan fingerprint")}</th></tr>
          </thead>
          <tbody>
            {groups.map((group) => (
              <tr key={group.plan_hash}>
                <td><PlanSummary plan={(group.plan?.plan ?? group.plan ?? {}) as Record<string, any>} /></td>
                <td>
                  {group.count}
                  <div className="source">{group.hosts.join(", ")}</div>
                </td>
                <td className="source">{group.plan_hash.slice(0, 16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <TargetTable targets={targets} action={campaign?.action_type ?? ""} />
    </section>
  );
}

type PlanGroups = {
  items: {
    plan_hash: string;
    count: number;
    hosts: string[];
    // The plan content arrives in the shape of a job result: kind and plan.
    plan?: { plan?: Record<string, unknown> } & Record<string, unknown>;
  }[];
  plan_set_hash?: string;
};

function ApprovalStep({ campaignID, campaign }: { campaignID: string; campaign?: Campaign }) {
  const t = useT();
  const [errorMessage, setErrorMessage] = useState("");
  const queryClient = useQueryClient();
  const targets = useTargets(campaignID, {});
  const approve = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/campaigns/${campaignID}/approve`, {
        reason: "bulk workspace",
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
    <section className="tile">
      <h2 style={{ marginTop: 0 }}>7. {t("Approval and run")}</h2>
      <p className="subtitle">
        {t("You are approving this operation, this payload, this list of hosts, this rollout policy and this set of plans - together, as one fingerprint.")}
      </p>
      <p className="source">{t("fingerprint")} {campaign.approval_fingerprint}</p>
      {errorMessage && <p className="page-error">{errorMessage}</p>}
      {campaign.state === "awaiting_approval" ? (
        <button onClick={() => approve.mutate()} disabled={approve.isPending}>
          {approve.isPending ? t("Approving…") : t("Approve and start")}
        </button>
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
    </section>
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
    <table>
      <thead>
        <tr><th>{t("Host")}</th><th>{t("Wave")}</th><th>{t("State")}</th><th>{t("Blocker")}</th><th>{t("Message")}</th></tr>
      </thead>
      <tbody>
        {rows.map((target) => (
          <tr key={target.host_id}>
            <td>
              <Link to={`/hosts/${target.host_id}/${moduleForAction(action)}?campaign=${target.campaign_id}`}>
                {target.hostname || target.host_id.slice(0, 8)}
              </Link>
            </td>
            <td>{target.wave}{target.wave === 0 && ` (${t("canary")})`}</td>
            <td><JobState state={target.state} /></td>
            <td>{blockerName(t, target)}</td>
            <td>{target.message || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
    {/* The rows come page by page: a campaign on the whole fleet must not
        become the whole fleet in the browser. */}
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
  return target.error_code;
}
