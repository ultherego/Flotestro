import { Fragment, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { RemediationOrder, RemediationPreview, Whoami } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Actions, Card, Columns, Field, FieldGrid, PageHeader } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { Breakdown, StatusBar, type WidgetTone } from "../components/widgets";
import { FacetList, useFleetFacets } from "./Bulk";
import { useT } from "../i18n";

type HostWithFinding = { host_id: string; hostname: string; observed: string; action?: string };

type Check = {
  check_id: string;
  title: string;
  severity: string;
  expected: string;
  failed: number;
  passed: number;
  unknown: number;
  not_applicable: number;
  fixable: number;
  hosts?: HostWithFinding[];
};

type View = { hosts: number; checks: Check[]; generated_at: string };

function severityBadge(severity: string, count: number) {
  if (count === 0) return <span className="badge ok">0</span>;
  return <span className={`badge ${severityTone(severity)}`}>{count}</span>;
}

/** The colour of a severity: high is an error, info is a note, the rest a warning. */
function severityTone(severity: string): WidgetTone {
  return severity === "high" ? "error" : severity === "info" ? "unknown" : "warn";
}

/** The order the severities are listed in, the gravest first. */
const SEVERITIES = ["high", "medium", "low", "info"];

function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/** How the hosts of a fleet remediation are chosen. */
type ScopeMode = "findings" | "filters";

/** The order as the screen holds it before the preview and the campaign. */
type RemediationOrderDraft = {
  scope: ScopeMode;
  site: string;
  environment: string;
  reason: string;
  canary: number;
  wave: number;
  concurrent: number;
  manualGate: boolean;
};

/**
 * The selector the order sends: the hosts listed under the chosen checks,
 * or the site and environment filters. The server resolves it; the screen
 * never decides which host is in.
 */
type RemediationSelector = { site?: string; environment?: string; host_ids?: string[] };

function selectorOf(draft: RemediationOrderDraft, checks: Check[], selected: Set<string>): RemediationSelector {
  if (draft.scope === "filters") {
    return { site: draft.site.trim() || undefined, environment: draft.environment.trim() || undefined };
  }
  const ids = new Set<string>();
  for (const check of checks) {
    if (!selected.has(check.check_id)) continue;
    for (const host of check.hosts ?? []) ids.add(host.host_id);
  }
  return { host_ids: [...ids].sort() };
}

/**
 * The fleet's compliance with the hardening profile.
 *
 * One bad setting on a hundred hosts is one problem, not a hundred - and
 * that only shows once the findings stand next to each other. The fix
 * however goes host by host: each one creates an ordinary job of the module
 * that owns the given thing.
 */
export function FleetSecurity() {
  const t = useT();
  const [expanded, setExpanded] = useState("");
  // The checks ticked for a fleet remediation. Only a check with a
  // remediating operation behind it can be ticked: there is nothing to
  // plan for the rest.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const permissions = usePermissions();
  const remediates = permissions.has("security.remediate");
  const { data, error } = useQuery({
    queryKey: ["security", "fleet"],
    queryFn: () => api.get<View>("/api/v1/security"),
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Computing findings…")}</Empty>;

  const toggle = (checkId: string) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(checkId)) next.delete(checkId);
      else next.add(checkId);
      return next;
    });

  // The fleet-wide sums: a finding on a hundred hosts counts a hundred
  // times here, because that is how many jobs the fix takes.
  const sum = (key: "failed" | "passed" | "fixable" | "unknown" | "not_applicable") => data.checks.reduce((total, check) => total + check[key], 0);
  const needAction = sum("failed");
  const fixable = sum("fixable");
  const unknown = sum("unknown");

  // The findings by severity: the same sums as the bar, cut the other way.
  // A severity the profile does not use is still named, at zero.
  const bySeverity = SEVERITIES.map((severity) => ({
    severity,
    count: data.checks.filter((check) => check.severity === severity).reduce((total, check) => total + check.failed, 0),
  }));
  const otherSeverities = data.checks
    .filter((check) => !SEVERITIES.includes(check.severity))
    .reduce<Record<string, number>>((acc, check) => { acc[check.severity] = (acc[check.severity] ?? 0) + check.failed; return acc; }, {});

  // The hosts with the most findings, counted over the host lists the
  // checks carry. A check that carries no host list is counted in the
  // bar but not here, and the widget says when that leaves it blank.
  const byHost = new Map<string, { hostname: string; count: number }>();
  for (const check of data.checks) {
    for (const host of check.hosts ?? []) {
      const entry = byHost.get(host.host_id) ?? { hostname: host.hostname, count: 0 };
      entry.count += 1;
      byHost.set(host.host_id, entry);
    }
  }
  const worstHosts = [...byHost.entries()].sort((x, y) => y[1].count - x[1].count).slice(0, 8);

  return (
    <>
      <PageHeader
        title={t("Security")}
        description={t("Versioned checks over the facts hosts already report. One bad setting on a hundred hosts is one problem, not a hundred — and the fix is one campaign: every host gets its own plan of module jobs, one approval covers the whole set.")}
        actions={<ExportButton path="/api/v1/security" />}
      />

      <div className="widgets">
        {/* The fleet-wide sums, one segment per verdict: a finding on a
            hundred hosts counts a hundred times, because that is how many
            jobs the fix takes. Fixable is a part of "need action", named
            because it is the part that takes no decision. */}
        <Card
          className="span-12"
          title={t("Findings")}
          description={`${t("{n} hosts", { n: data.hosts })} · ${t("{n} checks", { n: data.checks.length })}`}
        >
          <StatusBar segments={[
            { label: t("Need action"), value: needAction, tone: "error" },
            { label: t("Passed"), value: sum("passed"), tone: "ok" },
            { label: t("Unknown"), value: unknown, tone: "unknown" },
            { label: t("Not applicable"), value: sum("not_applicable"), tone: "neutral" },
            { label: t("Fixable"), value: fixable, tone: "info" },
          ]} />
        </Card>

        <Card
          className="span-8"
          flush
          footer={<p>{t("{n} hosts", { n: data.hosts })} · {t("computed")} <Time value={data.generated_at} /></p>}
        >
          <table>
            <thead>
              <tr>
                {remediates && <th title={t("Tick the checks to fix on the fleet; a check without a remediating operation cannot be ticked.")}>{t("Fix")}</th>}
                <th>{t("Check")}</th><th className="num">{t("Need action")}</th><th className="num">{t("Passed")}</th><th className="num">{t("Unknown")}</th><th className="num">{t("N/A")}</th><th>{t("Expected")}</th><th className="num">{t("Fixable")}</th>
              </tr>
            </thead>
            <tbody>
              {data.checks.map((check) => (
                <Fragment key={check.check_id}>
                  <tr>
                    {remediates && (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={t("Fix {check} on the fleet", { check: check.check_id })}
                          checked={selected.has(check.check_id)}
                          disabled={!check.fixable}
                          onChange={() => toggle(check.check_id)}
                        />
                      </td>
                    )}
                    <td>
                      <button
                        className="expander"
                        aria-expanded={expanded === check.check_id}
                        aria-label={expanded === check.check_id
                          ? t("Hide the hosts failing {check}", { check: check.check_id })
                          : t("Show the hosts failing {check}", { check: check.check_id })}
                        onClick={() =>
                          setExpanded((current) =>
                            current === check.check_id ? "" : check.check_id,
                          )
                        }
                        disabled={!check.failed}
                      >
                        {expanded === check.check_id ? "▾" : "▸"}
                      </button>
                      {check.title}
                      {/* The severity stands under the title, because the
                          colour of the count alone does not say why one
                          finding is red and another amber. */}
                      <div className="source">
                        <span className="mono">{check.check_id}</span>
                        {" · "}
                        <span className={`badge ${severityTone(check.severity)}`}>{check.severity}</span>
                      </div>
                    </td>
                    <td className="num">{severityBadge(check.severity, check.failed)}</td>
                    <td className="num">{check.passed}</td>
                    {/* Unknown is not passed: a host that did not report the
                        fact is not a compliant host. */}
                    <td className="num">{check.unknown ? <span className="badge unknown">{check.unknown}</span> : 0}</td>
                    {/* A check that does not apply to the host enters neither
                        compliance nor non-compliance. */}
                    <td className="num">{check.not_applicable}</td>
                    <td className="mono">{check.expected}</td>
                    <td className="num">
                      {check.fixable}
                      {check.failed > check.fixable && (
                        <div className="source">
                          {t("{n} need a decision", { n: check.failed - check.fixable })}
                        </div>
                      )}
                    </td>
                  </tr>
                  {expanded === check.check_id &&
                    (check.hosts ?? []).map((host) => (
                      <tr key={`${check.check_id}-${host.host_id}`} className="detail-row">
                        <td colSpan={remediates ? 3 : 2}>
                          <Link to={`/hosts/${host.host_id}/security`}>{host.hostname}</Link>
                        </td>
                        <td colSpan={4} className="mono">{host.observed}</td>
                        <td>{host.action ? <code>{host.action}</code> : <span className="source">—</span>}</td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="span-4" title={t("By severity")} description={t("Findings that need action, by the severity of the check.")}>
          <div className="fp-tones">
            <Breakdown items={[
              ...bySeverity.map((row) => ({ label: row.severity, value: row.count, tone: severityTone(row.severity) })),
              ...Object.entries(otherSeverities).map(([severity, count]) => ({ label: severity, value: count, tone: severityTone(severity) })),
            ]} />
          </div>
          <h4 className="widget-subhead">{t("Hosts with most findings")}</h4>
          {worstHosts.length === 0 ? (
            <p className="fp-blank">
              {needAction > 0 ? t("The checks carry no host list.") : t("No host has a finding.")}
            </p>
          ) : (
            <div className="fp-links">
              <Breakdown tone="error" items={worstHosts.map(([hostId, entry]) => ({
                label: <Link to={`/hosts/${hostId}/security`}>{entry.hostname}</Link>,
                value: entry.count,
              }))} />
            </div>
          )}
        </Card>

        {remediates && selected.size > 0 && (
          <FleetRemediation checks={data.checks} selected={selected} />
        )}
      </div>
    </>
  );
}

/**
 * The fleet remediation flow: the scope, the preview and the order.
 *
 * The operator picks checks and hosts; there is no fix-all. The preview
 * shows every host's plan grouped by its steps - a hundred hosts with the
 * same change are one change - and the hosts that get none, with the
 * reason. The order creates a campaign that waits for one approval over
 * the whole set of plans, and the campaign page takes it from there.
 */
function FleetRemediation({ checks, selected }: { checks: Check[]; selected: Set<string> }) {
  const t = useT();
  const navigate = useNavigate();
  // The sites and environments the fleet has, offered under the filters.
  const facets = useFleetFacets();
  const [draft, setDraft] = useState<RemediationOrderDraft>({
    scope: "findings", site: "", environment: "", reason: "",
    canary: 1, wave: 5, concurrent: 2, manualGate: false,
  });
  const change = (delta: Partial<RemediationOrderDraft>) =>
    setDraft((previous) => ({ ...previous, ...delta }));

  const checkIds = [...selected].sort();
  const selector = selectorOf(draft, checks, selected);
  // The preview is bound to what it was computed for: a check ticked or
  // a filter changed after it shows the old answer no more.
  const previewKey = JSON.stringify({ checkIds, selector });
  const [shown, setShown] = useState<{ key: string; preview: RemediationPreview } | null>(null);
  const preview = shown && shown.key === previewKey ? shown.preview : null;

  const compute = useMutation({
    mutationFn: () =>
      api.post<RemediationPreview>("/api/v1/security/remediation/preview", { check_ids: checkIds, selector }),
    onSuccess: (result) => setShown({ key: previewKey, preview: result }),
  });
  const create = useMutation({
    mutationFn: () =>
      api.post<RemediationOrder>("/api/v1/security/remediation", {
        check_ids: checkIds,
        selector,
        reason: draft.reason.trim(),
        canary_size: draft.canary,
        wave_size: draft.wave,
        max_concurrent: draft.concurrent,
        manual_gate: draft.manualGate,
      }),
    onSuccess: (result) => navigate(`/campaigns/${result.campaign.id}`),
  });

  const listedHosts = draft.scope === "findings" ? (selector.host_ids ?? []).length : 0;
  const scopeMissing = draft.scope === "filters"
    ? !draft.site.trim() && !draft.environment.trim()
    : listedHosts === 0;
  const errorOf = (failure: unknown) => (failure instanceof Error ? failure.message : failure ? String(failure) : "");

  return (
    <Card
      className="span-12"
      title={t("Remediate on the fleet")}
      description={t("{n} checks chosen. Every host gets its own plan of module jobs; hosts with the same steps are one group, and one approval covers the whole set. Nothing changes until the campaign is approved.", { n: checkIds.length })}
    >
      <FieldGrid>
        <Field label={t("Scope")} hint={draft.scope === "findings"
          ? t("The hosts listed under the chosen checks: up to {n} per check.", { n: 50 })
          : t("Every host of the site or environment; the ones without a finding are left out with a reason.")}>
          <select value={draft.scope} onChange={(e) => change({ scope: e.target.value as ScopeMode })}>
            <option value="findings">{t("hosts with findings ({n})", { n: listedHosts })}</option>
            <option value="filters">{t("site or environment")}</option>
          </select>
        </Field>
        {draft.scope === "filters" && (
          <>
            <Field label={t("Site")}>
              <input placeholder={t("site")} value={draft.site} onChange={(e) => change({ site: e.target.value })} list="remediation-sites" />
              <FacetList id="remediation-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")}>
              <input placeholder={t("environment")} value={draft.environment} onChange={(e) => change({ environment: e.target.value })} list="remediation-environments" />
              <FacetList id="remediation-environments" facets={facets.data?.by_environment} />
            </Field>
          </>
        )}
      </FieldGrid>
      <Actions>
        <button className="secondary" onClick={() => compute.mutate()} disabled={compute.isPending || scopeMissing}>
          {compute.isPending ? t("Computing plans…") : t("Preview the plans")}
        </button>
        {scopeMissing && <span className="source">{t("Name the hosts first: there is no fix-all.")}</span>}
        {compute.error !== null && <p className="page-error">{errorOf(compute.error)}</p>}
      </Actions>

      {preview && (
        <>
          <p>
            {t("{eligible} of {hosts} hosts get a plan, in {groups} groups.", {
              eligible: preview.eligible, hosts: preview.hosts, groups: preview.groups.length,
            })}
            {" "}<span className="source">{t("computed")} <Time value={preview.generated_at} /></span>
          </p>
          {preview.groups.length > 0 && (
            <Columns>
              {preview.groups.map((group) => (
                <Card
                  key={group.plan_hash}
                  title={`${t("{n} hosts", { n: group.count })} · ${t("{n} steps", { n: group.steps.length })}`}
                  description={<span className="mono">{group.plan_hash.slice(0, 16)}</span>}
                >
                  <ol>
                    {group.steps.map((step) => (
                      <li key={step.position}>
                        <code>{step.action_type}</code> <span className="source">{step.check_id}</span>
                        {step.requires_reboot && <> <span className="badge warn">{t("reboot")}</span></>}
                      </li>
                    ))}
                  </ol>
                  <div className="source">
                    {group.hosts.map((host) => (
                      <Fragment key={host.host_id}>
                        <Link to={`/hosts/${host.host_id}/security`}>{host.hostname || host.host_id.slice(0, 8)}</Link>{" "}
                      </Fragment>
                    ))}
                  </div>
                </Card>
              ))}
            </Columns>
          )}
          {preview.excluded.length > 0 && (
            <>
              <h4 className="widget-subhead">{t("Hosts without a plan")}</h4>
              <table>
                <thead><tr><th>{t("Host")}</th><th>{t("Reason")}</th><th>{t("Message")}</th></tr></thead>
                <tbody>
                  {preview.excluded.map((host) => (
                    <tr key={host.host_id}>
                      <td><Link to={`/hosts/${host.host_id}/security`}>{host.hostname || host.host_id.slice(0, 8)}</Link></td>
                      <td><code>{host.reason}</code></td>
                      <td title={host.message}>{host.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {preview.eligible > 0 && (
            <>
              <h4 className="widget-subhead">{t("Rollout")}</h4>
              <FieldGrid>
                <Field label={t("Reason (kept in the audit trail)")} hint={t("Required, at least 8 characters: one order changes many hosts through operations that may each cut off access.")} wide>
                  <input value={draft.reason} onChange={(e) => change({ reason: e.target.value })} />
                </Field>
                <Field label={t("Canary")} hint={t("Wave zero: the hosts that go first.")}>
                  <input type="number" min={0} value={draft.canary} onChange={(e) => change({ canary: +e.target.value })} />
                </Field>
                <Field label={t("Wave size")} hint={t("Between 1 and 20 hosts per wave.")}>
                  <input type="number" min={1} max={20} value={draft.wave} onChange={(e) => change({ wave: +e.target.value })} />
                </Field>
                <Field label={t("At once")} hint={t("How many hosts run their plan at the same time.")}>
                  <input type="number" min={1} value={draft.concurrent} onChange={(e) => change({ concurrent: +e.target.value })} />
                </Field>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={draft.manualGate}
                    disabled={draft.canary <= 0}
                    onChange={(e) => change({ manualGate: e.target.checked })}
                  />{" "}
                  {t("stop after the canary until somebody advances the campaign")}
                </label>
              </FieldGrid>
              <Actions>
                <button onClick={() => create.mutate()} disabled={create.isPending || draft.reason.trim().length < 8}>
                  {create.isPending ? t("Creating…") : t("Create a campaign on {n} hosts", { n: preview.eligible })}
                </button>
                <span className="source">{t("The campaign waits for approval; nothing runs before it.")}</span>
                {create.error !== null && <p className="page-error">{errorOf(create.error)}</p>}
              </Actions>
            </>
          )}
        </>
      )}
    </Card>
  );
}
