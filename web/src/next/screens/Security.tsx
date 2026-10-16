import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { api, LIST_PAGE, loadedItems } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Facet, FleetActivity, RemediationOrder, RemediationPreview, Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Bars, Bones, Button, Card, Check, Empty, Field, Fields, Kpi, Modal, Note, Pill,
  Problem, Stack, Table, Tags, type Segment, type Tone,
} from "../kit";

/**
 * What the fleet's own facts say about how it is set up.
 *
 * One bad setting on a hundred hosts is one problem, not a hundred - so a
 * check is the row and the hosts are its count. What nobody could judge is
 * never counted as passing: the sweep has a time budget, and an answer
 * taken over part of the fleet says so.
 *
 * A finding nobody can act on from here is half a screen, so the checks
 * that carry a remediating operation can be ticked and fixed: the panel
 * plans every host separately, shows what the plans would do, and only
 * then orders one campaign that waits for approval like any other.
 */

/** One host failing one check, with what was found on it. */
export type HostWithFinding = {
  host_id: string;
  hostname: string;
  observed?: string;
  action?: string;
};

type FleetCheck = {
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

/** One page of the hosts failing one check, read with a cursor. */
type CheckHostsPage = {
  check_id: string;
  items: HostWithFinding[];
  count: number;
  next_cursor?: string;
  partial: boolean;
  partial_reason?: string;
};

/** The address one page of the hosts failing a check is read from. */
export function checkHostsAddress(checkID: string, cursor: string): string {
  return `/api/v1/security?check=${encodeURIComponent(checkID)}&limit=${LIST_PAGE}`
    + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
}

type View = {
  hosts: number;
  checks: FleetCheck[];
  generated_at: string;
  partial?: boolean;
  unknown_hosts: number;
  hosts_judged?: number;
  partial_reason?: string;
};

/** The order the severities are listed in, the gravest first. */
const SEVERITIES = ["high", "medium", "low", "info"];

/** The reason a remediation is ordered with, as the server measures it. */
const REASON_MIN_LENGTH = 8;

/** How the hosts of a fleet remediation are chosen. */
export type ScopeMode = "findings" | "filters";

/** The selector the order sends: the hosts of the ticked checks, or the filters. */
export type RemediationSelector = { site?: string; environment?: string; host_ids?: string[] };

/** The order as the screen holds it before the preview and the campaign. */
export type RemediationDraft = {
  scope: ScopeMode;
  site: string;
  environment: string;
  canary: number;
  wave: number;
  concurrent: number;
  manualGate: boolean;
};

/**
 * Whom the order names. There is no fix-all: either the hosts listed under
 * the ticked checks, or a site and an environment typed out.
 */
export function selectorOf(draft: RemediationDraft, checks: FleetCheck[], picked: string[]): RemediationSelector {
  if (draft.scope === "filters") {
    return { site: draft.site.trim() || undefined, environment: draft.environment.trim() || undefined };
  }
  const ids = new Set<string>();
  for (const check of checks) {
    if (!picked.includes(check.check_id)) continue;
    for (const host of check.hosts ?? []) ids.add(host.host_id);
  }
  return { host_ids: [...ids].sort() };
}

/** Whether the order still names nobody, which the server refuses. */
export function scopeMissing(draft: RemediationDraft, selector: RemediationSelector): boolean {
  return draft.scope === "filters"
    ? !draft.site.trim() && !draft.environment.trim()
    : (selector.host_ids ?? []).length === 0;
}

/** The colour of a severity: high is an error, info is a note, the rest a warning. */
export function severityTone(severity: string): Tone {
  return severity === "high" ? "error" : severity === "info" ? "unknown" : "warn";
}

/** A refusal in the reader's words rather than the client's. */
function refusalText(error: unknown): string {
  return error instanceof Error ? error.message : error ? String(error) : "";
}

/** The values the fleet already uses, offered under an input that still takes any word. */
function Known({ id, facets }: { id: string; facets?: Facet[] }) {
  return (
    <datalist id={id}>
      {(facets ?? []).map((facet) => <option key={facet.key} value={facet.key} label={`${facet.count}`} />)}
    </datalist>
  );
}

export function Security() {
  const t = useT();
  const navigate = useNavigate();

  /* The checks ticked for a fleet remediation, and the order written
     against them. The preview is held beside the question it answered, so
     a check ticked afterwards cannot leave an old answer on screen. */
  const [picked, setPicked] = useState<string[]>([]);
  const [draft, setDraft] = useState<RemediationDraft>({
    scope: "findings", site: "", environment: "", canary: 1, wave: 5, concurrent: 2, manualGate: false,
  });
  const [shown, setShown] = useState<{ key: string; preview: RemediationPreview } | null>(null);
  // The check whose failing hosts are open under its row. One at a time: a
  // list of checks with every host list open under it is not a list.
  const [expanded, setExpanded] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");

  const view = useQuery({
    queryKey: ["security", "fleet"],
    queryFn: () => api.get<View>("/api/v1/security"),
  });
  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  // Ordering a remediation is its own right. Without it nothing on this
  // screen can be ticked, so nobody fills a form in to be refused at the end.
  const remediates = (me.data?.permissions ?? []).includes("security.remediate");
  const facets = useQuery({
    queryKey: ["fleet-activity"],
    queryFn: () => api.get<FleetActivity>("/api/v1/fleet/activity?hours=24"),
    staleTime: 60_000,
    retry: false,
    enabled: remediates,
  });

  const data = view.data;
  const checks = data?.checks ?? [];
  const chosen = [...picked].sort();
  const selector = selectorOf(draft, checks, picked);
  const previewKey = JSON.stringify({ chosen, selector });
  const preview = shown && shown.key === previewKey ? shown.preview : null;

  const compute = useMutation({
    mutationFn: () => api.post<RemediationPreview>(
      "/api/v1/security/remediation/preview", { check_ids: chosen, selector }),
    onSuccess: (answer) => setShown({ key: previewKey, preview: answer }),
  });
  const order = useMutation({
    mutationFn: (given: string) => api.post<RemediationOrder>("/api/v1/security/remediation", {
      check_ids: chosen,
      selector,
      reason: given,
      canary_size: draft.canary,
      wave_size: draft.wave,
      max_concurrent: draft.concurrent,
      manual_gate: draft.manualGate,
    }),
    onSuccess: (made) => {
      setConfirming(false);
      setReason("");
      navigate(`/next/campaigns/${made.campaign.id}`);
    },
  });

  if (view.error) return <Problem>{String(view.error)}</Problem>;

  const sum = (key: "failed" | "passed" | "fixable" | "unknown") =>
    data === undefined ? undefined : checks.reduce((total, one) => total + one[key], 0);

  const failed = sum("failed");
  const fixable = sum("fixable");
  const unknown = sum("unknown");
  const passed = sum("passed");

  const bySeverity = SEVERITIES.map((severity) => ({
    label: t(severity),
    value: checks.filter((one) => one.severity === severity).reduce((total, one) => total + one.failed, 0),
    tone: severityTone(severity),
  }));

  /* The hosts carrying the most findings, counted over the host lists the
     checks carry: where to start is a question about machines, not checks. */
  const byHost = new Map<string, { hostname: string; count: number }>();
  for (const check of checks) {
    for (const host of check.hosts ?? []) {
      const entry = byHost.get(host.host_id) ?? { hostname: host.hostname, count: 0 };
      entry.count += 1;
      byHost.set(host.host_id, entry);
    }
  }
  const worst = [...byHost.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);

  const outcome: Segment[] = [
    { label: t("Failing"), value: failed, tone: "error" },
    { label: t("Passing"), value: passed, tone: "ok" },
    { label: t("Not judged"), value: unknown, tone: "unknown" },
  ];

  const toggle = (checkID: string) =>
    setPicked((current) => current.includes(checkID)
      ? current.filter((one) => one !== checkID)
      : [...current, checkID]);

  const listed = draft.scope === "findings" ? (selector.host_ids ?? []).length : 0;
  const unnamed = scopeMissing(draft, selector);

  return (
    <>
      <Board screen={SECURITY_SCREEN} catalogue={SECURITY} drawn={{
        findings: (
          <Kpi
            hero
            icon="security"
            label={t("Findings")}
            value={failed ?? null}
            tone={failed ? "error" : "ok"}
            note={data ? t("over {n} hosts the sweep judged", { n: data.hosts_judged ?? data.hosts }) : undefined}
          />
        ),
        fixable: (
          <Kpi
            icon="bulk"
            label={t("Fixable from here")}
            value={fixable ?? null}
            tone={fixable ? "warn" : "ok"}
            note={t("one campaign covers the whole set")}
          />
        ),
        unjudged: (
          <Kpi
            icon="overview"
            label={t("Not judged")}
            value={unknown ?? null}
            tone={unknown ? "unknown" : "ok"}
            note={data?.partial ? t("the sweep did not reach the whole fleet") : t("every host answered")}
          />
        ),
        outcome: (
          <Card
            title={t("How the checks came out")}
            note={data ? t("Taken {when}.", { when: relativeTime(data.generated_at) }) : undefined}
            foot={data?.partial && data.partial_reason ? t(data.partial_reason) : undefined}
          >
            <Band segments={outcome} testId="outcome" />
          </Card>
        ),
        severity: (
          <Card title={t("By severity")} note={t("A finding counted once per host it was found on.")}>
            {data ? <Bars items={bySeverity} /> : <Bones rows={4} />}
          </Card>
        ),
        worst: (
          <Card title={t("Where to start")} note={t("The hosts carrying the most findings.")}>
            {worst.length === 0
              ? (data ? <Empty>{t("No host carries a finding.")}</Empty> : <Bones rows={4} />)
              : (
                <Bars items={worst.map(([id, one]) => ({
                  label: <Link to={`/next/hosts/${id}/security`}>{one.hostname}</Link>,
                  value: one.count,
                  tone: "error" as Tone,
                }))} />
              )}
          </Card>
        ),
        checks: (
          <Card
            title={t("Checks")}
            note={remediates
              ? t("One row per check, whatever it was found on. Tick the ones to fix on the fleet.")
              : t("One row per check, whatever it was found on.")}
            flush
          >
            <Table
              rows={[...checks].sort((a, b) => b.failed - a.failed || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))}
              keyOf={(one) => one.check_id}
              rowTestId={(one) => `check-${one.check_id}`}
              testId="checks"
              loading={view.isLoading}
              empty={t("No check ran over this fleet.")}
              /* The hosts failing a check open under the check, read a
                 page at a time. A row that says "forty hosts" and offers
                 no way to learn which forty is half an answer. */
              opened={(one) => one.check_id === expanded}
              detail={(one) => <CheckHosts check={one} />}
              remember="fl.columns.security-checks"
              columns={[
                ...(remediates
                  ? [{
                      key: "fix",
                      head: t("Fix"),
                      cell: (one: FleetCheck) => (
                        <input
                          type="checkbox"
                          aria-label={one.fixable > 0
                            ? t("Fix {check} on the fleet", { check: one.check_id })
                            : t("{check} has no remediating operation", { check: one.check_id })}
                          data-testid={`fix-${one.check_id}`}
                          checked={picked.includes(one.check_id)}
                          disabled={one.fixable === 0}
                          onChange={() => toggle(one.check_id)}
                        />
                      ),
                    }]
                  : []),
                {
                  key: "title",
                  head: t("Check"),
                  cell: (one) => one.failed > 0
                    ? (
                      <Button
                        kind="word"
                        onClick={() => setExpanded(one.check_id === expanded ? "" : one.check_id)}
                        testId={`hosts-${one.check_id}`}
                        title={one.check_id === expanded
                          ? t("Hide the hosts failing {check}", { check: one.check_id })
                          : t("Show the hosts failing {check}", { check: one.check_id })}
                      >
                        {one.title}
                      </Button>
                    )
                    : one.title,
                },
                { key: "id", head: t("Identifier"), minor: true, tight: true, cell: (one) => (
                  <code title={one.check_id}>{one.check_id}</code>
                ) },
                { key: "severity", head: t("Severity"), cell: (one) => (
                  <Pill tone={severityTone(one.severity)}>{t(one.severity)}</Pill>
                ) },
                { key: "failed", head: t("Failing"), num: true, cell: (one) => (
                  one.failed > 0 ? <b className="fl-error">{one.failed}</b> : <span className="fl-faint">0</span>
                ) },
                { key: "unknown", head: t("Not judged"), num: true, minor: true, cell: (one) => (
                  // Unknown is not passing: a check nobody could judge on a
                  // host says nothing about that host.
                  one.unknown > 0 ? <b className="fl-unknown">{one.unknown}</b> : <span className="fl-faint">0</span>
                ) },
                { key: "passed", head: t("Passing"), num: true, minor: true, cell: (one) => one.passed },
                // A check that does not apply to a host enters neither
                // compliance nor non-compliance, and is counted apart.
                {
                  key: "na", head: t("Does not apply"), num: true, minor: true, optional: true,
                  cell: (one) => one.not_applicable,
                },
                { key: "fixable", head: t("Fixable"), num: true, cell: (one) => (
                  one.fixable > 0 ? <Pill tone="warn">{one.fixable}</Pill> : <span className="fl-faint">—</span>
                ) },
                { key: "decision", head: t("Need a decision"), cell: (one) => (
                  // Why a finding is not fixable from here, said on the row
                  // rather than left to the gap between two numbers.
                  one.failed > one.fixable
                    ? (
                      <span data-testid={`decision-${one.check_id}`}>
                        {one.fixable === 0
                          ? t("{n} need a decision: this check has no remediating operation.", { n: one.failed })
                          : t("{n} need a decision: no operation fixes them on those hosts.", { n: one.failed - one.fixable })}
                      </span>
                    )
                    : <span className="fl-faint">—</span>
                ) },
                { key: "expected", head: t("Expected"), minor: true, tight: true, cell: (one) => (
                  <code title={one.expected}>{one.expected}</code>
                ) },
              ]}
            />
          </Card>
        ),

        remediate: remediates && picked.length > 0 && (
          <Card
            title={t("Remediate on the fleet")}
            note={t("{n} checks ticked. Every host gets its own plan of module jobs; hosts with the same steps are one group, and one approval covers the whole set. Nothing changes until the campaign is approved.", { n: chosen.length })}
            tools={
              <Button kind="quiet" onClick={() => { setPicked([]); setShown(null); }} testId="remediation-clear">
                {t("Clear the ticks")}
              </Button>
            }
          >
            <Stack>
              <Fields>
                <Field
                  label={t("Scope")}
                  hint={draft.scope === "findings"
                    ? t("The hosts listed under the ticked checks: up to {n} per check.", { n: 50 })
                    : t("Every host of the site or the environment; the ones without a finding are left out with a reason.")}
                >
                  <select
                    value={draft.scope}
                    onChange={(event) => setDraft({ ...draft, scope: event.target.value as ScopeMode })}
                    data-testid="remediation-scope"
                  >
                    <option value="findings">{t("hosts with findings ({n})", { n: listed })}</option>
                    <option value="filters">{t("site or environment")}</option>
                  </select>
                </Field>
                {draft.scope === "filters" && (
                  <>
                    <Field label={t("Site")}>
                      <input
                        value={draft.site}
                        list="remediation-sites"
                        onChange={(event) => setDraft({ ...draft, site: event.target.value })}
                        data-testid="remediation-site"
                      />
                      <Known id="remediation-sites" facets={facets.data?.by_site} />
                    </Field>
                    <Field label={t("Environment")}>
                      <input
                        value={draft.environment}
                        list="remediation-environments"
                        onChange={(event) => setDraft({ ...draft, environment: event.target.value })}
                        data-testid="remediation-environment"
                      />
                      <Known id="remediation-environments" facets={facets.data?.by_environment} />
                    </Field>
                  </>
                )}
              </Fields>

              <Actions>
                <Button
                  kind="quiet"
                  disabled={compute.isPending || unnamed}
                  onClick={() => compute.mutate()}
                  testId="remediation-preview"
                >
                  {compute.isPending ? t("Computing plans…") : t("Preview the plans")}
                </Button>
                {unnamed && <Note>{t("Name the hosts first: there is no fix-all.")}</Note>}
              </Actions>
              {compute.error !== null && <Problem>{refusalText(compute.error)}</Problem>}

              {compute.isPending && preview === null && <Bones rows={4} />}

              {preview && (
                <>
                  <Note>
                    {t("{eligible} of {hosts} hosts get a plan, in {groups} groups.", {
                      eligible: preview.eligible, hosts: preview.hosts, groups: preview.groups.length,
                    })}
                    {" "}
                    {t("Computed {when}.", { when: absoluteTime(preview.generated_at) })}
                  </Note>

                  <h3 className="fl-subhead">{t("What the plans would do")}</h3>
                  <Table
                    rows={preview.groups}
                    keyOf={(group) => group.plan_hash}
                    rowTestId={(group) => `plan-${group.plan_hash.slice(0, 16)}`}
                    testId="remediation-plans"
                    empty={t("No host gets a plan from these checks.")}
                    columns={[
                      {
                        key: "hosts",
                        head: t("Hosts"),
                        num: true,
                        cell: (group) => group.count,
                      },
                      {
                        key: "steps",
                        head: t("Steps"),
                        cell: (group) => (
                          <Tags>
                            {group.steps.map((step) => (
                              <Pill
                                key={step.position}
                                dot={false}
                                tone={step.requires_reboot ? "warn" : "neutral"}
                                title={step.check_id}
                              >
                                {step.action_type}
                                {step.requires_reboot && <> · {t("reboot")}</>}
                              </Pill>
                            ))}
                          </Tags>
                        ),
                      },
                      {
                        key: "which",
                        head: t("Which hosts"),
                        minor: true,
                        cell: (group) => (
                          <Tags>
                            {group.hosts.map((host) => (
                              <Pill key={host.host_id} dot={false}>
                                <Link to={`/next/hosts/${host.host_id}/security`}>
                                  {host.hostname || host.host_id.slice(0, 8)}
                                </Link>
                              </Pill>
                            ))}
                          </Tags>
                        ),
                      },
                      {
                        key: "hash",
                        head: t("Plan"),
                        minor: true,
                        tight: true,
                        cell: (group) => <code title={group.plan_hash}>{group.plan_hash.slice(0, 16)}</code>,
                      },
                    ]}
                  />

                  {preview.excluded.length > 0 && (
                    <>
                      <h3 className="fl-subhead">{t("Hosts without a plan")}</h3>
                      <Table
                        rows={preview.excluded}
                        keyOf={(host) => host.host_id}
                        rowTestId={(host) => `excluded-${host.host_id}`}
                        testId="remediation-excluded"
                        columns={[
                          {
                            key: "host",
                            head: t("Host"),
                            cell: (host) => (
                              <Link to={`/next/hosts/${host.host_id}/security`}>
                                {host.hostname || host.host_id.slice(0, 8)}
                              </Link>
                            ),
                          },
                          { key: "why", head: t("Reason"), tight: true, cell: (host) => <code>{host.reason}</code> },
                          { key: "what", head: t("What it says"), cell: (host) => host.message },
                        ]}
                      />
                    </>
                  )}

                  {preview.eligible > 0 && (
                    <>
                      <h3 className="fl-subhead">{t("Rollout")}</h3>
                      <Fields>
                        <Field label={t("Canary")} hint={t("Wave zero: the hosts that go first.")}>
                          <input type="number" min={0} value={draft.canary}
                                 onChange={(event) => setDraft({ ...draft, canary: Number(event.target.value) })}
                                 data-testid="remediation-canary" />
                        </Field>
                        <Field label={t("Wave size")} hint={t("Between 1 and 20 hosts per wave.")}>
                          <input type="number" min={1} max={20} value={draft.wave}
                                 onChange={(event) => setDraft({ ...draft, wave: Number(event.target.value) })}
                                 data-testid="remediation-wave" />
                        </Field>
                        <Field label={t("At once")} hint={t("How many hosts run their plan at the same time.")}>
                          <input type="number" min={1} value={draft.concurrent}
                                 onChange={(event) => setDraft({ ...draft, concurrent: Number(event.target.value) })}
                                 data-testid="remediation-concurrent" />
                        </Field>
                      </Fields>
                      <Check
                        checked={draft.manualGate}
                        disabled={draft.canary <= 0}
                        onChange={(value) => setDraft({ ...draft, manualGate: value })}
                      >
                        {t("stop after the canary until somebody advances the campaign")}
                      </Check>
                      <Actions>
                        <Button
                          onClick={() => { setReason(""); setConfirming(true); }}
                          disabled={order.isPending}
                          testId="remediation-order"
                        >
                          {t("Create a campaign on {n} hosts", { n: preview.eligible })}
                        </Button>
                        <Note>{t("The campaign waits for approval; nothing runs before it.")}</Note>
                      </Actions>
                    </>
                  )}
                </>
              )}
            </Stack>
          </Card>
        ),
      }} />

      {confirming && preview && (
        <Modal
          title={t("Remediate {n} hosts", { n: preview.eligible })}
          onClose={() => setConfirming(false)}
          actions={
            <>
              <Button
                kind="danger"
                disabled={reason.trim().length < REASON_MIN_LENGTH || order.isPending}
                onClick={() => order.mutate(reason.trim())}
                testId="remediation-confirm"
              >
                {order.isPending ? t("Working…") : t("Create the campaign")}
              </Button>
              <Button kind="quiet" onClick={() => setConfirming(false)} disabled={order.isPending}>
                {t("Cancel")}
              </Button>
            </>
          }
        >
          <Note>
            {t("{eligible} hosts get a plan of module jobs from {n} checks. One order changes many hosts through operations that may each cut off access, so the campaign waits for approval and nothing runs before it.", {
              eligible: preview.eligible, n: chosen.length,
            })}
          </Note>
          <Fields>
            <Field
              label={t("Reason (kept in the audit trail)")}
              hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })}
              wide
            >
              <input value={reason} onChange={(event) => setReason(event.target.value)}
                     data-testid="remediation-reason" />
            </Field>
          </Fields>
          {order.error !== null && <Problem>{refusalText(order.error)}</Problem>}
        </Modal>
      )}
    </>
  );
}

/**
 * The hosts failing one check, a page at a time.
 *
 * Until the first page lands, the sample the fleet answer already carried
 * is drawn: it is the same rows, and an empty list under an open row
 * would read as "no host fails this" when the truth is "nothing has
 * arrived yet".
 */
function CheckHosts({ check }: { check: FleetCheck }) {
  const t = useT();
  const list = useInfiniteQuery({
    queryKey: ["security", "fleet", "check", check.check_id],
    queryFn: ({ pageParam }) => api.get<CheckHostsPage>(checkHostsAddress(check.check_id, pageParam)),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const hosts = list.data ? loadedItems<HostWithFinding>(list.data) : (check.hosts ?? []);
  const left = Math.max(0, check.failed - hosts.length);

  return (
    <Card
      title={t("Hosts failing {check}", { check: check.check_id })}
      note={check.expected ? t("Expected: {expected}", { expected: check.expected }) : undefined}
      flush
      foot={list.hasNextPage
        ? (
          <Button
            kind="quiet"
            onClick={() => void list.fetchNextPage()}
            disabled={list.isFetchingNextPage}
            testId={`more-${check.check_id}`}
          >
            {list.isFetchingNextPage ? t("Reading…") : t("Load more ({n} left)", { n: left })}
          </Button>
        )
        : undefined}
    >
      {list.error
        ? <Problem>{refusalText(list.error)}</Problem>
        : (
          <Table
            rows={hosts}
            keyOf={(one) => one.host_id}
            rowTestId={(one) => `failing-${one.host_id}`}
            testId={`check-hosts-${check.check_id}`}
            loading={list.isLoading && hosts.length === 0}
            empty={t("No host is listed as failing this check.")}
            columns={[
              {
                key: "host",
                head: t("Host"),
                cell: (one) => (
                  <Link to={`/next/hosts/${one.host_id}/security`}>{one.hostname || one.host_id.slice(0, 8)}</Link>
                ),
              },
              {
                key: "observed",
                head: t("What was found"),
                tight: true,
                // What nobody read is an em dash; a check can fail without
                // the host having said what it found.
                cell: (one) => one.observed
                  ? <code title={one.observed}>{one.observed}</code>
                  : <span className="fl-faint">—</span>,
              },
              {
                key: "action",
                head: t("Fixed by"),
                tight: true,
                cell: (one) => one.action
                  ? <code title={one.action}>{one.action}</code>
                  : <span className="fl-faint">—</span>,
              },
            ]}
          />
        )}
    </Card>
  );
}

export const SECURITY_SCREEN = "next_security";

export const SECURITY: BoardEntry[] = [
  { key: "findings", title: "Findings", width: 4, height: 1 },
  { key: "fixable", title: "Fixable from here", width: 4, height: 1 },
  { key: "unjudged", title: "Not judged", width: 4, height: 1 },
  { key: "outcome", title: "How the checks came out", width: 5, height: 1 },
  { key: "severity", title: "By severity", width: 3, height: 2 },
  { key: "worst", title: "Where to start", width: 4, height: 2 },
  { key: "checks", title: "Checks", width: 12, height: 4 },
  { key: "remediate", title: "Remediate on the fleet", width: 12, height: 5 },
];
