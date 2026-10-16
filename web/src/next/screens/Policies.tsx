import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type {
  Policy, PolicyCampaignLink, PolicyOutcome, PolicyResult, PolicyRule, PolicyRuleKind,
  PolicySelector, PolicySpec, PolicyRemediationMode, PolicyVerdict, PolicyVersion,
  SelectorExpression, Whoami,
} from "../../lib/types";
import { POLICY_MODES, POLICY_RULE_KINDS, POLICY_VERDICTS } from "../../lib/types";
import { absoluteTime, relativeTime } from "../../lib/format";
import { stateName } from "../../lib/states";
import { useToast } from "../../components/Toast";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import { buildExpression, describeExpression, RULE_FIELDS, type Rule, type RuleField } from "../../pages/Groups";
import { FacetList, useFleetFacets } from "../../pages/Bulk";
import { campaignTone } from "./Campaigns";
import {
  Actions, Band, Banner, Bones, Button, Card, Check, Download, Empty, Fact, Facts, Field, Fields,
  HeadActions, Kpi, Modal, Note, Pill, Problem, Stack, Table, Toolbar, TwoLine,
  type Segment, type Tone,
} from "../kit";

/**
 * What is to be true on a group of hosts, and how the fleet stands
 * against it.
 *
 * The screen holds the whole list and, under it, the one policy somebody
 * opened - which is what the address `/policies/<id>` names. A
 * policy nobody has evaluated has no verdicts rather than four noughts:
 * a fleet nobody has judged and a fleet that is wholly compliant are
 * different answers, and the second one is the dangerous one to invent.
 */

/* ------------------------------------------------- the vocabulary of a policy */

/**
 * The colour of a verdict. Drift is a warning: the host is where the policy
 * does not want it, and somebody decides what happens.
 */
export function verdictTone(verdict: PolicyVerdict | string): Tone {
  switch (verdict) {
    case "compliant": return "ok";
    case "drift": return "warn";
    case "error": return "error";
    default: return "unknown";
  }
}

/** The verdicts in the order the bars and the tables show them. */
export const VERDICT_ORDER: PolicyVerdict[] = ["compliant", "drift", "error", "not_applicable"];

/**
 * The shares of a compliance reading: one segment per verdict, in the fixed
 * order, as fractions of the total. A policy nobody evaluated has none.
 */
export function complianceShares(
  counts: Partial<Record<PolicyVerdict, number>> | undefined,
): { verdict: PolicyVerdict; count: number; share: number }[] {
  const total = VERDICT_ORDER.reduce((sum, verdict) => sum + (counts?.[verdict] ?? 0), 0);
  if (total === 0) return [];
  return VERDICT_ORDER
    .map((verdict) => ({ verdict, count: counts?.[verdict] ?? 0, share: (counts?.[verdict] ?? 0) / total }))
    .filter((segment) => segment.count > 0);
}

/** One line per rule: the declaration in the words the server uses. */
export function ruleSummary(rule: PolicyRule): string {
  switch (rule.kind) {
    case "package_installed": return `package ${rule.name ?? ""} installed`;
    case "package_absent": return `package ${rule.name ?? ""} absent`;
    case "unit_state": {
      const halves = [];
      if (rule.enabled !== undefined) halves.push(rule.enabled ? "enabled" : "disabled");
      if (rule.active !== undefined) halves.push(rule.active ? "active" : "inactive");
      return `unit ${rule.unit ?? ""} ${halves.join(" and ")}`.trim();
    }
    case "file_content": return `file ${rule.path ?? ""} at ${(rule.sha256 ?? "").slice(0, 12)}`;
    case "sysctl": return `sysctl ${rule.key ?? ""} = ${rule.value ?? ""}`;
    case "ssh_key_present": return `key ${rule.fingerprint ?? ""} on ${rule.user ?? ""}`;
    default: return rule.kind;
  }
}

/**
 * The state of a policy in one word for the list: never published, a draft
 * on top of a version, disabled, or published as it stands.
 */
export function policyStanding(
  policy: Pick<Policy, "version" | "draft" | "enabled">,
): "unpublished" | "draft" | "disabled" | "published" {
  if (policy.version === 0) return "unpublished";
  if (!policy.enabled) return "disabled";
  if (policy.draft) return "draft";
  return "published";
}

export function verdictLabel(verdict: PolicyVerdict | string, t: Translate): string {
  switch (verdict) {
    case "compliant": return t("compliant");
    case "drift": return t("drift");
    case "error": return t("error");
    case "not_applicable": return t("not applicable");
    default: return verdict;
  }
}

export function modeLabel(mode: PolicyRemediationMode | string, t: Translate): string {
  switch (mode) {
    case "report": return t("report only");
    case "campaign": return t("campaign, awaiting approval");
    case "automatic": return t("automatic, approved at publication");
    default: return mode;
  }
}

/* ----------------------------------------------- the vocabulary of a rule */

/** A fresh rule of a kind, with the fields the kind needs and nothing else. */
export function emptyRule(kind: PolicyRuleKind): PolicyRule {
  switch (kind) {
    case "package_installed":
    case "package_absent":
      return { kind, name: "" };
    case "unit_state":
      return { kind, unit: "", enabled: true, active: true };
    case "file_content":
      return { kind, path: "", sha256: "" };
    case "sysctl":
      return { kind, key: "", value: "" };
    case "ssh_key_present":
      return { kind, user: "", fingerprint: "" };
  }
}

/**
 * A rule with only the fields of its kind: switching the kind in the editor
 * must not carry a package name into a sysctl rule, and the server would
 * store whatever it got.
 */
export function pruneRule(rule: PolicyRule): PolicyRule {
  const kept = emptyRule(rule.kind as PolicyRuleKind) ?? { kind: rule.kind };
  for (const field of Object.keys(kept) as (keyof PolicyRule)[]) {
    if (field === "kind") continue;
    if (rule[field] !== undefined) (kept as Record<string, unknown>)[field] = rule[field];
  }
  if (rule.kind === "unit_state") {
    // The halves of a unit state are optional: an undeclared half is left
    // out rather than sent as false.
    if (rule.enabled === undefined) delete kept.enabled;
    if (rule.active === undefined) delete kept.active;
  }
  if (rule.kind === "ssh_key_present" && rule.public_key) kept.public_key = rule.public_key;
  return kept;
}

/**
 * The rules as JSON, for the fallback editor; and back, refusing what is not
 * a list of objects with a kind. The server checks the rest.
 */
export function rulesToText(rules: PolicyRule[]): string {
  return JSON.stringify(rules, null, 2);
}

export function rulesFromText(text: string): { rules?: PolicyRule[]; error?: string } {
  try {
    const parsed: unknown = JSON.parse(text);
    if (!Array.isArray(parsed)) return { error: "the rules are a list" };
    for (const entry of parsed) {
      if (typeof entry !== "object" || entry === null || typeof (entry as PolicyRule).kind !== "string") {
        return { error: "every rule is an object with a kind" };
      }
    }
    return { rules: parsed as PolicyRule[] };
  } catch (error) {
    return { error: String(error instanceof Error ? error.message : error) };
  }
}

/**
 * A selector expression taken apart into the rows of the builder: a leaf, a
 * negated leaf, or one level of all/any over those.
 */
export function rulesFromExpression(
  expression: SelectorExpression | null | undefined,
): { rules: Rule[]; combine: "all" | "any" } | null {
  if (!expression) return { rules: [{ field: "tag", value: "", negated: false }], combine: "all" };
  const leaf = (node: SelectorExpression): Rule | null => {
    let negated = false;
    if (node.not) {
      negated = true;
      node = node.not;
    }
    if (node.all || node.any || node.not) return null;
    const entries = Object.entries(node).filter(([, value]) => typeof value === "string" && value !== "");
    if (entries.length !== 1) return null;
    const [field, value] = entries[0];
    return { field: field as RuleField, value: value as string, negated };
  };
  const children = expression.all ?? expression.any;
  if (children) {
    const rules = children.map(leaf);
    if (rules.some((rule) => rule === null)) return null;
    return { rules: rules as Rule[], combine: expression.all ? "all" : "any" };
  }
  const single = leaf(expression);
  return single ? { rules: [single], combine: "all" } : null;
}

/** The interval in minutes for the form; the server takes seconds. */
export function intervalMinutes(seconds: number): number {
  return Math.max(1, Math.round(seconds / 60));
}

/* ------------------------------------------------------------- the clock */

/** The list refreshes with the loop: a verdict a minute old is current enough. */
const POLICIES_INTERVAL = 60 * 1000;

/** How many verdicts one page of the results reads. */
const RESULT_PAGE = 100;

/** How many characters of reason a deletion keeps in the trail. */
const REASON_MINIMUM = 8;

/* ------------------------------------------------------------ the screen */

/**
 * The desired-state policies of the fleet, and the one that is open.
 */
export function Policies() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // The address names the policy that is open; a row of the list leads to
  // it, so the screen and the single policy are one place and not two.
  const { id = "" } = useParams();

  const [creating, setCreating] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [reason, setReason] = useState("");
  const [said, setSaid] = useState<{ text: string; error?: boolean } | null>(null);

  const list = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.get<Collection<Policy>>("/api/v1/policies"),
    refetchInterval: POLICIES_INTERVAL,
  });
  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const permissions = new Set(me.data?.permissions ?? []);
  const canWrite = permissions.has("policy.write");
  const canPublish = permissions.has("policy.publish");

  const open = useQuery({
    queryKey: ["policy", id],
    queryFn: () => api.getWithMeta<Policy>(`/api/v1/policies/${id}`),
    enabled: id !== "",
    refetchInterval: 60 * 1000,
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["policy", id] });
    void queryClient.invalidateQueries({ queryKey: ["policy-results", id] });
    void queryClient.invalidateQueries({ queryKey: ["policy-versions", id] });
    void queryClient.invalidateQueries({ queryKey: ["policy-campaigns", id] });
    void queryClient.invalidateQueries({ queryKey: ["policies"] });
  };

  const publish = useMutation({
    mutationFn: () => api.post<Policy>(`/api/v1/policies/${id}/publish`, { reason }),
    onSuccess: (published) => {
      setPublishing(false);
      setReason("");
      setSaid({ text: t("Published as version {n}; the loop judges by it from now on.", { n: published.version }) });
      refresh();
    },
    onError: (error) => setSaid({ text: failure(error), error: true }),
  });

  const evaluate = useMutation({
    mutationFn: () => api.post<PolicyOutcome>(`/api/v1/policies/${id}/evaluate`),
    onSuccess: (outcome) => {
      const counts = outcome.counts;
      setSaid({
        text: t("Evaluated {hosts} hosts: {compliant} compliant, {drift} drifted, {error} errors, {na} not applicable.{remediation}", {
          hosts: outcome.hosts,
          compliant: counts.compliant,
          drift: counts.drift,
          error: counts.error,
          na: counts.not_applicable,
          remediation: outcome.remediation ? ` ${outcome.remediation}` : "",
        }),
      });
      refresh();
    },
    onError: (error) => setSaid({ text: failure(error), error: true }),
  });

  const remove = useMutation({
    mutationFn: (why: string) => api.del<void>(
      `/api/v1/policies/${id}`,
      { reason: why },
      { headers: open.data?.etag ? { "If-Match": open.data.etag } : {} },
    ),
    onSuccess: () => {
      setRemoving(false);
      void queryClient.invalidateQueries({ queryKey: ["policies"] });
      // The page is left behind, so the outcome is told where it can still
      // be seen.
      toast.success(t("Policy {name} is deleted; its campaigns stay.", { name: open.data?.data.name ?? "" }));
      navigate("/policies");
    },
    onError: (error) => {
      setSaid({ text: failure(error), error: true });
      toast.error(failure(error));
    },
  });

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  const loaded = list.data !== undefined;
  const policies = list.data?.items ?? [];
  const published = policies.filter((policy) => policy.version > 0);
  const drafts = policies.filter((policy) => policy.version === 0 || policy.draft);
  const drifting = policies.filter((policy) => (policy.counts?.drift ?? 0) > 0);
  const erring = policies.filter((policy) => (policy.counts?.error ?? 0) > 0);

  const standing: Segment[] = [
    { label: t("Published"), value: loaded ? published.length : undefined, tone: "info" },
    { label: t("Drafts"), value: loaded ? drafts.length : undefined, tone: "neutral" },
    { label: t("With drift"), value: loaded ? drifting.length : undefined, tone: "warn" },
    { label: t("With errors"), value: loaded ? erring.length : undefined, tone: "error" },
  ];

  const record = open.data?.data;
  const counts = record?.counts;
  const judged = record?.last_evaluated_at ? record : undefined;
  const total = judged ? POLICY_VERDICTS.reduce((sum, verdict) => sum + (counts?.[verdict] ?? 0), 0) : undefined;

  return (
    <>
      {canWrite && !creating && (
        <HeadActions>
          <Button onClick={() => setCreating(true)} testId="new-policy">{t("New policy")}</Button>
        </HeadActions>
      )}

      {creating && (
        <NewPolicy
          onDone={(created) => {
            setCreating(false);
            void queryClient.invalidateQueries({ queryKey: ["policies"] });
            navigate(`/policies/${created.id}`);
          }}
          onCancel={() => setCreating(false)}
        />
      )}

      {said && (
        <Banner
          tone={said.error ? "error" : "info"}
          actions={<Button kind="quiet" onClick={() => setSaid(null)}>{t("Close")}</Button>}
        >
          {said.text}
        </Banner>
      )}

      {open.error && <Problem>{String(open.error)}</Problem>}

      <Board screen={POLICIES_SCREEN} catalogue={POLICIES} drawn={{
        count: (
          <Kpi
            hero
            icon="security"
            label={t("Policies")}
            value={loaded ? policies.length : null}
            note={t("declared over this fleet")}
            testId="kpi-policies"
          />
        ),
        published: (
          <Kpi
            icon="check"
            label={t("Published")}
            value={loaded ? published.length : null}
            note={t("the loop judges by these")}
            testId="kpi-published"
          />
        ),
        drifting: (
          <Kpi
            icon="vulnerabilities"
            label={t("With drift")}
            value={loaded ? drifting.length : null}
            tone={drifting.length > 0 ? "warn" : "ok"}
            note={t("a host is where the policy does not want it")}
            testId="kpi-drifting"
          />
        ),
        erring: (
          <Kpi
            icon="monitoring"
            label={t("With errors")}
            value={loaded ? erring.length : null}
            tone={erring.length > 0 ? "error" : "ok"}
            note={t("a rule could not be judged at all")}
            testId="kpi-erring"
          />
        ),
        standing: (
          <Card
            title={t("Standing")}
            note={t("A draft is judged by nobody until it is published; a published policy is frozen as it stands.")}
          >
            <Band segments={standing} testId="policy-standing" />
          </Card>
        ),
        list: (
          <Card title={t("Policies")} flush foot={loaded ? t("{n} policies", { n: policies.length }) : undefined}>
            <Table
              rows={policies}
              keyOf={(one) => one.id}
              rowTestId={(one) => `policy-${one.name}`}
              testId="policies"
              loading={!loaded}
              empty={t("No policy is declared. Without one the panel reports what the hosts are, not what they should be.")}
              columns={[
                {
                  key: "name",
                  head: t("Name"),
                  cell: (one) => (
                    <TwoLine sub={one.description || undefined}>
                      <Link to={`/policies/${one.id}`}>{one.name}</Link>
                    </TwoLine>
                  ),
                },
                { key: "version", head: t("Version"), cell: (one) => <Standing policy={one} /> },
                { key: "mode", head: t("Remediation"), minor: true, cell: (one) => modeLabel(one.remediation_mode, t) },
                { key: "rules", head: t("Rules"), num: true, cell: (one) => one.rules.length },
                {
                  key: "compliance",
                  head: t("Compliance"),
                  cell: (one) => <Compliance counts={one.counts} testId={`compliance-${one.id}`} />,
                },
                {
                  key: "evaluated",
                  head: t("Last evaluated"),
                  cell: (one) => (one.last_evaluated_at
                    ? <span title={absoluteTime(one.last_evaluated_at)}>{relativeTime(one.last_evaluated_at)}</span>
                    : <Pill tone="unknown">{t("never")}</Pill>),
                },
              ]}
            />
          </Card>
        ),
        policy: (
          <Card
            title={record ? record.name : t("The policy")}
            note={record
              ? (record.description || t("A desired-state policy: judged from the inventory, never by touching a host."))
              : undefined}
            foot={record
              ? (
                <Actions>
                  {canWrite && record.version > 0 && (
                    <Button kind="quiet" onClick={() => evaluate.mutate()} disabled={evaluate.isPending} testId="evaluate">
                      {t("Evaluate now")}
                    </Button>
                  )}
                  {canPublish && (
                    <Button onClick={() => setPublishing(true)} testId="publish">
                      {record.version === 0 ? t("Publish") : t("Publish a new version")}
                    </Button>
                  )}
                  {canWrite && (
                    <Button kind="danger" onClick={() => setRemoving(true)} disabled={remove.isPending} testId="delete-policy">
                      {t("Delete…")}
                    </Button>
                  )}
                </Actions>
              )
              : undefined}
          >
            {!record
              ? (id !== "" && open.isLoading
                ? <Bones rows={5} />
                : <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>)
              : (
                <Facts>
                  <Fact label={t("Version")}><Standing policy={record} /></Fact>
                  <Fact label={t("Remediation")}>{modeLabel(record.remediation_mode, t)}</Fact>
                  <Fact label={t("Interval")}>{t("every {n} min", { n: intervalMinutes(record.check_interval_seconds) })}</Fact>
                  <Fact label={t("Published")}>
                    {record.published_at
                      ? (
                        <TwoLine sub={record.published_by}>
                          <span title={absoluteTime(record.published_at)}>{relativeTime(record.published_at)}</span>
                        </TwoLine>
                      )
                      : "—"}
                  </Fact>
                  <Fact label={t("Enabled")}>{record.enabled ? t("yes") : t("no")}</Fact>
                  <Fact label={t("Hosts named by")} mono>
                    {describeSelector(record.selector, t)}
                  </Fact>
                </Facts>
              )}
          </Card>
        ),
        compliance: (
          <Card
            title={t("Compliance")}
            note={record && judged
              ? t("{n} verdicts of version {v}, last evaluated {when}", {
                n: total ?? 0, v: record.version, when: relativeTime(record.last_evaluated_at),
              })
              : record
                ? t("Not evaluated yet.")
                : undefined}
          >
            {!record
              ? <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>
              : (
                <Band
                  testId="policy-compliance"
                  segments={POLICY_VERDICTS.map((verdict) => ({
                    // A policy nobody has judged has no verdicts; four
                    // noughts would read as a fleet nothing is wrong with.
                    label: verdictLabel(verdict, t),
                    value: judged ? counts?.[verdict] ?? 0 : undefined,
                    tone: verdictTone(verdict),
                  }))}
                />
              )}
          </Card>
        ),
        document: record && open.data
          ? <Editor
              policy={record}
              etag={open.data.etag}
              canWrite={canWrite}
              onSaved={(saved) => {
                setSaid({ text: t("Saved.") });
                queryClient.setQueryData(["policy", id], saved);
                refresh();
              }}
            />
          : (
            <Card title={t("Document")}>
              <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>
            </Card>
          ),
        results: <Results policyID={id} />,
        versions: <Versions policyID={id} />,
        campaigns: <PolicyCampaigns policyID={id} />,
      }} />

      {/* The publication is the approval: the document is frozen as it
          stands and, in campaign or automatic mode, a drift becomes a
          campaign on the authority of whoever published it. */}
      {publishing && record && (
        <Modal
          title={record.version === 0 ? t("Publish") : t("Publish version {n}", { n: record.version + 1 })}
          onClose={() => { setPublishing(false); setReason(""); }}
          actions={
            <>
              <Button kind="quiet" onClick={() => { setPublishing(false); setReason(""); }} disabled={publish.isPending}>
                {t("Cancel")}
              </Button>
              <Button onClick={() => publish.mutate()} disabled={publish.isPending} testId="publish-confirm">
                {publish.isPending ? t("Publishing…") : t("Publish")}
              </Button>
            </>
          }
        >
          <Stack>
            <Note>
              {t("The document is frozen as it stands, the loop judges by it, and in campaign or automatic mode a drift becomes a campaign on your authority. It asks for fresh authentication like the approval of a campaign.")}
            </Note>
            {record.remediation_mode === "automatic" && (
              <Banner tone="warn">
                {t("Automatic remediation: the campaigns this policy orders are approved by this publication and start without a second look. This needs the policy.remediate.auto permission.")}
              </Banner>
            )}
            <Fields>
              <Field label={t("Reason")} hint={t("Recorded with the version.")} wide>
                <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="publish-reason" />
              </Field>
            </Fields>
          </Stack>
        </Modal>
      )}

      {/* A policy taken away takes its verdicts with it; the campaigns it
          already ordered stay, because they are work somebody approved. */}
      {removing && record && (
        <DeletePolicy
          name={record.name}
          pending={remove.isPending}
          onClose={() => setRemoving(false)}
          onDelete={(why) => remove.mutate(why)}
        />
      )}
    </>
  );
}

/** A refusal in the words the API used, so the code can be looked up. */
function failure(error: unknown): string {
  if (error instanceof ApiError) return `${error.code}: ${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

/** The version with the standing beside it. */
export function Standing({ policy }: { policy: Pick<Policy, "version" | "draft" | "enabled"> }) {
  const t = useT();
  switch (policyStanding(policy)) {
    case "unpublished":
      return <Pill tone="unknown">{t("not published")}</Pill>;
    case "disabled":
      return <TwoLine sub={<Pill tone="unknown">{t("disabled")}</Pill>}>{`v${policy.version}`}</TwoLine>;
    case "draft":
      return <TwoLine sub={<Pill tone="warn">{t("draft on top")}</Pill>}>{`v${policy.version}`}</TwoLine>;
    default:
      return <>{`v${policy.version}`}</>;
  }
}

/**
 * The verdicts of a policy as one stacked bar, compliant first and the
 * rest in the fixed order, each piece as wide as its share and carrying
 * its own count.
 *
 * A row of pills says the same numbers and loses the thing the bar was
 * for: a column of them cannot be read down. The widths can, which is
 * why the list the owner reads has always had a bar here.
 */
export function Compliance({ counts, testId }: {
  counts: Policy["counts"] | undefined;
  testId?: string;
}) {
  const t = useT();
  const segments = complianceShares(counts);
  if (segments.length === 0) return <Pill tone="unknown">{t("not evaluated")}</Pill>;
  return (
    <Band
      testId={testId}
      segments={segments.map((segment): Segment => ({
        label: verdictLabel(segment.verdict, t),
        value: segment.count,
        tone: verdictTone(segment.verdict),
      }))}
    />
  );
}

/** Whom a policy concerns, as one line. */
function describeSelector(selector: PolicySelector | undefined, t: Translate): string {
  if (!selector) return t("nobody is named yet");
  if (selector.expression) return describeExpression(selector.expression);
  const parts = [
    selector.site && `site=${selector.site}`,
    selector.environment && `environment=${selector.environment}`,
    selector.os_family && `os_family=${selector.os_family}`,
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(" ") : t("nobody is named yet");
}

/* --------------------------------------------------------- the new policy */

/**
 * A draft: the rules and the hosts are written on its own page, and nothing
 * is judged until somebody publishes it.
 */
function NewPolicy({ onDone, onCancel }: { onDone: (created: Policy) => void; onCancel: () => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [mode, setMode] = useState<PolicyRemediationMode>("report");
  const [message, setMessage] = useState("");

  const create = useMutation({
    mutationFn: () => api.post<Policy>("/api/v1/policies", {
      name: name.trim(), description: "", selector: {}, rules: [], remediation_mode: mode,
    }),
    onSuccess: onDone,
    onError: (error) => setMessage(failure(error)),
  });

  return (
    <Card
      title={t("New policy")}
      note={t("A draft: the rules and the hosts are written below once it exists, and nothing is judged until it is published.")}
      foot={
        <Actions>
          <Button onClick={() => { setMessage(""); create.mutate(); }} disabled={name.trim() === "" || create.isPending} testId="create-policy">
            {t("Create the draft")}
          </Button>
          <Button kind="quiet" onClick={onCancel} disabled={create.isPending}>{t("Cancel")}</Button>
          {message && <Problem>{message}</Problem>}
        </Actions>
      }
    >
      <Fields>
        <Field label={t("Name")}>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("e.g. baseline-cron")} autoFocus data-testid="policy-name" />
        </Field>
        <Field label={t("Remediation")} hint={t("What happens to a drift; automatic needs its own permission at the publication.")}>
          <select value={mode} onChange={(event) => setMode(event.target.value as PolicyRemediationMode)} aria-label={t("Remediation")} data-testid="policy-mode">
            {POLICY_MODES.map((value) => <option key={value} value={value}>{modeLabel(value, t)}</option>)}
          </select>
        </Field>
      </Fields>
    </Card>
  );
}

/* ----------------------------------------------------------- the deletion */

function DeletePolicy({ name, pending, onClose, onDelete }: {
  name: string;
  pending: boolean;
  onClose: () => void;
  onDelete: (reason: string) => void;
}) {
  const t = useT();
  const [why, setWhy] = useState("");
  return (
    <Modal
      title={t("Delete the policy {name}?", { name })}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={pending}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={why.trim().length < REASON_MINIMUM || pending}
            onClick={() => onDelete(why.trim())}
            testId="delete-policy-confirm"
          >
            {pending ? t("Deleting…") : t("Delete")}
          </Button>
        </>
      }
    >
      <Stack>
        <Note>{t("The policy and its verdicts go away. The campaigns it already ordered stay, because they are work somebody approved.")}</Note>
        <Fields>
          <Field label={t("Reason (kept in the trail)")} hint={t("At least 8 characters.")} wide>
            <input value={why} onChange={(event) => setWhy(event.target.value)} data-testid="delete-policy-reason" />
          </Field>
        </Fields>
      </Stack>
    </Modal>
  );
}

/* ------------------------------------------------------------- the editor */

type Draft = {
  name: string;
  description: string;
  mode: PolicyRemediationMode;
  enabled: boolean;
  intervalMinutes: number;
  rules: PolicyRule[];
  rulesText: string;
  rulesAsText: boolean;
  targetMode: "filters" | "expression" | "json";
  site: string;
  environment: string;
  osFamily: string;
  selectorRules: Rule[];
  combine: "all" | "any";
  expressionText: string;
};

function draftOf(policy: Policy): Draft {
  const selector = policy.selector ?? {};
  const decomposed = rulesFromExpression(selector.expression);
  const targetMode: Draft["targetMode"] = selector.expression
    ? (decomposed ? "expression" : "json")
    : "filters";
  return {
    name: policy.name,
    description: policy.description,
    mode: policy.remediation_mode,
    enabled: policy.enabled,
    intervalMinutes: intervalMinutes(policy.check_interval_seconds),
    rules: policy.rules ?? [],
    rulesText: rulesToText(policy.rules ?? []),
    rulesAsText: false,
    targetMode,
    site: selector.site ?? "",
    environment: selector.environment ?? "",
    osFamily: selector.os_family ?? "",
    selectorRules: decomposed?.rules ?? [{ field: "tag", value: "", negated: false }],
    combine: decomposed?.combine ?? "all",
    expressionText: selector.expression ? JSON.stringify(selector.expression, null, 2) : "",
  };
}

/** The selector the draft sends: the flat fields, the built expression, or the JSON as typed. */
export function selectorOf(
  draft: Pick<Draft, "targetMode" | "site" | "environment" | "osFamily" | "selectorRules" | "combine" | "expressionText">,
): { selector?: PolicySelector; error?: string } {
  switch (draft.targetMode) {
    case "filters":
      return {
        selector: {
          site: draft.site.trim() || undefined,
          environment: draft.environment.trim() || undefined,
          os_family: draft.osFamily.trim() || undefined,
        },
      };
    case "expression": {
      const expression = buildExpression(draft.selectorRules, draft.combine);
      return { selector: { expression: expression ?? undefined } };
    }
    default:
      try {
        const expression = draft.expressionText.trim() === ""
          ? undefined
          : (JSON.parse(draft.expressionText) as SelectorExpression);
        return { selector: { expression } };
      } catch (error) {
        return { error: String(error instanceof Error ? error.message : error) };
      }
  }
}

function Editor({ policy, etag, canWrite, onSaved }: {
  policy: Policy;
  etag: string;
  canWrite: boolean;
  onSaved: (saved: { data: Policy; etag: string }) => void;
}) {
  const t = useT();
  const [draft, setDraft] = useState<Draft>(() => draftOf(policy));
  const [error, setError] = useState("");
  // The sites and environments the fleet has, offered under the filters.
  const facets = useFleetFacets();
  // A refetch that brings a newer version replaces the form; typing in
  // between is not lost silently, because the tag would then refuse the
  // write and the message says to read again.
  useEffect(() => { setDraft(draftOf(policy)); }, [policy.id, policy.updated_at, policy.version]); // eslint-disable-line react-hooks/exhaustive-deps
  const change = (delta: Partial<Draft>) => setDraft((current) => ({ ...current, ...delta }));

  const save = useMutation({
    mutationFn: async () => {
      const rules = draft.rulesAsText ? rulesFromText(draft.rulesText) : { rules: draft.rules };
      if (rules.error) throw new Error(rules.error);
      const selector = selectorOf(draft);
      if (selector.error) throw new Error(selector.error);
      const spec: PolicySpec = {
        name: draft.name.trim(),
        description: draft.description.trim(),
        selector: selector.selector ?? {},
        rules: (rules.rules ?? []).map(pruneRule),
        remediation_mode: draft.mode,
        enabled: draft.enabled,
        check_interval_seconds: Math.max(1, draft.intervalMinutes) * 60,
      };
      // The write goes on the tag the screen read; a stale one is refused
      // by the server with the current one, and the message says so.
      await api.put<Policy>(`/api/v1/policies/${policy.id}`, spec, { headers: etag ? { "If-Match": etag } : {} });
      return api.getWithMeta<Policy>(`/api/v1/policies/${policy.id}`);
    },
    onSuccess: (saved) => { setError(""); onSaved(saved); },
    onError: (failed) => setError(failure(failed)),
  });

  const updateRule = (index: number, delta: Partial<PolicyRule>) =>
    change({ rules: draft.rules.map((rule, i) => (i === index ? { ...rule, ...delta } : rule)) });

  const { selector, error: selectorError } = selectorOf(draft);
  const carried = selectorError
    ? t("the expression does not parse: {error}", { error: selectorError })
    : describeSelector(selector, t);

  return (
    <Card
      title={t("Document")}
      note={policy.draft
        ? t("This draft differs from version {v}; the loop keeps judging by the published text until the next publication.", { v: policy.version })
        : policy.version === 0
          ? t("A draft nobody has published; nothing is judged yet.")
          : t("As published in version {v}.", { v: policy.version })}
      foot={canWrite
        ? (
          <Actions>
            <Button onClick={() => save.mutate()} disabled={save.isPending || draft.name.trim() === ""} testId="save-draft">
              {t("Save the draft")}
            </Button>
            <Button kind="quiet" onClick={() => setDraft(draftOf(policy))} disabled={save.isPending}>
              {t("Discard changes")}
            </Button>
          </Actions>
        )
        : undefined}
    >
      {/* Everything the editor holds sits inside one stack: a Toolbar left
          as a direct child of the card would be lifted out of the body and
          into the card's own bar, and every rule row with it. */}
      <Stack>
        <Fields>
          <Field label={t("Name")}>
            <input value={draft.name} onChange={(event) => change({ name: event.target.value })} disabled={!canWrite} aria-label={t("Name")} data-testid="draft-name" />
          </Field>
          <Field label={t("Remediation")} hint={t("report writes verdicts; campaign orders a campaign that waits for approval; automatic approves it with the publication.")}>
            <select value={draft.mode} onChange={(event) => change({ mode: event.target.value as PolicyRemediationMode })} disabled={!canWrite} aria-label={t("Remediation")}>
              {POLICY_MODES.map((mode) => <option key={mode} value={mode}>{modeLabel(mode, t)}</option>)}
            </select>
          </Field>
          <Field label={t("Check interval (minutes)")}>
            <input
              type="number"
              min={1}
              max={1440}
              value={draft.intervalMinutes}
              onChange={(event) => change({ intervalMinutes: Number(event.target.value) })}
              disabled={!canWrite}
              aria-label={t("Check interval (minutes)")}
            />
          </Field>
          <Field label={t("Description")} wide>
            <input value={draft.description} onChange={(event) => change({ description: event.target.value })} disabled={!canWrite} aria-label={t("Description")} />
          </Field>
        </Fields>

        <Check checked={draft.enabled} disabled={!canWrite} onChange={(on) => change({ enabled: on })}>
          {t("judge this policy; a disabled policy keeps its verdicts and is not judged")}
        </Check>

        <Toolbar
          end={
            <Check
              checked={draft.rulesAsText}
              onChange={(on) => change(on
                ? { rulesAsText: true, rulesText: rulesToText(draft.rules) }
                : { rulesAsText: false, ...(rulesFromText(draft.rulesText).rules ? { rules: rulesFromText(draft.rulesText).rules } : {}) })}
            >
              {t("edit as JSON")}
            </Check>
          }
        >
          <Note>{t("{n} rules; each names facts the host reports and one typed operation that fixes the drift.", { n: draft.rules.length })}</Note>
        </Toolbar>

        {draft.rulesAsText
          ? (
            <textarea
              rows={12}
              value={draft.rulesText}
              onChange={(event) => change({ rulesText: event.target.value })}
              disabled={!canWrite}
              aria-label={t("Rules as JSON")}
              data-testid="rules-json"
            />
          )
          : (
            <Stack>
              {draft.rules.map((rule, index) => (
                <Toolbar
                  key={index}
                  end={
                    <Button
                      kind="quiet"
                      onClick={() => change({ rules: draft.rules.filter((_, i) => i !== index) })}
                      disabled={!canWrite}
                    >
                      {t("Remove")}
                    </Button>
                  }
                >
                  <Pill tone="neutral" dot={false}>{index}</Pill>
                  <select
                    value={rule.kind}
                    aria-label={t("Rule {n}", { n: index + 1 })}
                    onChange={(event) => change({ rules: draft.rules.map((one, i) => (i === index ? emptyRule(event.target.value as PolicyRuleKind) : one)) })}
                    disabled={!canWrite}
                  >
                    {POLICY_RULE_KINDS.includes(rule.kind as PolicyRuleKind) ? null : <option value={rule.kind}>{rule.kind}</option>}
                    {POLICY_RULE_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
                  </select>
                  <RuleFields rule={rule} disabled={!canWrite} onChange={(delta) => updateRule(index, delta)} />
                </Toolbar>
              ))}
              {canWrite && (
                <Actions>
                  <Button kind="quiet" onClick={() => change({ rules: [...draft.rules, emptyRule("package_installed")] })} testId="add-rule">
                    {t("Add a rule")}
                  </Button>
                </Actions>
              )}
            </Stack>
          )}

        <Fields>
          <Field label={t("Hosts named by")}>
            <select
              value={draft.targetMode}
              onChange={(event) => change({ targetMode: event.target.value as Draft["targetMode"] })}
              disabled={!canWrite}
              aria-label={t("Hosts named by")}
              data-testid="target-mode"
            >
              <option value="filters">{t("site, environment and OS")}</option>
              <option value="expression">{t("groups and tags")}</option>
              <option value="json">{t("an expression as JSON")}</option>
            </select>
          </Field>
          {draft.targetMode === "filters" && (
            <>
              <Field label={t("Site")}>
                <input value={draft.site} onChange={(event) => change({ site: event.target.value })} disabled={!canWrite} list="next-policy-sites" aria-label={t("Site")} />
                <FacetList id="next-policy-sites" facets={facets.data?.by_site} />
              </Field>
              <Field label={t("Environment")}>
                <input value={draft.environment} onChange={(event) => change({ environment: event.target.value })} disabled={!canWrite} list="next-policy-environments" aria-label={t("Environment")} />
                <FacetList id="next-policy-environments" facets={facets.data?.by_environment} />
              </Field>
              <Field label={t("OS family")}>
                <input value={draft.osFamily} onChange={(event) => change({ osFamily: event.target.value })} placeholder="debian" disabled={!canWrite} aria-label={t("OS family")} />
              </Field>
            </>
          )}
        </Fields>

        {draft.targetMode === "expression" && (
          <SelectorRules
            rules={draft.selectorRules}
            combine={draft.combine}
            disabled={!canWrite}
            onRules={(rules) => change({ selectorRules: rules })}
            onCombine={(combine) => change({ combine })}
          />
        )}
        {draft.targetMode === "json" && (
          <textarea
            rows={8}
            value={draft.expressionText}
            onChange={(event) => change({ expressionText: event.target.value })}
            disabled={!canWrite}
            aria-label={t("an expression as JSON")}
            data-testid="expression-json"
          />
        )}

        <Note>{t("the policy will carry {what}", { what: carried })}</Note>
        {error && <Problem>{error}</Problem>}
      </Stack>
    </Card>
  );
}

/** The typed fields of one rule. */
function RuleFields({ rule, disabled, onChange }: {
  rule: PolicyRule;
  disabled: boolean;
  onChange: (delta: Partial<PolicyRule>) => void;
}) {
  const t = useT();
  const text = (field: keyof PolicyRule, placeholder: string) => (
    <input
      value={(rule[field] as string | undefined) ?? ""}
      placeholder={placeholder}
      aria-label={placeholder}
      onChange={(event) => onChange({ [field]: event.target.value } as Partial<PolicyRule>)}
      disabled={disabled}
    />
  );
  const half = (field: "enabled" | "active", label: string) => (
    <select
      value={rule[field] === undefined ? "" : rule[field] ? "yes" : "no"}
      aria-label={label}
      onChange={(event) => onChange({ [field]: event.target.value === "" ? undefined : event.target.value === "yes" } as Partial<PolicyRule>)}
      disabled={disabled}
    >
      <option value="">{t("{what}: not declared", { what: label })}</option>
      <option value="yes">{t("{what}: yes", { what: label })}</option>
      <option value="no">{t("{what}: no", { what: label })}</option>
    </select>
  );
  switch (rule.kind) {
    case "package_installed":
    case "package_absent":
      return text("name", t("package name"));
    case "unit_state":
      return <>{text("unit", "cron.service")}{half("enabled", t("enabled"))}{half("active", t("active"))}</>;
    case "file_content":
      return <>{text("path", "/etc/example.conf")}{text("sha256", t("sha256 of the managed version"))}</>;
    case "sysctl":
      return <>{text("key", "net.ipv4.ip_forward")}{text("value", t("value"))}</>;
    case "ssh_key_present":
      return <>{text("user", t("account"))}{text("fingerprint", "SHA256:…")}{text("public_key", t("public key line (optional; lets the panel set it on an empty account)"))}</>;
    default:
      return <Pill tone="error">{t("unsupported kind")}</Pill>;
  }
}

/** The rows a selector expression is built from: a field, a value, a not. */
function SelectorRules({ rules, combine, disabled, onRules, onCombine }: {
  rules: Rule[];
  combine: "all" | "any";
  disabled: boolean;
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
        <Note>{t("the host has to match")}</Note>
        <select
          value={combine}
          aria-label={t("the host has to match")}
          onChange={(event) => onCombine(event.target.value as "all" | "any")}
          disabled={disabled}
        >
          <option value="all">{t("every rule")}</option>
          <option value="any">{t("any rule")}</option>
        </select>
      </Toolbar>
      {rules.map((rule, index) => (
        <Toolbar
          key={index}
          end={
            <Button
              kind="quiet"
              disabled={disabled || rules.length === 1}
              onClick={() => onRules(rules.filter((_, i) => i !== index))}
            >
              {t("Remove")}
            </Button>
          }
        >
          <Check checked={rule.negated} disabled={disabled} onChange={(on) => update(index, { negated: on })}>{t("not")}</Check>
          <select
            value={rule.field}
            aria-label={t("Host rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { field: event.target.value as RuleField, value: "" })}
            disabled={disabled}
          >
            {RULE_FIELDS.map((field) => <option key={field} value={field}>{names[field]}</option>)}
          </select>
          <input
            value={rule.value}
            placeholder={t("value")}
            aria-label={t("Value of host rule {n}", { n: index + 1 })}
            onChange={(event) => update(index, { value: event.target.value })}
            disabled={disabled}
          />
        </Toolbar>
      ))}
      <Actions>
        <Button kind="quiet" disabled={disabled} onClick={() => onRules([...rules, { field: "tag", value: "", negated: false }])}>
          {t("Add a host rule")}
        </Button>
      </Actions>
    </Stack>
  );
}

/* ------------------------------------------- the results, versions, campaigns */

function Results({ policyID }: { policyID: string }) {
  const t = useT();
  const [verdict, setVerdict] = useState<PolicyVerdict | "">("");
  const [host, setHost] = useState("");
  const [cursor, setCursor] = useState("");
  const [rows, setRows] = useState<PolicyResult[]>([]);

  const query = new URLSearchParams({ limit: String(RESULT_PAGE) });
  if (verdict) query.set("verdict", verdict);
  if (host.trim()) query.set("host_id", host.trim());
  if (cursor) query.set("cursor", cursor);

  const page = useQuery({
    queryKey: ["policy-results", policyID, verdict, host, cursor],
    queryFn: () => api.get<{ items: PolicyResult[]; total: number; next_cursor?: string }>(
      `/api/v1/policies/${policyID}/results?${query}`,
    ),
    enabled: policyID !== "",
  });
  useEffect(() => {
    if (!page.data) return;
    setRows((current) => (cursor ? [...current, ...page.data.items] : page.data.items));
  }, [page.data, cursor]);
  // Another policy opened is another set of verdicts; the rows gathered for
  // the one before it do not belong to it.
  useEffect(() => { setCursor(""); setRows([]); }, [policyID]);
  const reset = () => { setCursor(""); setRows([]); };

  if (policyID === "") {
    return (
      <Card title={t("Results")}>
        <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>
      </Card>
    );
  }

  return (
    <Card
      title={t("Results")}
      flush
      bar={
        <Toolbar
          end={<Download path={`/api/v1/policies/${policyID}/results`} params={query} />}
        >
          <select
            value={verdict}
            aria-label={t("every verdict")}
            onChange={(event) => { setVerdict(event.target.value as PolicyVerdict | ""); reset(); }}
            data-testid="result-verdict"
          >
            <option value="">{t("every verdict")}</option>
            {POLICY_VERDICTS.map((value) => <option key={value} value={value}>{verdictLabel(value, t)}</option>)}
          </select>
          <input
            placeholder={t("host id")}
            aria-label={t("host id")}
            value={host}
            onChange={(event) => { setHost(event.target.value); reset(); }}
            data-testid="result-host"
          />
          <Note>{page.data ? t("{n} verdicts", { n: page.data.total }) : ""}</Note>
        </Toolbar>
      }
      foot={page.data?.next_cursor
        ? (
          <Actions>
            <Button kind="quiet" onClick={() => setCursor(page.data?.next_cursor ?? "")} disabled={page.isFetching} testId="results-more">
              {t("Load more")}
            </Button>
          </Actions>
        )
        : undefined}
    >
      {page.error
        ? <Problem>{String(page.error)}</Problem>
        : (
          <Table
            rows={rows}
            keyOf={(one) => `${one.host_id}:${one.rule_index}`}
            rowTestId={(one) => `result-${one.host_id}-${one.rule_index}`}
            testId="policy-results"
            loading={!page.data}
            empty={t("No verdict yet: the policy has not been evaluated, or nothing matches the filter.")}
            columns={[
              {
                key: "host",
                head: t("Host"),
                cell: (one) => <Link to={`/hosts/${one.host_id}/policies`}>{one.hostname || one.host_id}</Link>,
              },
              { key: "rule", head: t("Rule"), tight: true, cell: (one) => <code>{one.rule ? ruleSummary(one.rule) : `#${one.rule_index}`}</code> },
              { key: "verdict", head: t("Verdict"), cell: (one) => <Pill tone={verdictTone(one.verdict)}>{verdictLabel(one.verdict, t)}</Pill> },
              { key: "reason", head: t("Reason"), cell: (one) => one.reason || "—" },
              { key: "version", head: t("Version"), num: true, minor: true, cell: (one) => `v${one.version}` },
              {
                key: "evaluated",
                head: t("Evaluated"),
                cell: (one) => <span title={absoluteTime(one.evaluated_at)}>{relativeTime(one.evaluated_at)}</span>,
              },
            ]}
          />
        )}
    </Card>
  );
}

function Versions({ policyID }: { policyID: string }) {
  const t = useT();
  const versions = useQuery({
    queryKey: ["policy-versions", policyID],
    queryFn: () => api.get<Collection<PolicyVersion>>(`/api/v1/policies/${policyID}/versions`),
    enabled: policyID !== "",
  });

  if (policyID === "") {
    return (
      <Card title={t("Versions")}>
        <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>
      </Card>
    );
  }
  if (versions.error) return <Card title={t("Versions")}><Problem>{String(versions.error)}</Problem></Card>;

  return (
    <Card title={t("Versions")} flush note={t("Every publication, frozen as it stood and signed by whoever published it.")}>
      <Table
        rows={versions.data?.items ?? []}
        keyOf={(one) => String(one.version)}
        rowTestId={(one) => `version-${one.version}`}
        testId="policy-versions"
        loading={!versions.data}
        empty={t("Never published.")}
        columns={[
          { key: "version", head: t("Version"), num: true, cell: (one) => `v${one.version}` },
          {
            key: "published",
            head: t("Published"),
            cell: (one) => (
              <TwoLine sub={one.published_by}>
                <span title={absoluteTime(one.published_at)}>{relativeTime(one.published_at)}</span>
              </TwoLine>
            ),
          },
          {
            key: "authentication",
            head: t("Authentication"),
            minor: true,
            tight: true,
            cell: (one) => <code>{[one.authentication, one.acr, ...(one.amr ?? [])].filter(Boolean).join(" ") || "—"}</code>,
          },
          { key: "reason", head: t("Reason"), cell: (one) => one.reason || "—" },
          { key: "rules", head: t("Rules"), num: true, cell: (one) => one.document.rules.length },
          { key: "mode", head: t("Remediation"), minor: true, cell: (one) => modeLabel(one.document.remediation_mode, t) },
        ]}
      />
    </Card>
  );
}

function PolicyCampaigns({ policyID }: { policyID: string }) {
  const t = useT();
  const campaigns = useQuery({
    queryKey: ["policy-campaigns", policyID],
    queryFn: () => api.get<Collection<PolicyCampaignLink>>(`/api/v1/policies/${policyID}/campaigns`),
    enabled: policyID !== "",
    refetchInterval: 30 * 1000,
  });

  if (policyID === "") {
    return (
      <Card title={t("Remediation campaigns")}>
        <Empty icon="security">{t("Open a policy from the list to read what it declares and how the fleet stands against it.")}</Empty>
      </Card>
    );
  }
  if (campaigns.error) return <Card title={t("Remediation campaigns")}><Problem>{String(campaigns.error)}</Problem></Card>;

  return (
    <Card
      title={t("Remediation campaigns")}
      flush
      note={t("Ordered by this policy for a drift set; each waits for its approval on its own page.")}
    >
      <Table
        rows={campaigns.data?.items ?? []}
        keyOf={(one) => one.id}
        rowTestId={(one) => `policy-campaign-${one.id}`}
        testId="policy-campaigns"
        loading={!campaigns.data}
        empty={t("No campaign ordered: report mode, no drift, or a drift nothing can fix.")}
        columns={[
          { key: "name", head: t("Campaign"), cell: (one) => <Link to={`/campaigns/${one.id}`}>{one.name}</Link> },
          { key: "state", head: t("State"), cell: (one) => <Pill tone={campaignTone(one.state)}>{t(stateName(one.state))}</Pill> },
          { key: "version", head: t("Version"), num: true, cell: (one) => `v${one.policy_version}` },
          {
            key: "created",
            head: t("Created"),
            cell: (one) => <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>,
          },
        ]}
      />
    </Card>
  );
}

/* ------------------------------------------------------------- the board */

export const POLICIES_SCREEN = "next_policies";

export const POLICIES: BoardEntry[] = [
  { key: "count", title: "How many policies", width: 3, height: 1 },
  { key: "published", title: "Published", width: 3, height: 1 },
  { key: "drifting", title: "With drift", width: 3, height: 1 },
  { key: "erring", title: "With errors", width: 3, height: 1 },
  { key: "standing", title: "Standing", width: 12, height: 1 },
  { key: "list", title: "Policies", width: 12, height: 5 },
  { key: "policy", title: "The policy", width: 6, height: 3 },
  { key: "compliance", title: "Compliance", width: 6, height: 2 },
  { key: "document", title: "Document", width: 12, height: 6 },
  { key: "results", title: "Results", width: 12, height: 5 },
  { key: "versions", title: "Versions", width: 6, height: 4 },
  { key: "campaigns", title: "Remediation campaigns", width: 6, height: 4 },
];
