import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type {
  Policy, PolicyCampaignLink, PolicyOutcome, PolicyResult, PolicyRule, PolicyRuleKind, PolicySelector,
  PolicySpec, PolicyRemediationMode, PolicyVerdict, PolicyVersion, SelectorExpression, Whoami,
} from "../lib/types";
import { POLICY_MODES, POLICY_RULE_KINDS, POLICY_VERDICTS } from "../lib/types";
import { ErrorBox, Empty, JobState, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { StatusBar } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { buildExpression, describeExpression, SelectorBuilder, type Rule, type RuleField } from "./Groups";
import { Standing, VerdictChip, modeLabel, ruleSummary, verdictLabel } from "./Policies";
import { FacetList, useFleetFacets } from "./Bulk";
import { useT } from "../i18n";

/* ---------------------------------------------------------------------- */
/* The rule editor's vocabulary.                                          */
/* ---------------------------------------------------------------------- */

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
 * A rule with only the fields of its kind: switching the kind in the
 * editor must not carry a package name into a sysctl rule, and the server
 * would store whatever it got.
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
 * The rules as JSON, for the fallback editor; and back, refusing what is
 * not a list of objects with a kind. The server checks the rest.
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
 * A selector expression taken apart into the rows of the builder: a leaf,
 * a negated leaf, or one level of all/any over those. Anything deeper is
 * edited as JSON - the builder would otherwise flatten it silently.
 */
export function rulesFromExpression(expression: SelectorExpression | null | undefined): { rules: Rule[]; combine: "all" | "any" } | null {
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

/* ---------------------------------------------------------------------- */
/* The page.                                                               */
/* ---------------------------------------------------------------------- */

const RESULT_PAGE = 100;

/**
 * One policy: what it declares, whom it concerns, how the fleet stands
 * against it, and what it ordered.
 *
 * The document is edited as a draft and judged as a version: the page
 * says which of the two it shows, and the publication - the approval the
 * document names - asks for a reason and fresh authentication.
 */
export function PolicyPage() {
  const t = useT();
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const policy = useQuery({
    queryKey: ["policy", id],
    queryFn: () => api.getWithMeta<Policy>(`/api/v1/policies/${id}`),
    refetchInterval: 60 * 1000,
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);
  const canWrite = permissions.has("policy.write");
  const canPublish = permissions.has("policy.publish");
  const [publishing, setPublishing] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<{ text: string; error?: boolean }>({ text: "" });
  const confirm = useConfirm();
  const toast = useToast();

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["policy", id] });
    queryClient.invalidateQueries({ queryKey: ["policy-results", id] });
    queryClient.invalidateQueries({ queryKey: ["policy-versions", id] });
    queryClient.invalidateQueries({ queryKey: ["policy-campaigns", id] });
    queryClient.invalidateQueries({ queryKey: ["policies"] });
  };
  const publish = useMutation({
    mutationFn: () => api.post<Policy>(`/api/v1/policies/${id}/publish`, { reason }),
    onSuccess: (published) => {
      setPublishing(false);
      setReason("");
      setMessage({ text: t("Published as version {n}; the loop judges by it from now on.", { n: published.version }) });
      refresh();
    },
    onError: (error) => setMessage({ text: error instanceof ApiError ? `${error.code}: ${error.message}` : String(error), error: true }),
  });
  const evaluate = useMutation({
    mutationFn: () => api.post<PolicyOutcome>(`/api/v1/policies/${id}/evaluate`),
    onSuccess: (outcome) => {
      const counts = outcome.counts;
      setMessage({
        text: t("Evaluated {hosts} hosts: {compliant} compliant, {drift} drifted, {error} errors, {na} not applicable.{remediation}", {
          hosts: outcome.hosts, compliant: counts.compliant, drift: counts.drift, error: counts.error, na: counts.not_applicable,
          remediation: outcome.remediation ? ` ${outcome.remediation}` : "",
        }),
      });
      refresh();
    },
    onError: (error) => setMessage({ text: error instanceof ApiError ? `${error.code}: ${error.message}` : String(error), error: true }),
  });
  const remove = useMutation({
    mutationFn: () => api.del<void>(`/api/v1/policies/${id}`, undefined, { headers: policy.data?.etag ? { "If-Match": policy.data.etag } : {} }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      // The page is left behind, so the outcome is told where it can
      // still be seen.
      toast.success(t("Policy {name} is deleted; its campaigns stay.", { name: policy.data?.data.name ?? "" }));
      navigate("/policies");
    },
    onError: (error) => {
      const text = error instanceof ApiError ? `${error.code}: ${error.message}` : String(error);
      setMessage({ text, error: true });
      toast.error(text);
    },
  });
  const askToDelete = async () => {
    const answer = await confirm({
      title: t("Delete the policy"),
      body: t("Delete the policy and its verdicts? Its campaigns stay."),
      confirmLabel: t("Delete"),
      danger: true,
    });
    if (answer.ok) remove.mutate();
  };

  if (policy.error) return <ErrorBox error={policy.error} />;
  if (!policy.data) return <Empty>{t("Loading…")}</Empty>;
  const record = policy.data.data;
  const counts = record.counts;
  const total = POLICY_VERDICTS.reduce((sum, verdict) => sum + (counts?.[verdict] ?? 0), 0);

  return (
    <>
      <PageHeader
        icon="security"
        breadcrumb={[{ label: t("Policies"), to: "/policies" }]}
        title={record.name}
        description={record.description || t("A desired-state policy: judged from the inventory, never by touching a host.")}
        actions={(
          <>
            {canWrite && record.version > 0 && (
              <button className="secondary" onClick={() => evaluate.mutate()} disabled={evaluate.isPending}>{t("Evaluate now")}</button>
            )}
            {canPublish && !publishing && (
              <button onClick={() => setPublishing(true)}>{record.version === 0 ? t("Publish") : t("Publish a new version")}</button>
            )}
            {canWrite && (
              <button className="secondary" onClick={askToDelete} disabled={remove.isPending}>{t("Delete")}</button>
            )}
          </>
        )}
      />

      {publishing && (
        <Card
          title={record.version === 0 ? t("Publish") : t("Publish version {n}", { n: record.version + 1 })}
          description={t("The publication is the approval: the document is frozen as it stands, the loop judges by it, and in campaign or automatic mode a drift becomes a campaign on your authority. It asks for fresh authentication like the approval of a campaign.")}
          tone={record.remediation_mode === "automatic" ? "warn" : undefined}
        >
          {record.remediation_mode === "automatic" && (
            <p className="hm-message">{t("Automatic remediation: the campaigns this policy orders are approved by this publication and start without a second look. This needs the policy.remediate.auto permission.")}</p>
          )}
          <FieldGrid>
            <Field label={t("Reason")} hint={t("Recorded with the version.")} wide>
              <input value={reason} onChange={(e) => setReason(e.target.value)} autoFocus />
            </Field>
          </FieldGrid>
          <Actions>
            <button onClick={() => publish.mutate()} disabled={publish.isPending}>{t("Publish")}</button>
            <button className="secondary" onClick={() => setPublishing(false)}>{t("Cancel")}</button>
          </Actions>
        </Card>
      )}

      {message.text && <p className={message.error ? "hm-message error" : "hm-message"}>{message.text}</p>}

      <div className="widgets">
        <Card className="span-8" title={t("Compliance")} description={record.last_evaluated_at
          ? t("{n} verdicts of version {v}; last evaluated {when}", { n: total, v: record.version, when: new Date(record.last_evaluated_at).toLocaleString() })
          : t("Not evaluated yet.")}>
          <StatusBar segments={POLICY_VERDICTS.map((verdict) => ({
            label: verdictLabel(verdict, t),
            value: record.last_evaluated_at ? counts?.[verdict] ?? 0 : undefined,
            tone: verdict === "compliant" ? "ok" : verdict === "drift" ? "warn" : verdict === "error" ? "error" : "unknown",
          }))} />
        </Card>
        <Card className="span-4" title={t("Standing")}>
          <dl className="hm-facts">
            <div className="hm-fact"><dt>{t("Version")}</dt><dd><Standing policy={record} /></dd></div>
            <div className="hm-fact"><dt>{t("Remediation")}</dt><dd>{modeLabel(record.remediation_mode, t)}</dd></div>
            <div className="hm-fact"><dt>{t("Interval")}</dt><dd>{t("every {n} min", { n: intervalMinutes(record.check_interval_seconds) })}</dd></div>
            <div className="hm-fact"><dt>{t("Published")}</dt><dd>{record.published_at ? <><Time value={record.published_at} /> · {record.published_by}</> : "—"}</dd></div>
            <div className="hm-fact"><dt>{t("Enabled")}</dt><dd>{record.enabled ? t("yes") : t("no")}</dd></div>
          </dl>
        </Card>

        <Card className="span-12" title={t("Document")} description={record.draft
          ? t("This draft differs from version {v}; the loop keeps judging by the published text until the next publication.", { v: record.version })
          : record.version === 0 ? t("A draft nobody has published; nothing is judged yet.") : t("As published in version {v}.", { v: record.version })}>
          <Editor policy={record} etag={policy.data.etag} canWrite={canWrite} onSaved={(saved) => { setMessage({ text: t("Saved.") }); queryClient.setQueryData(["policy", id], saved); refresh(); }} />
        </Card>

        <Card className="span-12" title={t("Results")} flush>
          <Results policyID={id} />
        </Card>

        <Card className="span-6" title={t("Versions")} flush>
          <Versions policyID={id} />
        </Card>
        <Card className="span-6" title={t("Remediation campaigns")} description={t("Ordered by this policy for a drift set; each waits for its approval on its own page.")} flush>
          <Campaigns policyID={id} />
        </Card>
      </div>
    </>
  );
}

/* ---------------------------------------------------------------------- */
/* The editor.                                                             */
/* ---------------------------------------------------------------------- */

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
export function selectorOf(draft: Pick<Draft, "targetMode" | "site" | "environment" | "osFamily" | "selectorRules" | "combine" | "expressionText">): { selector?: PolicySelector; error?: string } {
  switch (draft.targetMode) {
    case "filters":
      return { selector: { site: draft.site.trim() || undefined, environment: draft.environment.trim() || undefined, os_family: draft.osFamily.trim() || undefined } };
    case "expression": {
      const expression = buildExpression(draft.selectorRules, draft.combine);
      return { selector: { expression: expression ?? undefined } };
    }
    default:
      try {
        const expression = draft.expressionText.trim() === "" ? undefined : (JSON.parse(draft.expressionText) as SelectorExpression);
        return { selector: { expression } };
      } catch (error) {
        return { error: String(error instanceof Error ? error.message : error) };
      }
  }
}

function Editor({ policy, etag, canWrite, onSaved }: { policy: Policy; etag: string; canWrite: boolean; onSaved: (saved: { data: Policy; etag: string }) => void }) {
  const t = useT();
  const [draft, setDraft] = useState<Draft>(() => draftOf(policy));
  const [error, setError] = useState("");
  // The sites and environments the fleet has, offered under the filters.
  const facets = useFleetFacets();
  // A refetch that brings a newer version replaces the form; typing in
  // between is not lost silently, because the tag would then refuse the
  // write and the message says to read again.
  useEffect(() => { setDraft(draftOf(policy)); }, [policy.updated_at, policy.version]); // eslint-disable-line react-hooks/exhaustive-deps
  const change = (delta: Partial<Draft>) => setDraft((current) => ({ ...current, ...delta }));

  const save = useMutation({
    mutationFn: async () => {
      const rules = draft.rulesAsText ? rulesFromText(draft.rulesText) : { rules: draft.rules };
      if (rules.error) throw new Error(rules.error);
      const selector = selectorOf(draft);
      if (selector.error) throw new Error(selector.error);
      const spec: PolicySpec = {
        name: draft.name.trim(), description: draft.description.trim(), selector: selector.selector ?? {},
        rules: (rules.rules ?? []).map(pruneRule), remediation_mode: draft.mode, enabled: draft.enabled,
        check_interval_seconds: Math.max(1, draft.intervalMinutes) * 60,
      };
      // The write goes on the tag the page read; a stale one is refused
      // by the server with the current one, and the message says so. The
      // record is read again for the tag of the version just written.
      await api.put<Policy>(`/api/v1/policies/${policy.id}`, spec, { headers: etag ? { "If-Match": etag } : {} });
      return api.getWithMeta<Policy>(`/api/v1/policies/${policy.id}`);
    },
    onSuccess: (saved) => { setError(""); onSaved(saved); },
    onError: (failure) => setError(failure instanceof ApiError ? `${failure.code}: ${failure.message}` : String(failure instanceof Error ? failure.message : failure)),
  });

  const updateRule = (index: number, delta: Partial<PolicyRule>) =>
    change({ rules: draft.rules.map((rule, i) => (i === index ? { ...rule, ...delta } : rule)) });

  return (
    <>
      <FieldGrid>
        <Field label={t("Name")}>
          <input value={draft.name} onChange={(e) => change({ name: e.target.value })} disabled={!canWrite} />
        </Field>
        <Field label={t("Remediation")} hint={t("report writes verdicts; campaign orders a campaign that waits for approval; automatic approves it with the publication.")}>
          <select value={draft.mode} onChange={(e) => change({ mode: e.target.value as PolicyRemediationMode })} disabled={!canWrite}>
            {POLICY_MODES.map((mode) => <option key={mode} value={mode}>{modeLabel(mode, t)}</option>)}
          </select>
        </Field>
        <Field label={t("Check interval (minutes)")}>
          <input type="number" min={1} max={1440} value={draft.intervalMinutes} onChange={(e) => change({ intervalMinutes: Number(e.target.value) })} disabled={!canWrite} />
        </Field>
        <Field label={t("Enabled")} hint={t("A disabled policy keeps its verdicts and is not judged.")}>
          <label className="toggle"><input type="checkbox" checked={draft.enabled} onChange={(e) => change({ enabled: e.target.checked })} disabled={!canWrite} /> {t("judge this policy")}</label>
        </Field>
        <Field label={t("Description")} wide>
          <input value={draft.description} onChange={(e) => change({ description: e.target.value })} disabled={!canWrite} />
        </Field>
      </FieldGrid>

      <h4 className="widget-subhead">{t("Rules")}</h4>
      <Toolbar end={(
        <label className="toggle">
          <input type="checkbox" checked={draft.rulesAsText} onChange={(e) => change(e.target.checked
            ? { rulesAsText: true, rulesText: rulesToText(draft.rules) }
            : { rulesAsText: false, ...(rulesFromText(draft.rulesText).rules ? { rules: rulesFromText(draft.rulesText).rules } : {}) })} />{" "}
          {t("edit as JSON")}
        </label>
      )}>
        <span className="source">{t("{n} rules; each names facts the host reports and one typed operation that fixes the drift.", { n: draft.rules.length })}</span>
      </Toolbar>
      {draft.rulesAsText ? (
        <textarea className="mono" rows={12} value={draft.rulesText} onChange={(e) => change({ rulesText: e.target.value })} disabled={!canWrite} />
      ) : (
        <>
          {draft.rules.map((rule, index) => (
            <Toolbar key={index}>
              <span className="badge">{index}</span>
              <select value={rule.kind} onChange={(e) => change({ rules: draft.rules.map((r, i) => (i === index ? emptyRule(e.target.value as PolicyRuleKind) : r)) })} disabled={!canWrite}>
                {POLICY_RULE_KINDS.includes(rule.kind as PolicyRuleKind) ? null : <option value={rule.kind}>{rule.kind}</option>}
                {POLICY_RULE_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
              </select>
              <RuleFields rule={rule} disabled={!canWrite} onChange={(delta) => updateRule(index, delta)} />
              <button type="button" className="secondary" onClick={() => change({ rules: draft.rules.filter((_, i) => i !== index) })} disabled={!canWrite}>{t("Remove")}</button>
            </Toolbar>
          ))}
          {canWrite && (
            <Actions>
              <button type="button" className="secondary" onClick={() => change({ rules: [...draft.rules, emptyRule("package_installed")] })}>{t("Add a rule")}</button>
            </Actions>
          )}
        </>
      )}

      <h4 className="widget-subhead">{t("Hosts")}</h4>
      <FieldGrid>
        <Field label={t("Named by")}>
          <select value={draft.targetMode} onChange={(e) => change({ targetMode: e.target.value as Draft["targetMode"] })} disabled={!canWrite}>
            <option value="filters">{t("site, environment and OS")}</option>
            <option value="expression">{t("groups and tags")}</option>
            <option value="json">{t("an expression as JSON")}</option>
          </select>
        </Field>
        {draft.targetMode === "filters" && (
          <>
            <Field label={t("Site")}>
              <input value={draft.site} onChange={(e) => change({ site: e.target.value })} disabled={!canWrite} list="policy-sites" />
              <FacetList id="policy-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")}>
              <input value={draft.environment} onChange={(e) => change({ environment: e.target.value })} disabled={!canWrite} list="policy-environments" />
              <FacetList id="policy-environments" facets={facets.data?.by_environment} />
            </Field>
            <Field label={t("OS family")}><input value={draft.osFamily} onChange={(e) => change({ osFamily: e.target.value })} placeholder="debian" disabled={!canWrite} /></Field>
          </>
        )}
      </FieldGrid>
      {draft.targetMode === "expression" && (
        <SelectorBuilder rules={draft.selectorRules} combine={draft.combine} onRules={(rules) => change({ selectorRules: rules })} onCombine={(combine) => change({ combine })} />
      )}
      {draft.targetMode === "json" && (
        <textarea className="mono" rows={8} value={draft.expressionText} onChange={(e) => change({ expressionText: e.target.value })} disabled={!canWrite} />
      )}
      <p className="source">
        {(() => {
          const { selector, error: selectorError } = selectorOf(draft);
          if (selectorError) return t("the expression does not parse: {error}", { error: selectorError });
          if (selector?.expression) return <>{t("the policy will carry")} <span className="mono">{describeExpression(selector.expression)}</span></>;
          const parts = [selector?.site && `site=${selector.site}`, selector?.environment && `environment=${selector.environment}`, selector?.os_family && `os_family=${selector.os_family}`].filter(Boolean);
          return parts.length ? <>{t("the policy will carry")} <span className="mono">{parts.join(" ")}</span></> : t("no host is named yet; the publication refuses a policy over nobody");
        })()}
      </p>

      {error && <p className="hm-message error">{error}</p>}
      {canWrite && (
        <Actions>
          <button onClick={() => save.mutate()} disabled={save.isPending || draft.name.trim() === ""}>{t("Save the draft")}</button>
          <button className="secondary" onClick={() => setDraft(draftOf(policy))}>{t("Discard changes")}</button>
        </Actions>
      )}
    </>
  );
}

/** The typed fields of one rule. */
function RuleFields({ rule, disabled, onChange }: { rule: PolicyRule; disabled: boolean; onChange: (delta: Partial<PolicyRule>) => void }) {
  const t = useT();
  const text = (field: keyof PolicyRule, placeholder: string, mono = false) => (
    <input
      className={mono ? "mono" : undefined}
      value={(rule[field] as string | undefined) ?? ""}
      placeholder={placeholder}
      onChange={(e) => onChange({ [field]: e.target.value } as Partial<PolicyRule>)}
      disabled={disabled}
    />
  );
  const half = (field: "enabled" | "active", label: string) => (
    <select value={rule[field] === undefined ? "" : rule[field] ? "yes" : "no"} onChange={(e) => onChange({ [field]: e.target.value === "" ? undefined : e.target.value === "yes" } as Partial<PolicyRule>)} disabled={disabled}>
      <option value="">{t("{what}: not declared", { what: label })}</option>
      <option value="yes">{t("{what}: yes", { what: label })}</option>
      <option value="no">{t("{what}: no", { what: label })}</option>
    </select>
  );
  switch (rule.kind) {
    case "package_installed":
    case "package_absent":
      return text("name", t("package name"), true);
    case "unit_state":
      return <>{text("unit", "cron.service", true)}{half("enabled", t("enabled"))}{half("active", t("active"))}</>;
    case "file_content":
      return <>{text("path", "/etc/example.conf", true)}{text("sha256", t("sha256 of the managed version"), true)}</>;
    case "sysctl":
      return <>{text("key", "net.ipv4.ip_forward", true)}{text("value", t("value"), true)}</>;
    case "ssh_key_present":
      return <>{text("user", t("account"), true)}{text("fingerprint", "SHA256:…", true)}{text("public_key", t("public key line (optional; lets the panel set it on an empty account)"), true)}</>;
    default:
      return <span className="badge error">{t("unsupported kind")}</span>;
  }
}

/* ---------------------------------------------------------------------- */
/* The results, the versions and the campaigns.                           */
/* ---------------------------------------------------------------------- */

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
    queryFn: () => api.get<{ items: PolicyResult[]; total: number; next_cursor?: string }>(`/api/v1/policies/${policyID}/results?${query}`),
  });
  useEffect(() => {
    if (!page.data) return;
    setRows((current) => (cursor ? [...current, ...page.data.items] : page.data.items));
  }, [page.data, cursor]);
  const reset = () => { setCursor(""); setRows([]); };

  return (
    <>
      <Toolbar>
        <select value={verdict} onChange={(e) => { setVerdict(e.target.value as PolicyVerdict | ""); reset(); }}>
          <option value="">{t("every verdict")}</option>
          {POLICY_VERDICTS.map((value) => <option key={value} value={value}>{verdictLabel(value, t)}</option>)}
        </select>
        <input placeholder={t("host id")} value={host} onChange={(e) => { setHost(e.target.value); reset(); }} className="mono" />
        <span className="source">{page.data ? t("{n} verdicts", { n: page.data.total }) : ""}</span>
        <ExportButton path={`/api/v1/policies/${policyID}/results`} params={query} />
      </Toolbar>
      {page.error ? (
        <ErrorBox error={page.error} />
      ) : !page.data && rows.length === 0 ? (
        <Empty>{t("Loading…")}</Empty>
      ) : rows.length === 0 ? (
        <EmptyState>{t("No verdict yet: the policy has not been evaluated, or nothing matches the filter.")}</EmptyState>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Host")}</th><th>{t("Rule")}</th><th>{t("Verdict")}</th><th>{t("Reason")}</th><th>{t("Version")}</th><th>{t("Evaluated")}</th></tr>
          </thead>
          <tbody>
            {rows.map((result) => (
              <tr key={`${result.host_id}:${result.rule_index}`}>
                <td><Link to={`/hosts/${result.host_id}/policies`}>{result.hostname || result.host_id}</Link></td>
                <td className="mono">{result.rule ? ruleSummary(result.rule) : `#${result.rule_index}`}</td>
                <td><VerdictChip verdict={result.verdict} /></td>
                <td>{result.reason || "—"}</td>
                <td className="num">v{result.version}</td>
                <td><Time value={result.evaluated_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {page.data?.next_cursor && (
        <Actions>
          <button className="secondary" onClick={() => setCursor(page.data?.next_cursor ?? "")} disabled={page.isFetching}>{t("Load more")}</button>
        </Actions>
      )}
    </>
  );
}

function Versions({ policyID }: { policyID: string }) {
  const t = useT();
  const versions = useQuery({
    queryKey: ["policy-versions", policyID],
    queryFn: () => api.get<Collection<PolicyVersion>>(`/api/v1/policies/${policyID}/versions`),
  });
  if (versions.error) return <ErrorBox error={versions.error} />;
  if (!versions.data) return <Empty>{t("Loading…")}</Empty>;
  if (versions.data.items.length === 0) return <EmptyState>{t("Never published.")}</EmptyState>;
  return (
    <table>
      <thead><tr><th>{t("Version")}</th><th>{t("Published")}</th><th>{t("By")}</th><th>{t("Authentication")}</th><th>{t("Reason")}</th><th>{t("Rules")}</th><th>{t("Remediation")}</th></tr></thead>
      <tbody>
        {versions.data.items.map((version) => (
          <tr key={version.version}>
            <td className="num">v{version.version}</td>
            <td><Time value={version.published_at} /></td>
            <td>{version.published_by}</td>
            <td className="mono">{[version.authentication, version.acr, ...(version.amr ?? [])].filter(Boolean).join(" ") || "—"}</td>
            <td>{version.reason || "—"}</td>
            <td className="num">{version.document.rules.length}</td>
            <td>{modeLabel(version.document.remediation_mode, t)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Campaigns({ policyID }: { policyID: string }) {
  const t = useT();
  const campaigns = useQuery({
    queryKey: ["policy-campaigns", policyID],
    queryFn: () => api.get<Collection<PolicyCampaignLink>>(`/api/v1/policies/${policyID}/campaigns`),
    refetchInterval: 30 * 1000,
  });
  if (campaigns.error) return <ErrorBox error={campaigns.error} />;
  if (!campaigns.data) return <Empty>{t("Loading…")}</Empty>;
  if (campaigns.data.items.length === 0) return <EmptyState>{t("No campaign ordered: report mode, no drift, or a drift nothing can fix.")}</EmptyState>;
  return (
    <table>
      <thead><tr><th>{t("Campaign")}</th><th>{t("State")}</th><th>{t("Version")}</th><th>{t("Created")}</th></tr></thead>
      <tbody>
        {campaigns.data.items.map((campaign) => (
          <tr key={campaign.id}>
            <td><Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link></td>
            <td><JobState state={campaign.state} /></td>
            <td className="num">v{campaign.policy_version}</td>
            <td><Time value={campaign.created_at} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
