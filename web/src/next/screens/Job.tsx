import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Collection } from "../../lib/api";
import { absoluteTime, bytes, relativeTime } from "../../lib/format";
import { useErrorGuides } from "../../lib/errors";
import { OPERATIONS_INTERVAL, useProgress } from "../../lib/stream";
import { stateName } from "../../lib/states";
import {
  ACTION_WORDS, changeAction, isHostPlan, isPackageChange, planWords,
  type HostPlan, type PackageChange, type PackagePlanFacts,
} from "../../components/plan";
import type { Attempt, Job as JobRecord } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Banner, Bones, Card, Empty, Fact, Facts, Field, Fields, Grid, Kpi, Kpis, Modal, Note, Pill,
  Problem, Ring, Screen, Stack, Table, Tabs, Tag, Tags, useTab, type Tone,
} from "../kit";
import { jobTone, orderAgainAddress, prettyJSON, reasonAccepted, waitedBudget } from "./Jobs";

/**
 * One operation on one host: what was asked, what happened, what it
 * returned.
 *
 * The row in the list carries what a row has room for; everything else is
 * here - the whole payload the consent is bound to, the plan the host
 * computed, every attempt with its output in full, and who approved or
 * stopped it and why. Nothing on this screen is computed by the panel: a
 * figure the fleet never reported is an em dash, never a nought.
 */

/** One job as the API tells it in full, beyond what a row of the list needs. */
export type JobDetail = JobRecord & {
  fanout_id?: string;
  approvals?: { approver: string; reason?: string; approved_at: string }[];
  approved_at?: string;
  canceled_by?: string;
  cancel_reason?: string;
  cancel_requested_at?: string;
  cancel_ack_at?: string;
  cancel_outcome?: string;
  cancel_phase?: string;
  timeout_seconds?: number;
  max_output_bytes?: number;
  preconditions?: unknown;
  request_id?: string;
  updated_at?: string;
};

/** The states a job does not leave; the screen stops polling on them. */
const TERMINAL = ["succeeded", "failed", "timed_out", "canceled", "cancelled", "expired", "rejected"];

/** The states after which the same order can be placed again. */
const REORDERABLE = ["failed", "timed_out", "canceled", "expired"];

/** How much of an output stands on the screen before the operator asks for the rest. */
export const OUTPUT_PREVIEW = 4000;

/** How many rows of a plan's changes are drawn before the rest is asked for. */
const CHANGES_SHOWN = 8;

/**
 * The name of the file an output is saved under: the job, the attempt and
 * the stream, so two files from one job tell each other apart on disk.
 */
export function outputFilename(jobID: string, attempt: number, stream: string): string {
  return `job-${jobID.slice(0, 8)}-attempt-${attempt}-${stream}.txt`;
}

/**
 * The payload as a list of fields: a dotted path and a value for every
 * leaf. A payload too deep, too long or holding a list of objects has no
 * honest field form and reads as its JSON instead.
 */
export function payloadPairs(value: unknown): { path: string; value: string }[] | null {
  let payload = value;
  if (typeof payload === "string") {
    try {
      payload = JSON.parse(payload);
    } catch {
      return null;
    }
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return null;
  const pairs: { path: string; value: string }[] = [];
  const walk = (node: Record<string, unknown>, prefix: string, depth: number): boolean => {
    for (const [key, item] of Object.entries(node)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (item !== null && typeof item === "object" && !Array.isArray(item)) {
        if (depth >= 2 || !walk(item as Record<string, unknown>, path, depth + 1)) return false;
      } else if (Array.isArray(item)) {
        if (item.some((entry) => entry !== null && typeof entry === "object")) return false;
        pairs.push({ path, value: item.length === 0 ? "[]" : item.map(String).join(", ") });
      } else {
        pairs.push({ path, value: item === null ? "null" : typeof item === "string" ? item : String(item) });
      }
    }
    return true;
  };
  if (!walk(payload as Record<string, unknown>, "", 0)) return null;
  return pairs.length > 0 && pairs.length <= 24 ? pairs : null;
}

/**
 * The host's answer to a cancel, in a sentence: what the request found and
 * what the host was doing.
 */
export function cancelAckLine(
  job: { cancel_outcome?: string; cancel_phase?: string },
  t: (key: string, params?: Record<string, string | number>) => string,
): string {
  const phase = job.cancel_phase || "under way";
  switch (job.cancel_outcome) {
    case "not_started":
      return t("The host had not started the task; it will not start.");
    case "interrupted":
      return t("The host interrupted the task while it was {phase}.", { phase });
    case "not_interruptible":
      return t("The host runs the task to its end ({phase}); the result settles it.", { phase });
    case "already_done":
      return t("The host had already finished the task; its result settles it.");
    default:
      return "";
  }
}

/**
 * The host's reading of itself after a change, as the attempt carries it.
 */
export type Verification = {
  verifier?: string;
  verified?: boolean;
  expected?: string;
  observed?: string;
  reason?: string;
};

/** The attempt as this screen reads it: the collection type plus the verification. */
type AttemptDetail = Attempt & { verification?: Verification; output_truncated?: boolean };

/**
 * The verification in one line: the verifier, what it expected, what it
 * observed, and the reason when the two differ.
 */
export function verificationLine(
  verification: Verification,
  t: (key: string, params?: Record<string, string | number>) => string,
): string {
  const said = (value: string | undefined) => (value && value.trim() ? value : t("unknown"));
  const head = t("{verifier}: expected {expected}, observed {observed}", {
    verifier: said(verification.verifier),
    expected: said(verification.expected),
    observed: said(verification.observed),
  });
  if (verification.verified) return head;
  return verification.reason ? `${head} — ${verification.reason}` : head;
}

/**
 * The sentence a job carries when the change was made and the state was not
 * observed. Repeating such an operation would repeat a change that already
 * happened, so it is said before anything else on the screen.
 */
export function appliedUnverifiedNote(job: { result_error_code?: string }, t: (key: string) => string): string {
  if (job.result_error_code !== "applied_unverified") return "";
  return t("The change was made and the host did not show the state that was ordered. Read the host before ordering again: repeating the operation would repeat a change that already happened.");
}

/** Whether a JSON value says anything: an order without preconditions carries an empty object or nothing. */
export function hasContent(value: unknown): boolean {
  const text = prettyJSON(value);
  return text !== "" && text !== "{}" && text !== "[]" && text !== "null";
}

/** The sub-tabs of one job, in the order a reader wants them. */
const JOB_TABS = ["order", "result", "attempts", "approvals"] as const;

export function Job() {
  const t = useT();
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const [tab, go] = useTab(JOB_TABS);

  const job = useQuery({
    queryKey: ["jobs", "detail", id],
    queryFn: () => api.get<JobDetail>(`/api/v1/jobs/${id}`),
    // A job in flight changes under the screen; one that ended does not.
    refetchInterval: (query) => (query.state.data && TERMINAL.includes(query.state.data.state) ? false : OPERATIONS_INTERVAL),
  });
  const attempts = useQuery({
    queryKey: ["attempts", id],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${id}/attempts`),
    refetchInterval: job.data && TERMINAL.includes(job.data.state) ? false : OPERATIONS_INTERVAL,
  });
  const progress = useProgress(`/api/v1/jobs/${id}/events`);

  // One decision at a time, and every decision carries a reason the trail
  // keeps. The reason is cleared with the dialog so a cancel never inherits
  // the sentence somebody typed for an approval.
  const [asking, setAsking] = useState<"approve" | "cancel" | null>(null);
  const [reason, setReason] = useState("");
  const close = () => { setAsking(null); setReason(""); };
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    void queryClient.invalidateQueries({ queryKey: ["attempts", id] });
  };
  const approve = useMutation({
    mutationFn: (data: JobDetail) =>
      api.post(`/api/v1/jobs/${id}/approve`, { payload_hash: data.payload_hash, reason: reason.trim() || undefined }),
    onSuccess: () => { close(); refresh(); },
  });
  const cancel = useMutation({
    mutationFn: () => api.post(`/api/v1/jobs/${id}/cancel`, { reason: reason.trim() }),
    onSuccess: () => { close(); refresh(); },
  });

  const help = (
    <p>
      {t("One operation on one host, with every attempt it took. The attempt keeps the outcome the fleet reported: a later reading by an operator is recorded beside it and never in place of it. The payload here is the text the approval's hash covers, so what is read is exactly what is consented to.")}
    </p>
  );

  if (job.error) {
    return (
      <Screen title={t("Job")} icon="jobs" help={help}>
        <Card><Problem>{String(job.error)}</Problem></Card>
      </Screen>
    );
  }
  if (!job.data) {
    return (
      <Screen title={t("Job")} icon="jobs" help={help}>
        <Card><Bones rows={4} /></Card>
      </Screen>
    );
  }

  const data = job.data;
  const host = data.hostname || data.host_id.slice(0, 8);
  const awaiting = data.state === "awaiting_approval";
  const budget = data.state === "queued" ? waitedBudget(data.wait_reason) : "";
  const report = progress.get(id);
  const fields = payloadPairs(data.payload);
  const unverified = appliedUnverifiedNote(data, t);

  // The plan the host computed, from the last attempt that carries one: a
  // planning operation ends with it, and an apply that replans first
  // carries it too.
  const planned = [...(attempts.data?.items ?? [])].reverse()
    .find((item) => isHostPlan(item.detail?.kind as string) || item.detail?.kind === "package_plan");
  const packagePlan = planned?.detail?.kind === "package_plan";
  const plan = (packagePlan ? planned?.detail : planned?.detail?.plan) as (HostPlan & PackagePlanFacts) | undefined;
  const planHash = (planned?.detail?.plan_hash as string | undefined) || plan?.plan_hash;

  // The verifications of the job, in the order of the attempts that made them.
  const verifications = (attempts.data?.items ?? [])
    .map((item) => ({ attempt: item.id, verification: (item as AttemptDetail).verification }))
    .filter((entry): entry is { attempt: string; verification: Verification } => !!entry.verification);

  const actions = (
    <>
      {awaiting && (
        <>
          <button type="button" onClick={() => { approve.reset(); setReason(""); setAsking("approve"); }} data-testid="approve">
            {t("Approve")}
          </button>
          <button type="button" className="fl-danger" onClick={() => { cancel.reset(); setReason(""); setAsking("cancel"); }} data-testid="cancel">
            {t("Cancel")}
          </button>
        </>
      )}
      {REORDERABLE.includes(data.state) && (
        <Link
          className="fl-btn fl-quiet"
          to={orderAgainAddress(data)}
          title={t("Opens the Bulk workspace with the same operation, payload and host written in.")}
          data-testid="order-again"
        >
          {t("Order again")}
        </Link>
      )}
    </>
  );

  return (
    <Screen
      title={data.action_type}
      icon="jobs"
      help={help}
      actions={actions}
      banner={unverified ? <Banner tone="warn">{unverified}</Banner> : undefined}
      /* The lead is a paragraph, so what goes in it has to read as a line
         of text: the kit's Tags is a block and cannot stand inside one. */
      lead={
        <>
          <Pill tone={jobTone(data.state)}>{t(stateName(data.state))}</Pill>{" "}
          {budget && (
            <>
              <Pill tone="warn" title={t("The fleet or the site has no free capacity for this operation; the job starts when a token of this budget is free.")}>
                {t("waiting for budget {key}", { key: budget })}
              </Pill>{" "}
            </>
          )}
          {data.wait_reason && !budget && <><Tag>{data.wait_reason}</Tag>{" "}</>}
          <Tag to={`/hosts/${data.host_id}`}>{host}</Tag>{" "}
          <Tag>{t("requested by {who}", { who: data.created_by })}</Tag>
        </>
      }
    >
      <Kpis>
        <Kpi
          hero
          icon="jobs"
          label={t("State")}
          value={t(stateName(data.state))}
          note={data.finished_at
            ? t("finished {when}", { when: relativeTime(data.finished_at) })
            : t("created {when}", { when: relativeTime(data.created_at) })}
          testId="kpi-state"
        />
        <Kpi
          label={t("Attempts")}
          value={attempts.data ? attempts.data.items.length : null}
          testId="kpi-attempts"
        />
        <Kpi
          label={t("Approvals")}
          value={data.requires_approval ? data.collected_approvals : t("none needed")}
          note={data.requires_approval ? t("of {n} required", { n: data.required_approvals }) : undefined}
          tone={data.requires_approval && data.collected_approvals < data.required_approvals ? "warn" : undefined}
          testId="kpi-approvals"
        />
        <Kpi
          label={t("Timeout")}
          value={data.timeout_seconds ?? null}
          unit="s"
          note={data.max_output_bytes ? t("output up to {size}", { size: bytes(data.max_output_bytes) }) : undefined}
          testId="kpi-timeout"
        />
      </Kpis>

      {/* The reading of an operation in flight comes from the stream alone
          and cannot be read after the fact, so the card exists only while
          the host is reporting one. */}
      {report && (
        <Card title={t("Progress")} note={report.message}>
          <Ring
            share={report.percent !== undefined ? report.percent / 100 : undefined}
            label={t("reported")}
            tone="info"
            legend={[
              { label: t("Step"), value: report.step ?? "—" },
              { label: t("Of"), value: report.total ?? "—" },
            ]}
          />
        </Card>
      )}

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "order", label: t("Order") },
          { value: "result", label: t("Result") },
          { value: "attempts", label: t("Attempts"), count: attempts.data?.items.length },
          { value: "approvals", label: t("Approvals"), count: data.approvals?.length },
        ]}
      />

      {/* One job was six containers on one board until 17.10. The order,
          what came of it, what was tried and who consented are four
          readings, and a reader wants one of them at a time. */}
      {tab === "order" && (
      <Grid>
        <Card span={12} title={t("The order")}>
          <Facts>
            <Fact label={t("Identifier")}><span className="fl-mono">{data.id}</span></Fact>
            <Fact label={t("Host")}><Link to={`/hosts/${data.host_id}`}>{host}</Link></Fact>
            <Fact label={t("Campaign")}>
              {data.campaign_id
                ? <Link className="fl-mono" to={`/campaigns/${data.campaign_id}`}>{data.campaign_id}</Link>
                : "—"}
            </Fact>
            <Fact label={t("Read fan-out")}>
              {data.fanout_id
                ? <Link className="fl-mono" to={`/reads/${data.fanout_id}`}>{data.fanout_id}</Link>
                : "—"}
            </Fact>
            <Fact label={t("Requested by")}>{data.created_by}</Fact>
            <Fact label={t("Created")}>
              <span title={absoluteTime(data.created_at)}>{relativeTime(data.created_at)}</span>
            </Fact>
            <Fact label={t("Expires")}>
              {data.expires_at
                ? <span title={absoluteTime(data.expires_at)}>{relativeTime(data.expires_at)}</span>
                : "—"}
            </Fact>
            <Fact label={t("Finished")}>
              {data.finished_at
                ? <span title={absoluteTime(data.finished_at)}>{relativeTime(data.finished_at)}</span>
                : "—"}
            </Fact>
            <Fact label={t("Timeout")}>{data.timeout_seconds ? t("{n} s", { n: data.timeout_seconds }) : "—"}</Fact>
            <Fact label={t("Budget class")}>{data.budget_class || "—"}</Fact>
          </Facts>
        </Card>

      </Grid>
      )}

      {tab === "result" && (
      <Grid>
        <Card span={12} title={t("Decision and result")}>
          <Facts>
            <Fact label={t("Approvals")}>
              {data.required_approvals > 1
                ? t("{collected} of {required} approvals", { collected: data.collected_approvals, required: data.required_approvals })
                : data.requires_approval ? t("one approval") : t("none needed")}
            </Fact>
            <Fact label={t("Approved by")}>
              {data.approved_by
                ? <>{data.approved_by}{data.approved_at && <> · <span title={absoluteTime(data.approved_at)}>{relativeTime(data.approved_at)}</span></>}</>
                : "—"}
            </Fact>
            <Fact label={t("Canceled by")}>{data.canceled_by || "—"}</Fact>
            <Fact label={t("Cancel reason")}>{data.cancel_reason || "—"}</Fact>
            {/* A cancel of a task the host holds is a request and an answer:
                the request goes out, the host says what it found, and only
                that settles the job. Both moments stand here, so a job in
                cancel_requested says whom it is waiting for. */}
            {data.cancel_requested_at && (
              <Fact label={t("Cancel requested")}>
                <Tags>
                  <Tag>{absoluteTime(data.cancel_requested_at)}</Tag>
                  {!data.cancel_ack_at && <Pill tone="warn">{t("waiting for the host to answer")}</Pill>}
                </Tags>
              </Fact>
            )}
            {data.cancel_ack_at && (
              <Fact label={t("Cancel acknowledged")}>
                <Tags>
                  <Tag>{absoluteTime(data.cancel_ack_at)}</Tag>
                  <Tag>{data.cancel_outcome}</Tag>
                  {data.cancel_phase && <Tag>{data.cancel_phase}</Tag>}
                </Tags>
                {cancelAckLine(data, t) && <Note>{cancelAckLine(data, t)}</Note>}
              </Fact>
            )}
            <Fact label={t("Result")}>{data.result_status ? t(stateName(data.result_status)) : "—"}</Fact>
            <Fact label={t("Error code")}><ErrorCode code={data.result_error_code} /></Fact>
            <Fact label={t("Message")}>{data.result_message || "—"}</Fact>
            {/* Only the host's own reading turns a change into a success, so
                it stands with the result and not in a corner of the output. */}
            <Fact label={t("Verification")}>
              {verifications.length === 0 ? (
                <Note>{t("The host reported no verification for this operation.")}</Note>
              ) : (
                <Stack>
                  {verifications.map(({ attempt, verification }) => (
                    <Tags key={attempt}>
                      <Pill tone={verification.verified ? "ok" : "error"}>
                        {verification.verified ? t("observed") : t("not observed")}
                      </Pill>
                      <span className="fl-mono">{verificationLine(verification, t)}</span>
                    </Tags>
                  ))}
                </Stack>
              )}
            </Fact>
            <Fact label={t("Payload hash")}><span className="fl-mono">{data.payload_hash}</span></Fact>
          </Facts>
        </Card>
      </Grid>
      )}

      {tab === "approvals" && (
      <Grid>
        <Card
          span={12}
          title={t("Approval history")}
          note={t("Every consent recorded for this job, in the order it was given.")}
          flush
        >
          {!data.approvals?.length ? (
            <Empty>{data.requires_approval ? t("No approval yet.") : t("The operation needs no approval.")}</Empty>
          ) : (
            <Table
              testId="approvals"
              rows={data.approvals}
              keyOf={(one) => `${one.approver}:${one.approved_at}`}
              columns={[
                { key: "who", head: t("Approver"), cell: (one) => one.approver },
                { key: "why", head: t("Reason"), cell: (one) => one.reason || "—" },
                {
                  key: "when",
                  head: t("When"),
                  cell: (one) => <span title={absoluteTime(one.approved_at)}>{relativeTime(one.approved_at)}</span>,
                },
              ]}
            />
          )}
        </Card>
      </Grid>
      )}

      {tab === "order" && (
      <Grid>
        <Card
          span={6}
          title={t("Payload")}
          note={t("The order as the host receives it; the hash above is computed over exactly this.")}
          tools={<Save text={prettyJSON(data.payload)} filename={`job-${data.id.slice(0, 8)}-payload.json`} />}
        >
          {/* The fields first, for reading; the JSON stays under them,
              because the hash is computed over that text and a reviewer
              approves exactly it. */}
          {fields && (
            <>
              <Facts>
                {fields.map((pair) => (
                  <Fact key={pair.path} label={pair.path}><span className="fl-mono">{pair.value}</span></Fact>
                ))}
              </Facts>
              <Note>{t("As JSON, the text the hash covers")}</Note>
            </>
          )}
          <pre className="fl-mono" data-testid="payload">{prettyJSON(data.payload) || "—"}</pre>
          {hasContent(data.preconditions) && (
            <>
              <Note>{t("Preconditions")}</Note>
              <pre className="fl-mono" data-testid="preconditions">{prettyJSON(data.preconditions)}</pre>
            </>
          )}
        </Card>

        <Card
          span={6}
          title={t("Plan")}
          note={plan
            ? t("What the host computed it would change; the hash names this plan.")
            : t("The host has computed no plan for this job.")}
          tools={plan
            ? <Save text={prettyJSON(planned?.detail)} filename={`job-${data.id.slice(0, 8)}-plan.json`} />
            : undefined}
        >
          {plan ? (
            <Stack>
              <Facts>
                <Fact label={t("Plan hash")}><span className="fl-mono">{planHash || "—"}</span></Fact>
              </Facts>
              <PlanBody plan={plan} />
              <pre className="fl-mono" data-testid="plan-json">{prettyJSON(planned?.detail)}</pre>
            </Stack>
          ) : attempts.isLoading ? (
            <Bones rows={3} />
          ) : (
            <Empty>{t("No plan.")}</Empty>
          )}
        </Card>
      </Grid>
      )}

      {tab === "attempts" && (
        attempts.error ? (
          <Card title={t("Attempts")}><Problem>{String(attempts.error)}</Problem></Card>
        ) : !attempts.data ? (
          <Card title={t("Attempts")}><Bones rows={3} /></Card>
        ) : attempts.data.items.length === 0 ? (
          <Card title={t("Attempts")} note={t("Every attempt at carrying out the job, with its output in full.")}>
            <Empty>{t("No execution attempts.")}</Empty>
          </Card>
        ) : (
          <Stack wide>
            {attempts.data.items.map((attempt) => (
              <AttemptCard key={attempt.id} jobID={data.id} attempt={attempt as AttemptDetail} />
            ))}
          </Stack>
        )
      )}

      {asking === "approve" && awaiting && (
        <Modal
          title={t("Approve this job")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                disabled={approve.isPending}
                onClick={() => approve.mutate(data)}
                data-testid="confirm-approve"
              >
                {t("Approve this payload")}
              </button>
            </>
          }
        >
          {/* The consent is given to the payload on this screen: the hash
              the approval carries is the hash of what stands here, so a
              swap between reading and clicking is refused by the server. */}
          <Note>
            {t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
              operation: data.action_type, host, hash: data.payload_hash.slice(0, 12),
            })}
          </Note>
          <pre className="fl-mono" data-testid="approve-payload">{prettyJSON(data.payload)}</pre>
          <Fields>
            <Field
              label={t("Reason for the trail")}
              wide
              hint={t("Optional for an approval; the second approver of a destructive operation reads it.")}
            >
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {approve.error && <Problem>{String(approve.error)}</Problem>}
        </Modal>
      )}

      {asking === "cancel" && awaiting && (
        <Modal
          title={t("Cancel this job")}
          onClose={close}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={close}>{t("Back")}</button>
              <button
                type="button"
                className="fl-danger"
                disabled={!reasonAccepted(reason) || cancel.isPending}
                title={reasonAccepted(reason) ? undefined : t("A cancel needs a reason of at least 8 characters.")}
                onClick={() => cancel.mutate()}
                data-testid="confirm-cancel"
              >
                {t("Cancel this job")}
              </button>
            </>
          }
        >
          <Note>{t("The job is withdrawn before the host has touched anything; the reason goes to the audit trail.")}</Note>
          <Fields>
            <Field label={t("Reason for the trail")} wide hint={t("Required, at least 8 characters.")}>
              <input autoFocus value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {cancel.error && <Problem>{String(cancel.error)}</Problem>}
        </Modal>
      )}
    </Screen>
  );
}

/**
 * One attempt at carrying out the job: when the host had it, what it came
 * back with, and the output of each stream in full.
 */
function AttemptCard({ jobID, attempt }: { jobID: string; attempt: AttemptDetail }) {
  const t = useT();
  const moment = (label: string, value?: string) =>
    value ? <Fact key={label} label={label}><span title={absoluteTime(value)}>{relativeTime(value)}</span></Fact> : null;
  const before = attempt.unit_state_before;
  const after = attempt.unit_state_after;
  return (
    <Card
      title={t("Attempt {n}", { n: attempt.attempt_number })}
      tools={
        <Tags>
          <Pill tone={attempt.status ? jobTone(attempt.status) : "unknown"}>
            {attempt.status ? t(stateName(attempt.status)) : t("unknown")}
          </Pill>
          {attempt.replayed && <Pill tone="info">{t("replayed from journal")}</Pill>}
          {attempt.error_code && <Pill tone="error">{attempt.error_code}</Pill>}
          {attempt.output_truncated && <Pill tone="warn">{t("output cut by the host at its limit")}</Pill>}
        </Tags>
      }
    >
      <Stack>
        <Facts>
          <Fact label={t("Exit code")}>{attempt.exit_code ?? "—"}</Fact>
          {moment(t("Dispatched"), attempt.dispatched_at)}
          {moment(t("Accepted"), attempt.accepted_at)}
          {moment(t("Started"), attempt.started_at)}
          {moment(t("Finished"), attempt.finished_at)}
          {attempt.message && <Fact label={t("Message")}>{attempt.message}</Fact>}
          {before && after && (
            <Fact label={t("Unit")}>
              <span className="fl-mono">
                {`${before.active_state}/${before.sub_state} pid ${before.main_pid} → ${after.active_state}/${after.sub_state} pid ${after.main_pid}`}
              </span>
            </Fact>
          )}
          {/* The reading the host made after this attempt's change, next to
              the attempt that made it. */}
          {attempt.verification && (
            <Fact label={t("Verification")}>
              <span className="fl-mono">{verificationLine(attempt.verification, t)}</span>
            </Fact>
          )}
        </Facts>
        {/* The typed result the host answered with, as it answered it. The
            old screen summarised a dozen known kinds in a line each; the
            whole of it stands here instead, so a kind nobody wrote a
            sentence for is still readable. */}
        {hasContent(attempt.detail) && (
          <>
            <Note>{t("What the host returned")}</Note>
            <pre className="fl-mono" data-testid="attempt-detail">{prettyJSON(attempt.detail)}</pre>
          </>
        )}
        {attempt.stdout && (
          <Output label="stdout" text={attempt.stdout} filename={outputFilename(jobID, attempt.attempt_number, "stdout")} />
        )}
        {attempt.stderr && (
          <Output label="stderr" text={attempt.stderr} filename={outputFilename(jobID, attempt.attempt_number, "stderr")} />
        )}
      </Stack>
    </Card>
  );
}

/** One stream of an attempt, cut to a readable length with the whole on request. */
function Output({ label, text, filename }: { label: string; text: string; filename: string }) {
  const t = useT();
  const [all, setAll] = useState(false);
  const long = text.length > OUTPUT_PREVIEW;
  return (
    <Stack>
      <Tags>
        <Tag>{label}</Tag>
        <Tag>{t("{n} characters", { n: text.length })}</Tag>
        {long && (
          <button type="button" className="fl-quiet fl-small" onClick={() => setAll(!all)} data-testid={`more-${label}`}>
            {all ? t("Show the first {n} characters", { n: OUTPUT_PREVIEW }) : t("Show all")}
          </button>
        )}
        <Save text={text} filename={filename} />
      </Tags>
      <pre className="fl-mono" data-testid={`output-${label}`}>{long && !all ? `${text.slice(0, OUTPUT_PREVIEW)}\n…` : text}</pre>
    </Stack>
  );
}

/**
 * Saves a text as a file in the operator's own browser: the bytes are
 * already on the screen, so nothing more is fetched and nothing is sent.
 */
export function Save({ text, filename }: { text: string; filename: string }) {
  const t = useT();
  const save = () => {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    // The address is released once the click has started the save; a
    // release in the same tick cuts the download short in some browsers.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <button type="button" className="fl-quiet fl-small" onClick={save} disabled={!text} data-testid="download">
      {t("Download")}
    </button>
  );
}

/**
 * An error code with the guide the server serves for it: what it means,
 * what to do next and whether a repeat is worth anything.
 */
export function ErrorCode({ code }: { code?: string | null }) {
  const t = useT();
  const guides = useErrorGuides();
  if (!code) return <>—</>;
  const guide = guides.get(code);
  if (!guide) return <Pill tone="error">{code}</Pill>;
  const retry: Record<string, string> = {
    never: t("a retry will fail the same way"),
    automatic: t("retried automatically"),
    after_change: t("retry after the named change"),
    after_replan: t("compute the plan again first"),
    read_state: t("read the state of the host before repeating"),
  };
  const title = `${t(guide.meaning)}\n${t("Next")}: ${t(guide.action)}\n${t("Retry")}: ${retry[guide.retry] ?? guide.retry}`;
  return <Pill tone={guide.counts_as_failure ? "error" : "neutral"} title={title}>{code}</Pill>;
}

/**
 * A plan as the operator reads it: what it does, what it costs, what it
 * leaves out, the changes themselves, and the text that lands on the host
 * verbatim where there is one.
 *
 * It is written here rather than taken from the old panel's plan component
 * because that one carries the old panel's appearance with it; the facts it
 * draws are the same facts.
 */
export function PlanBody({ plan, action }: { plan: HostPlan & PackagePlanFacts; action?: string }) {
  const t = useT();
  if (plan.refusal) {
    return <Pill tone="error">{t("refused: {reason}", { reason: plan.refusal })}</Pill>;
  }
  if (plan.validator_failed) {
    return (
      <Pill tone="error">
        {t("validator failed")}{plan.validator_output ? `: ${plan.validator_output.slice(0, 200)}` : ""}
      </Pill>
    );
  }
  const verbatim = plan.document
    ? { label: t("Document"), text: plan.document }
    : plan.commands?.length
      ? { label: t("Commands"), text: plan.commands.join("\n") }
      : null;
  return (
    <Stack>
      <Tags>
        {action && <Tag>{action}</Tag>}
        <Tag>{planWords(plan, t)}</Tag>
        {/* The source resolved to a UUID is what goes to the host; the path
            from the order stays only for comparison. */}
        {plan.resolved_source && plan.resolved_source !== plan.requested_source && (
          <Tag>{`${plan.requested_source} → ${plan.resolved_source}`}</Tag>
        )}
        {plan.warnings?.map((warning) => <Pill key={warning} tone="warn">{warning}</Pill>)}
      </Tags>
      <PlanCost plan={plan} />
      <PlanLeftOut plan={plan} />
      <PlanChanges changes={plan.changes} />
      {verbatim && (
        <>
          <Note>{verbatim.label}</Note>
          <pre className="fl-mono" data-testid="plan-verbatim">{verbatim.text}</pre>
        </>
      )}
    </Stack>
  );
}

/** What a plan costs beyond what it does: a reboot, bytes down the wire, room on disk, a way back. */
function PlanCost({ plan }: { plan: PackagePlanFacts }) {
  const t = useT();
  const purposes: Record<string, string> = {
    download: t("download cache"), install: t("installed files"), boot: t("boot files"),
  };
  const facts: { key: string; text: string; tone?: Tone }[] = [];
  if (plan.reboot_predicted) facts.push({ key: "reboot", text: t("reboot predicted"), tone: "warn" });
  if (plan.download_bytes) facts.push({ key: "download", text: t("download {size}", { size: bytes(plan.download_bytes) }) });
  for (const fact of plan.space ?? []) {
    const known = Boolean(fact.basis) && fact.basis !== "unknown";
    const short = known && (fact.needed_bytes ?? 0) > (fact.available_bytes ?? 0);
    const purpose = purposes[fact.purpose ?? ""] ?? fact.purpose ?? "";
    facts.push({
      key: `${fact.purpose}:${fact.path}`,
      tone: short ? "warn" : undefined,
      text: known
        ? t("{path} ({purpose}): needs {needed}, {available} free", {
          path: fact.path, purpose, needed: bytes(fact.needed_bytes), available: bytes(fact.available_bytes),
        })
        : t("{path} ({purpose}): need unknown, {available} free", {
          path: fact.path, purpose, available: bytes(fact.available_bytes),
        }),
    });
  }
  // The rollback answer is a fact of the plan too: a mechanism the host can
  // undo the change with, or none with the reason.
  if (plan.rollback?.mechanism) {
    facts.push(plan.rollback.available
      ? { key: "rollback", text: t("rollback: {mechanism}", { mechanism: plan.rollback.mechanism }) }
      : {
        key: "rollback",
        tone: "warn",
        text: t("no rollback: {reason}", { reason: plan.rollback.reason ?? plan.rollback.mechanism }),
      });
  }
  if (facts.length === 0) return null;
  return (
    <Tags>
      {facts.map((fact) => <Pill key={fact.key} tone={fact.tone ?? "neutral"}>{fact.text}</Pill>)}
    </Tags>
  );
}

/**
 * What the plan leaves out. An update no advisory classifies is not a fault
 * of the host, so it reads as a note; a broken package database is.
 */
function PlanLeftOut({ plan }: { plan: PackagePlanFacts }) {
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
      <Tags>
        {blocked.map((entry) => (
          <Tag key={`${entry.kind ?? "database"}:${entry.name}`}>
            {entry.status ? `${entry.name} — ${entry.status}` : entry.name}
          </Tag>
        ))}
      </Tags>
    </Stack>
  );
}

/**
 * The changes of a plan: one row per package with the version it has now
 * and the one it gets, folded to the first few with the rest on request.
 * A plan whose changes are sentences reads as sentences.
 */
export function PlanChanges({ changes, shown = CHANGES_SHOWN }: {
  changes?: (string | PackageChange)[];
  shown?: number;
}) {
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
  const rows = all ? packages : packages.slice(0, shown);
  const security = packages.filter((change) => change.security).length;
  const removals = packages.filter((change) => changeAction(change) === "remove").length;
  const downgrades = packages.filter((change) => changeAction(change) === "downgrade").length;
  return (
    <Stack>
      <Table
        testId="plan-changes"
        rows={rows}
        keyOf={(change) => change.name}
        columns={[
          { key: "name", head: t("Package"), tight: true, cell: (change) => <code>{change.name}</code> },
          {
            key: "action",
            head: t("Change"),
            cell: (change) => {
              const action = changeAction(change);
              // The direction is what the host said; a dash is a host that
              // did not say, never an upgrade by default.
              if (!action) {
                return <span className="fl-faint" title={t("The plan does not name the direction of this change.")}>—</span>;
              }
              const heavy = action === "remove" || action === "downgrade";
              return <Pill tone={heavy ? "warn" : "neutral"}>{t(ACTION_WORDS[action] ?? action)}</Pill>;
            },
          },
          { key: "now", head: t("Now"), tight: true, cell: (change) => <code>{change.current_version || "—"}</code> },
          { key: "after", head: t("After"), tight: true, cell: (change) => <code>{change.candidate_version || "—"}</code> },
          {
            key: "note",
            head: t("Note"),
            minor: true,
            cell: (change) => {
              const delta = change.installed_delta_known ? change.installed_delta_bytes ?? 0 : undefined;
              return (
                <Tags>
                  {change.security && <Pill tone="warn">{t("security")}</Pill>}
                  {change.protected && <Pill tone="error">{t("protected")}</Pill>}
                  {change.blocked && <Pill tone="error">{t("blocked")}</Pill>}
                  {change.origin && <Tag>{change.origin}</Tag>}
                  {change.architecture && <Tag>{change.architecture}</Tag>}
                  {change.reason && change.reason !== "requested" && <Tag>{t(change.reason)}</Tag>}
                  {delta !== undefined && delta !== 0 && (
                    <Tag>{`${delta > 0 ? "+" : "−"}${bytes(Math.abs(delta))}`}</Tag>
                  )}
                </Tags>
              );
            },
          },
        ]}
      />
      <Tags>
        <Tag>{t("{n} packages", { n: packages.length })}</Tag>
        {security > 0 && <Pill tone="warn">{t("{n} security", { n: security })}</Pill>}
        {removals > 0 && <Pill tone="warn">{t("{n} removed", { n: removals })}</Pill>}
        {downgrades > 0 && <Pill tone="warn">{t("{n} downgraded", { n: downgrades })}</Pill>}
        {packages.length > shown && (
          <button type="button" className="fl-quiet fl-small" onClick={() => setAll(!all)} data-testid="all-changes">
            {all ? t("Show fewer") : t("Show all {n}", { n: packages.length })}
          </button>
        )}
      </Tags>
      {sentences.map((change, index) => <Note key={`${index}:${change}`}>{change}</Note>)}
    </Stack>
  );
}
