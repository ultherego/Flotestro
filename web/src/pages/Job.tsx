import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import { absoluteTime } from "../lib/format";
import { isHostPlan, PlanChanges, PlanFacts, PlanSummary, planWords, type HostPlan, type PackagePlanFacts } from "../components/plan";
import type { Attempt, Job } from "../lib/types";
import { ErrorBox, ErrorCode, Time, Pair, Pairs, ProgressBar, Empty, JobState } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { OPERATIONS_INTERVAL, useProgress } from "../lib/stream";
import { AttemptHead, orderAgainAddress, prettyJSON, reasonAccepted, REORDERABLE_STATES, waitedBudget } from "./Jobs";
import { useT } from "../i18n";

/**
 * One job as the API tells it in full: the list carries what a row needs,
 * the single view also the approvals, the cancel and the order's limits.
 */
type JobDetail = Job & {
  fanout_id?: string;
  approvals?: { approver: string; reason?: string; approved_at: string }[];
  approved_at?: string;
  canceled_by?: string;
  cancel_reason?: string;
  timeout_seconds?: number;
  max_output_bytes?: number;
  preconditions?: unknown;
  request_id?: string;
  updated_at?: string;
};

/** The states a job does not leave; the page stops polling on them. */
const TERMINAL = ["succeeded", "failed", "timed_out", "canceled", "cancelled", "expired", "rejected"];

/** How much of an output stands on the page before the operator asks for the rest. */
export const OUTPUT_PREVIEW = 4000;

/**
 * The name of the file an output is saved under: the job, the attempt and
 * the stream, so two files from one job tell each other apart on disk.
 */
export function outputFilename(jobID: string, attempt: number, stream: string): string {
  return `job-${jobID.slice(0, 8)}-attempt-${attempt}-${stream}.txt`;
}

/**
 * The payload as a list of fields: a dotted path and a value for every
 * leaf, so "unit.name: cron.service" reads without the braces. A payload
 * that is not an object, or that is deeper than a form would be, gives no
 * list and stays as JSON. A payload arrives as an object or as a JSON
 * text, the way prettyJSON takes it.
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
        // A list of words reads as one line; a list of objects is a
        // table of its own and the JSON is the honest form of it.
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

/** Whether a JSON value says anything: an order without preconditions carries an empty object or nothing. */
export function hasContent(value: unknown): boolean {
  const text = prettyJSON(value);
  return text !== "" && text !== "{}" && text !== "[]" && text !== "null";
}

/**
 * The job page: everything the row shows, and what the row has no room
 * for - the whole payload, the plan the host computed, the output of every
 * attempt in full, and who approved or canceled it and why.
 */
export function JobPage() {
  const t = useT();
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const job = useQuery({
    queryKey: ["jobs", "detail", id],
    queryFn: () => api.get<JobDetail>(`/api/v1/jobs/${id}`),
    // A job in flight changes under the page; one that ended does not.
    refetchInterval: (query) => (query.state.data && TERMINAL.includes(query.state.data.state) ? false : OPERATIONS_INTERVAL),
  });
  const attempts = useQuery({
    queryKey: ["attempts", id],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${id}/attempts`),
    refetchInterval: job.data && TERMINAL.includes(job.data.state) ? false : OPERATIONS_INTERVAL,
  });
  const progress = useProgress(`/api/v1/jobs/${id}/events`);

  const [approving, setApproving] = useState(false);
  const [approvalReason, setApprovalReason] = useState("");
  const [canceling, setCanceling] = useState(false);
  const [cancelReason, setCancelReason] = useState("");
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["jobs"] });
    queryClient.invalidateQueries({ queryKey: ["attempts", id] });
  };
  const approve = useMutation({
    mutationFn: (data: JobDetail) =>
      api.post(`/api/v1/jobs/${id}/approve`, { payload_hash: data.payload_hash, reason: approvalReason.trim() || undefined }),
    onSuccess: () => { setApproving(false); refresh(); },
  });
  const cancel = useMutation({
    mutationFn: () => api.post(`/api/v1/jobs/${id}/cancel`, { reason: cancelReason.trim() }),
    onSuccess: () => { setCanceling(false); refresh(); },
  });

  if (job.error) return <ErrorBox error={job.error} />;
  if (!job.data) return <Empty>{t("Loading…")}</Empty>;
  const data = job.data;
  const host = data.hostname || data.host_id.slice(0, 8);
  const awaiting = data.state === "awaiting_approval";
  // The plan the host computed, from the last attempt that carries one:
  // a planning operation ends with it, and an apply that replans first
  // carries it too.
  // A package plan is the detail itself: its packages and facts sit at the
  // top level, next to the kind, not under a "plan" of their own.
  const planned = [...(attempts.data?.items ?? [])].reverse()
    .find((item) => isHostPlan(item.detail?.kind as string) || item.detail?.kind === "package_plan");
  const packagePlan = planned?.detail?.kind === "package_plan";
  const plan = (packagePlan ? planned?.detail : planned?.detail?.plan) as (HostPlan & PackagePlanFacts) | undefined;
  const planHash = (planned?.detail?.plan_hash as string | undefined) || plan?.plan_hash;
  const report = progress.get(id);
  const fields = payloadPairs(data.payload);

  return (
    <>
      <PageHeader
        breadcrumb={[{ label: t("Jobs"), to: "/jobs" }]}
        title={data.action_type}
        description={
          <>
            <JobState state={data.state} /> · <Link to={`/hosts/${data.host_id}/overview`}>{host}</Link> ·{" "}
            {t("requested by {who}", { who: data.created_by })}
          </>
        }
        actions={
          <>
            {awaiting && (
              <>
                <button onClick={() => { setCanceling(false); setApproving(true); }}>{t("Approve")}</button>
                <button className="secondary" onClick={() => { setApproving(false); setCanceling(true); }}>{t("Cancel")}</button>
              </>
            )}
            {REORDERABLE_STATES.includes(data.state) && (
              <Link className="button secondary" to={orderAgainAddress(data)} title={t("Opens the Bulk workspace with the same operation, payload and host written in.")}>
                {t("Order again")}
              </Link>
            )}
          </>
        }
      />

      {/* The consent is given to the payload on this page: the hash the
          approval carries is the hash of what stands here, so a swap
          between reading and clicking is refused by the server. */}
      {approving && awaiting && (
        <Card
          title={t("Approve the job?")}
          description={t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
            operation: data.action_type, host, hash: data.payload_hash.slice(0, 12),
          })}
          footer={
            <Actions>
              <button onClick={() => approve.mutate(data)} disabled={approve.isPending}>{t("Approve this payload")}</button>
              <button className="secondary" onClick={() => setApproving(false)}>{t("Back")}</button>
              {approve.error && <span className="page-error">{approve.error instanceof Error ? approve.error.message : String(approve.error)}</span>}
            </Actions>
          }
        >
          <pre>{prettyJSON(data.payload)}</pre>
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} hint={t("Optional for an approval; the second approver of a destructive operation reads it.")} wide>
              <input value={approvalReason} onChange={(e) => setApprovalReason(e.target.value)} />
            </Field>
          </FieldGrid>
        </Card>
      )}

      {canceling && awaiting && (
        <Card
          title={t("Cancel the job?")}
          description={t("The job is withdrawn before the host has touched anything; the reason goes to the audit trail.")}
          footer={
            <Actions>
              <button
                className="danger"
                disabled={!reasonAccepted(cancelReason) || cancel.isPending}
                title={reasonAccepted(cancelReason) ? undefined : t("A cancel needs a reason of at least 8 characters.")}
                onClick={() => cancel.mutate()}
              >
                {t("Cancel this job")}
              </button>
              <button className="secondary" onClick={() => setCanceling(false)}>{t("Back")}</button>
              {cancel.error && <span className="page-error">{cancel.error instanceof Error ? cancel.error.message : String(cancel.error)}</span>}
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Reason (kept in the audit trail)")} hint={t("Required, at least 8 characters.")} wide>
              <input autoFocus value={cancelReason} onChange={(e) => setCancelReason(e.target.value)} />
            </Field>
          </FieldGrid>
        </Card>
      )}

      <div className="widgets">
        <Card className="span-6" title={t("Job")}>
          <Pairs>
            <Pair label={t("Identifier")}><span className="mono">{data.id}</span></Pair>
            <Pair label={t("Host")}><Link to={`/hosts/${data.host_id}/overview`}>{host}</Link></Pair>
            <Pair label={t("Campaign")}>
              {data.campaign_id ? <Link to={`/campaigns/${data.campaign_id}`} className="mono">{data.campaign_id}</Link> : "—"}
            </Pair>
            <Pair label={t("Read fan-out")}>
              {data.fanout_id ? <Link to={`/reads/${data.fanout_id}`} className="mono">{data.fanout_id}</Link> : "—"}
            </Pair>
            <Pair label={t("State")}>
              <JobState state={data.state} />
              {data.state === "queued" && waitedBudget(data.wait_reason) && (
                <> <span className="badge warn">{t("waiting for budget {key}", { key: waitedBudget(data.wait_reason) })}</span></>
              )}
              {data.wait_reason && !waitedBudget(data.wait_reason) && <span className="source"> · {data.wait_reason}</span>}
              {report && (
                <ProgressBar percent={report.percent} step={report.step} total={report.total} caption={report.message} />
              )}
            </Pair>
            <Pair label={t("Requested by")}>{data.created_by}</Pair>
            <Pair label={t("Created")}><Time value={data.created_at} /> <span className="source">{absoluteTime(data.created_at)}</span></Pair>
            <Pair label={t("Expires")}><Time value={data.expires_at} /></Pair>
            <Pair label={t("Finished")}>{data.finished_at ? <><Time value={data.finished_at} /> <span className="source">{absoluteTime(data.finished_at)}</span></> : "—"}</Pair>
            <Pair label={t("Timeout")}>{data.timeout_seconds ? t("{n} s", { n: data.timeout_seconds }) : "—"}</Pair>
            <Pair label={t("Budget class")}>{data.budget_class || "—"}</Pair>
          </Pairs>
        </Card>

        <Card className="span-6" title={t("Decision and result")}>
          <Pairs>
            <Pair label={t("Approvals")}>
              {data.required_approvals > 1
                ? t("{collected} of {required} approvals", { collected: data.collected_approvals, required: data.required_approvals })
                : data.requires_approval ? t("one approval") : t("none needed")}
            </Pair>
            <Pair label={t("Approved by")}>
              {data.approved_by ? <>{data.approved_by}{data.approved_at && <> · <Time value={data.approved_at} /></>}</> : "—"}
            </Pair>
            <Pair label={t("Canceled by")}>{data.canceled_by || "—"}</Pair>
            <Pair label={t("Cancel reason")}>{data.cancel_reason || "—"}</Pair>
            <Pair label={t("Result")}>{data.result_status || "—"}</Pair>
            <Pair label={t("Error code")}>{data.result_error_code ? <ErrorCode code={data.result_error_code} /> : "—"}</Pair>
            <Pair label={t("Message")}>{data.result_message || "—"}</Pair>
            <Pair label={t("Payload hash")}><span className="mono" style={{ wordBreak: "break-all" }}>{data.payload_hash}</span></Pair>
          </Pairs>
        </Card>

        <Card
          className="span-12"
          title={t("Approval history")}
          description={t("Every consent recorded for this job, in the order it was given.")}
          flush
        >
          {!data.approvals?.length ? (
            <Empty>{data.requires_approval ? t("No approval yet.") : t("The operation needs no approval.")}</Empty>
          ) : (
            <table>
              <thead><tr><th>{t("Approver")}</th><th>{t("Reason")}</th><th>{t("When")}</th></tr></thead>
              <tbody>
                {data.approvals.map((approval) => (
                  <tr key={`${approval.approver}:${approval.approved_at}`}>
                    <td>{approval.approver}</td>
                    <td>{approval.reason || "—"}</td>
                    <td><Time value={approval.approved_at} /> <span className="source">{absoluteTime(approval.approved_at)}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          className="span-6"
          title={t("Payload")}
          description={t("The order as the host receives it; the hash above is computed over exactly this.")}
          actions={<DownloadButton text={prettyJSON(data.payload)} filename={`job-${data.id.slice(0, 8)}-payload.json`} />}
        >
          {/* The fields first, for reading; the JSON stays under them,
              because the hash is computed over that text and a reviewer
              approves exactly it. */}
          {fields && (
            <>
              <Pairs>
                {fields.map((pair) => (
                  <Pair key={pair.path} label={pair.path}><span className="mono">{pair.value}</span></Pair>
                ))}
              </Pairs>
              <div className="source">{t("As JSON, the text the hash covers")}</div>
            </>
          )}
          <pre>{prettyJSON(data.payload) || "—"}</pre>
          {hasContent(data.preconditions) && (
            <>
              <div className="source">{t("Preconditions")}</div>
              <pre>{prettyJSON(data.preconditions)}</pre>
            </>
          )}
        </Card>

        <Card
          className="span-6"
          title={t("Plan")}
          description={plan ? t("What the host computed it would change; the hash names this plan.") : t("The host has computed no plan for this job.")}
          actions={plan ? <DownloadButton text={prettyJSON(planned?.detail)} filename={`job-${data.id.slice(0, 8)}-plan.json`} /> : undefined}
        >
          {plan ? (
            <>
              <Pairs>
                <Pair label={t("Plan hash")}><span className="mono">{planHash || "—"}</span></Pair>
                {/* A package plan reads as a table of packages below; the
                    summary line of a host plan names its action and change. */}
                <Pair label={t("Summary")}>
                  {packagePlan ? <><span>{planWords(plan, t)}</span><PlanFacts plan={plan} /></> : <PlanSummary plan={plan} />}
                </Pair>
              </Pairs>
              {packagePlan && <PlanChanges changes={plan.changes} />}
              <pre>{prettyJSON(planned?.detail)}</pre>
            </>
          ) : attempts.isLoading ? (
            <Empty>{t("Loading…")}</Empty>
          ) : (
            <Empty>{t("No plan.")}</Empty>
          )}
        </Card>

        <Card
          className="span-12"
          title={t("Attempts")}
          description={t("Every attempt at carrying out the job, with its output in full.")}
        >
          {attempts.error ? (
            <ErrorBox error={attempts.error} />
          ) : !attempts.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : attempts.data.items.length === 0 ? (
            <Empty>{t("No execution attempts.")}</Empty>
          ) : (
            attempts.data.items.map((attempt) => (
              <div key={attempt.id} className="attempt">
                <AttemptHead attempt={attempt} />
                <div className="source">
                  {attempt.dispatched_at && <>{t("dispatched")} <Time value={attempt.dispatched_at} /></>}
                  {attempt.accepted_at && <> · {t("accepted")} <Time value={attempt.accepted_at} /></>}
                  {attempt.started_at && <> · {t("started")} <Time value={attempt.started_at} /></>}
                  {attempt.finished_at && <> · {t("finished")} <Time value={attempt.finished_at} /></>}
                  {(attempt as Attempt & { output_truncated?: boolean }).output_truncated && (
                    <> · <span className="badge warn">{t("output cut by the host at its limit")}</span></>
                  )}
                </div>
                {attempt.stdout && (
                  <Output label="stdout" text={attempt.stdout} filename={outputFilename(data.id, attempt.attempt_number, "stdout")} />
                )}
                {attempt.stderr && (
                  <Output label="stderr" text={attempt.stderr} filename={outputFilename(data.id, attempt.attempt_number, "stderr")} />
                )}
              </div>
            ))
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * One stream of an attempt. A long output opens at its first pages and
 * unfolds on request; the whole of it can be saved as a file, because a
 * transaction log is read in an editor, not in a table cell.
 */
function Output({ label, text, filename }: { label: string; text: string; filename: string }) {
  const t = useT();
  const [all, setAll] = useState(false);
  const long = text.length > OUTPUT_PREVIEW;
  return (
    <div>
      <div className="attempt-head">
        <span className="source">{label} · {t("{n} characters", { n: text.length })}</span>
        {long && (
          <button type="button" className="secondary" onClick={() => setAll(!all)}>
            {all ? t("Show the first {n} characters", { n: OUTPUT_PREVIEW }) : t("Show all")}
          </button>
        )}
        <DownloadButton text={text} filename={filename} />
      </div>
      <pre>{long && !all ? text.slice(0, OUTPUT_PREVIEW) + "\n…" : text}</pre>
    </div>
  );
}

/**
 * Saves a text as a file in the operator's own browser: the bytes are
 * already on the page, so nothing more is fetched and nothing is sent.
 */
function DownloadButton({ text, filename }: { text: string; filename: string }) {
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
    // The address is released after the click has started the save; a
    // release in the same tick would cut the download short in some browsers.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <button type="button" className="secondary" onClick={save} disabled={!text}>
      {t("Download")}
    </button>
  );
}
