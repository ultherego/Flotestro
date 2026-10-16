import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, type Collection, type Page } from "../../../lib/api";
import { useDebounced } from "../../../lib/debounce";
import { absoluteTime, relativeTime, toInstant } from "../../../lib/format";
import { needsReason } from "../../../lib/actions";
import { OPERATIONS_INTERVAL, useProgress } from "../../../lib/stream";
import { stateName } from "../../../components/ui";
import type { Attempt, Host, Job, OperationContract } from "../../../lib/types";
import { contractWords, useOperations } from "../../../pages/Bulk";
import { useT } from "../../../i18n";
import { hoursAgo, jobTone, prettyJSON, reasonAccepted } from "../Jobs";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Bars, Bones, Button, Card, Empty, Field, Fields, Meter, Modal, Note, Pill, Presets, Problem,
  Readout, Stack, Table, Tags, Toolbar, TwoLine, type Segment,
} from "../../kit";

/**
 * Every operation ever asked of this machine, newest first.
 *
 * The list is the fleet list narrowed to one host: the same filters, the
 * same pages, the same decisions. Two of those decisions cannot be taken
 * back, so they stop the screen and ask - an approval is bound to the hash
 * of the payload somebody has just read, and a cancel carries a reason the
 * trail keeps. A fixed sentence in place of that reason told nobody why,
 * which is how this came to be a dialog and not a button.
 */

/** The states a job passes through before the host has touched anything. */
const BEFORE_START = ["planned", "awaiting_approval", "queued", "leased", "dispatched"];
/** The states in which the host is working on the job. */
const STARTED = ["running"];

/** The states the filter offers, in the order a job moves through them. */
const JOB_STATES = [
  "awaiting_approval", "queued", "dispatched", "running",
  "succeeded", "failed", "timed_out", "canceled", "expired",
];

/** How many jobs one page of the list carries. */
const JOBS_PAGE = 50;

/**
 * The campaign a job belongs to, as the chip names it: the campaign's name
 * where the job's author carries it ("campaign:<name>"), else the first
 * letters of its identifier.
 */
export function campaignLabel(job: Pick<Job, "campaign_id" | "created_by">): string {
  const author = job.created_by;
  if (author.startsWith("campaign:") && author.length > "campaign:".length) return author.slice("campaign:".length);
  return (job.campaign_id ?? "").slice(0, 8);
}

/**
 * Whether a cancel request would stop this job, from the contract of its
 * operation: before the start every operation is cancellable, once the host
 * reported a start only one that stops cleanly.
 */
export function cancellable(job: Job, contract: OperationContract | undefined): boolean {
  if (BEFORE_START.includes(job.state)) return true;
  if (!STARTED.includes(job.state)) return false;
  return contract?.cancel_mode === "safe";
}

/** What a decision is being taken on, and which decision it is. */
type Asking = { verdict: "approve" | "cancel"; job: Job };

export function Jobs({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const progress = useProgress("/api/v1/events");
  const [state, setState] = useState("");
  const [action, setAction] = useState("");
  const [since, setSince] = useState("");
  // The typed prefix reaches the server after a pause, not per keystroke.
  const settledAction = useDebounced(action.trim());
  const [opened, setOpened] = useState("");
  const [asking, setAsking] = useState<Asking | null>(null);
  const [reason, setReason] = useState("");

  const params = new URLSearchParams({ host_id: host.id, limit: String(JOBS_PAGE) });
  if (state) params.set("state", state);
  if (settledAction) params.set("action_prefix", settledAction);
  if (toInstant(since)) params.set("since", toInstant(since));

  const list = useInfiniteQuery({
    queryKey: ["jobs", host.id, params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.get<Page<Job>>(`/api/v1/jobs?${page}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    refetchInterval: OPERATIONS_INTERVAL,
  });

  // The cancel button is drawn from the contract of the operation and the
  // operator's permission: a button that leads only to a refusal is a fault.
  const catalogue = useOperations();
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = whoami.data?.permissions ?? [];
  const mayCancel = permissions.includes("job.cancel");
  const mayApprove = permissions.includes("job.approve");
  const contractOf = (type: string): OperationContract | undefined =>
    catalogue.data?.items.find((one) => one.action === type);

  const decide = useMutation({
    mutationFn: async ({ verdict, job, reason: why }: Asking & { reason: string }) => {
      if (verdict === "approve") {
        await api.post(`/api/v1/jobs/${job.id}/approve`, {
          payload_hash: job.payload_hash,
          reason: why.trim() || undefined,
        });
      } else {
        await api.post(`/api/v1/jobs/${job.id}/cancel`, { reason: why.trim() });
      }
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
    onSuccess: () => { setAsking(null); setReason(""); },
  });

  const ask = (verdict: "approve" | "cancel", job: Job) => {
    decide.reset();
    setReason("");
    setAsking({ verdict, job });
  };

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  // The listed jobs by where they stand; the list is unknown until it
  // loads, and the band shows dashes rather than a quiet machine.
  const jobs = loadedItems(list.data);
  const loaded = list.data !== undefined;
  const succeeded = ["succeeded", "completed", "no_change"];
  const failed = ["failed", "timed_out", "expired", "partially_applied"];
  const waiting = ["awaiting_approval", "queued", "planned", "planning", "paused", "awaiting_budget"];
  const running = ["dispatched", "running"];
  const count = (states: string[]) =>
    (loaded ? jobs.filter((one) => states.includes(one.state)).length : undefined);
  const band: Segment[] = [
    { label: t("succeeded"), value: count(succeeded), tone: "ok" },
    { label: t("failed"), value: count(failed), tone: "error" },
    { label: t("running"), value: count(running), tone: "info" },
    { label: t("waiting"), value: count(waiting), tone: "warn" },
    {
      label: t("other"),
      value: loaded
        ? jobs.filter((one) => ![...succeeded, ...failed, ...running, ...waiting].includes(one.state)).length
        : undefined,
      tone: "unknown",
    },
  ];

  const operations = Object.entries(jobs.reduce<Record<string, number>>((all, job) => {
    const module = job.action_type.split(".")[0];
    all[module] = (all[module] ?? 0) + 1;
    return all;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);

  // Who ordered the listed jobs: a person by name, every campaign as one
  // requester.
  const requesters = Object.entries(jobs.reduce<Record<string, number>>((all, job) => {
    const who = job.created_by.startsWith("campaign:") ? t("campaigns") : job.created_by;
    all[who] = (all[who] ?? 0) + 1;
    return all;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5);

  const filtered = state !== "" || settledAction !== "" || toInstant(since) !== "";
  const listed = filtered
    ? t("The {n} listed jobs on this host that match the filter, by where they stand.", { n: jobs.length })
    : t("The last {n} jobs on this host, by where they stand.", { n: loaded ? jobs.length : JOBS_PAGE });

  const wantsReason = asking !== null && (asking.verdict === "cancel" || needsReason(asking.job.action_type));
  const ready = !wantsReason || reasonAccepted(reason);

  return (
    <>
      <Board screen={HOST_JOBS_SCREEN} catalogue={HOST_JOBS} drawn={{
        outcomes: (
          <Card title={t("Outcomes")} note={listed}>
            {/* A state nobody has counted yet is an em dash under the band,
                never a nought: an unread list and a quiet host are not the
                same answer. */}
            <Band segments={band} testId="job-states" />
          </Card>
        ),
        modules: (
          <Card title={t("By module")} note={t("Which modules the operations belong to.")}>
            {!loaded
              ? <Bones rows={4} />
              : operations.length === 0
                ? <Empty icon="jobs">{t("No jobs for this host.")}</Empty>
                : <Bars items={operations.map(([module, n]) => ({
                    label: <code title={module}>{module}</code>, value: n,
                  }))} />}
          </Card>
        ),
        requesters: (
          <Card title={t("Requested by")} note={t("Who asked for the listed operations.")}>
            {!loaded
              ? <Bones rows={3} />
              : requesters.length === 0
                ? <Empty icon="jobs">{t("No jobs for this host.")}</Empty>
                : <Bars items={requesters.map(([who, n]) => ({ label: who, value: n }))} />}
          </Card>
        ),
        jobs: (
          <Card
            title={t("Jobs")}
            flush
            note={t("Every operation requested on this host, newest first.")}
            foot={
              <>
                <span className="fl-note">{t("{n} listed", { n: jobs.length })}</span>
                {list.hasNextPage && (
                  <Button
                    kind="quiet"
                    onClick={() => void list.fetchNextPage()}
                    disabled={list.isFetchingNextPage}
                    testId="more"
                  >
                    {list.isFetchingNextPage ? t("loading…") : t("Load more")}
                  </Button>
                )}
              </>
            }
          >
            <Toolbar>
              <select
                value={state}
                onChange={(event) => setState(event.target.value)}
                aria-label={t("state: any")}
                data-testid="state"
              >
                <option value="">{t("state: any")}</option>
                {JOB_STATES.map((one) => <option key={one} value={one}>{t(stateName(one))}</option>)}
              </select>
              <input
                placeholder={t("operation prefix, e.g. packages.")}
                aria-label={t("operation prefix, e.g. packages.")}
                value={action}
                onChange={(event) => setAction(event.target.value)}
                data-testid="action"
              />
              <input
                type="datetime-local"
                value={since}
                onChange={(event) => setSince(event.target.value)}
                aria-label={t("Since")}
                data-testid="since"
              />
              {/* A preset sets the lower bound to the moment of the click:
                  "the last day" is what an operator asks after an incident. */}
              <Presets
                label={t("Time range")}
                options={([[1, t("last hour")], [24, t("last 24 h")], [24 * 7, t("last 7 days")]] as const)
                  .map(([hours, label]) => ({ label, onPick: () => setSince(hoursAgo(hours)) }))}
              />
              {filtered && (
                <Button
                  kind="plain"
                  onClick={() => { setState(""); setAction(""); setSince(""); }}
                  testId="clear"
                >
                  {t("Clear filters")}
                </Button>
              )}
            </Toolbar>

            <Table
              rows={jobs}
              keyOf={(one) => one.id}
              rowTestId={(one) => `job-${one.id}`}
              /* The attempts open under the job they belong to, as the
                 panel being replaced opened them, with the two ways on
                 from there under them. */
              opened={(one) => one.id === opened}
              detail={(one) => (
                <Stack>
                  <Attempts jobId={one.id} />
                  <Note>
                    <Link to={`/next/jobs/${one.id}`}>{t("Open the job: full payload, plan and output")}</Link>
                    {" · "}
                    <Link to={`/next/hosts/${host.id}/logs?job=${one.id}`}>{t("Read the journal of this job")}</Link>
                  </Note>
                </Stack>
              )}
              testId="jobs"
              loading={list.isLoading}
              empty={filtered ? t("No job matches the filter.") : t("No jobs for this host.")}
              columns={[
                { key: "operation", head: t("Operation"), tight: true, cell: (one) => (
                  <TwoLine sub={one.campaign_id
                    ? (
                      <Link to={`/next/campaigns/${one.campaign_id}`} title={`${t("Part of a campaign")} · ${one.campaign_id}`}>
                        {t("campaign {id}", { id: campaignLabel(one) })}
                      </Link>
                    )
                    : undefined}>
                    <Link to={`/next/jobs/${one.id}`} title={one.id}>
                      <code>{one.action_type}</code>
                    </Link>
                  </TwoLine>
                ) },
                { key: "state", head: t("State"), cell: (one) => {
                  const moving = progress.get(one.id);
                  return (
                    <Tags>
                      <Pill tone={jobTone(one.state)}>{t(stateName(one.state))}</Pill>
                      {/* The reading accompanies the state and never
                          replaces it: the reader is to see both that it
                          runs and how far it has got. */}
                      {moving && (
                        <Meter
                          share={(moving.percent ?? 0) / 100}
                          tone="info"
                          text={moving.percent !== undefined
                            ? `${Math.round(moving.percent)}%`
                            : t("{step} of {total}", { step: moving.step ?? 0, total: moving.total ?? 0 })}
                        />
                      )}
                    </Tags>
                  );
                } },
                { key: "by", head: t("Requested by"), minor: true, tight: true, cell: (one) => (
                  // A campaign's job is requested by the campaign; the chip
                  // beside the operation already names it.
                  one.created_by.startsWith("campaign:")
                    ? <span className="fl-faint">{t("the campaign")}</span>
                    : <span title={one.created_by}>{one.created_by}</span>
                ) },
                { key: "approved", head: t("Approved by"), minor: true, tight: true, cell: (one) => (
                  one.required_approvals > 1
                    ? (
                      <span title={one.approved_by}>
                        {t("{collected} of {required} approvals", {
                          collected: one.collected_approvals, required: one.required_approvals,
                        })}
                      </span>
                    )
                    : one.approved_by
                      ? <span title={one.approved_by}>{one.approved_by}</span>
                      : <span className="fl-faint">—</span>
                ) },
                // The result is the typed answer of the host: an error code,
                // or a status other than the one the state pill already says.
                { key: "result", head: t("Result"), tight: true, cell: (one) => (
                  one.result_error_code
                    ? <Pill tone="error" title={one.result_message}>{one.result_error_code}</Pill>
                    : one.result_status && one.result_status !== one.state
                      ? <span title={one.result_message}>{t(stateName(one.result_status))}</span>
                      : <span className="fl-faint">—</span>
                ) },
                { key: "created", head: t("Created"), minor: true, cell: (one) => (
                  <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
                ) },
                { key: "do", actions: true, cell: (one) => {
                  const contract = contractOf(one.action_type);
                  const [, cancelMeaning] = contractWords(t, "cancel", contract?.cancel_mode);
                  return (
                    <>
                      <Button
                        kind="quiet"
                        onClick={() => setOpened(opened === one.id ? "" : one.id)}
                        testId={`open-${one.id}`}
                      >
                        {opened === one.id ? t("Close") : t("Attempts")}
                      </Button>
                      {mayApprove && one.state === "awaiting_approval" && (
                        <Button onClick={() => ask("approve", one)} testId={`approve-${one.id}`}>
                          {t("Approve")}
                        </Button>
                      )}
                      {mayCancel && cancellable(one, contract) ? (
                        <Button
                          kind="danger"
                          title={STARTED.includes(one.state)
                            ? cancelMeaning
                            : t("The host has not started this yet; a cancel stops it before it does.")}
                          onClick={() => ask("cancel", one)}
                          testId={`cancel-${one.id}`}
                        >
                          {t("Cancel")}
                        </Button>
                      ) : STARTED.includes(one.state) && contract?.cancel_mode ? (
                        <span className="fl-faint" title={cancelMeaning}>{t("runs to its end")}</span>
                      ) : null}
                    </>
                  );
                } },
              ]}
            />
          </Card>
        ),
      }} />

      {asking && (
        <Modal
          title={asking.verdict === "approve" ? t("Approve this job") : t("Cancel this job")}
          onClose={() => { setAsking(null); setReason(""); }}
          actions={
            <>
              <Button kind="quiet" onClick={() => { setAsking(null); setReason(""); }}>{t("Back")}</Button>
              <Button
                kind={asking.verdict === "cancel" ? "danger" : "do"}
                disabled={!ready || decide.isPending}
                onClick={() => decide.mutate({ ...asking, reason })}
                title={ready ? undefined : t("The decision is recorded with a reason of at least 8 characters.")}
                testId="confirm"
              >
                {asking.verdict === "approve" ? t("Approve this payload") : t("Cancel this job")}
              </Button>
            </>
          }
        >
          {asking.verdict === "approve" ? (
            <>
              <Note>
                {t("You approve exactly this payload for {operation} on {host}; the consent is bound to hash {hash}.", {
                  operation: asking.job.action_type,
                  host: host.hostname,
                  hash: asking.job.payload_hash.slice(0, 12),
                })}
              </Note>
              <Readout label={t("The payload")} value={prettyJSON(asking.job.payload)} lines={16} testId="payload" />
            </>
          ) : (
            <Note>{t("The cancel is recorded against this job with the reason you give.")}</Note>
          )}
          <Fields>
            <Field
              label={t("Reason for the trail")}
              wide
              hint={wantsReason
                ? t("At least 8 characters; this operation is one the control plane records a reason for.")
                : t("Optional for this operation.")}
            >
              <input
                autoFocus
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                data-testid="reason"
              />
            </Field>
          </Fields>
          {decide.error && <Problem>{String(decide.error)}</Problem>}
        </Modal>
      )}
    </>
  );
}

/**
 * The attempts of one job: what the host tried, and what came back on its
 * standard output and error.
 */
function Attempts({ jobId }: { jobId: string }) {
  const t = useT();
  const { data, error, isLoading } = useQuery({
    queryKey: ["attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
  });
  if (error) return <Problem>{String(error)}</Problem>;
  if (isLoading) return <Bones rows={4} />;
  if (!data?.items.length) return <Empty icon="jobs">{t("No execution attempts.")}</Empty>;
  return (
    <Stack>
      {data.items.map((attempt) => (
        <Stack key={attempt.id}>
          <Tags>
            <Pill dot={false}>{t("attempt {n}", { n: attempt.attempt_number })}</Pill>
            {attempt.status
              ? <Pill tone={jobTone(attempt.status)}>{t(stateName(attempt.status))}</Pill>
              : <Pill tone="unknown">{t("no answer yet")}</Pill>}
            {attempt.error_code && <Pill tone="error" title={attempt.message}>{attempt.error_code}</Pill>}
            {attempt.exit_code !== undefined && (
              <Pill tone={attempt.exit_code === 0 ? "ok" : "error"} dot={false}>
                {t("exit {code}", { code: attempt.exit_code })}
              </Pill>
            )}
            {attempt.replayed && <Pill tone="unknown">{t("replayed")}</Pill>}
            {attempt.started_at && (
              <span className="fl-note" title={absoluteTime(attempt.started_at)}>
                {relativeTime(attempt.started_at)}
              </span>
            )}
          </Tags>
          {attempt.verification && (
            <Note>
              {t("Verified by {verifier}: expected {expected}, found {observed}.", {
                verifier: attempt.verification.verifier ?? "—",
                expected: attempt.verification.expected ?? "—",
                observed: attempt.verification.observed ?? "—",
              })}
              {attempt.verification.reason ? ` ${attempt.verification.reason}` : ""}
            </Note>
          )}
          {attempt.stdout && (
            <Readout label={t("Output")} value={attempt.stdout.slice(0, 4000)} lines={16} testId={`stdout-${attempt.id}`} />
          )}
          {attempt.stderr && (
            <Readout label={t("Errors")} value={attempt.stderr.slice(0, 2000)} lines={10} testId={`stderr-${attempt.id}`} />
          )}
        </Stack>
      ))}
    </Stack>
  );
}

/** The name this screen's arrangement is stored under. */
export const HOST_JOBS_SCREEN = "next_host_jobs";

/** The containers this screen can draw, and the shape each ships with. */
export const HOST_JOBS: BoardEntry[] = [
  { key: "outcomes", title: "Outcomes", width: 5, height: 2 },
  { key: "modules", title: "By module", width: 4, height: 2 },
  { key: "requesters", title: "Requested by", width: 3, height: 2 },
  { key: "jobs", title: "Jobs", width: 12, height: 6 },
];
