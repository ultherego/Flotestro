import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess, type Allowance } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import type { Host, Job } from "../../../lib/types";
import { useToast } from "../../../components/Toast";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Band, Banner, Bars, Bones, Button, Card, Check, Empty, Field, Fields, HeadActions, Modal, Note,
  Pill, Problem, Table, Tags, TwoLine, type Segment, type Tone,
} from "../../kit";

/**
 * What this machine copies, where to, and whether anybody has ever read a
 * copy back.
 *
 * The data never passes through the panel: the host talks to the
 * repository directly and what stands here is metadata. Two facts make a
 * copy a safeguard rather than a hope - that it is recent, and that it
 * has been read back - and they are counted side by side.
 *
 * A definition the panel has not heard about is not a definition with
 * nothing in it. Until the report lands the counts are unknown, and a
 * backup that was never verified is not a failed verification.
 */

/* ------------------------------------------------------------- the data */

export type Definition = {
  id: string;
  name: string;
  tool: string;
  repository?: string;
  paths?: string[];
  excludes?: string[];
  tags?: string[];
  keep_last?: number;
  keep_daily?: number;
  keep_weekly?: number;
  keep_monthly?: number;
  prune?: boolean;
  runbook?: string;
  initialize?: boolean;
  password_secret?: string;
  env_secrets?: Record<string, string>;
  note?: string;
  updated_by: string;
  updated_at: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  last_run_at?: string;
  last_verify_at?: string;
  unverified: boolean;
  snapshots?: number;
  repository_size?: number;
};

type Tool = { name: string; available: boolean; version?: string };

type Report = {
  host_id: string;
  definitions: Definition[];
  status: string;
  tools?: { tools?: Tool[]; runbooks?: string[]; runbooks_known?: boolean };
};

type Snapshot = { id: string; time: string; paths?: string[]; tags?: string[]; size_bytes?: number };

type RepositoryState = {
  tool?: string;
  tool_version?: string;
  snapshots?: Snapshot[];
  last_success_at?: string;
  total_size_bytes?: number;
  unavailable_reason?: string;
};

type AttemptDetail = {
  kind?: string;
  message?: string;
  state?: RepositoryState;
  plan?: { plan_hash?: string };
  outcome?: { snapshot_id?: string; bytes_added?: number; message?: string };
};

type Attempt = { status?: string; message?: string; detail?: AttemptDetail };

type Run = {
  definition: string;
  kind: string;
  outcome: string;
  snapshot_id?: string;
  bytes_added?: number;
  files_new?: number;
  duration_seconds?: number;
  snapshots?: number;
  repository_size?: number;
  message?: string;
  started_by?: string;
  recorded_at: string;
};

/** What the operator has asked for and has not yet confirmed. */
type Intent = {
  action: string;
  label: string;
  description: string;
  payload: Record<string, unknown>;
  danger?: boolean;
};

/** The shortest reason the API takes for a change of this risk. */
export const MIN_REASON_LENGTH = 8;

/** The changes this module offers; when every one is refused, it says so once. */
export const BACKUP_CHANGES = ["backup.run", "backup.verify", "backup.restore"];

/** Where a restore unpacks unless somebody says otherwise. */
export const RESTORE_TARGET = "/srv/flotestro-restore";

/* ---------------------------------------------------------- the reading */

/**
 * A size in the units a person reads. A size nobody reported comes back
 * undefined, so the kit draws the em dash: a repository nobody has
 * measured is not a repository of nought bytes.
 */
export function size(value?: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** How the last copy stands. Unknown is its own answer, never "ok". */
export function backupTone(status: string): Tone {
  if (status === "ok") return "ok";
  if (status === "warning") return "warn";
  if (status === "unknown") return "unknown";
  return "error";
}

/** How many of a list answer a question; undefined when there is no list. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/**
 * The definition as the API takes it back. The panel writes the whole
 * record, so a field the form never carried would be cleared by a save:
 * the request is built from the definition as it stands.
 */
export function definitionRequest(
  item: Definition, planHash: string, extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: item.name,
    plan_hash: planHash,
    tool: item.tool,
    repository: item.repository ?? "",
    paths: item.paths ?? [],
    excludes: item.excludes ?? [],
    tags: item.tags ?? [],
    keep_last: item.keep_last ?? 0,
    keep_daily: item.keep_daily ?? 0,
    keep_weekly: item.keep_weekly ?? 0,
    keep_monthly: item.keep_monthly ?? 0,
    prune: item.prune ?? false,
    runbook: item.runbook ?? "",
    initialize: item.initialize ?? false,
    ...(item.password_secret ? { password_secret: { name: item.password_secret } } : {}),
    ...(item.env_secrets && Object.keys(item.env_secrets).length
      ? {
          env_secrets: Object.fromEntries(
            Object.entries(item.env_secrets).map(([variable, secret]) => [variable, { name: secret }]),
          ),
        }
      : {}),
    ...extra,
  };
}

/* ----------------------------------------------------------- the pieces */

/**
 * A control that exists only where the order it places would be taken.
 *
 * Refused and asked about, it stands disabled with the server's own reason
 * on it; refused and not asked about, it is not drawn at all. While the
 * verdict is on its way there is no button at all.
 */
function Guarded({ verdict, explain = false, children }: {
  verdict: Allowance;
  explain?: boolean;
  children: (disabled: boolean, reason: string | undefined) => ReactNode;
}) {
  if (verdict.allowed) return <>{children(false, verdict.note || undefined)}</>;
  if (!explain || verdict.pending) return null;
  return <>{children(true, verdict.reason || undefined)}</>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ hostID, actions }: { hostID: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(hostID, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

/**
 * The confirmation of an order that changes the host.
 *
 * It names the machine again, takes the reason the trail keeps, and asks
 * for the hostname to be typed. A restore takes one field more: where the
 * copy is unpacked, because that directory is what the operator is really
 * agreeing to.
 */
function Confirm({ host, label, description, danger = false, busy, target, onConfirm, onCancel }: {
  host: Host;
  label: string;
  description: string;
  danger?: boolean;
  busy: boolean;
  /** The directory a restore unpacks into, asked for here or not at all. */
  target?: { label: string; hint: string; initial: string };
  onConfirm: (reason: string, target: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [where, setWhere] = useState(target?.initial ?? "");
  const ready = reason.trim().length >= MIN_REASON_LENGTH
    && typed === host.hostname
    && (!target || where.trim() !== "");
  return (
    <Modal
      title={label}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind={danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason, where.trim())}
            testId="confirm-order"
          >
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{description}</Note>
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {` · ${host.management_address || t("address unknown")} · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        {target && (
          <Field label={target.label} hint={target.hint} wide>
            <input value={where} onChange={(event) => setWhere(event.target.value)} data-testid="restore-target" />
          </Field>
        )}
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-host" />
        </Field>
      </Fields>
    </Modal>
  );
}

/** The answer to an order, with the job it names one click away. */
function JobNotice({ job }: { job: Job }) {
  const t = useT();
  const sentence = job.requires_approval
    ? t("Job {id} is waiting for approval.")
    : t("Job {id} has been queued.");
  const [before, after = ""] = sentence.split("{id}");
  return (
    <Banner tone="info">
      {before}
      <Link to={`/jobs/${job.id}`}>{job.id.slice(0, 8)}</Link>
      {after}
    </Banner>
  );
}

/* ------------------------------------------------------------- the form */

/**
 * The backup definition. The repository password is named, never pasted.
 *
 * An edit starts from the definition as it stands, because the panel
 * writes the whole record back: a field the form did not carry used to be
 * cleared by saving.
 */
export function DefinitionForm({ runbooks, existing, busy, onSave, onCancel }: {
  runbooks: string[];
  existing: Definition | null;
  busy: boolean;
  onSave: (body: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [name, setName] = useState(existing?.name ?? "");
  const [tool, setTool] = useState(existing?.tool ?? "restic");
  const [repository, setRepository] = useState(existing?.repository ?? "");
  const [paths, setPaths] = useState((existing?.paths ?? []).join(" "));
  const [excludes, setExcludes] = useState((existing?.excludes ?? []).join(" "));
  const [tags, setTags] = useState((existing?.tags ?? []).join(" "));
  const [secret, setSecret] = useState(existing?.password_secret ?? "");
  const [runbook, setRunbook] = useState(existing?.runbook ?? "");
  const [keepLast, setKeepLast] = useState(String(existing?.keep_last ?? 7));
  const [keepDaily, setKeepDaily] = useState(String(existing?.keep_daily ?? 0));
  const [keepWeekly, setKeepWeekly] = useState(String(existing?.keep_weekly ?? 0));
  const [keepMonthly, setKeepMonthly] = useState(String(existing?.keep_monthly ?? 0));
  const [prune, setPrune] = useState(existing?.prune ?? false);
  const [note, setNote] = useState(existing?.note ?? "");
  const [initialize, setInitialize] = useState(existing ? existing.initialize ?? false : true);

  const byRunbook = tool === "runbook";
  const ready = name !== "" && (byRunbook ? runbook !== "" : repository !== "" && paths !== "");

  return (
    <Card
      title={t("Backup definition")}
      note={existing
        ? t("What stands here is the definition as it is now. Saving writes all of it back, so a field cleared here is cleared on the host as well.")
        : t("The repository password is named, not pasted: the host fetches its value from the secret store once, while the backup runs, and passes it to the tool through the environment — never as a command-line argument, which every user on the host can read.")}
      foot={
        <>
          <Button
            disabled={!ready || busy}
            testId="definition-save"
            onClick={() => onSave({
              name, tool, repository, initialize, prune, note,
              paths: paths.split(/[\s,]+/).filter(Boolean),
              excludes: excludes.split(/[\s,]+/).filter(Boolean),
              tags: tags.split(/[\s,]+/).filter(Boolean),
              keep_last: Number(keepLast) || 0,
              keep_daily: Number(keepDaily) || 0,
              keep_weekly: Number(keepWeekly) || 0,
              keep_monthly: Number(keepMonthly) || 0,
              runbook: byRunbook ? runbook : "",
              password_secret: secret,
              // The form has no place for the environment of the tool, and
              // a save must not be what removes it.
              ...(existing?.env_secrets ? { env_secrets: existing.env_secrets } : {}),
            })}
          >
            {existing ? t("Save changes") : t("Save definition")}
          </Button>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
        </>
      }
    >
      <Fields>
        <Field label={t("Name")}>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="nightly"
            disabled={existing !== null}
            data-testid="definition-name"
          />
        </Field>
        <Field label={t("Tool")}>
          <select value={tool} onChange={(event) => setTool(event.target.value)} data-testid="definition-tool">
            <option value="restic">restic</option>
            <option value="borg">borg</option>
            <option value="runbook">runbook</option>
          </select>
        </Field>
        {byRunbook && (
          <Field label={t("runbooks")}>
            <select value={runbook} onChange={(event) => setRunbook(event.target.value)}>
              <option value="">{t("choose a runbook")}</option>
              {runbooks.map((one) => <option key={one} value={one}>{one}</option>)}
            </select>
          </Field>
        )}
        <Field label={t("Destination")} wide>
          <input
            value={repository}
            onChange={(event) => setRepository(event.target.value)}
            placeholder="/srv/backup or s3:https://…"
            data-testid="definition-repository"
          />
        </Field>
        <Field label={t("Paths (/etc /var/lib/app)")} wide>
          <input value={paths} onChange={(event) => setPaths(event.target.value)} data-testid="definition-paths" />
        </Field>
        <Field label={t("Excludes (*.tmp)")}>
          <input value={excludes} onChange={(event) => setExcludes(event.target.value)} />
        </Field>
        <Field label={t("Tags")}>
          <input value={tags} onChange={(event) => setTags(event.target.value)} />
        </Field>
        <Field label={t("Password secret (name only)")}>
          <input value={secret} onChange={(event) => setSecret(event.target.value)} />
        </Field>
        <Field label={t("Keep last")}>
          <input value={keepLast} onChange={(event) => setKeepLast(event.target.value)} />
        </Field>
        <Field label={t("Keep daily")}>
          <input value={keepDaily} onChange={(event) => setKeepDaily(event.target.value)} />
        </Field>
        <Field label={t("Keep weekly")}>
          <input value={keepWeekly} onChange={(event) => setKeepWeekly(event.target.value)} />
        </Field>
        <Field label={t("Keep monthly")}>
          <input value={keepMonthly} onChange={(event) => setKeepMonthly(event.target.value)} />
        </Field>
        <Field label={t("Note")} wide>
          <input value={note} onChange={(event) => setNote(event.target.value)} />
        </Field>
      </Fields>
      <Check checked={initialize} onChange={setInitialize}>
        {t("Create the repository on the first backup if it does not exist yet")}
      </Check>
      <Check checked={prune} onChange={setPrune}>
        {t("Delete from the repository what the retention above no longer keeps")}
      </Check>
    </Card>
  );
}

/* ----------------------------------------------------------- the module */

export function Backups({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const toast = useToast();

  const [intent, setIntent] = useState<Intent | null>(null);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");
  const [form, setForm] = useState(false);
  // The definition being changed. The panel writes the whole definition, so
  // a form that starts empty is a form that clears what it does not show.
  const [editing, setEditing] = useState<Definition | null>(null);
  const [selected, setSelected] = useState("");
  const [planJob, setPlanJob] = useState("");
  // Which definition the repository was read for. A plan belongs to one
  // definition, and a copy or a restore is bound to the plan of its own.
  const [planFor, setPlanFor] = useState("");
  const [forgetting, setForgetting] = useState("");
  const [ordered, setOrdered] = useState<Job | null>(null);

  const planGuard = useAllowed(host.id, "backup.plan");
  const runGuard = useAllowed(host.id, "backup.run");
  const verifyGuard = useAllowed(host.id, "backup.verify");
  const restoreGuard = useAllowed(host.id, "backup.restore");

  const report = useQuery({
    queryKey: ["backups", host.id],
    queryFn: () => api.get<Report>(`/api/v1/hosts/${host.id}/backups`),
  });

  // The copy list belongs to the job, not to the panel state: it is the
  // repository's answer from one moment, after the password was given.
  const plan = useQuery({
    queryKey: ["job-attempts", planJob],
    queryFn: () => api.get<{ items: Attempt[] }>(`/api/v1/jobs/${planJob}/attempts`),
    enabled: planJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: Attempt[] } | undefined)?.items;
      return attempts?.[attempts.length - 1]?.status ? false : 2000;
    },
  });
  const planAttempts = plan.data?.items ?? [];
  const lastPlan = planAttempts[planAttempts.length - 1];
  const repositoryState = lastPlan?.detail?.state;
  // The fingerprint of what the operator is looking at. A copy and a
  // restore carry it, so a repository that has taken or lost a copy since
  // refuses the order instead of quietly working on something else.
  const planHash = lastPlan?.detail?.plan?.plan_hash ?? "";
  const planHashFor = (name: string) => (planFor === name ? planHash : "");

  const history = useQuery({
    queryKey: ["backup-runs", host.id, selected],
    queryFn: () => api.get<{ items: Run[] }>(
      `/api/v1/hosts/${host.id}/backups/runs?definition=${encodeURIComponent(selected)}`,
    ),
    enabled: selected !== "",
  });

  const failed = (error: unknown) => {
    const text = error instanceof Error ? error.message : String(error);
    setProblem(text);
    toast.error(text);
  };

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job, variables) => {
      const text = job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) });
      setOrdered(job);
      setNotice("");
      setProblem("");
      // The notice is at the top of the module and the copy list may be far
      // below it; the toast names the job wherever the page is.
      toast.success(text, { link: { to: `/hosts/${host.id}/jobs`, label: t("Jobs") } });
      if ((variables as { action?: string }).action === "backup.plan") {
        setPlanJob(job.id);
        const asked = (variables as { payload?: { backup?: { id?: string } } }).payload?.backup?.id;
        setPlanFor(asked ?? "");
      }
      setIntent(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: failed,
  });

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Definition>(`/api/v1/hosts/${host.id}/backups`, body),
    onSuccess: (definition) => {
      setNotice(t("Definition {name} saved. Plan it to read the repository.", { name: definition.name }));
      setProblem("");
      setForm(false);
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: failed,
  });

  const remove = useMutation({
    mutationFn: ({ name, reason }: { name: string; reason: string }) =>
      api.del(
        `/api/v1/hosts/${host.id}/backups`
        + `?name=${encodeURIComponent(name)}&reason=${encodeURIComponent(reason)}`,
      ),
    onSuccess: () => {
      setNotice(t("Definition removed. The history of its runs stays."));
      setProblem("");
      setForgetting("");
      void queryClient.invalidateQueries({ queryKey: ["backups", host.id] });
    },
    onError: failed,
  });

  if (report.error) return <Problem>{String(report.error)}</Problem>;

  const definitions = report.data?.definitions ?? [];
  const tools = report.data?.tools?.tools ?? [];
  const runbooks = report.data?.tools?.runbooks ?? [];
  const definition = definitions.find((one) => one.name === selected);
  // The definitions are unknown until the report lands; the band shows
  // dashes then, not a host with nothing to copy.
  const known = report.data ? definitions : undefined;
  const unverified = countWhere(known, (one) => one.unverified);
  const stale = countWhere(known, (one) => one.status !== "ok" && one.status !== "unknown");
  const byTool = Object.entries(definitions.reduce<Record<string, number>>((into, one) => {
    into[one.tool] = (into[one.tool] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]);

  const state: Segment[] = [
    { label: t("fresh"), value: countWhere(known, (one) => one.status === "ok"), tone: "ok" },
    { label: t("warning"), value: countWhere(known, (one) => one.status === "warning"), tone: "warn" },
    {
      label: t("Need action"),
      value: countWhere(known, (one) =>
        !["ok", "warning", "unknown", "never"].includes(one.status)),
      tone: "error",
    },
    { label: t("no backup yet"), value: countWhere(known, (one) => one.status === "never"), tone: "neutral" },
    { label: t("unknown"), value: countWhere(known, (one) => one.status === "unknown"), tone: "unknown" },
  ];

  const restore = (snapshot: Snapshot) => {
    if (!definition) return;
    setIntent({
      action: "backup.restore",
      label: t("Restore copy"),
      danger: true,
      description: t("Copy {id} is unpacked into a directory on {host}. The target must be empty; what goes back from there to its place is a separate decision.", {
        id: snapshot.id, host: host.hostname,
      }),
      payload: { backup: definitionRequest(definition, planHashFor(definition.name), {
        snapshot_id: snapshot.id,
        overwrite: "empty-target",
      }) },
    });
  };

  return (
    <>
      {/* Actions on the whole module stand in the heading beside the
          machine's name, where every other screen puts its own. */}
      <HeadActions>
        <Button
          kind="quiet"
          testId="definition-open"
          onClick={() => { setEditing(null); setForm((open) => !open); }}
        >
          {form ? t("Cancel") : t("Define a backup")}
        </Button>
      </HeadActions>

      <ReadOnlyNotice hostID={host.id} actions={BACKUP_CHANGES} />
      {problem && <Problem>{problem}</Problem>}
      {notice && <Banner tone="info">{notice}</Banner>}
      {ordered && <JobNotice job={ordered} />}

      <Board screen="next_host_backups" catalogue={HOST_BACKUPS} drawn={{
        state: (
          <Card title={t("Backups")} note={t("By the state of the last copy.")}>
            <Band segments={state} testId="backup-state" />
          </Card>
        ),
        verification: (
          <Card
            title={t("Verification and tools")}
            note={t("A copy nobody has ever read back is a promise, not a safeguard.")}
          >
            {!known ? <Bones rows={3} /> : (
              <>
                <Bars items={[
                  { label: t("Verified"), value: definitions.length - (unverified ?? 0), tone: "ok" },
                  { label: t("not verified"), value: unverified ?? 0, tone: "warn" },
                  { label: t("Need action"), value: stale ?? 0, tone: "error" },
                ]} />
                {byTool.length > 0 && (
                  <>
                    <Note>{t("By tool")}</Note>
                    <Bars items={byTool.map(([tool, count]) => ({ label: tool, value: count }))} />
                  </>
                )}
              </>
            )}
          </Card>
        ),
        tools: (
          <Card
            title={t("Tools on this host")}
            note={t("Backups run with the tools this host already has; the panel installs none of them.")}
            foot={runbooks.length > 0 ? `${t("runbooks")}: ${runbooks.join(", ")}` : undefined}
          >
            {!report.data ? <Bones rows={2} /> : tools.length === 0 ? (
              <Empty icon="backups">{t("The host has not said which backup tools it has.")}</Empty>
            ) : (
              <Tags>
                {tools.map((tool) => (
                  <Pill key={tool.name} tone={tool.available ? "ok" : "unknown"}>
                    {tool.name}
                    {tool.available && tool.version ? ` · ${tool.version.split("\n")[0]}` : ""}
                    {!tool.available ? ` · ${t("not installed")}` : ""}
                  </Pill>
                ))}
              </Tags>
            )}
          </Card>
        ),
        form: form && (
          <DefinitionForm
            key={editing?.name ?? "new"}
            runbooks={runbooks}
            existing={editing}
            busy={save.isPending}
            onSave={(body) => save.mutate(body)}
            onCancel={() => { setForm(false); setEditing(null); }}
          />
        ),
        list: (
          <Card title={t("Backups")} flush>
            {!report.isLoading && definitions.length === 0 ? (
              <Empty
                icon="backups"
                action={<Button kind="quiet" onClick={() => { setEditing(null); setForm(true); }}>{t("Define a backup")}</Button>}
              >
                {t("The panel does not back up anything on this host yet. A definition says what to copy, where to and how long it stays.")}
              </Empty>
            ) : (
              <Table
                rows={definitions}
                keyOf={(one) => one.name}
                loading={report.isLoading}
                testId="definitions"
                rowTestId={(one) => `definition-${one.name}`}
                columns={[
                  {
                    key: "name",
                    head: t("Definition"),
                    cell: (one) => (
                      <TwoLine sub={[one.tool, one.runbook, (one.paths ?? []).join(", ")].filter(Boolean).join(" · ")}>
                        <Button
                          kind="word"
                          onClick={() => {
                            // The plan belongs to the definition it was read for.
                            setPlanJob("");
                            setSelected(selected === one.name ? "" : one.name);
                          }}
                        >
                          {one.name}
                        </Button>
                      </TwoLine>
                    ),
                  },
                  {
                    key: "where",
                    head: t("Destination"),
                    tight: true,
                    cell: (one) => (
                      <TwoLine sub={one.password_secret
                        ? t("password from {secret}", { secret: one.password_secret })
                        : undefined}
                      >
                        {one.repository || "—"}
                      </TwoLine>
                    ),
                  },
                  {
                    key: "last",
                    head: t("Last copy"),
                    cell: (one) => (
                      <TwoLine sub={one.last_success_at
                        ? <span title={absoluteTime(one.last_success_at)}>{relativeTime(one.last_success_at)}</span>
                        : undefined}
                      >
                        <Pill tone={backupTone(one.status)}>
                          {one.status === "never"
                            ? t("no backup yet")
                            : one.age_hours === undefined
                              ? one.status
                              : one.age_hours < 48
                                ? t("{n} h old", { n: Math.round(one.age_hours) })
                                : t("{n} d old", { n: Math.round(one.age_hours / 24) })}
                        </Pill>
                      </TwoLine>
                    ),
                  },
                  {
                    key: "verified",
                    head: t("Verified"),
                    // A copy nobody has ever read back is a promise, not a
                    // safeguard - and it is to look like one.
                    cell: (one) => one.unverified
                      ? <Pill tone="warn">{t("not verified")}</Pill>
                      : (
                        <TwoLine sub={one.last_verify_at
                          ? <span title={absoluteTime(one.last_verify_at)}>{relativeTime(one.last_verify_at)}</span>
                          : undefined}
                        >
                          <Pill tone="ok">{t("verified")}</Pill>
                        </TwoLine>
                      ),
                  },
                  {
                    key: "size",
                    head: t("Size"),
                    num: true,
                    minor: true,
                    cell: (one) => (
                      <TwoLine sub={one.snapshots === undefined
                        ? undefined
                        : t("{n} copies", { n: one.snapshots })}
                      >
                        {size(one.repository_size) ?? "—"}
                      </TwoLine>
                    ),
                  },
                  {
                    key: "do",
                    head: t("Actions"),
                    actions: true,
                    // Every order stands behind the server's preview of what
                    // this operator may place on this host; the definition
                    // itself is the panel's own record and stays editable.
                    cell: (one) => (
                      <>
                        <Guarded verdict={planGuard}>
                          {() => (
                            <Button
                              kind="quiet"
                              disabled={host.connection_state !== "online"}
                              testId={`plan-${one.name}`}
                              onClick={() => request.mutate({
                                action: "backup.plan",
                                // "run" asks for the plan of a copy and not
                                // only for the state of the repository: the
                                // plan carries the fingerprint a copy or a
                                // restore is then bound to.
                                payload: { backup: definitionRequest(one, planHashFor(one.name), { plan: "run" }) },
                              })}
                            >
                              {t("Read repository")}
                            </Button>
                          )}
                        </Guarded>
                        <Guarded verdict={runGuard}>
                          {() => (
                            <Button
                              kind="quiet"
                              testId={`run-${one.name}`}
                              onClick={() => setIntent({
                                action: "backup.run",
                                label: t("Run backup"),
                                description: t("{name} copies {paths} from {host} to {repository}. The data goes straight from the host; the panel only records that it happened.", {
                                  name: one.name,
                                  paths: (one.paths ?? []).join(", "),
                                  host: host.hostname,
                                  repository: one.repository ?? "",
                                }),
                                payload: { backup: definitionRequest(one, planHashFor(one.name)) },
                              })}
                            >
                              {t("Back up now")}
                            </Button>
                          )}
                        </Guarded>
                        <Guarded verdict={verifyGuard}>
                          {() => (
                            <Button
                              kind="quiet"
                              testId={`verify-${one.name}`}
                              onClick={() => setIntent({
                                action: "backup.verify",
                                label: t("Verify backup"),
                                description: t("{name} is checked on {host}, including reading part of the data back. Until something reads a copy, it is a promise, not a safeguard.", {
                                  name: one.name, host: host.hostname,
                                }),
                                payload: { backup: definitionRequest(one, planHashFor(one.name), { read_data: true }) },
                              })}
                            >
                              {t("Verify")}
                            </Button>
                          )}
                        </Guarded>
                        <Button
                          kind="quiet"
                          testId={`edit-${one.name}`}
                          onClick={() => { setEditing(one); setForm(true); }}
                        >
                          {t("Edit")}
                        </Button>
                        <Button
                          kind="danger"
                          testId={`forget-${one.name}`}
                          onClick={() => setForgetting(one.name)}
                        >
                          {t("Forget")}
                        </Button>
                      </>
                    ),
                  },
                ]}
              />
            )}
          </Card>
        ),
        copies: repositoryState && (
          <Card
            title={t("Copies in the repository")}
            foot={`${t("Read from the repository by job {id}", { id: planJob.slice(0, 8) })}`
              + (repositoryState.tool_version ? ` · ${repositoryState.tool_version.split("\n")[0]}` : "")}
            flush
          >
            {repositoryState.unavailable_reason ? (
              <Banner tone="warn">
                {t("The repository could not be read: {reason}", { reason: repositoryState.unavailable_reason })}
              </Banner>
            ) : (
              <Table
                rows={[...(repositoryState.snapshots ?? [])].reverse()}
                keyOf={(one) => one.id}
                empty={t("The repository holds no copy yet.")}
                testId="snapshots"
                rowTestId={(one) => `snapshot-${one.id}`}
                columns={[
                  { key: "id", head: t("Copy"), tight: true, cell: (one) => <code>{one.id}</code> },
                  {
                    key: "when",
                    head: t("Taken"),
                    cell: (one) => <span title={absoluteTime(one.time)}>{relativeTime(one.time)}</span>,
                  },
                  {
                    key: "paths",
                    head: t("Paths"),
                    minor: true,
                    tight: true,
                    cell: (one) => one.paths?.join(", ") || "—",
                  },
                  {
                    key: "do",
                    head: t("Restore"),
                    actions: true,
                    cell: (one) => (
                      <Guarded verdict={restoreGuard}>
                        {() => (
                          <Button
                            kind="danger"
                            disabled={!definition}
                            testId={`restore-${one.id}`}
                            onClick={() => restore(one)}
                          >
                            {t("Restore…")}
                          </Button>
                        )}
                      </Guarded>
                    ),
                  },
                ]}
              />
            )}
          </Card>
        ),
        history: selected !== "" && (
          <Card title={t("History of {name}", { name: selected })} flush>
            <Table
              rows={history.data?.items ?? []}
              keyOf={(one, index) => `${one.recorded_at}-${index}`}
              loading={history.isLoading}
              empty={t("Nothing has run for this definition yet.")}
              testId="runs"
              columns={[
                {
                  key: "when",
                  head: t("When"),
                  cell: (one) => <span title={absoluteTime(one.recorded_at)}>{relativeTime(one.recorded_at)}</span>,
                },
                { key: "kind", head: t("Operation"), tight: true, cell: (one) => <code>{one.kind}</code> },
                {
                  key: "outcome",
                  head: t("Result"),
                  cell: (one) => (
                    <TwoLine sub={one.message}>
                      {one.outcome === "succeeded"
                        ? <Pill tone="ok">{t("succeeded")}</Pill>
                        : <Pill tone="error">{t("failed")}</Pill>}
                    </TwoLine>
                  ),
                },
                {
                  key: "copy",
                  head: t("Copy"),
                  minor: true,
                  tight: true,
                  cell: (one) => one.snapshot_id ? <code>{one.snapshot_id}</code> : "—",
                },
                { key: "added", head: t("Added"), num: true, cell: (one) => size(one.bytes_added) ?? "—" },
                { key: "by", head: t("By"), minor: true, cell: (one) => one.started_by || "—" },
              ]}
            />
          </Card>
        ),
      }} />

      {intent && (
        <Confirm
          host={host}
          label={intent.label}
          description={intent.description}
          danger={intent.danger}
          busy={request.isPending}
          // A restore asks where it unpacks: the directory is the thing the
          // operator is really agreeing to, so it is confirmed with the host.
          target={intent.action === "backup.restore" ? {
            label: t("Target directory"),
            hint: t("An absolute path on {host}; it must be empty. The panel never restores straight into system directories, and not into /tmp either — the host helper has its own private one, where restored data would vanish with the operation.", { host: host.hostname }),
            initial: RESTORE_TARGET,
          } : undefined}
          onCancel={() => setIntent(null)}
          onConfirm={(reason, where) => request.mutate({
            action: intent.action,
            reason,
            payload: intent.action === "backup.restore"
              ? { backup: { ...(intent.payload.backup as Record<string, unknown>), target: where } }
              : intent.payload,
          })}
        />
      )}

      {forgetting && (
        <Confirm
          host={host}
          label={t("Forget")}
          danger
          description={t("The panel forgets the definition {name} on {host}. Nothing is deleted from the repository and the history of its runs stays.", {
            name: forgetting, host: host.hostname,
          })}
          busy={remove.isPending}
          onCancel={() => setForgetting("")}
          onConfirm={(reason) => remove.mutate({ name: forgetting, reason })}
        />
      )}
    </>
  );
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_BACKUPS: BoardEntry[] = [
  { key: "state", title: "Backups", width: 5, height: 2 },
  { key: "verification", title: "Verification and tools", width: 4, height: 2 },
  { key: "tools", title: "Tools on this host", width: 3, height: 2 },
  { key: "form", title: "Backup definition", width: 12, height: 5 },
  { key: "list", title: "Backups", width: 12, height: 4 },
  { key: "copies", title: "Copies in the repository", width: 6, height: 3 },
  { key: "history", title: "History", width: 6, height: 3 },
];

/** The name this module's arrangement is stored under. */
export const HOST_BACKUPS_SCREEN = "next_host_backups";
