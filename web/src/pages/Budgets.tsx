import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Budget, BudgetLimit, Whoami } from "../lib/types";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader } from "../components/layout";
import { Breakdown, Meter, StatusBar, type WidgetTone } from "../components/widgets";
import { useConfirm } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/* ---------------------------------------------------------------------- */
/* The shape of a budget row.                                              */
/* ---------------------------------------------------------------------- */

/** One live lease of a budget: who holds how many tokens since when. */
export type BudgetHolder = {
  /** job:<id> for a job, the target id for a campaign host, fanout:<id> for a fan-out read. */
  owner: string;
  /** campaign:<id>, jobs:<author> or reads:<author> - the unit of fairness. */
  claimant: string;
  /** The class the lease was taken with; "unknown" when the API cannot place the holder. */
  class: string;
  tokens: number;
  since: string;
};

/**
 * A budget row as the API answers it now: the five numbers every client
 * reads, and behind them who holds the tokens and who waits for them.
 */
export type BudgetState = Budget & {
  /** The hosts of running campaigns standing in awaiting_budget behind this key. */
  waiting_targets: number;
  /** The live leases, newest first, at most fifty. */
  holders: BudgetHolder[];
  /** The tokens in use per class of work; every lease counts, not only the listed ones. */
  by_class: Record<string, number>;
};

/* ---------------------------------------------------------------------- */
/* The vocabulary of a budget key.                                         */
/* ---------------------------------------------------------------------- */

/** The family of a budget key: what the capacity guards. */
export type BudgetKind = "global" | "site" | "domain" | "gateway" | "backend" | "other";

/**
 * A budget key taken apart. The keys are three colon-separated parts -
 * the family, the scope and the resource - and an asterisk in the scope
 * is the default policy of the family: the capacity every site or backend
 * gets until somebody describes it on its own.
 */
export type BudgetKey = {
  kind: BudgetKind;
  /** The site, the failure domain, the gateway, the backup repository, or empty for a fleet-wide key. */
  scope: string;
  /** What the capacity is spent on: mutations, reads, packages, reboot, backup. */
  resource: string;
  /** The row is the default policy of its family rather than one scope's. */
  pattern: boolean;
};

/**
 * Reads a key the way the store builds it. A key the panel does not know
 * the shape of is still shown whole under "other" rather than dropped: the
 * capacity is real even when its name is new.
 */
export function describeBudgetKey(key: string): BudgetKey {
  const [family, scope, resource, ...rest] = key.split(":");
  if (family === "global" && scope !== undefined && resource === undefined) {
    return { kind: "global", scope: "", resource: scope, pattern: false };
  }
  if ((family === "site" || family === "domain" || family === "gateway" || family === "backend") && scope !== undefined && resource !== undefined && rest.length === 0) {
    return { kind: family, scope, resource, pattern: scope === "*" };
  }
  return { kind: "other", scope: "", resource: key, pattern: false };
}

/**
 * The portion of a budget one claimant may hold while others ask for it,
 * computed the way the store computes it: the capacity split between the
 * claimants, never below one token. Shown so the operator sees why a
 * campaign holds three tokens of a budget with ten free.
 */
export function fairShare(capacity: number, claimants: number): number {
  return Math.max(1, Math.floor(capacity / Math.max(claimants, 1)));
}

/** A budget with no token free is saturated: every new operation on it waits. */
export function saturated(budget: Pick<Budget, "used" | "capacity">): boolean {
  return budget.capacity > 0 && budget.used >= budget.capacity;
}

/** The work standing behind a budget: jobs in the queue and campaign hosts, added up. */
export function waiting(budget: Pick<BudgetState, "waiting_jobs" | "waiting_targets">): number {
  return budget.waiting_jobs + budget.waiting_targets;
}

/**
 * The colour of a budget's usage. Full is an error only in the sense that
 * work is waiting on it; a queue behind a budget with room is the fair
 * share at work, and it is a warning so the operator looks. A row of the
 * first shape, without the waiting hosts, is read the same way.
 */
export function budgetTone(budget: Pick<Budget, "used" | "capacity" | "waiting_jobs"> & { waiting_targets?: number }): WidgetTone {
  if (saturated(budget)) return "error";
  const queued = budget.waiting_jobs + (budget.waiting_targets ?? 0);
  if (queued > 0 || (budget.capacity > 0 && budget.used / budget.capacity > 0.7)) return "warn";
  return "ok";
}

/**
 * The priority classes in the order of their urgency, and how long each
 * waits before its fair share stops binding, as the design fixes them.
 * The API reports the tokens in use per class; the promotion age is the
 * page's hint of what the class means.
 */
export const CLASSES: { name: string; promotion: string }[] = [
  { name: "incident", promotion: "at once" },
  { name: "interactive", promotion: "15 seconds" },
  { name: "maintenance", promotion: "2 minutes" },
  { name: "background", promotion: "5 minutes" },
];

/**
 * The tokens in use per class across every budget, the known classes
 * always and in their order - zero is information too - and a class the
 * API named on its own, "unknown" among them, after them only when it
 * holds something. A token the panel cannot place is still a token taken.
 */
export function classTotals(budgets: Pick<BudgetState, "by_class">[]): { name: string; tokens: number }[] {
  const totals = new Map<string, number>();
  for (const budget of budgets) {
    for (const [name, tokens] of Object.entries(budget.by_class ?? {})) {
      totals.set(name, (totals.get(name) ?? 0) + tokens);
    }
  }
  const known = CLASSES.map((item) => ({ name: item.name, tokens: totals.get(item.name) ?? 0 }));
  const others = [...totals.entries()]
    .filter(([name, tokens]) => tokens > 0 && !CLASSES.some((item) => item.name === name))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, tokens]) => ({ name, tokens }));
  return [...known, ...others];
}

/**
 * Where a holder leads. A campaign host leads to its campaign, a fan-out
 * to its read, and a job to the job list filtered by the author who
 * ordered it - the list has no filter by id, and the author's running
 * jobs are the ones holding tokens. A holder of a shape the panel does not
 * know leads nowhere and is shown by its owner as it is.
 */
export function holderLink(holder: Pick<BudgetHolder, "owner" | "claimant">): { to: string; label: string } | null {
  const campaign = holder.claimant.startsWith("campaign:") ? holder.claimant.slice("campaign:".length) : "";
  if (campaign) return { to: `/campaigns/${encodeURIComponent(campaign)}`, label: "campaign" };
  if (holder.owner.startsWith("job:")) {
    const author = holder.claimant.startsWith("jobs:") ? holder.claimant.slice("jobs:".length) : "";
    return { to: author ? `/jobs?actor=${encodeURIComponent(author)}` : "/jobs", label: "job" };
  }
  if (holder.owner.startsWith("fanout:")) {
    return { to: `/reads/${encodeURIComponent(holder.owner.slice("fanout:".length))}`, label: "read" };
  }
  return null;
}

/* ---------------------------------------------------------------------- */
/* The conditional write.                                                  */
/* ---------------------------------------------------------------------- */

function budgetPath(key: string): string {
  return `/api/v1/budgets/${encodeURIComponent(key)}`;
}

/** The configured record of one budget and the tag of that version. */
async function readLimit(key: string): Promise<{ limit: BudgetLimit; etag: string }> {
  const { data, etag } = await api.getWithMeta<BudgetLimit>(budgetPath(key));
  return { limit: data, etag };
}

/**
 * Writes the capacity and the note on the version named by the tag. A
 * capacity written over somebody else's change a minute ago is a policy
 * nobody decided, so the tag goes in If-Match and the server refuses a
 * stale one.
 */
async function writeLimit(key: string, body: { capacity: number; note: string }, etag: string): Promise<void> {
  await api.put<unknown>(budgetPath(key), body, { headers: etag ? { "If-Match": etag } : {} });
}

/**
 * Takes a configured budget away on the version named by the tag. The
 * server refuses while somebody holds tokens of it: a ceiling is not
 * pulled from under running work.
 */
async function deleteLimit(key: string, reason: string, etag: string): Promise<void> {
  await api.del<unknown>(budgetPath(key), { reason }, { headers: etag ? { "If-Match": etag } : {} });
}

/** The shape of a key the store reads: three colon-separated parts, or global:<resource>. */
const KEY_PATTERN = /^(global:[a-z0-9_-]+|(site|domain|gateway|backend):([a-z0-9_.-]+|\*):[a-z0-9_-]+)$/;

/* ---------------------------------------------------------------------- */
/* The page.                                                               */
/* ---------------------------------------------------------------------- */

/** How often the picture is refreshed: tokens come and go with every task. */
const BUDGETS_INTERVAL = 10 * 1000;

/**
 * The capacity budgets of the fleet.
 *
 * A host waiting on a budget looks like a forgotten host: the campaign
 * does not move, the job stands in the queue, and nothing says why. This
 * page is where the reason is seen as a budget - how much it carries, how
 * much is taken, who is asking - and where the capacity is changed when
 * the policy, not the fleet, is what stands in the way.
 */
export function Budgets() {
  const t = useT();
  const [creating, setCreating] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["budgets"],
    queryFn: () => api.get<{ items: BudgetState[] }>("/api/v1/budgets"),
    refetchInterval: BUDGETS_INTERVAL,
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canWrite = (whoami.data?.permissions ?? []).includes("budget.write");

  // An installation without the budgets answers so by name; that is a fact
  // about the installation, not a failure of the page.
  if (error instanceof ApiError && error.status === 501) {
    return (
      <>
        <PageHeader icon="overview" title={t("Budgets")} />
        <Empty>{t("Budgets are disabled in this installation.")}</Empty>
      </>
    );
  }
  if (error) return <ErrorBox error={error} />;
  const loaded = data !== undefined;
  const budgets = data?.items ?? [];
  const full = budgets.filter(saturated);
  const waited = budgets.filter((budget) => waiting(budget) > 0);
  const free = budgets.filter((budget) => !saturated(budget) && waiting(budget) === 0);
  const waitingJobs = budgets.reduce((sum, budget) => sum + budget.waiting_jobs, 0);
  const waitingTargets = budgets.reduce((sum, budget) => sum + budget.waiting_targets, 0);
  const byKind = (["global", "site", "domain", "gateway", "backend", "other"] as BudgetKind[])
    .map((kind) => ({ kind, value: budgets.filter((budget) => describeBudgetKey(budget.key).kind === kind).length }))
    .filter((entry) => entry.value > 0);
  const byClass = classTotals(budgets);

  return (
    <>
      <PageHeader
        icon="overview"
        title={t("Budgets")}
        description={t("The capacity of the fleet, in tokens: how many operations the fleet, a site or a backup backend carries at once. A campaign or a job that finds no free token waits here, and the free tokens are divided fairly between everyone asking.")}
        actions={canWrite && (
          <button className={creating ? "secondary" : ""} onClick={() => setCreating(!creating)}>
            {creating ? t("Hide the form") : t("New budget")}
          </button>
        )}
      />

      {creating && <NewBudget existing={budgets.map((budget) => budget.key)} onDone={() => setCreating(false)} />}

      <div className="widgets">
        <Card className="span-6" title={t("Capacity")} description={t("{n} budgets, {jobs} jobs and {hosts} campaign hosts waiting", { n: budgets.length, jobs: waitingJobs, hosts: waitingTargets })}>
          <StatusBar segments={[
            { label: t("Keys"), value: loaded ? budgets.length : undefined, tone: "info" },
            { label: t("Saturated"), value: loaded ? full.length : undefined, tone: "error" },
            { label: t("With work waiting"), value: loaded ? waited.length : undefined, tone: "warn", to: waitingJobs > 0 ? "/jobs?state=queued" : waitingTargets > 0 ? "/campaigns" : undefined },
            { label: t("With room"), value: loaded ? free.length : undefined, tone: "ok" },
          ]} />
        </Card>
        <Card className="span-3" title={t("By family")} description={t("What the keys guard.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : byKind.length === 0 ? (
            <p className="fp-blank">{t("No budget is configured.")}</p>
          ) : (
            <Breakdown tone="info" items={byKind.map((entry) => ({ label: <KindLabel kind={entry.kind} />, value: entry.value }))} />
          )}
        </Card>
        <Card className="span-3" title={t("By class")} description={t("Tokens in use per class of work, over every budget; the age is how long the class waits before its fair share stops binding.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : (
            <Breakdown tone="info" items={byClass.map((item) => ({
              label: <ClassLabel name={item.name} />,
              value: item.tokens,
              // A token the panel cannot place is still a token taken, and
              // it is marked so the operator does not read it as a class.
              tone: item.name === "unknown" ? "unknown" as WidgetTone : undefined,
            }))} />
          )}
        </Card>

        <Card className="span-12" flush>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : budgets.length === 0 ? (
            <Empty>
              {canWrite
                ? t("No budget is configured. Without one the fleet carries whatever is asked of it; set a capacity under a key such as global:mutations or site:*:packages with the button above.")
                : t("No budget is configured. Without one the fleet carries whatever is asked of it; a capacity is set with the API under a key such as global:mutations or site:*:packages.")}
            </Empty>
          ) : (
            <BudgetTable budgets={budgets} canWrite={canWrite} />
          )}
        </Card>
      </div>
    </>
  );
}

/** The family of a key in words; the key itself stays beside it. */
function KindLabel({ kind }: { kind: BudgetKind }) {
  const t = useT();
  switch (kind) {
    case "global":
      return <>{t("Fleet")}</>;
    case "site":
      return <>{t("Site")}</>;
    case "domain":
      return <>{t("Failure domain")}</>;
    case "gateway":
      return <>{t("Gateway")}</>;
    case "backend":
      return <>{t("Backup backend")}</>;
    default:
      return <>{t("Other")}</>;
  }
}

type Translate = (text: string, params?: Record<string, string | number>) => string;

/* The class names and the promotion ages are the design's words, so they
   go through the catalogue one by one rather than as an expression. A
   class the API named on its own is shown by that name. */
function classLabel(name: string, t: Translate): string {
  switch (name) {
    case "incident": return t("incident");
    case "interactive": return t("interactive");
    case "maintenance": return t("maintenance");
    case "background": return t("background");
    case "unknown": return t("unknown");
    default: return name;
  }
}

function promotionLabel(promotion: string, t: Translate): string {
  switch (promotion) {
    case "at once": return t("at once");
    case "15 seconds": return t("15 seconds");
    case "2 minutes": return t("2 minutes");
    default: return t("5 minutes");
  }
}

/** A class with its promotion age beside it as a hint, when the design fixes one. */
function ClassLabel({ name }: { name: string }) {
  const t = useT();
  const known = CLASSES.find((item) => item.name === name);
  return (
    <>
      {classLabel(name, t)}
      {known && <span className="source" title={t("How long this class waits before its fair share stops binding.")}>{" · "}{promotionLabel(known.promotion, t)}</span>}
    </>
  );
}

/**
 * The budgets, one per key. A pattern row is marked as the default of its
 * family: its numbers are the sites nobody described separately, added
 * up under the one policy they share.
 */
function BudgetTable({ budgets, canWrite }: { budgets: BudgetState[]; canWrite: boolean }) {
  const t = useT();
  const [editing, setEditing] = useState("");
  return (
    <table>
      <thead>
        <tr>
          <th>{t("Key")}</th>
          <th className="num">{t("Capacity")}</th>
          <th>{t("In use")}</th>
          <th title={t("The campaigns, jobs and reads that hold tokens of this budget right now.")}>{t("Held by")}</th>
          <th className="num" title={t("How many campaigns, jobs and reads ask for tokens of this budget at the moment.")}>{t("Claimants")}</th>
          <th className="num" title={t("The most tokens one claimant may hold while others ask: the capacity split between the claimants, never below one.")}>{t("Share per claimant")}</th>
          <th className="num" title={t("Jobs queued until a token of this budget frees up.")}>{t("Waiting jobs")}</th>
          <th className="num" title={t("Campaign hosts waiting for a token of this budget before they start.")}>{t("Waiting hosts")}</th>
          {canWrite && <th />}
        </tr>
      </thead>
      <tbody>
        {budgets.map((budget) => {
          const described = describeBudgetKey(budget.key);
          const tone = budgetTone(budget);
          const open = editing === budget.key;
          return (
            <BudgetRows
              key={budget.key}
              budget={budget}
              described={described}
              tone={tone}
              canWrite={canWrite}
              open={open}
              onEdit={() => setEditing(open ? "" : budget.key)}
              onDone={() => setEditing("")}
            />
          );
        })}
      </tbody>
    </table>
  );
}

function BudgetRows({ budget, described, tone, canWrite, open, onEdit, onDone }: {
  budget: BudgetState;
  described: BudgetKey;
  tone: WidgetTone;
  canWrite: boolean;
  open: boolean;
  onEdit: () => void;
  onDone: () => void;
}) {
  const t = useT();
  const share = fairShare(budget.capacity, budget.claimants);
  return (
    <>
      <tr data-testid="budget-row" data-key={budget.key}>
        <td>
          <span className="mono">{budget.key}</span>
          {described.pattern && (
            <>{" "}<span className="badge unknown" title={t("The default policy of every key of this family nobody described separately.")}>{t("default")}</span></>
          )}
          <div className="source">
            <KindLabel kind={described.kind} />
            {described.scope && !described.pattern && <> · {described.scope}</>}
            {" · "}{described.resource}
          </div>
        </td>
        <td className="num">{budget.capacity}</td>
        <td>
          <Meter value={budget.used} max={budget.capacity} tone={tone} text={`${budget.used} / ${budget.capacity}`} />
        </td>
        <td><Holders holders={budget.holders} /></td>
        <td className="num">{budget.claimants}</td>
        <td className="num">{share}</td>
        <td className="num">
          {/* The jobs in the queue are the job list's to show; the count
              here leads to them, because a number with nowhere to go only
              raises the question it could answer. */}
          {budget.waiting_jobs > 0
            ? <Link to="/jobs?state=queued" className="badge warn">{budget.waiting_jobs}</Link>
            : budget.waiting_jobs}
        </td>
        <td className="num">
          {/* The waiting hosts are each on their campaign's screen; the
              count leads to the campaigns, the running ones among them. */}
          {budget.waiting_targets > 0
            ? <Link to="/campaigns" className="badge warn">{budget.waiting_targets}</Link>
            : budget.waiting_targets}
        </td>
        {canWrite && (
          <td>
            <Actions>
              <button className="secondary" onClick={onEdit} aria-expanded={open}>{open ? t("Close") : t("Edit")}</button>
              <DeleteBudget budget={budget} />
            </Actions>
          </td>
        )}
      </tr>
      {open && (
        <tr data-testid="budget-editor" data-key={budget.key}>
          <td colSpan={canWrite ? 9 : 8}>
            <CapacityEditor budget={budget} onDone={onDone} />
          </td>
        </tr>
      )}
    </>
  );
}

/** How many holders a row names before it counts the rest. */
const HOLDERS_SHOWN = 4;

/**
 * Who holds the tokens of one budget, newest first. A holder is named by
 * where it leads - the campaign, the author's jobs, the read - with its
 * class and its weight; the row names a few and counts the rest, because
 * a budget of two hundred reads is not a column of two hundred lines.
 */
function Holders({ holders }: { holders: BudgetHolder[] }) {
  const t = useT();
  if (holders.length === 0) return <span className="source">{t("nobody")}</span>;
  const shown = holders.slice(0, HOLDERS_SHOWN);
  const rest = holders.length - shown.length;
  return (
    <div className="stack" style={{ gap: 2 }} data-testid="budget-holders">
      {shown.map((holder) => <HolderLine key={holder.owner} holder={holder} />)}
      {rest > 0 && <span className="source">{t("and {n} more", { n: rest })}</span>}
    </div>
  );
}

function HolderLine({ holder }: { holder: BudgetHolder }) {
  const t = useT();
  const link = holderLink(holder);
  const name = link
    ? <Link to={link.to} className="mono" title={holder.owner}>{holderName(link.label, t)}</Link>
    : <span className="mono" title={holder.claimant}>{holder.owner}</span>;
  return (
    <span className="source" data-testid="budget-holder" data-owner={holder.owner}>
      {name}
      {" · "}
      <span className={holder.class === "unknown" ? "badge unknown" : "badge"}>{classLabel(holder.class, t)}</span>
      {" · "}
      {t("{n} tokens", { n: holder.tokens })}
      {" · "}
      <Time value={holder.since} />
    </span>
  );
}

/* The kinds of holders are the design's words, so they go through the
   catalogue one by one. */
function holderName(label: string, t: Translate): string {
  switch (label) {
    case "campaign": return t("campaign");
    case "job": return t("job");
    default: return t("read");
  }
}

/**
 * Taking one budget away. The key then falls back to the pattern of its
 * family or to no limit at all, which the dialog says; the reason goes
 * to the trail. A budget with tokens held is refused by the server, and
 * the refusal is shown as what it is - work in flight - rather than as
 * an error of the page.
 */
function DeleteBudget({ budget }: { budget: BudgetState }) {
  const t = useT();
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const described = describeBudgetKey(budget.key);
  const remove = useMutation({
    mutationFn: async (reason: string) => {
      const { etag } = await readLimit(budget.key);
      await deleteLimit(budget.key, reason, etag);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["budgets"] });
      toast.success(t("Budget {key} deleted.", { key: budget.key }));
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        toast.error(t("{key} holds tokens of running work; wait for it to finish or cancel it, then delete the budget.", { key: budget.key }));
        return;
      }
      if (error instanceof ApiError && error.forbidden) {
        toast.error(t("You may not change this budget: a site budget needs the right in its site, the rest in the whole fleet."));
        return;
      }
      toast.error(error instanceof Error ? error.message : String(error));
    },
  });
  const ask = async () => {
    const { ok, reason } = await confirm({
      title: t("Delete the budget {key}?", { key: budget.key }),
      body: (
        <>
          <p>
            {described.pattern
              ? t("The default of this family goes away: a site nobody described separately is then unlimited for this resource.")
              : t("The key falls back to the default of its family, or to no limit at all when no default describes it. A deleted budget is not a budget of zero.")}
          </p>
          {budget.used > 0 && <p className="page-error">{t("{n} tokens are held right now; the server will refuse until the work finishes.", { n: budget.used })}</p>}
        </>
      ),
      confirmLabel: t("Delete"),
      danger: true,
      reason: { required: true },
    });
    if (ok && reason) remove.mutate(reason);
  };
  // The row button is plain: a column of two dozen red buttons is a wall
  // of alarm where nothing is wrong. The confirmation that follows is
  // the one drawn as a danger.
  return (
    <button className="secondary" onClick={ask} disabled={remove.isPending} data-testid="budget-delete" data-key={budget.key}>
      {t("Delete")}
    </button>
  );
}

/**
 * A budget configured for the first time: the key, its capacity and the
 * note. The key is typed, because the families and their resources are
 * the store's vocabulary and a menu of every combination would be longer
 * than the explanation; the field checks the shape before the request
 * leaves and refuses a key that is already on the list, which is edited
 * in place instead.
 */
function NewBudget({ existing, onDone }: { existing: string[]; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [key, setKey] = useState("");
  const [capacity, setCapacity] = useState("1");
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");

  const trimmed = key.trim();
  const validKey = KEY_PATTERN.test(trimmed);
  const duplicate = existing.includes(trimmed);
  const parsed = Number(capacity);
  const validCapacity = Number.isInteger(parsed) && parsed >= 1;
  const ready = validKey && !duplicate && validCapacity;

  const create = useMutation({
    mutationFn: () => writeLimit(trimmed, { capacity: parsed, note: note.trim() }, ""),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["budgets"] });
      toast.success(t("Budget {key} set to {n} tokens.", { key: trimmed, n: parsed }));
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.forbidden) {
        setMessage(t("You may not change this budget: a site budget needs the right in its site, the rest in the whole fleet."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  return (
    <Card
      title={t("New budget")}
      description={t("A capacity under a key the store reads: global:<resource> for the whole fleet, or site, domain, gateway or backend, a scope or an asterisk for the family's default, and the resource - mutations, reads, packages, reboot, units, backup.")}
      footer={
        <Actions>
          <button onClick={() => create.mutate()} disabled={!ready || create.isPending}>{create.isPending ? t("saving…") : t("Set the capacity")}</button>
          <button className="secondary" onClick={onDone} disabled={create.isPending}>{t("Cancel")}</button>
          {message && <span className="page-error">{message}</span>}
        </Actions>
      }
    >
      <FieldGrid>
        <Field
          label={t("Key")}
          hint={duplicate
            ? t("This key is already configured; edit it in the list.")
            : trimmed && !validKey
              ? t("Not a budget key: global:mutations, site:warsaw:packages, site:*:reads, domain:rack-1:units, backend:offsite:backup.")
              : t("Exact for one scope, or with an asterisk as the default every scope of the family gets.")}
        >
          <input className="mono" value={key} placeholder="site:*:packages" onChange={(e) => setKey(e.target.value)} autoFocus aria-invalid={Boolean(trimmed) && (!validKey || duplicate)} data-testid="new-budget-key" />
        </Field>
        <Field label={t("Capacity")} hint={t("Tokens at once under this key; at least 1. To stop the work, pause the campaign instead.")}>
          <input type="number" min={1} step={1} value={capacity} onChange={(e) => setCapacity(e.target.value)} aria-invalid={!validCapacity} data-testid="new-budget-capacity" />
        </Field>
        <Field label={t("Note (kept in the audit trail)")} hint={t("Why this capacity: the link of the site, the disk of the backend.")} wide>
          <input value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </FieldGrid>
    </Card>
  );
}

/**
 * The capacity of one budget, changed in place.
 *
 * The record is read first for its tag: the write is refused when
 * somebody changed it since, and the editor says so rather than winning
 * quietly. The note goes to the audit trail with the change, because a
 * limit raised without a word takes the meaning away from every limit
 * below it.
 */
function CapacityEditor({ budget, onDone }: { budget: BudgetState; onDone: () => void }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [capacity, setCapacity] = useState(String(budget.capacity));
  const [note, setNote] = useState("");
  const [message, setMessage] = useState("");

  const record = useQuery({
    queryKey: ["budgets", budget.key, "limit"],
    queryFn: () => readLimit(budget.key),
    staleTime: 0,
    refetchOnWindowFocus: false,
  });
  // The note of the last change is the starting point of this one: a
  // policy is usually adjusted, not rewritten. A record read again after a
  // conflict brings the other editor's note the same way.
  useEffect(() => {
    if (record.data) setNote(record.data.limit.note);
  }, [record.data]);

  const save = useMutation({
    mutationFn: () => writeLimit(budget.key, { capacity: Number(capacity), note: note.trim() }, record.data?.etag ?? ""),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["budgets"] });
      onDone();
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 412) {
        setMessage(t("The budget changed since it was read; it is read again, check the numbers and save once more."));
        record.refetch();
        return;
      }
      if (error instanceof ApiError && error.forbidden) {
        setMessage(t("You may not change this budget: a site budget needs the right in its site, the rest in the whole fleet."));
        return;
      }
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const parsed = Number(capacity);
  const valid = Number.isInteger(parsed) && parsed >= 1;
  // A note alone is a change too: the reason of a policy is part of it.
  const changed = record.data !== undefined && (parsed !== budget.capacity || note.trim() !== record.data.limit.note);
  const ready = valid && changed;

  return (
    <>
      <FieldGrid>
        <Field label={t("Capacity")} hint={t("Tokens at once under this key; at least 1. To stop the work, pause the campaign instead.")}>
          <input type="number" min={1} step={1} value={capacity} onChange={(e) => setCapacity(e.target.value)} aria-label={t("Capacity")} />
        </Field>
        <Field label={t("Note (kept in the audit trail)")} hint={t("Why this capacity: the link of the site, the disk of the backend.")} wide>
          <input value={note} onChange={(e) => setNote(e.target.value)} aria-label={t("Note")} />
        </Field>
      </FieldGrid>
      <Actions>
        <button onClick={() => save.mutate()} disabled={!ready || save.isPending}>{t("Save")}</button>
        <button className="secondary" onClick={onDone} disabled={save.isPending}>{t("Cancel")}</button>
        {record.error && <span className="source">{record.error instanceof Error ? record.error.message : String(record.error)}</span>}
        {record.data && (
          <span className="source">
            {t("Last changed")} <Time value={record.data.limit.updated_at} />
          </span>
        )}
        {message && <span className="source">{message}</span>}
      </Actions>
    </>
  );
}
