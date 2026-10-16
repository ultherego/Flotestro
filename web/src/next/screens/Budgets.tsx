import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Budget, BudgetLimit, Whoami } from "../../lib/types";
import { absoluteTime, relativeTime } from "../../lib/format";
import { useToast } from "../../components/Toast";
import { useT, type Translate } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Band, Bars, Bones, Button, Card, Empty, Fact, Facts, Field, Fields, HeadActions,
  Kpi, Meter, Modal, Note, Pill, Problem, Stack, Table, Tag, Tags, TwoLine,
  type Segment, type Tone,
} from "../kit";

/**
 * The capacity of the fleet, in tokens.
 *
 * A budget is a number the store reads before an operation runs: how much
 * of the fleet one change may touch at once. Everything on this screen is
 * read from the store, so a figure nobody could take is an em dash rather
 * than a nought - a fleet whose budgets have not arrived is not a fleet
 * with no capacity, and drawing it as one would read as an installation
 * that refuses everything.
 */

/* ------------------------------------------------------------ the shape */

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
 * A budget row as the API answers it: the five numbers every client reads,
 * and behind them who holds the tokens and who waits for them.
 */
export type BudgetState = Budget & {
  /** The hosts of running campaigns standing in awaiting_budget behind this key. */
  waiting_targets: number;
  /** The live leases, newest first, at most fifty. */
  holders: BudgetHolder[];
  /** The tokens in use per class of work; every lease counts, not only the listed ones. */
  by_class: Record<string, number>;
};

/* -------------------------------------------------- the vocabulary of a key */

/** The family of a budget key: what the capacity guards. */
export type BudgetKind = "global" | "site" | "domain" | "gateway" | "backend" | "other";

/** A budget key taken apart. */
export type BudgetKey = {
  kind: BudgetKind;
  /** The site, the failure domain, the gateway, the backup repository, or empty fleet-wide. */
  scope: string;
  /** What the capacity is spent on: mutations, reads, packages, reboot, backup. */
  resource: string;
  /** The row is the default policy of its family rather than one scope's. */
  pattern: boolean;
};

/** Reads a key the way the store builds it. */
export function describeBudgetKey(key: string): BudgetKey {
  const [family, scope, resource, ...rest] = key.split(":");
  if (family === "global" && scope !== undefined && resource === undefined) {
    return { kind: "global", scope: "", resource: scope, pattern: false };
  }
  if (
    (family === "site" || family === "domain" || family === "gateway" || family === "backend")
    && scope !== undefined && resource !== undefined && rest.length === 0
  ) {
    return { kind: family, scope, resource, pattern: scope === "*" };
  }
  return { kind: "other", scope: "", resource: key, pattern: false };
}

/**
 * The portion of a budget one claimant may hold while others ask for it,
 * computed the way the store computes it: the capacity split between the
 * claimants, never below one token.
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
  return (budget.waiting_jobs ?? 0) + (budget.waiting_targets ?? 0);
}

/** The colour of a budget's usage. */
export function budgetTone(
  budget: Pick<Budget, "used" | "capacity" | "waiting_jobs"> & { waiting_targets?: number },
): Tone {
  if (saturated(budget)) return "error";
  const queued = (budget.waiting_jobs ?? 0) + (budget.waiting_targets ?? 0);
  if (queued > 0 || (budget.capacity > 0 && budget.used / budget.capacity > 0.7)) return "warn";
  return "ok";
}

/**
 * The priority classes in the order of their urgency, and how long each
 * waits before its fair share stops binding, as the design fixes them.
 */
export const CLASSES: { name: string; promotion: string }[] = [
  { name: "incident", promotion: "at once" },
  { name: "interactive", promotion: "15 seconds" },
  { name: "maintenance", promotion: "2 minutes" },
  { name: "background", promotion: "5 minutes" },
];

/**
 * The tokens in use per class across every budget: the known classes always
 * and in their order - zero is information too - and a class the API named
 * on its own, "unknown" among them, after them only when it holds something.
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

/** Where a holder leads, inside the new panel. */
export function holderLink(holder: Pick<BudgetHolder, "owner" | "claimant">): { to: string; label: string } | null {
  const campaign = holder.claimant.startsWith("campaign:") ? holder.claimant.slice("campaign:".length) : "";
  if (campaign) return { to: `/next/campaigns/${encodeURIComponent(campaign)}`, label: "campaign" };
  if (holder.owner.startsWith("job:")) {
    const author = holder.claimant.startsWith("jobs:") ? holder.claimant.slice("jobs:".length) : "";
    return { to: author ? `/next/jobs?actor=${encodeURIComponent(author)}` : "/next/jobs", label: "job" };
  }
  if (holder.owner.startsWith("fanout:")) {
    return { to: `/next/reads/${encodeURIComponent(holder.owner.slice("fanout:".length))}`, label: "read" };
  }
  return null;
}

/* ------------------------------------------------------ the conditional write */

function budgetPath(key: string): string {
  return `/api/v1/budgets/${encodeURIComponent(key)}`;
}

/** The configured record of one budget and the tag of that version. */
async function readLimit(key: string): Promise<{ limit: BudgetLimit; etag: string }> {
  const { data, etag } = await api.getWithMeta<BudgetLimit>(budgetPath(key));
  return { limit: data, etag };
}

/** Writes the capacity and the note on the version named by the tag. */
async function writeLimit(key: string, body: { capacity: number; note: string }, etag: string): Promise<void> {
  await api.put<unknown>(budgetPath(key), body, { headers: etag ? { "If-Match": etag } : {} });
}

/** Takes a configured budget away on the version named by the tag. */
async function deleteLimit(key: string, reason: string, etag: string): Promise<void> {
  await api.del<unknown>(budgetPath(key), { reason }, { headers: etag ? { "If-Match": etag } : {} });
}

/** The shape of a key the store reads: three colon-separated parts, or global:<resource>. */
const KEY_PATTERN = /^(global:[a-z0-9_-]+|(site|domain|gateway|backend):([a-z0-9_.-]+|\*):[a-z0-9_-]+)$/;

/** How often the picture is refreshed: tokens come and go with every task. */
const BUDGETS_INTERVAL = 10 * 1000;

/** How many characters of reason a deletion keeps in the trail. */
const REASON_MINIMUM = 8;

/** How many holders a row names before it counts the rest. */
const HOLDERS_SHOWN = 4;

/* ------------------------------------------------------------- the screen */

export function Budgets() {
  const t = useT();
  const [creating, setCreating] = useState(false);
  const [picked, setPicked] = useState("");
  const [removing, setRemoving] = useState(false);

  const list = useQuery({
    queryKey: ["budgets"],
    queryFn: () => api.get<{ items: BudgetState[] }>("/api/v1/budgets"),
    refetchInterval: BUDGETS_INTERVAL,
  });
  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const canWrite = (me.data?.permissions ?? []).includes("budget.write");

  // An installation without the budgets answers so by name; that is a fact
  // about the installation, not a failure of the screen.
  if (list.error instanceof ApiError && list.error.status === 501) {
    return (
      <Card title={t("Budgets")}>
        <Empty icon="settings">{t("Budgets are disabled in this installation.")}</Empty>
      </Card>
    );
  }
  if (list.error) return <Problem>{String(list.error)}</Problem>;

  // Nothing has arrived until the answer has: every count below is unknown
  // rather than nought while the request is still out.
  const loaded = list.data !== undefined;
  const budgets = list.data?.items ?? [];
  const full = budgets.filter(saturated);
  const waited = budgets.filter((budget) => waiting(budget) > 0);
  const free = budgets.filter((budget) => !saturated(budget) && waiting(budget) === 0);
  const waitingJobs = loaded ? budgets.reduce((sum, budget) => sum + (budget.waiting_jobs ?? 0), 0) : undefined;
  const waitingTargets = loaded ? budgets.reduce((sum, budget) => sum + (budget.waiting_targets ?? 0), 0) : undefined;

  const byKind = (["global", "site", "domain", "gateway", "backend", "other"] as BudgetKind[])
    .map((kind) => ({ kind, value: budgets.filter((budget) => describeBudgetKey(budget.key).kind === kind).length }))
    .filter((entry) => entry.value > 0);
  const byClass = classTotals(budgets);

  const states: Segment[] = [
    { label: t("Keys"), value: loaded ? budgets.length : undefined, tone: "info" },
    { label: t("Saturated"), value: loaded ? full.length : undefined, tone: "error" },
    {
      label: t("With work waiting"),
      value: loaded ? waited.length : undefined,
      tone: "warn",
      to: waitingJobs ? "/next/jobs?state=queued" : waitingTargets ? "/next/campaigns" : undefined,
    },
    { label: t("With room"), value: loaded ? free.length : undefined, tone: "ok" },
  ];

  const chosen = budgets.find((one) => one.key === picked);

  return (
    <>
      {canWrite && (
        <HeadActions>
          <Button
            kind={creating ? "quiet" : "do"}
            onClick={() => setCreating(!creating)}
            testId="new-budget"
          >
            {creating ? t("Hide the form") : t("New budget")}
          </Button>
        </HeadActions>
      )}

      {creating && (
        <NewBudget existing={budgets.map((budget) => budget.key)} onDone={() => setCreating(false)} />
      )}

      <Board screen={BUDGETS_SCREEN} catalogue={BUDGETS} drawn={{
        keys: (
          <Kpi
            hero
            icon="settings"
            label={t("Keys")}
            value={loaded ? budgets.length : null}
            note={t("capacities somebody set")}
            testId="kpi-keys"
          />
        ),
        saturated: (
          <Kpi
            icon="power"
            label={t("Saturated")}
            value={loaded ? full.length : null}
            tone={full.length > 0 ? "error" : "ok"}
            note={t("no token free; the next operation waits")}
            testId="kpi-saturated"
          />
        ),
        waiting_jobs: (
          <Kpi
            icon="jobs"
            label={t("Waiting jobs")}
            value={waitingJobs ?? null}
            tone={waitingJobs ? "warn" : "ok"}
            note={t("queued until a token frees up")}
            to={waitingJobs ? "/next/jobs?state=queued" : undefined}
            testId="kpi-waiting-jobs"
          />
        ),
        waiting_hosts: (
          <Kpi
            icon="campaigns"
            label={t("Waiting hosts")}
            value={waitingTargets ?? null}
            tone={waitingTargets ? "warn" : "ok"}
            note={t("campaign hosts held before they start")}
            to={waitingTargets ? "/next/campaigns" : undefined}
            testId="kpi-waiting-hosts"
          />
        ),
        capacity: (
          <Card
            title={t("Capacity")}
            note={t("A key with no token free holds up every new operation under it.")}
          >
            <Band segments={states} testId="budget-states" />
          </Card>
        ),
        by_family: (
          <Card title={t("By family")} note={t("What the keys guard.")}>
            {!loaded
              ? <Bones rows={4} />
              : byKind.length === 0
                ? <Empty>{t("No budget is configured.")}</Empty>
                : <Bars items={byKind.map((entry) => ({ label: kindLabel(entry.kind, t), value: entry.value, tone: "info" as Tone }))} />}
          </Card>
        ),
        by_class: (
          <Card
            title={t("By class")}
            note={t("Tokens in use per class of work, over every budget; the age is how long the class waits before its fair share stops binding.")}
          >
            {!loaded
              ? <Bones rows={4} />
              : (
                <Bars items={byClass.map((item) => ({
                  label: <ClassLabel name={item.name} />,
                  value: item.tokens,
                  // A token the panel cannot place is still a token taken,
                  // and it is marked so nobody reads it as a class.
                  tone: (item.name === "unknown" ? "unknown" : "accent") as Tone,
                }))} />
              )}
          </Card>
        ),
        list: (
          <Card
            title={t("Budgets")}
            flush
            foot={loaded ? t("{n} keys", { n: budgets.length }) : undefined}
          >
            <Table
              rows={budgets}
              keyOf={(one) => one.key}
              rowTestId={(one) => `budget-${one.key}`}
              testId="budgets"
              loading={!loaded}
              empty={canWrite
                ? t("No budget is configured. Without one the fleet carries whatever is asked of it; set a capacity under a key such as global:mutations or site:*:packages with the button above.")
                : t("No budget is configured. Without one the fleet carries whatever is asked of it; a capacity is set with the API under a key such as global:mutations or site:*:packages.")}
              columns={[
                {
                  key: "key",
                  head: t("Key"),
                  cell: (one) => {
                    const described = describeBudgetKey(one.key);
                    return (
                      <TwoLine sub={describeScope(described, t)}>
                        <Button kind="word" onClick={() => setPicked(one.key)} testId={`pick-${one.key}`}>
                          <code>{one.key}</code>
                        </Button>
                        {described.pattern && (
                          <Pill tone="unknown" dot={false} title={t("The default policy of every key of this family nobody described separately.")}>
                            {t("default")}
                          </Pill>
                        )}
                      </TwoLine>
                    );
                  },
                },
                { key: "capacity", head: t("Capacity"), num: true, cell: (one) => one.capacity },
                {
                  key: "used",
                  head: t("In use"),
                  cell: (one) => (
                    <Meter
                      share={one.capacity > 0 ? one.used / one.capacity : 0}
                      tone={budgetTone(one)}
                      text={`${one.used} / ${one.capacity}`}
                    />
                  ),
                },
                { key: "holders", head: t("Held by"), minor: true, cell: (one) => <Holders holders={one.holders ?? []} /> },
                { key: "claimants", head: t("Claimants"), num: true, cell: (one) => one.claimants },
                { key: "share", head: t("Share per claimant"), num: true, minor: true, cell: (one) => fairShare(one.capacity, one.claimants) },
                {
                  key: "jobs",
                  head: t("Waiting jobs"),
                  num: true,
                  // A number with nowhere to go only raises the question it
                  // could answer, so a count above nought leads to the queue.
                  cell: (one) => (one.waiting_jobs > 0
                    ? <Tag to="/next/jobs?state=queued">{one.waiting_jobs}</Tag>
                    : one.waiting_jobs),
                },
                {
                  key: "targets",
                  head: t("Waiting hosts"),
                  num: true,
                  cell: (one) => ((one.waiting_targets ?? 0) > 0
                    ? <Tag to="/next/campaigns">{one.waiting_targets}</Tag>
                    : one.waiting_targets ?? 0),
                },
              ]}
            />
          </Card>
        ),
        budget: (
          <Card
            title={chosen ? <code>{chosen.key}</code> : t("The budget")}
            note={chosen ? describeScope(describeBudgetKey(chosen.key), t) : undefined}
            foot={chosen && canWrite
              ? (
                <Button kind="danger" onClick={() => setRemoving(true)} testId="budget-delete">
                  {t("Delete…")}
                </Button>
              )
              : undefined}
          >
            {!chosen
              ? <Empty>{t("Choose a key to read what holds it and to change its capacity.")}</Empty>
              : (
                <Stack>
                  <Facts>
                    <Fact label={t("Family")}>{kindLabel(describeBudgetKey(chosen.key).kind, t)}</Fact>
                    <Fact label={t("Scope")}>
                      {describeBudgetKey(chosen.key).pattern
                        ? <Pill tone="unknown" dot={false}>{t("every scope of the family")}</Pill>
                        : describeBudgetKey(chosen.key).scope || <Pill tone="neutral" dot={false}>{t("the whole fleet")}</Pill>}
                    </Fact>
                    <Fact label={t("Resource")}>{describeBudgetKey(chosen.key).resource}</Fact>
                    <Fact label={t("In use")}>
                      <Meter
                        share={chosen.capacity > 0 ? chosen.used / chosen.capacity : 0}
                        tone={budgetTone(chosen)}
                        text={`${chosen.used} / ${chosen.capacity}`}
                      />
                    </Fact>
                    <Fact label={t("Claimants")}>{chosen.claimants}</Fact>
                    <Fact label={t("Share per claimant")}>{fairShare(chosen.capacity, chosen.claimants)}</Fact>
                    <Fact label={t("Waiting jobs")}>{chosen.waiting_jobs}</Fact>
                    <Fact label={t("Waiting hosts")}>{chosen.waiting_targets ?? 0}</Fact>
                    <Fact label={t("Held by")}><Holders holders={chosen.holders ?? []} /></Fact>
                  </Facts>
                  {canWrite
                    ? <CapacityEditor budget={chosen} />
                    : <Note>{t("You may not change this budget: a site budget needs the right in its site, the rest in the whole fleet.")}</Note>}
                </Stack>
              )}
          </Card>
        ),
      }} />

      {/* Taking a capacity away is a decision: the key falls back to its
          family's default, or to no limit at all where none describes it. */}
      {removing && chosen && <DeleteBudget budget={chosen} onClose={() => setRemoving(false)} />}
    </>
  );
}

/* ------------------------------------------------------------- the words */

/** The family of a key in words; the key itself stays beside it. */
export function kindLabel(kind: BudgetKind, t: Translate): string {
  switch (kind) {
    case "global": return t("Fleet");
    case "site": return t("Site");
    case "domain": return t("Failure domain");
    case "gateway": return t("Gateway");
    case "backend": return t("Backup backend");
    default: return t("Other");
  }
}

/** The second line of a key: its family, its scope where it has one, its resource. */
function describeScope(described: BudgetKey, t: Translate): string {
  const parts = [kindLabel(described.kind, t)];
  if (described.scope && !described.pattern) parts.push(described.scope);
  parts.push(described.resource);
  return parts.join(" · ");
}

/* The class names and the promotion ages are the design's words, so they go
   through the catalogue one by one rather than as an expression. A class the
   API named on its own is shown by that name. */
export function classLabel(name: string, t: Translate): string {
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

/** A class with its promotion age beside it, where the design fixes one. */
function ClassLabel({ name }: { name: string }) {
  const t = useT();
  const known = CLASSES.find((item) => item.name === name);
  return (
    <span title={known ? t("How long this class waits before its fair share stops binding.") : undefined}>
      {known ? `${classLabel(name, t)} · ${promotionLabel(known.promotion, t)}` : classLabel(name, t)}
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

/** Who holds the tokens of one budget, newest first. */
function Holders({ holders }: { holders: BudgetHolder[] }) {
  const t = useT();
  if (holders.length === 0) return <>{t("nobody")}</>;
  const shown = holders.slice(0, HOLDERS_SHOWN);
  const rest = holders.length - shown.length;
  return (
    <Tags>
      {shown.map((holder) => {
        const link = holderLink(holder);
        const said = t("{what} · {class} · {n} tokens · {since}", {
          what: link ? holderName(link.label, t) : holder.owner,
          class: classLabel(holder.class, t),
          n: holder.tokens,
          since: relativeTime(holder.since),
        });
        return (
          <Tag key={holder.owner} to={link?.to} title={`${holder.owner} · ${holder.claimant} · ${absoluteTime(holder.since)}`}>
            {said}
          </Tag>
        );
      })}
      {rest > 0 && <Tag>{t("and {n} more", { n: rest })}</Tag>}
    </Tags>
  );
}

/* ------------------------------------------------------- the new capacity */

/**
 * A budget configured for the first time: the key, its capacity and the
 * note that says why.
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
      void queryClient.invalidateQueries({ queryKey: ["budgets"] });
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
      note={t("A capacity under a key the store reads: global:<resource> for the whole fleet, or site, domain, gateway or backend, a scope or an asterisk for the family's default, and the resource - mutations, reads, packages, reboot, units, backup.")}
      foot={
        <Actions>
          <Button onClick={() => { setMessage(""); create.mutate(); }} disabled={!ready || create.isPending} testId="new-budget-save">
            {create.isPending ? t("saving…") : t("Set the capacity")}
          </Button>
          <Button kind="quiet" onClick={onDone} disabled={create.isPending}>{t("Cancel")}</Button>
          {message && <Problem>{message}</Problem>}
        </Actions>
      }
    >
      <Fields>
        <Field
          label={t("Key")}
          hint={duplicate
            ? t("This key is already configured; open it in the list.")
            : trimmed && !validKey
              ? t("Not a budget key: global:mutations, site:warsaw:packages, site:*:reads, domain:rack-1:units, backend:offsite:backup.")
              : t("Exact for one scope, or with an asterisk as the default every scope of the family gets.")}
        >
          <input
            value={key}
            placeholder="site:*:packages"
            onChange={(event) => setKey(event.target.value)}
            autoFocus
            aria-invalid={Boolean(trimmed) && (!validKey || duplicate)}
            data-testid="new-budget-key"
          />
        </Field>
        <Field label={t("Capacity")} hint={t("Tokens at once under this key; at least 1. To stop the work, pause the campaign instead.")}>
          <input
            type="number"
            min={1}
            step={1}
            value={capacity}
            onChange={(event) => setCapacity(event.target.value)}
            aria-invalid={!validCapacity}
            data-testid="new-budget-capacity"
          />
        </Field>
        <Field label={t("Note (kept in the audit trail)")} hint={t("Why this capacity: the link of the site, the disk of the backend.")} wide>
          <input value={note} onChange={(event) => setNote(event.target.value)} data-testid="new-budget-note" />
        </Field>
      </Fields>
    </Card>
  );
}

/* --------------------------------------------------- the capacity in place */

/**
 * The capacity of one budget, changed on the version it was read at.
 *
 * The write carries the tag the record was read with: two administrators
 * cannot overwrite each other silently, and a refusal says to read again.
 */
function CapacityEditor({ budget }: { budget: BudgetState }) {
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
  // The note of the last change is the starting point of this one: a policy
  // is usually adjusted, not rewritten.
  useEffect(() => {
    if (record.data) setNote(record.data.limit.note);
  }, [record.data]);
  // Another key chosen is another record: the form follows the choice.
  useEffect(() => {
    setCapacity(String(budget.capacity));
    setMessage("");
  }, [budget.key]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = useMutation({
    mutationFn: () => writeLimit(budget.key, { capacity: Number(capacity), note: note.trim() }, record.data?.etag ?? ""),
    onSuccess: () => {
      setMessage("");
      void queryClient.invalidateQueries({ queryKey: ["budgets"] });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 412) {
        setMessage(t("The budget changed since it was read; it is read again, check the numbers and save once more."));
        void record.refetch();
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
    <Stack>
      <Fields>
        <Field label={t("Capacity")} hint={t("Tokens at once under this key; at least 1. To stop the work, pause the campaign instead.")}>
          <input
            type="number"
            min={1}
            step={1}
            value={capacity}
            onChange={(event) => setCapacity(event.target.value)}
            aria-label={t("Capacity")}
            data-testid="capacity"
          />
        </Field>
        <Field label={t("Note (kept in the audit trail)")} hint={t("Why this capacity: the link of the site, the disk of the backend.")} wide>
          <input value={note} onChange={(event) => setNote(event.target.value)} aria-label={t("Note")} data-testid="capacity-note" />
        </Field>
      </Fields>
      <Actions>
        <Button onClick={() => save.mutate()} disabled={!ready || save.isPending} testId="capacity-save">{t("Save")}</Button>
        <Button
          kind="quiet"
          onClick={() => { setCapacity(String(budget.capacity)); setNote(record.data?.limit.note ?? ""); setMessage(""); }}
          disabled={save.isPending}
        >
          {t("Discard changes")}
        </Button>
      </Actions>
      {record.error && <Note>{record.error instanceof Error ? record.error.message : String(record.error)}</Note>}
      {record.data && (
        <Note>
          {t("Last changed {when}", { when: relativeTime(record.data.limit.updated_at) })}
        </Note>
      )}
      {message && <Problem>{message}</Problem>}
    </Stack>
  );
}

/* --------------------------------------------------------- the deletion */

/** Taking one budget away, on the version it was read at and with a reason. */
function DeleteBudget({ budget, onClose }: { budget: BudgetState; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const described = describeBudgetKey(budget.key);

  const remove = useMutation({
    mutationFn: async () => {
      const { etag } = await readLimit(budget.key);
      await deleteLimit(budget.key, reason.trim(), etag);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["budgets"] });
      toast.success(t("Budget {key} deleted.", { key: budget.key }));
      onClose();
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

  return (
    <Modal
      title={t("Delete the budget {key}?", { key: budget.key })}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={remove.isPending}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={reason.trim().length < REASON_MINIMUM || remove.isPending}
            onClick={() => remove.mutate()}
            testId="budget-delete-confirm"
          >
            {remove.isPending ? t("Deleting…") : t("Delete")}
          </Button>
        </>
      }
    >
      <Stack>
        <Note>
          {described.pattern
            ? t("The default of this family goes away: a site nobody described separately is then unlimited for this resource.")
            : t("The key falls back to the default of its family, or to no limit at all when no default describes it. A deleted budget is not a budget of zero.")}
        </Note>
        {budget.used > 0 && (
          <Problem>{t("{n} tokens are held right now; the server will refuse until the work finishes.", { n: budget.used })}</Problem>
        )}
        <Fields>
          <Field label={t("Reason (kept in the trail)")} hint={t("At least 8 characters.")} wide>
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="budget-delete-reason" />
          </Field>
        </Fields>
      </Stack>
    </Modal>
  );
}

/* ------------------------------------------------------------- the board */

export const BUDGETS_SCREEN = "next_budgets";

export const BUDGETS: BoardEntry[] = [
  { key: "keys", title: "How many keys", width: 3, height: 1 },
  { key: "saturated", title: "Saturated", width: 3, height: 1 },
  { key: "waiting_jobs", title: "Waiting jobs", width: 3, height: 1 },
  { key: "waiting_hosts", title: "Waiting hosts", width: 3, height: 1 },
  { key: "capacity", title: "Capacity", width: 6, height: 2 },
  { key: "by_family", title: "By family", width: 3, height: 2 },
  { key: "by_class", title: "By class", width: 3, height: 2 },
  { key: "list", title: "Budgets", width: 12, height: 5 },
  { key: "budget", title: "The budget", width: 12, height: 4 },
];
