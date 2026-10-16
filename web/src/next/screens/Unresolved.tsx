import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type {
  Unresolved as UnresolvedItem,
  UnresolvedCounts,
  UnresolvedKind,
  UnresolvedOperations,
  UnresolvedRulingKind,
  UnresolvedRulings,
} from "../../lib/types";
import { useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Card, Field, Fields, Find, Kpi, Modal, Note, Pager, Pill, Problem, Seg, Table,
  Toolbar, TwoLine, type Tone,
} from "../kit";

/**
 * What the fleet left in a state nobody could confirm.
 *
 * Nothing here ages out. The dashboard counts the failures of the last
 * day, so an operation nobody could confirm used to leave the screen
 * because a day had passed - and the pilot is judged against "no
 * unexplained unknown outcome", which cannot be read off a screen that
 * forgets. An item leaves this list when somebody rules on it, and the
 * ruling is a record of its own: the task keeps the outcome the fleet
 * reported, because an operator's reading is a second fact about the same
 * attempt and not a correction of the first.
 */

/**
 * The two questions, kept apart.
 *
 * Summing them would read the same for "forty changes we cannot confirm
 * happened" and "forty changes we cannot confirm held", and those are
 * different work. Hosts are counted apart from operations for the same
 * reason: one host with forty of them is not forty hosts with one each.
 */
export function describeKind(kind: UnresolvedKind): { title: string; question: string } {
  return kind === "outcome_unknown"
    ? { title: "Outcome unknown", question: "Did it happen?" }
    : { title: "Applied, unverified", question: "Did it hold?" };
}

/**
 * The colour of each uncertainty, which is the other place they must not
 * read as one thing.
 *
 * An outcome nobody knows is unknown and not a fault: nothing says the
 * change failed. A change applied and never verified is a warning,
 * because something was done to the host and nobody can say it stuck.
 */
export function kindTone(kind: UnresolvedKind): Tone {
  return kind === "outcome_unknown" ? "unknown" : "warn";
}

/** Whether a fleet has anything open at all. */
export function anythingOpen(counts: UnresolvedCounts): boolean {
  return counts.outcome_unknown_operations > 0 || counts.applied_unverified_operations > 0;
}

/**
 * The most attempts one batch ruling may carry: one of the server's own
 * caps (jobs.MaxPage), so a batch is named rather than unbounded.
 */
export const BATCH_LIMIT = 500;

/** What the verifier expected and what it read off the host. */
export type VerifierReading = {
  expected?: string;
  observed?: string;
  reason?: string;
  verified?: boolean;
};

/**
 * The verifier's reading, which crosses the wire as base64 because the
 * server writes it as bytes.
 *
 * Decoded through TextDecoder and not atob alone: atob gives one byte per
 * character, so a path with a non-ASCII character in it would come out
 * mangled in the one place an operator is reading it to find that
 * character. Anything unreadable is no reading at all - this is
 * host-shaped data, and a screen must not fall over because a host sent
 * something odd.
 */
export function verifierReading(raw: unknown): VerifierReading | null {
  if (raw && typeof raw === "object") return raw as VerifierReading;
  if (typeof raw !== "string" || raw === "") return null;
  try {
    const bytes = Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return parsed && typeof parsed === "object" ? (parsed as VerifierReading) : null;
  } catch {
    return null;
  }
}

/**
 * Which of three things the row actually says, which is not the same as
 * which question is open.
 *
 * "Did it hold?" covers two situations that call for different work: a
 * host that answered and shows something else - where the panel KNOWS the
 * change did not hold - and a host that could not be read at all. The
 * first is a conclusion, the second is the absence of one, and a screen
 * that names them alike reads as an excuse instead of a diagnosis.
 */
export type ReadingKind = "did_not_hold" | "could_not_read" | "outcome_unknown";

/**
 * The reading the server decided, with the old rule as a fallback.
 *
 * The rule lives in SQL because the list is paged and counted there: a
 * screen that classified while the server counted would put numbers above
 * a list that disagrees with them, and an operator who sees that learns to
 * trust neither. What is left here is reading the field - and, for a row
 * from a panel that predates it, the old derivation, so an upgrade in
 * progress shows rows rather than blanks.
 */
export function readingKind(
  kind: UnresolvedKind,
  reading: VerifierReading | null,
  said?: string,
): ReadingKind {
  if (said === "did_not_hold" || said === "could_not_read" || said === "outcome_unknown") {
    return said;
  }
  if (kind === "outcome_unknown") return "outcome_unknown";
  if (!reading || !reading.observed || reading.observed === "unknown") return "could_not_read";
  return "did_not_hold";
}

/** The rulings an operator may record, in the order the form offers them. */
const RULINGS: { value: UnresolvedRulingKind; label: string }[] = [
  { value: "confirmed_applied", label: "The change is there" },
  { value: "confirmed_not_applied", label: "The change is not there" },
  { value: "accepted_unknown", label: "It will not be known, and that is accepted" },
];

export function Unresolved() {
  const t = useT();
  const client = useQueryClient();
  const [kind, setKind] = useState<UnresolvedKind | "">("");
  // Which of the three readings to show, or all of them. It narrows inside
  // the question rather than beside it, so choosing one clears the other
  // control: two narrowings that overlap would let an operator ask for a
  // combination that cannot hold anything and read the empty answer as
  // good news.
  const [reading, setReading] = useState<ReadingKind | "">("");
  const [size, setSize] = useState(50);
  const [page, setPage] = useState(1);
  // What is typed, and what has been asked of the server. Two states on
  // purpose: a request per keystroke over a list of thousands is a screen
  // that fights the typing.
  const [typed, setTyped] = useState("");
  const [search, setSearch] = useState("");
  const [ruling, setRuling] = useState<UnresolvedItem | null>(null);
  const [batch, setBatch] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(typed.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [typed]);

  const query = new URLSearchParams({ limit: String(size), offset: String((page - 1) * size) });
  if (kind) query.set("kind", kind);
  if (reading) query.set("reading", reading);
  if (search) query.set("q", search);

  const list = useQuery({
    queryKey: ["unresolved", query.toString()],
    queryFn: () => api.get<UnresolvedOperations>(`/api/v1/unresolved?${query}`),
  });

  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  // A page that stopped existing - the list shrank because somebody ruled
  // on it - is not an error to show the operator, it is the last page.
  //
  // Only on an answer about THIS page, though. While the next page is being
  // fetched the total belongs to the previous one, and a clamp that fired
  // then would take a reader back to where they came from the moment they
  // asked to move - which is what pressing 2 did.
  const settled = list.data !== undefined && !list.isPlaceholderData;
  useEffect(() => {
    if (settled && page > pages) setPage(pages);
  }, [settled, page, pages]);

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  const counts = list.data?.counts;
  const items = list.data?.items ?? [];
  const showKind = (next: UnresolvedKind | "") => { setKind(next); setReading(""); setPage(1); };
  const showReading = (next: ReadingKind | "") => { setReading(next); setKind(""); setPage(1); };

  /* What the table says when it has no rows. The fleet's state is read
     from the counts and never from the rows in front of the operator: a
     narrowed list that happens to be empty is not a fleet with nothing
     open, and saying so would be the one lie this screen exists to
     prevent. */
  const empty = list.isLoading
    ? t("Loading…")
    : search !== ""
      ? t("No unconfirmed operation matches what you typed.")
      : counts && anythingOpen(counts)
        ? t("Nothing of this kind is open.")
        : t("Every operation this fleet reported has an outcome somebody could confirm.");

  /* A count the server did not send is unknown, and unknown is an em dash
     and the word - never a nought. The two readings inside "did it hold?"
     are the ones a panel mid-upgrade leaves out, so they are the ones this
     matters for. */
  const hostsNote = (hosts: number | undefined) =>
    typeof hosts === "number" ? t("on {n} hosts", { n: hosts }) : undefined;

  return (
    <>
      <Board screen={UNRESOLVED_SCREEN} catalogue={UNRESOLVED} drawn={{
        happen: (
          <Kpi
            icon="help"
            label={t("Did it happen?")}
            value={counts?.outcome_unknown_operations ?? null}
            tone={counts && counts.outcome_unknown_operations > 0 ? "unknown" : "ok"}
            note={hostsNote(counts?.outcome_unknown_hosts)}
            testId="count-outcome_unknown"
          />
        ),
        hold: (
          <Kpi
            icon="check"
            label={t("Did it hold?")}
            value={counts?.applied_unverified_operations ?? null}
            tone={counts && counts.applied_unverified_operations > 0 ? "warn" : "ok"}
            note={hostsNote(counts?.applied_unverified_hosts)}
            testId="count-applied_unverified"
          />
        ),
        notheld: (
          <Kpi
            icon="vulnerabilities"
            label={t("Did not hold")}
            value={counts?.did_not_hold_operations ?? null}
            tone={counts?.did_not_hold_operations ? "error" : "ok"}
            note={hostsNote(counts?.did_not_hold_hosts)}
            testId="count-did_not_hold"
          />
        ),
        unreadable: (
          <Kpi
            icon="reads"
            label={t("Could not be read")}
            value={counts?.could_not_read_operations ?? null}
            tone={counts?.could_not_read_operations ? "unknown" : "ok"}
            note={hostsNote(counts?.could_not_read_hosts)}
            testId="count-could_not_read"
          />
        ),
        list: (
          <Card
            title={t("Unconfirmed operations")}
            note={t("Operations the fleet could not confirm. Nothing here disappears with time: an item leaves this list when somebody rules on it, and the ruling is recorded beside the task rather than in place of its outcome.")}
            flush
            tools={total > 0 ? (
              <button type="button" className="fl-quiet fl-small" data-testid="rule-on-all"
                      onClick={() => { setBatch(true); setRuling(null); }}>
                {t("Rule on all {n} of them", { n: total })}
              </button>
            ) : undefined}
            foot={<Pager page={page} size={size} total={total} onPage={setPage} onSize={setSize} />}
          >
            <Toolbar
              end={
                <Seg<ReadingKind | "">
                  value={reading}
                  onChange={showReading}
                  options={[
                    { value: "", label: t("Any reading") },
                    { value: "did_not_hold", label: t("Did not hold") },
                    { value: "could_not_read", label: t("Could not be read") },
                  ]}
                />
              }
            >
              <Find value={typed} onChange={setTyped} placeholder={t("a host or an operation")}
                    testId="unresolved-search" />
              <Seg<UnresolvedKind | "">
                value={kind}
                onChange={showKind}
                options={[
                  { value: "", label: t("Both") },
                  { value: "outcome_unknown", label: t("Did it happen?") },
                  { value: "applied_unverified", label: t("Did it hold?") },
                ]}
              />
            </Toolbar>
            <Table
              rows={items}
              keyOf={(one) => one.attempt_id}
              rowTestId={(one) => `unresolved-${one.attempt_id}`}
              empty={empty}
              columns={[
                { key: "host", head: t("Host"), cell: (one) => (
                  <Link to={`/next/hosts/${one.host_id}`}>{one.hostname || one.host_id}</Link>
                ) },
                // Straight to the task and whatever evidence it holds: the
                // operator's next move is to read it, not to search for it.
                { key: "action", head: t("Operation"), tight: true, cell: (one) => (
                  <Link to={`/jobs/${one.job_id}`}>{one.action}</Link>
                ) },
                { key: "question", head: t("Question"), cell: (one) => (
                  <Pill tone={kindTone(one.kind)} title={t(describeKind(one.kind).title)}>
                    {t(describeKind(one.kind).question)}
                  </Pill>
                ) },
                { key: "reason", head: t("Reason"), cell: (one) => <Reason item={one} /> },
                { key: "since", head: t("Since"), cell: (one) => (
                  <span title={absoluteTime(one.first_seen)}>{relativeTime(one.first_seen)}</span>
                ) },
                { key: "checked", head: t("Last looked at"), minor: true, cell: (one) => (
                  one.last_checked_at
                    ? <span title={absoluteTime(one.last_checked_at)}>{relativeTime(one.last_checked_at)}</span>
                    // Not "never": nobody has tried again since, which is a
                    // fact about the panel and not about the host.
                    : <Pill tone="unknown">{t("not since")}</Pill>
                ) },
                { key: "rule", actions: true, cell: (one) => (
                  <button type="button" className="fl-quiet fl-small"
                          data-testid={`rule-${one.attempt_id}`}
                          onClick={() => { setRuling(one); setBatch(false); }}>
                    {t("Rule on this")}
                  </button>
                ) },
              ]}
            />
          </Card>
        ),
      }} />

      {/* A ruling is a decision that goes in the trail and carries a
          reason, which is what the dialog is for. It is not a form
          somebody wants the list behind: the row it is about is named in
          the dialog itself. */}
      {ruling && (
        <RulingForm
          item={ruling}
          onClose={() => setRuling(null)}
          onRuled={() => {
            setRuling(null);
            void client.invalidateQueries({ queryKey: ["unresolved"] });
          }}
        />
      )}

      {batch && (
        <BatchRulingForm
          kind={kind}
          reading={reading}
          search={search}
          total={total}
          onClose={() => setBatch(false)}
          onRuled={() => {
            setBatch(false);
            setPage(1);
            void client.invalidateQueries({ queryKey: ["unresolved"] });
          }}
        />
      )}
    </>
  );
}

/**
 * What the row says, before what the host said.
 *
 * The screen used to name a category of uncertainty where it could name a
 * fact, and the owner read the tab without being able to tell what it was
 * telling him. What is composed here is in the operator's language, from
 * the two fields the verifier recorded; the host's own sentence stays
 * underneath and marked as the host's, because it is evidence and it is in
 * the language the agent writes its log in.
 */
function Reason({ item }: { item: UnresolvedItem }) {
  const t = useT();
  const reading = verifierReading(item.verification);
  const said = readingKind(item.kind, reading, item.reading);
  const verdict = said === "did_not_hold"
    ? t("The change did not hold.")
    : said === "could_not_read"
      ? t("The host could not be read, so the state is unknown.")
      : t("The agent restarted while the host was carrying this operation, so whether it finished is unknown.");
  return (
    <div data-testid={`reading-${item.attempt_id}`} data-reading={said}>
      <TwoLine
        sub={said === "did_not_hold" ? (
          <>
            <span className="fl-faint">{t("Ordered")}</span>{" "}
            <code>{reading?.expected ?? "—"}</code>
            {" · "}
            <span className="fl-faint">{t("On the host")}</span>{" "}
            <code>{reading?.observed ?? "—"}</code>
          </>
        ) : undefined}
      >
        {verdict}
      </TwoLine>
      {item.reason ? (
        <Note><span data-testid="reason-host-words">{t("what the host itself said")}: {item.reason}</span></Note>
      ) : null}
    </div>
  );
}

/** The three rulings, as the one control both forms ask with. */
function Verdict({ value, onChange, testId }: {
  value: UnresolvedRulingKind;
  onChange: (value: UnresolvedRulingKind) => void;
  testId: string;
}) {
  const t = useT();
  return (
    <Field label={t("What did you find?")}>
      <select value={value} data-testid={testId}
              onChange={(event) => onChange(event.target.value as UnresolvedRulingKind)}>
        {RULINGS.map((one) => <option key={one.value} value={one.value}>{t(one.label)}</option>)}
      </select>
    </Field>
  );
}

/**
 * The form for one ruling.
 *
 * The basis is required, and the form says why: a ruling with none is a
 * screen being cleared. The three rulings are deliberately not "ok / not
 * ok" - accepting that the outcome will never be known is a decision too,
 * one with a name and a date on it, which is the difference between this
 * and an item ageing off a dashboard.
 */
function RulingForm({ item, onClose, onRuled }: {
  item: UnresolvedItem;
  onClose: () => void;
  onRuled: () => void;
}) {
  const t = useT();
  const [verdict, setVerdict] = useState<UnresolvedRulingKind>("confirmed_applied");
  const [basis, setBasis] = useState("");

  const record = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/unresolved/${item.attempt_id}/ruling`, {
        kind: item.kind,
        ruling: verdict,
        basis,
      }),
    onSuccess: onRuled,
  });

  return (
    <Modal
      title={t("Rule on this operation")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose}>{t("Cancel")}</button>
          <button type="button" data-testid="ruling-save"
                  disabled={basis.trim() === "" || record.isPending}
                  onClick={() => record.mutate()}>
            {t("Record the ruling")}
          </button>
        </>
      }
    >
      <Note>
        {t("The task keeps the outcome the fleet reported. What you write here is recorded beside it, with your name and the time.")}
      </Note>
      <p>
        <code>{item.action}</code>{" · "}{item.hostname || item.host_id}
      </p>
      <Fields>
        <Verdict value={verdict} onChange={setVerdict} testId="ruling-verdict" />
        <Field label={t("On what basis?")} wide
               hint={t("Required: a ruling without one is a screen being cleared.")}>
          <textarea autoFocus rows={2} value={basis} data-testid="ruling-basis"
                    placeholder={t("What you read, and where you looked.")}
                    onChange={(event) => setBasis(event.target.value)} />
        </Field>
      </Fields>
      {record.error ? <Problem>{String(record.error)}</Problem> : null}
    </Modal>
  );
}

/**
 * One ruling against every attempt the filter holds.
 *
 * It asks for the basis exactly as the single ruling does. A button that
 * cleared thirty-one rows without a word would turn this screen into a
 * counter to be zeroed, and then nobody could answer "who decided that,
 * and on what grounds" - which is the question the screen exists to keep
 * answerable.
 */
function BatchRulingForm({ kind, reading, search, total, onClose, onRuled }: {
  kind: UnresolvedKind | "";
  reading: ReadingKind | "";
  search: string;
  total: number;
  onClose: () => void;
  onRuled: () => void;
}) {
  const t = useT();
  const [verdict, setVerdict] = useState<UnresolvedRulingKind>("confirmed_not_applied");
  const [basis, setBasis] = useState("");
  const [done, setDone] = useState<UnresolvedRulings | null>(null);

  const record = useMutation({
    mutationFn: async () => {
      // The attempts this screen can see, named one by one. The server does
      // not re-read the filter: it would then also rule on whatever arrived
      // between this list being fetched and the button being pressed.
      const query = new URLSearchParams({ limit: String(BATCH_LIMIT), offset: "0" });
      if (kind) query.set("kind", kind);
      if (reading) query.set("reading", reading);
      // The same narrowing the screen is showing: "all of them" means all of
      // what the operator is looking at, not all of the fleet's.
      if (search) query.set("q", search);
      const page = await api.get<UnresolvedOperations>(`/api/v1/unresolved?${query}`);
      return api.post<UnresolvedRulings>("/api/v1/unresolved/rulings", {
        kind: kind || "applied_unverified",
        ruling: verdict,
        basis,
        attempt_ids: page.items.map((one) => one.attempt_id),
      });
    },
    onSuccess: (answer) => {
      // Not closed on success: what could not be ruled on has to be read,
      // and a form that vanished would take the refusals with it.
      if (answer.refused && answer.refused.length > 0) setDone(answer);
      else onRuled();
    },
  });

  if (done) {
    return (
      <Modal
        title={t("Rule on all {n} of them", { n: Math.min(total, BATCH_LIMIT) })}
        onClose={onRuled}
        actions={<button type="button" onClick={onRuled}>{t("Close")}</button>}
      >
        <p data-testid="batch-ruled">{t("{n} of {attempts} were ruled on.", { n: done.ruled, attempts: done.attempts })}</p>
        <Note>{t("These were not, and are still on the list:")}</Note>
        <ul>
          {done.refused?.map((one) => (
            <li key={one.attempt_id}><code>{one.attempt_id}</code> — {one.message}</li>
          ))}
        </ul>
      </Modal>
    );
  }

  return (
    <Modal
      title={t("Rule on all {n} of them", { n: Math.min(total, BATCH_LIMIT) })}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose}>{t("Cancel")}</button>
          <button type="button" data-testid="batch-save"
                  disabled={basis.trim() === "" || record.isPending}
                  onClick={() => record.mutate()}>
            {t("Record the ruling for all of them")}
          </button>
        </>
      }
    >
      <Note>
        {total > BATCH_LIMIT
          ? t("A batch carries at most {cap}; the rest stay on the list and can be ruled on next.", { cap: BATCH_LIMIT })
          : t("One ruling, written once and recorded against every one of them separately.")}
      </Note>
      <Fields>
        <Verdict value={verdict} onChange={setVerdict} testId="batch-verdict" />
        <Field label={t("On what basis?")} wide
               hint={t("Required, and recorded against every one of them: a ruling without one is a screen being cleared.")}>
          <textarea autoFocus rows={2} value={basis} data-testid="batch-basis"
                    placeholder={t("What you read, and where you looked.")}
                    onChange={(event) => setBasis(event.target.value)} />
        </Field>
      </Fields>
      {record.error ? <Problem>{String(record.error)}</Problem> : null}
    </Modal>
  );
}

export const UNRESOLVED_SCREEN = "next_unresolved";

export const UNRESOLVED: BoardEntry[] = [
  { key: "happen", title: "Did it happen?", width: 3, height: 2 },
  { key: "hold", title: "Did it hold?", width: 3, height: 2 },
  { key: "notheld", title: "Did not hold", width: 3, height: 2 },
  { key: "unreadable", title: "Could not be read", width: 3, height: 2 },
  { key: "list", title: "Unconfirmed operations", width: 12, height: 8 },
];
