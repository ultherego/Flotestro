import { Fragment, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type {
  Unresolved as UnresolvedItem,
  UnresolvedCounts,
  UnresolvedKind,
  UnresolvedOperations,
  UnresolvedRulingKind,
  UnresolvedRulings,
} from "../lib/types";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { useT } from "../i18n";

/**
 * What the fleet left in a state nobody could confirm.
 *
 * The dashboard counts failed tasks of the last 24 hours, so until now an
 * operation nobody could confirm left the screen because a day had passed.
 * For a product whose first rule is that unknown is not zero, that was the
 * one place the rule did not hold - and the pilot is judged against "no
 * unexplained unknown outcome", which cannot be read off a screen that
 * forgets.
 *
 * Nothing here ages out. An item leaves the list when somebody rules on it,
 * and the ruling is a row of its own: the job keeps the outcome the fleet
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

/** Whether a fleet has anything open at all. */
export function anythingOpen(counts: UnresolvedCounts): boolean {
  return counts.outcome_unknown_operations > 0 || counts.applied_unverified_operations > 0;
}

/** What the verifier expected and what it read off the host. */
export type VerifierReading = {
  expected?: string;
  observed?: string;
  reason?: string;
  verified?: boolean;
};

/**
 * The verifier's reading, which crosses the wire as base64 because the server
 * writes it as bytes.
 *
 * Decoded through TextDecoder and not atob alone: atob gives one byte per
 * character, so a path with a non-ASCII character in it would come out
 * mangled in the one place an operator is reading it to find that character.
 * Anything unreadable is no reading at all - this is host-shaped data, and a
 * screen must not fall over because a host sent something odd.
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
 * Which of three things the row actually says, which is not the same as which
 * question is open.
 *
 * "did it hold?" covers two situations that call for different work and had
 * been reading as one: a host that answered and shows something else - where
 * the panel KNOWS the change did not hold - and a host that could not be read
 * at all. The first is a conclusion, the second is the absence of one, and a
 * screen that names them the same way reads as an excuse instead of a
 * diagnosis.
 */
export type ReadingKind = "did_not_hold" | "could_not_read" | "outcome_unknown";

export function readingKind(kind: UnresolvedKind, reading: VerifierReading | null): ReadingKind {
  if (kind === "outcome_unknown") return "outcome_unknown";
  if (!reading || !reading.observed || reading.observed === "unknown") return "could_not_read";
  return "did_not_hold";
}

/** The most attempts one batch ruling may carry, as the server caps it. */
export const BATCH_LIMIT = 500;

/** The page sizes the screen offers. */
export const PAGE_SIZES = [5, 10, 20, 50, 100];

/**
 * The page numbers to show, with a gap where the numbers are skipped.
 *
 * Always the first and the last, always the ones either side of the current
 * one: a list of thirty pages does not fit, and a reader needs to know how
 * far the list goes as much as where in it they are.
 */
export function pageNumbers(current: number, pages: number, around = 2): (number | "gap")[] {
  if (pages < 1) return [];
  const wanted = new Set<number>([1, pages]);
  for (let n = current - around; n <= current + around; n++) {
    if (n >= 1 && n <= pages) wanted.add(n);
  }
  const sorted = [...wanted].sort((a, b) => a - b);
  const out: (number | "gap")[] = [];
  sorted.forEach((n, i) => {
    // A single skipped number is printed rather than hidden behind a gap that
    // takes as much room as it would.
    if (i > 0 && n - sorted[i - 1] === 2) out.push(n - 1);
    else if (i > 0 && n - sorted[i - 1] > 1) out.push("gap");
    out.push(n);
  });
  return out;
}

export default function Unresolved() {
  const t = useT();
  const client = useQueryClient();
  const [kind, setKind] = useState<UnresolvedKind | "">("");
  const [size, setSize] = useState(20);
  const [page, setPage] = useState(1);
  // The attempt whose ruling is open, or none. One at a time: the form is a
  // row of the table and two of them would push the list apart.
  const [ruling, setRuling] = useState<string | null>(null);
  const [batch, setBatch] = useState(false);

  const { data, error } = useQuery({
    queryKey: ["unresolved", kind, size, page],
    queryFn: () => {
      const query = new URLSearchParams({ limit: String(size), offset: String((page - 1) * size) });
      if (kind) query.set("kind", kind);
      return api.get<UnresolvedOperations>(`/api/v1/unresolved?${query}`);
    },
  });

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  // A page that stopped existing - the list shrank because somebody ruled on
  // it - is not an error to show the operator, it is the last page.
  useEffect(() => {
    if (page > pages) setPage(pages);
  }, [page, pages]);

  if (error) return <ErrorBox error={error} />;
  const counts = data?.counts;
  const items = data?.items ?? [];
  const show = (next: UnresolvedKind | "") => {
    setKind(next);
    setPage(1);
  };

  return (
    <>
      <PageHeader
        title={t("Needs confirmation")}
        description={t("Operations the fleet could not confirm.")}
        help={<p>{t("Operations the fleet could not confirm. Nothing here disappears with time: an item leaves this list when somebody rules on it, and the ruling is recorded beside the task rather than in place of its outcome.")}</p>}
        actions={counts && (
          // Beside the title, not in two cards above the table: the filter is
          // three words and two numbers, and as cards it pushed the first row
          // of the list a quarter of a screen down.
          //
          // Three buttons and not a total: the two questions ask for
          // different work, so each names its own count. The badge in the
          // navigation does add them, because that one is the length of a
          // queue - a different question from this one.
          <>
          <div className="segmented" role="group" aria-label={t("Which question to show")}>
            <button
              type="button"
              className={kind === "" ? "active" : ""}
              onClick={() => show("")}
              aria-pressed={kind === ""}
              data-testid="filter-both"
            >
              {t("Both")}
            </button>
            {(["outcome_unknown", "applied_unverified"] as UnresolvedKind[]).map((one) => {
              const described = describeKind(one);
              const operations =
                one === "outcome_unknown"
                  ? counts.outcome_unknown_operations
                  : counts.applied_unverified_operations;
              const hosts =
                one === "outcome_unknown"
                  ? counts.outcome_unknown_hosts
                  : counts.applied_unverified_hosts;
              return (
                <button
                  key={one}
                  type="button"
                  className={kind === one ? "active" : ""}
                  onClick={() => show(one)}
                  aria-pressed={kind === one}
                  data-testid={`filter-${one}`}
                  title={t(described.title)}
                >
                  {t(described.question)}{" "}
                  <span className="fp-chips" data-testid={`count-${one}`}>
                    <span className={operations > 0 ? "badge warn" : "badge"}>
                      {t("{n} operations", { n: operations })}
                    </span>
                    <span className={hosts > 0 ? "badge warn" : "badge"}>
                      {t("on {n} hosts", { n: hosts })}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
          {total > 0 && (
            <button
              type="button"
              className="secondary"
              onClick={() => { setBatch(true); setRuling(null); }}
              data-testid="rule-on-all"
            >
              {t("Rule on all {n} of them", { n: total })}
            </button>
          )}
          </>
        )}
      />

      {batch && (
        <BatchRulingForm
          kind={kind}
          total={total}
          onClose={() => setBatch(false)}
          onRuled={() => {
            setBatch(false);
            setPage(1);
            client.invalidateQueries({ queryKey: ["unresolved"] });
          }}
        />
      )}

      {items.length === 0 ? (
        <Empty>
          {counts && anythingOpen(counts)
            ? t("Nothing of this kind is open.")
            : t("Every operation this fleet reported has an outcome somebody could confirm.")}
        </Empty>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th scope="col">{t("Host")}</th>
              <th scope="col">{t("Operation")}</th>
              <th scope="col">{t("Question")}</th>
              <th scope="col">{t("Reason")}</th>
              <th scope="col">{t("Since")}</th>
              <th scope="col">{t("Last looked at")}</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <Fragment key={item.attempt_id}>
                <tr>
                  <td>
                    <Link to={`/hosts/${item.host_id}/overview`}>{item.hostname || item.host_id}</Link>
                  </td>
                  <td>
                    {/* Straight to the task and whatever evidence it holds: the
                        operator's next move is to read it, not to search for it. */}
                    <Link to={`/jobs/${item.job_id}`}>{item.action}</Link>
                  </td>
                  <td>{t(describeKind(item.kind).question)}</td>
                  <td><ReasonCell item={item} /></td>
                  <td><Time value={item.first_seen} /></td>
                  <td>
                    {item.last_checked_at ? (
                      <Time value={item.last_checked_at} />
                    ) : (
                      /* Not "never": nobody has tried again since, which is a
                         fact about the panel and not about the host. */
                      <span className="badge unknown">{t("not since")}</span>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="secondary"
                      onClick={() => setRuling(ruling === item.attempt_id ? null : item.attempt_id)}
                      aria-expanded={ruling === item.attempt_id}
                    >
                      {ruling === item.attempt_id ? t("Close") : t("Rule on this")}
                    </button>
                  </td>
                </tr>
                {/* Under the row it is about, not under the table: with a
                    screenful of rows, a form at the foot of the list says
                    which host it means in its heading and the eye does not
                    join the two. The panel opens an approval the same way. */}
                {ruling === item.attempt_id && (
                  <tr className="detail-row">
                    <td colSpan={7}>
                      <RulingForm
                        item={item}
                        onClose={() => setRuling(null)}
                        onRuled={() => {
                          setRuling(null);
                          client.invalidateQueries({ queryKey: ["unresolved"] });
                        }}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}

      {total > 0 && (
        <Toolbar
          end={
            <label className="inline">
              {t("Rows per page")}{" "}
              <select
                value={size}
                onChange={(e) => { setSize(Number(e.target.value)); setPage(1); }}
                data-testid="page-size"
              >
                {PAGE_SIZES.map((one) => (
                  <option key={one} value={one}>{one}</option>
                ))}
              </select>
            </label>
          }
        >
          <nav className="pager" aria-label={t("Pages")}>
            <button
              type="button"
              className="secondary"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              data-testid="page-previous"
            >
              {t("Previous")}
            </button>
            {pageNumbers(page, pages).map((one, i) =>
              one === "gap" ? (
                /* The gap is not a button and says so to a screen reader:
                   the numbers either side of it are the ones to press. */
                <span key={`gap-${i}`} className="muted" aria-hidden="true">…</span>
              ) : (
                <button
                  key={one}
                  type="button"
                  className={one === page ? "active" : "secondary"}
                  aria-current={one === page ? "page" : undefined}
                  onClick={() => setPage(one)}
                  data-testid={`page-${one}`}
                >
                  {one}
                </button>
              ),
            )}
            <button
              type="button"
              className="secondary"
              disabled={page >= pages}
              onClick={() => setPage(page + 1)}
              data-testid="page-next"
            >
              {t("Next")}
            </button>
            <span className="muted" data-testid="page-of">
              {t("{n} of {total}", { n: `${(page - 1) * size + 1}-${Math.min(page * size, total)}`, total })}
            </span>
          </nav>
        </Toolbar>
      )}
    </>
  );
}

/**
 * What the row says, before what the host said.
 *
 * The screen named a category of uncertainty where it could have named a
 * fact: "did it hold?" covered both a host that answered and shows something
 * else - where the panel knows the change did not hold - and a host that
 * could not be read, which is the absence of that conclusion. The owner read
 * the tab and could not tell what it was telling him, which is the evidence
 * that naming them alike was wrong.
 *
 * The host's own sentence stays, underneath and marked as the host's: it is
 * evidence, and it is in the language the agent writes its log in. What is
 * composed here is in the operator's language, from the two fields the
 * verifier recorded.
 */
function ReasonCell({ item }: { item: UnresolvedItem }) {
  const t = useT();
  const reading = verifierReading(item.verification);
  const sort = readingKind(item.kind, reading);
  return (
    <div className="reason">
      {sort === "did_not_hold" && (
        <>
          <p className="reason-verdict">{t("The change did not hold.")}</p>
          <p className="reason-reading">
            <span className="muted">{t("Ordered")}:</span> <code>{reading?.expected}</code>
            {" · "}
            <span className="muted">{t("On the host")}:</span> <code>{reading?.observed}</code>
          </p>
        </>
      )}
      {sort === "could_not_read" && (
        <p className="reason-verdict">{t("The host could not be read, so the state is unknown.")}</p>
      )}
      {sort === "outcome_unknown" && (
        <p className="reason-verdict">
          {t("The agent restarted while the host was carrying this operation, so whether it finished is unknown.")}
        </p>
      )}
      {item.reason ? (
        <p className="source" data-testid="reason-host-words">
          {t("what the host itself said")}: {item.reason}
        </p>
      ) : null}
    </div>
  );
}

/**
 * One ruling against every attempt the filter holds.
 *
 * It asks for the basis exactly as the single ruling does. A button that
 * cleared thirty-one rows without a word would turn this screen into a
 * counter to be zeroed, and then nobody could answer "who decided that, and
 * on what grounds" - which is the question the screen exists to keep
 * answerable.
 */
function BatchRulingForm({
  kind,
  total,
  onClose,
  onRuled,
}: {
  kind: UnresolvedKind | "";
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
      const page = await api.get<UnresolvedOperations>(`/api/v1/unresolved?${query}`);
      return api.post<UnresolvedRulings>("/api/v1/unresolved/rulings", {
        kind: kind || "applied_unverified",
        ruling: verdict,
        basis,
        attempt_ids: page.items.map((one) => one.attempt_id),
      });
    },
    onSuccess: (answer) => {
      // Not closed on success: what could not be ruled on has to be read, and
      // a form that vanished would take the refusals with it.
      if (answer.refused && answer.refused.length > 0) setDone(answer);
      else onRuled();
    },
  });

  return (
    <Card
      title={t("Rule on all {n} of them", { n: Math.min(total, BATCH_LIMIT) })}
      description={
        total > BATCH_LIMIT
          ? t("A batch carries at most {cap}; the rest stay on the list and can be ruled on next.", { cap: BATCH_LIMIT })
          : t("One ruling, written once and recorded against every one of them separately.")
      }
    >
      {done ? (
        <>
          <p>{t("{n} of {attempts} were ruled on.", { n: done.ruled, attempts: done.attempts })}</p>
          <p className="source">{t("These were not, and are still on the list:")}</p>
          <ul>
            {done.refused?.map((one) => (
              <li key={one.attempt_id}>
                <code>{one.attempt_id}</code> — {one.message}
              </li>
            ))}
          </ul>
          <Actions>
            <button type="button" onClick={onRuled}>{t("Close")}</button>
          </Actions>
        </>
      ) : (
        <>
          <FieldGrid>
            <Field label={t("What did you find?")}>
              <select
                value={verdict}
                onChange={(e) => setVerdict(e.target.value as UnresolvedRulingKind)}
                data-testid="batch-verdict"
              >
                <option value="confirmed_applied">{t("The change is there")}</option>
                <option value="confirmed_not_applied">{t("The change is not there")}</option>
                <option value="accepted_unknown">{t("It will not be known, and that is accepted")}</option>
              </select>
            </Field>
            <Field
              label={t("On what basis?")}
              wide
              hint={t("Required, and recorded against every one of them: a ruling without one is a screen being cleared.")}
            >
              <textarea
                autoFocus
                rows={2}
                value={basis}
                onChange={(e) => setBasis(e.target.value)}
                placeholder={t("What you read, and where you looked.")}
                data-testid="batch-basis"
              />
            </Field>
          </FieldGrid>

          {record.error ? <ErrorBox error={record.error} /> : null}

          <Actions>
            <button
              type="button"
              disabled={basis.trim() === "" || record.isPending}
              onClick={() => record.mutate()}
              data-testid="batch-save"
            >
              {t("Record the ruling for all of them")}
            </button>
            <button type="button" className="secondary" onClick={onClose}>
              {t("Cancel")}
            </button>
          </Actions>
        </>
      )}
    </Card>
  );
}

/**
 * The form for one ruling.
 *
 * The basis is required, and the form says why: a ruling with none is a
 * screen being cleared. The three rulings are deliberately not "ok / not ok":
 * accepting that the outcome will never be known is a decision too, and one
 * with a name and a date on it, which is the difference between this and an
 * item ageing off a dashboard.
 */
function RulingForm({
  item,
  onClose,
  onRuled,
}: {
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
    <>
      <p className="source">
        {t("The task keeps the outcome the fleet reported. What you write here is recorded beside it, with your name and the time.")}
      </p>
      <FieldGrid>
        <Field label={t("What did you find?")}>
          <select
            value={verdict}
            onChange={(e) => setVerdict(e.target.value as UnresolvedRulingKind)}
            data-testid="ruling-verdict"
          >
            <option value="confirmed_applied">{t("The change is there")}</option>
            <option value="confirmed_not_applied">{t("The change is not there")}</option>
            <option value="accepted_unknown">{t("It will not be known, and that is accepted")}</option>
          </select>
        </Field>
        <Field
          label={t("On what basis?")}
          wide
          hint={t("Required: a ruling without one is a screen being cleared.")}
        >
          <textarea
            autoFocus
            rows={2}
            value={basis}
            onChange={(e) => setBasis(e.target.value)}
            placeholder={t("What you read, and where you looked.")}
            data-testid="ruling-basis"
          />
        </Field>
      </FieldGrid>

      {record.error ? <ErrorBox error={record.error} /> : null}

      <Actions>
        <button
          type="button"
          disabled={basis.trim() === "" || record.isPending}
          onClick={() => record.mutate()}
          data-testid="ruling-save"
        >
          {t("Record the ruling")}
        </button>
        <button type="button" className="secondary" onClick={onClose}>
          {t("Cancel")}
        </button>
      </Actions>
    </>
  );
}
