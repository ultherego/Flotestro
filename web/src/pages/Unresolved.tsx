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
import { ErrorBox, Time } from "../components/ui";
import { Actions, Empty, Field, Fields, PageHead, Pager, Panel, Toolbar } from "../ui/kit";
import { Icon } from "../components/icons";
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

/**
 * The most rows one page may hold and the most attempts one batch ruling may
 * carry: one number, because it is one of the server's caps (jobs.MaxPage).
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

/**
 * The reading the server decided, with the old rule as a fallback.
 *
 * This used to be the rule itself, computed here. It moved into SQL on 15.10
 * because the list is paged and counted on the server: a screen that
 * classified while the server counted would put numbers above a list that
 * disagree with it, and an operator who sees that learns to trust neither.
 * What is left here is reading the field - and, for a row from a panel that
 * predates it, the old derivation, so an upgrade in progress shows rows rather
 * than blanks.
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

/**
 * The page sizes the screen offers. The last one is the most the server will
 * serve, so "more" means that and not an unbounded page: a list this one can
 * grow to tens of thousands of rows, and a page of all of them is a browser
 * that stops responding rather than a screen.
 */
export const PAGE_SIZES = [5, 10, 20, 50, 100, BATCH_LIMIT];

/**
 * The page numbers to show, with a gap where the numbers are skipped.
 *
 * Always the first and the last, always the ones either side of the current
 * one: a list of thirty pages does not fit, and a reader needs to know how
 * far the list goes as much as where in it they are.
 */

export default function Unresolved() {
  const t = useT();
  const client = useQueryClient();
  const [kind, setKind] = useState<UnresolvedKind | "">("");
  // Which of the three readings to show, or all of them. It narrows inside the
  // question rather than beside it, so choosing one clears the other control:
  // two narrowings that overlap would let an operator ask for a combination
  // that cannot hold anything and read the empty answer as good news.
  const [reading, setReading] = useState<ReadingKind | "">("");
  const [size, setSize] = useState(20);
  const [page, setPage] = useState(1);
  // What is typed, and what has been asked of the server. They are two states
  // on purpose: a request per keystroke over a list of thousands is a screen
  // that fights the typing.
  const [typed, setTyped] = useState("");
  const [search, setSearch] = useState("");
  // The attempt whose ruling is open, or none. One at a time: the form is a
  // row of the table and two of them would push the list apart.
  const [ruling, setRuling] = useState<string | null>(null);
  const [batch, setBatch] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(typed.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [typed]);

  const { data, error, isPlaceholderData } = useQuery({
    queryKey: ["unresolved", kind, reading, size, page, search],
    queryFn: () => {
      const query = new URLSearchParams({ limit: String(size), offset: String((page - 1) * size) });
      if (kind) query.set("kind", kind);
      if (reading) query.set("reading", reading);
      if (search) query.set("q", search);
      return api.get<UnresolvedOperations>(`/api/v1/unresolved?${query}`);
    },
  });

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  // A page that stopped existing - the list shrank because somebody ruled on
  // it - is not an error to show the operator, it is the last page.
  //
  // Only on an answer about THIS page, though. While the next page is being
  // fetched the total belongs to the previous one, and a clamp that fired then
  // would take a reader back to where they came from the moment they asked to
  // move - which is what pressing 2 did.
  const settled = data !== undefined && !isPlaceholderData;
  useEffect(() => {
    if (settled && page > pages) setPage(pages);
  }, [settled, page, pages]);

  if (error) return <ErrorBox error={error} />;
  const counts = data?.counts;
  const items = data?.items ?? [];
  const show = (next: UnresolvedKind | "") => {
    setKind(next);
    setReading("");
    setPage(1);
  };
  const showReading = (next: ReadingKind | "") => {
    setReading(next);
    setKind("");
    setPage(1);
  };

  return (
    <>
      <PageHead
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
          <div className="ui-segmented" role="group" aria-label={t("Which question to show")}>
            <button
              type="button"
              className={kind === "" ? "ui-active" : ""}
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
                  className={kind === one ? "ui-active" : ""}
                  onClick={() => show(one)}
                  aria-pressed={kind === one}
                  data-testid={`filter-${one}`}
                  title={t(described.title)}
                >
                  {t(described.question)}{" "}
                  <span className="ui-tags" data-testid={`count-${one}`}>
                    <span className={operations > 0 ? "ui-pill ui-warn" : "ui-pill"}>
                      {t("{n} operations", { n: operations })}
                    </span>
                    <span className={hosts > 0 ? "ui-pill ui-warn" : "ui-pill"}>
                      {t("on {n} hosts", { n: hosts })}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
          {/* Inside "did it hold?" there are two different situations, and
              until 15.10 one label covered both: a host that answered with
              something else - where the panel KNOWS the change did not hold -
              and a host the verifier could not read. The first is a
              conclusion, the second is the absence of one. Each gets its own
              number and its own way in, which is what the owner asked for
              when he said "readably". */}
          <div className="ui-segmented" role="group" aria-label={t("Which reading to show")}>
            {([
              ["did_not_hold", counts.did_not_hold_operations, counts.did_not_hold_hosts],
              ["could_not_read", counts.could_not_read_operations, counts.could_not_read_hosts],
            ] as const).map(([which, operations, hosts]) => (
              <button
                key={which}
                type="button"
                className={reading === which ? "ui-active" : ""}
                onClick={() => showReading(reading === which ? "" : which)}
                aria-pressed={reading === which}
                data-testid={`reading-${which}`}
                title={which === "did_not_hold"
                  ? t("The host answered and shows something other than what was ordered.")
                  : t("The verifier could not read the host, so the state is unknown.")}
              >
                {which === "did_not_hold" ? t("Did not hold") : t("Could not be read")}{" "}
                <span className="ui-tags">
                  <span className={(operations ?? 0) > 0 ? "ui-pill ui-warn" : "ui-pill"}>
                    {t("{n} operations", { n: operations ?? 0 })}
                  </span>
                  <span className={(hosts ?? 0) > 0 ? "ui-pill ui-warn" : "ui-pill"}>
                    {t("on {n} hosts", { n: hosts ?? 0 })}
                  </span>
                </span>
              </button>
            ))}
          </div>
          {total > 0 && (
            <button
              type="button"
              className="ui-btn-secondary"
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
          reading={reading}
          search={search}
          total={total}
          onClose={() => setBatch(false)}
          onRuled={() => {
            setBatch(false);
            setPage(1);
            client.invalidateQueries({ queryKey: ["unresolved"] });
          }}
        />
      )}

      <Panel className="ui-col-12" flush>
        <Toolbar
          end={
            <>
              <Pager page={page} size={size} total={total} sizes={PAGE_SIZES}
                     onPage={setPage} onSize={setSize} />
            </>
          }
        >
          <div className="ui-search">
            <Icon name="search" />
            <input
              type="search"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={t("a host or an operation")}
              aria-label={t("Search")}
              data-testid="unresolved-search"
            />
          </div>
        </Toolbar>

      {items.length === 0 ? (
        <Empty>
          {search !== ""
            ? t("No unconfirmed operation matches what you typed.")
            : counts && anythingOpen(counts)
              ? t("Nothing of this kind is open.")
              : t("Every operation this fleet reported has an outcome somebody could confirm.")}
        </Empty>
      ) : (
        <table>
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
                      <span className="ui-pill ui-unknown">{t("not since")}</span>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="ui-btn-secondary"
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
                  <tr className="ui-detailrow">
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

      </Panel>
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
  const sort = readingKind(item.kind, reading, item.reading);
  return (
    <div className="ui-reason">
      {sort === "did_not_hold" && (
        <>
          <p className="ui-reason-verdict">{t("The change did not hold.")}</p>
          <p className="ui-reason-reading">
            <span className="ui-faint">{t("Ordered")}:</span> <code>{reading?.expected}</code>
            {" · "}
            <span className="ui-faint">{t("On the host")}:</span> <code>{reading?.observed}</code>
          </p>
        </>
      )}
      {sort === "could_not_read" && (
        <p className="ui-reason-verdict">{t("The host could not be read, so the state is unknown.")}</p>
      )}
      {sort === "outcome_unknown" && (
        <p className="ui-reason-verdict">
          {t("The agent restarted while the host was carrying this operation, so whether it finished is unknown.")}
        </p>
      )}
      {item.reason ? (
        <p className="ui-note" data-testid="reason-host-words">
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
  reading,
  search,
  total,
  onClose,
  onRuled,
}: {
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
      // Not closed on success: what could not be ruled on has to be read, and
      // a form that vanished would take the refusals with it.
      if (answer.refused && answer.refused.length > 0) setDone(answer);
      else onRuled();
    },
  });

  return (
    <Panel
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
          <p className="ui-note">{t("These were not, and are still on the list:")}</p>
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
          <Fields>
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
          </Fields>

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
            <button type="button" className="ui-btn-secondary" onClick={onClose}>
              {t("Cancel")}
            </button>
          </Actions>
        </>
      )}
    </Panel>
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
      <p className="ui-note">
        {t("The task keeps the outcome the fleet reported. What you write here is recorded beside it, with your name and the time.")}
      </p>
      <Fields>
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
      </Fields>

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
        <button type="button" className="ui-btn-secondary" onClick={onClose}>
          {t("Cancel")}
        </button>
      </Actions>
    </>
  );
}
