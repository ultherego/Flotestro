import {
  Children, Fragment, createContext, isValidElement, useContext, useEffect, useId, useRef, useState,
  type CSSProperties, type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent, type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { Icon, type IconName } from "../components/icons";
import { exportAddress, exportFileName } from "../components/ExportButton";
import { fetchWithCredentials } from "../lib/api";
import { isStringList, useStoredState } from "../lib/storage";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";

/**
 * The pieces the new panel is drawn from, and the only ones it may use.
 *
 * Written on 16.10 with the panel itself: the owner's verdict on what came
 * before was that the screens were in pieces, so this is not a port of the
 * old primitives under new names. A screen composes what is here and owns
 * no appearance of its own - no screen writes a class, a colour or a
 * spacing of its own, and `next.css` is therefore the whole of what the
 * product looks like.
 *
 * Every class begins with `fl-` and every rule is scoped to `.fl-app`, so
 * the panel this replaces goes on running beside it, untouched, until the
 * last screen is written.
 */

export type Tone = "ok" | "warn" | "error" | "info" | "unknown" | "neutral" | "accent";
export type Span = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

const join = (...parts: (string | false | undefined | null)[]) => parts.filter(Boolean).join(" ");

const TONES = new Set(["ok", "warn", "error", "info", "unknown", "neutral", "accent"]);

/** How a thing is going, as the one class that says it. */
export function toneClass(name?: string | null): string | undefined {
  return name && TONES.has(name) ? `fl-${name}` : undefined;
}

/* ---------------------------------------------------------------- page */

/**
 * The head of a screen: what it is, one line on what it answers, and the
 * actions that belong to the whole of it.
 */
export function Head({ title, lead, actions, icon, help }: {
  title: ReactNode;
  lead?: ReactNode;
  actions?: ReactNode;
  /** The mark of the screen, the same one the rail gives its place. */
  icon?: IconName;
  /**
   * What this screen is for, at length, behind a mark beside the title.
   *
   * A paragraph at the top of a screen is read once and then stepped over
   * every day after that, so it waits here until somebody asks. It is not
   * optional in the sense of "nice to have": a screen whose purpose
   * cannot be asked is a screen somebody has to be told about.
   */
  help?: ReactNode;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  return (
    <header className="fl-head">
      {icon && <span className="fl-head-mark" aria-hidden="true"><Icon name={icon} /></span>}
      <div className="fl-head-text">
        <h1 className="fl-head-title">
          {title}
          {help && (
            <button
              type="button"
              className="fl-helpmark"
              aria-expanded={open}
              title={t("What this screen is for")}
              onClick={() => setOpen(!open)}
              data-testid="screen-help-toggle"
            >
              ?
            </button>
          )}
        </h1>
        {lead && <p className="fl-head-lead">{lead}</p>}
        {help && open && <div className="fl-help" data-testid="screen-help">{help}</div>}
      </div>
      {actions && <div className="fl-head-actions">{actions}</div>}
    </header>
  );
}

/**
 * What this screen offers at the top right of the heading the shell drew.
 *
 * The heading belongs to the shell so that every screen has the same one;
 * the one thing a screen knows that the shell does not is what can be
 * done from it, so that arrives here and lands in the heading's own slot.
 */
export function HeadActions({ children }: { children: ReactNode }) {
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  useEffect(() => { setSlot(document.getElementById("fl-head-slot")); }, []);
  // Until the heading's slot is there - the first render, and any screen
  // drawn on its own, as a test draws it - they stand where they are
  // written. Rendering nothing would make a screen's only way to act on
  // it disappear whenever it is not inside the shell.
  return slot ? createPortal(children, slot) : <>{children}</>;
}

/**
 * The frame of a screen, and the thing every screen in the panel is.
 *
 * A screen says what it is called, what it is for, what can be done from
 * it, and then hands over its cards. It does not decide a margin, a
 * width or a heading of its own: that is why forty screens written by
 * different hands on different days come out as one panel rather than as
 * forty. The test beside this file refuses a screen that reaches past
 * this frame for a layout of its own.
 */
export function Screen({ title, lead, help, icon, actions, banner, children }: {
  title: ReactNode;
  lead?: ReactNode;
  /** The long answer to "what is this screen for", behind the mark. */
  help?: ReactNode;
  icon?: IconName;
  actions?: ReactNode;
  /** What has to be taken account of before the screen is read at all. */
  banner?: ReactNode;
  children: ReactNode;
}) {
  /* The shell draws one heading for every screen, out of one table, so
     that forty of them cannot grow forty shapes of heading. Where it has
     drawn one, a screen hands over only what can be done from it; where
     it has not - a screen that names a thing rather than a section, a
     test, anything outside the shell - the screen draws the heading
     itself, so what it is called is never lost.
   
     Which of the two it is comes from the shell, not from looking for
     the slot in the document: a screen that draws its own heading also
     draws a slot, and a screen that looked would find its own and stop
     drawing the heading it had just drawn. */
  const drawn = useContext(ShellHead);
  return (
    <>
      {drawn
        ? actions && <HeadActions>{actions}</HeadActions>
        : (
          <Head
            title={title}
            lead={lead}
            help={help}
            icon={icon}
            /* A screen that draws its own heading offers the same slot
               the shell's does, or what the screen holds - the arranging
               mode, a module's own actions - lands on a line of its own
               under the title instead of beside it. */
            actions={<>{actions}<HeadSlot /></>}
          />
        )}
      {banner}
      {children}
    </>
  );
}

/**
 * As many cards across as the window has room for.
 *
 * A grid of twelfths says how wide a card is as a fraction, so on a 4k
 * screen a half is nineteen hundred pixels of label-and-value pairs and
 * on a laptop the same half is six hundred. This says how wide a card
 * wants to be instead, and lets the window decide how many fit - three
 * across at 1600, six at 3840, one on a phone. It is the answer to a
 * wide screen: more columns, not a narrower column.
 */
export function Flow({ children, min = 420 }: {
  children: ReactNode;
  /** The narrowest a card may get before one is dropped from the row. */
  min?: 320 | 420 | 520;
}) {
  return <div className={`fl-flow fl-flow-${min}`}>{children}</div>;
}

/**
 * Whether the shell has already drawn the heading above this screen.
 *
 * The shell sets it; a `Screen` reads it and either hands over its
 * actions or draws the heading itself.
 */
export const ShellHead = createContext(false);

/**
 * Where a screen's own actions land in the heading above it.
 *
 * Whoever draws the heading puts one of these in its actions, and
 * `HeadActions` finds it. Exactly one may stand on a page.
 */
export function HeadSlot() {
  return <span id="fl-head-slot" className="fl-head-slot" />;
}

/** The twelve columns everything stands on. */
export function Grid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={join("fl-grid", className)}>{children}</div>;
}

/** How many of the twelve a block takes. */
export function C({ span = 12, children }: { span?: Span; children: ReactNode }) {
  return <div className={`fl-c${span}`}>{children}</div>;
}

export function Stack({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "fl-stack-l" : "fl-stack"}>{children}</div>;
}

/**
 * The ones of these that are there, stacked - or nothing at all.
 *
 * A container on the board is left out when it has nothing to draw, but
 * `<Stack>{a && <Banner/>}{b && <Banner/>}</Stack>` is something to draw
 * even when neither banner is: the row is kept and the screen opens with
 * a band of empty floor across it. This hands back null in that case.
 */
export function stacked(...items: ReactNode[]): ReactNode {
  const real = items.filter((one) => one !== null && one !== undefined && one !== false && one !== "");
  if (real.length === 0) return null;
  return <Stack>{real.map((one, index) => <Fragment key={index}>{one}</Fragment>)}</Stack>;
}

export function Row({ children }: { children: ReactNode }) {
  return <div className="fl-row">{children}</div>;
}

/* ---------------------------------------------------------------- card */

/**
 * The one surface. A title that names, one place for the controls that
 * belong to this card, a body, and a foot for what is said after it.
 *
 * `flush` is for a body that is a table or a toolbar: it reaches the
 * card's own edges instead of floating inside a margin.
 */
export function Card({ title, note, tools, bar, children, foot, flush = false, span }: {
  title?: ReactNode;
  note?: ReactNode;
  tools?: ReactNode;
  /**
   * What steers what is below it - a search, the filters, a time range.
   *
   * It stands outside the part that scrolls, so it stays put with the
   * table's own head under it however far the rows are scrolled. A
   * toolbar passed as a child instead scrolls away with them.
   */
  bar?: ReactNode;
  children?: ReactNode;
  foot?: ReactNode;
  /** For a body that is a table or a toolbar: it reaches the edges. */
  flush?: boolean;
  span?: Span;
}) {
  /* A toolbar among the children is lifted out of the part that scrolls.
     It steers what is below it, so it stays put - and the table's head
     then sticks to the top of the scroller rather than to a guess at how
     tall the toolbar is. Wrapped onto three lines, that guess was wrong
     and the first rows showed through the gap. */
  const kids = Children.toArray(children);
  const steering = kids.filter((one) => isValidElement(one) && one.type === Toolbar);
  const rest = kids.filter((one) => !(isValidElement(one) && one.type === Toolbar));
  const steer = bar ?? (steering.length > 0 ? steering : undefined);
  const body = bar ? children : rest;

  const card = (
    <section className={join("fl-card", flush && "fl-flush")}>
      {(title || tools || note) && (
        <div className="fl-card-head">
          {title && <h2 className="fl-card-title">{title}</h2>}
          {tools && <div className="fl-card-tools">{tools}</div>}
          {note && <p className="fl-card-note">{note}</p>}
        </div>
      )}
      {steer && <div className="fl-card-bar">{steer}</div>}
      {body !== undefined && body !== null && body !== false && (
        <div className="fl-card-body">{body}</div>
      )}
      {foot && <div className="fl-card-foot">{foot}</div>}
    </section>
  );
  return span ? <div className={`fl-c${span}`}>{card}</div> : card;
}

/* --------------------------------------------------------- measurement */

/** The row of headline numbers. Four of them, or five; never fifteen. */
export function Kpis({ children }: { children: ReactNode }) {
  return <div className="fl-kpis">{children}</div>;
}

/**
 * A number somebody reads from across the room.
 *
 * Two rules belong to the piece and not to its caller. A value nobody
 * knows is an em dash and the word unknown - never a nought, because a
 * fleet nobody has asked and a fleet with nothing wrong are different
 * answers. And a state colours the figure and its mark, never the frame:
 * a row of tiles with two of them boxed in red stops being a row.
 */
export function Kpi({
  label, value, unit, tone, icon, note, delta, hero = false, spark, to, testId,
}: {
  label: string;
  /** null and undefined are both "nobody knows". */
  value: ReactNode | null | undefined;
  unit?: string;
  tone?: Tone;
  icon?: IconName;
  note?: ReactNode;
  /** How it moved; the caller says whether that direction is good news. */
  delta?: { text: string; direction?: "up" | "down"; good?: boolean };
  /** The one filled tile. It wears the accent, which carries no state. */
  hero?: boolean;
  /**
   * Where the number has been lately, drawn along the tile's lower edge.
   *
   * A figure on its own says what is true now and nothing about whether
   * it is going anywhere; the line costs no room because it bleeds into
   * the tile's own padding.
   */
  spark?: number[];
  to?: string;
  testId?: string;
}) {
  const t = useT();
  const unknown = value === null || value === undefined;
  const shown = unknown ? "unknown" : tone;
  const body = (
    <>
      <div className="fl-kpi-top">
        <span className="fl-kpi-label">{unknown ? t("{label}: unknown", { label }) : label}</span>
        {icon && <span className="fl-kpi-mark" aria-hidden="true"><Icon name={icon} /></span>}
      </div>
      <div className="fl-kpi-value">
        {unknown ? <span className="fl-kpi-dash" title={t("unknown")}>—</span> : value}
        {!unknown && unit && <span className="fl-kpi-unit">{unit}</span>}
      </div>
      {(note || (delta && !unknown)) && (
        <div className="fl-kpi-foot">
          {delta && !unknown && (
            <span className={join("fl-kpi-delta", delta.good === true && "fl-up", delta.good === false && "fl-down")}>
              {delta.text}
              {delta.direction && <span aria-hidden="true">{delta.direction === "up" ? "↑" : "↓"}</span>}
            </span>
          )}
          {note && <span className="fl-kpi-note">{note}</span>}
        </div>
      )}
      {spark && spark.length > 1 && !unknown && (
        <div className="fl-kpi-spark" aria-hidden="true"><Spark values={spark} /></div>
      )}
    </>
  );
  const className = join("fl-kpi", hero && "fl-hero", toneClass(shown));
  const id = testId ?? `kpi-${label}`;
  if (to) return <Link to={to} className={className} data-testid={id} data-state={shown ?? "none"}>{body}</Link>;
  return <div className={className} data-testid={id} data-state={shown ?? "none"}>{body}</div>;
}

/** A figure inside a card, where a second bordered box would only add lines. */
export function Figs({ children }: { children: ReactNode }) {
  return <div className="fl-figs">{children}</div>;
}

export function Fig({ label, value, tone }: { label: ReactNode; value: ReactNode | null | undefined; tone?: Tone }) {
  const unknown = value === null || value === undefined;
  return (
    <div className={join("fl-fig", toneClass(unknown ? "unknown" : tone))}>
      <span className="fl-fig-value">{unknown ? "—" : value}</span>
      <span className="fl-fig-label">{label}</span>
    </div>
  );
}

/* --------------------------------------------------------------- words */

export function Pill({ tone, children, title, dot = true }: {
  tone?: Tone | string;
  children: ReactNode;
  title?: string;
  dot?: boolean;
}) {
  return <span className={join("fl-pill", !dot && "fl-nodot", toneClass(tone))} title={title}>{children}</span>;
}

export function Tag({ children, to, title }: { children: ReactNode; to?: string; title?: string }) {
  return to
    ? <Link to={to} className="fl-tag" title={title}>{children}</Link>
    : <span className="fl-tag" title={title}>{children}</span>;
}

export function Tags({ children }: { children: ReactNode }) {
  return <div className="fl-tags">{children}</div>;
}

/** The state of a connection, as a dot in the colours of the pill. */
export function Dot({ state }: { state?: string | null }) {
  const tone = state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={join("fl-dot", toneClass(tone))} title={state ?? undefined} />;
}

/** Two lines in one cell: the name to open, the address to type. */
export function TwoLine({ children, sub }: { children: ReactNode; sub?: ReactNode }) {
  return (
    <div className="fl-twoline">
      <span>{children}</span>
      {sub && <span className="fl-twoline-sub">{sub}</span>}
    </div>
  );
}

export function Note({ children, testId }: { children: ReactNode; testId?: string }) {
  return <p className="fl-note" data-testid={testId}>{children}</p>;
}

/**
 * An empty list says so in one sentence and, where one exists, offers the
 * action that fills it. A blank card looks like a page that did not load.
 */
export function Empty({ children, action, icon = "check", testId }: {
  children: ReactNode;
  action?: ReactNode;
  /** The mark above the sentence; a bare sentence reads as a failure. */
  icon?: IconName;
  testId?: string;
}) {
  return (
    <div className="fl-empty" data-testid={testId}>
      <span className="fl-empty-mark" aria-hidden="true"><Icon name={icon} /></span>
      <p>{children}</p>
      {action && <div className="fl-empty-actions">{action}</div>}
    </div>
  );
}

/** What went wrong, in the reader's words rather than the server's. */
export function Problem({ children }: { children: ReactNode }) {
  return <div className="fl-problem" role="alert">{children}</div>;
}

/* --------------------------------------------------------------- table */

export type Column<Row> = {
  /** Distinguishes the column and keys its cells. */
  key: string;
  /**
   * A column the reader may fold away, and whether it starts folded.
   *
   * The panel being replaced let every long table be narrowed to the
   * columns somebody actually reads, and remembered it. A table with
   * one of these gains the control; what is folded is this browser's.
   */
  optional?: boolean;
  startFolded?: boolean;
  /** How deep this row sits under the one above: a tree in a table. */
  indent?: (row: Row) => number;
  /** The cell's content starts at the top: a square of a month, a list in a cell. */
  top?: boolean;
  head?: ReactNode;
  /**
   * The column's name where it is listed rather than drawn - in the
   * chooser. A head that is a control, or an icon, needs a word there.
   */
  label?: ReactNode;
  /**
   * What the server calls ordering by this column. Given one, the head
   * becomes the control: the panel being replaced sorted by clicking
   * the heading, and a reader who knows that looks there first.
   */
  sort?: string;
  cell: (row: Row) => ReactNode;
  /** Numbers are read down a column, so they line up on their digits. */
  num?: boolean;
  /** The buttons at the end of a row. */
  actions?: boolean;
  /** What a narrow screen may do without. */
  minor?: boolean;
  /**
   * A value read as one word - an identifier, an error code, a path. The
   * cell keeps it on one line and cuts it with the whole of it on hover:
   * broken across two lines, `unit.reset_failed` reads as two things.
   */
  tight?: boolean;
};

/**
 * One table for the whole panel. It scrolls inside its own card rather
 * than widening the page, its head stays in view while it does, and a row
 * shows data: whatever can be done to it lives where the row leads.
 */
export function Table<Row>({
  columns, rows, keyOf, empty, loading = false, rowTestId, testId,
  detail, opened, under, marked, remember, sort, onSort,
}: {
  columns: Column<Row>[];
  rows: Row[];
  keyOf: (row: Row, index: number) => string;
  empty?: ReactNode;
  /**
   * The rows have been asked for and have not arrived.
   *
   * A list that says "Loading…" where its rows will be tells the reader
   * nothing about whether they are in the right place, and the page
   * jumps when the rows land. The shape of what is coming says both.
   */
  loading?: boolean;
  /**
   * What a row opens into, under itself, across the whole width.
   *
   * The panel being replaced put a unit's drop-ins, an account's keys
   * and an attempt's output in a second row under the one they belong
   * to, and keeping that is the difference between reading a table and
   * hunting for the card it sent you to.
   */
  detail?: (row: Row) => ReactNode;
  /** Which rows are open. */
  opened?: (row: Row) => boolean;
  /**
   * A line the row carries under itself without being asked.
   *
   * For what a reader scanning the list needs to see - which fields a
   * change touched, what an approval rested on. Unlike `detail` it is
   * not behind a click, and a row with nothing to say returns nothing.
   */
  under?: (row: Row) => ReactNode;
  /** The row the cards beside the table are about. */
  marked?: (row: Row) => boolean;
  /** The browser key under which the folded columns are kept. */
  remember?: string;
  /** Which column the rows are in the order of, and which way. */
  sort?: { by: string; down: boolean };
  /** The reader asked for this column's order; the same one turns it round. */
  onSort?: (by: string) => void;
  rowTestId?: (row: Row) => string;
  testId?: string;
}) {
  const t = useT();
  const foldable = columns.filter((one) => one.optional);
  const [folded, setFolded] = useStoredState<string[]>(
    remember ?? "fl.columns.unnamed",
    foldable.filter((one) => one.startFolded).map((one) => one.key),
    isStringList,
  );
  const [choosing, setChoosing] = useState(false);
  const shown = columns.filter((one) => !one.optional || !folded.includes(one.key));

  if (rows.length === 0 && loading) return <Bones rows={5} height={18} />;
  if (rows.length === 0 && empty !== undefined) return <Empty>{empty}</Empty>;

  const classOf = (column: Column<Row>) =>
    join(
      column.num && "fl-num",
      column.actions && "fl-cell-actions",
      column.minor && "fl-minor",
      column.tight && "fl-tight",
      column.top && "fl-cell-top",
    ) || undefined;

  const fold = (key: string) =>
    setFolded((current) => current.includes(key) ? current.filter((one) => one !== key) : [...current, key]);

  return (
    <div className="fl-tablewrap">
      {foldable.length > 0 && (
        <div className="fl-columns">
          <button
            type="button"
            className="fl-plain"
            onClick={() => setChoosing((on) => !on)}
            aria-expanded={choosing}
            data-testid={testId ? `${testId}-columns` : "columns"}
          >
            {t("Columns")}
          </button>
          {choosing && (
            <div className="fl-columns-list">
              {foldable.map((one) => (
                <Check
                  key={one.key}
                  checked={!folded.includes(one.key)}
                  onChange={() => fold(one.key)}
                >
                  {one.label ?? one.head}
                </Check>
              ))}
            </div>
          )}
        </div>
      )}
      <table className="fl-table" data-testid={testId}>
        <thead>
          <tr>{shown.map((column) => {
            const by = column.sort;
            const on = by !== undefined && sort?.by === by;
            return (
              <th
                key={column.key}
                scope="col"
                className={classOf(column)}
                aria-sort={on ? (sort.down ? "descending" : "ascending") : by ? "none" : undefined}
              >
                {by && onSort ? (
                  <button
                    type="button"
                    className="fl-plain fl-head-sort"
                    onClick={() => onSort(by)}
                    data-testid={testId ? `${testId}-sort-${column.key}` : undefined}
                  >
                    {column.head}
                    <span aria-hidden="true">{on ? (sort.down ? "\u2193" : "\u2191") : "\u2195"}</span>
                  </button>
                ) : column.head}
              </th>
            );
          })}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const open = detail !== undefined && opened?.(row) === true;
            return (
              <Fragment key={keyOf(row, index)}>
                <tr data-testid={rowTestId?.(row)} className={join(marked?.(row) && "fl-row-marked", open && "fl-row-open")}>
                  {shown.map((column) => (
                    <td key={column.key} className={classOf(column)}>
                      {column.indent && (
                        <span className="fl-indent" data-depth={column.indent(row)} aria-hidden="true" />
                      )}
                      {column.cell(row)}
                    </td>
                  ))}
                </tr>
                {open && (
                  <tr className="fl-row-detail">
                    <td colSpan={shown.length}>{detail(row)}</td>
                  </tr>
                )}
                {(() => {
                  const says = under?.(row);
                  return says ? (
                    <tr className="fl-row-under">
                      <td colSpan={shown.length}>{says}</td>
                    </tr>
                  ) : null;
                })()}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* --------------------------------------------------------- the diff */

/**
 * What a change would do to a file, line by line.
 *
 * A patch read as plain text is a patch nobody reads: the whole point is
 * that the eye finds the two or three lines that differ without reading
 * the rest. The colours are the product's own, so the light theme gets
 * them right too.
 */
export function Diff({ text, label, testId }: { text: string; label?: ReactNode; testId?: string }) {
  const lines = text.split("\n");
  return (
    <div className="fl-diff" data-testid={testId}>
      {label && <span className="fl-readout-label">{label}</span>}
      <pre className="fl-diff-body">
        {lines.map((line, index) => (
          <span
            key={index}
            className={join(
              "fl-diff-line",
              line.startsWith("+") && !line.startsWith("+++") && "fl-diff-in",
              line.startsWith("-") && !line.startsWith("---") && "fl-diff-out",
              (line.startsWith("@@") || line.startsWith("+++") || line.startsWith("---")) && "fl-diff-where",
            )}
          >
            {line === "" ? " " : line}
          </span>
        ))}
      </pre>
    </div>
  );
}

/* ------------------------------------------------------------ readings */

/** A share of a whole, as a bar with nothing written on it. */
export function Bar({ share, tone }: { share: number; tone?: Tone | string }) {
  return (
    <span className="fl-bar-track">
      <span
        className={join("fl-bar-fill", toneClass(tone))}
        style={{ width: `${Math.round(Math.min(1, Math.max(0, share)) * 100)}%` }}
      />
    </span>
  );
}

/** A bar with its reading beside it, for a cell or a fact. */
export function Meter({ share, text, tone }: { share: number; text: ReactNode; tone?: Tone | string }) {
  return (
    <span className="fl-meter">
      <Bar share={share} tone={tone} />
      <span className="fl-meter-value">{text}</span>
    </span>
  );
}

/**
 * A label, a bar and a number in three tracks of one grid.
 *
 * The bar can never run under the words. That is the fault the owner named
 * on 15.10 - in the fleet composition the two were layered and the text
 * sat on the colour - and it is the reason this is a component rather than
 * a layout each screen arranges for itself.
 */
export function Bars({ items }: {
  /** A value nobody took is undefined: no bar at all, and a dash for it. */
  items: { label: ReactNode; value?: number; tone?: Tone | string }[];
}) {
  const counted = items.map((item) => item.value).filter((one): one is number => one !== undefined);
  const top = Math.max(1, ...counted);
  return (
    <dl className="fl-bars">
      {items.map((item, index) => (
        <div className={join("fl-bars-row", item.value === undefined && toneClass("unknown"))} key={index}>
          <dt>{item.label}</dt>
          <dd>{item.value === undefined ? <span className="fl-bar-track" /> : <Bar share={item.value / top} tone={item.tone ?? "accent"} />}</dd>
          <dd className="fl-bars-count">{item.value === undefined ? "—" : item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export type Segment = { label: string; value?: number; tone?: Tone; to?: string };

/**
 * How a fleet divides, as one band whose widths are the shares.
 *
 * What is at zero is not a sliver nobody can read: it goes under the band
 * as a word and a number. What nobody counted goes there too, said as
 * such - a count that never arrived is not a count of none.
 */
export function Band({ segments, testId }: { segments: Segment[]; testId?: string }) {
  const t = useT();
  const counted = segments.filter((one) => (one.value ?? 0) > 0);
  const zero = segments.filter((one) => one.value === 0);
  const unknown = segments.filter((one) => one.value === undefined);
  const total = counted.reduce((sum, one) => sum + (one.value ?? 0), 0);
  return (
    <div data-testid={testId}>
      {counted.length > 0 && (
        <div className="fl-band" role="list">
          {counted.map((one) => {
            const body = (
              <>
                <span className="fl-band-value">{one.value}</span>
                <span className="fl-band-label">{one.label}</span>
              </>
            );
            const className = join("fl-band-seg", toneClass(one.tone));
            const style = { "--fl-share": (one.value ?? 0) / total } as CSSProperties;
            return one.to
              ? <Link key={one.label} role="listitem" className={className} style={style} to={one.to} title={one.label}>{body}</Link>
              : <div key={one.label} role="listitem" className={className} style={style} title={one.label}>{body}</div>;
          })}
        </div>
      )}
      {(zero.length > 0 || unknown.length > 0) && (
        <div className="fl-quiet-row">
          {zero.map((one) => (
            <span className="fl-quiet-item" key={one.label}><b>0</b>{one.label}</span>
          ))}
          {unknown.map((one) => (
            <span className={join("fl-quiet-item", toneClass("unknown"))} key={one.label}>
              <b>—</b>{t("{label}: not counted", { label: one.label })}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------------------------------------------------------- facts, form */

export function Facts({ children }: { children: ReactNode }) {
  return <dl className="fl-facts">{children}</dl>;
}

export function Fact({ label, children, mono = false }: {
  label: ReactNode;
  /**
   * null and undefined are both "nobody knows", drawn as the em dash the
   * rest of the panel draws. Every screen wrote that dash by hand, which
   * is exactly where somebody eventually writes a nought instead.
   */
  children: ReactNode | null | undefined;
  /** A serial, a uuid, a boot id, a path: read as one word, not as prose. */
  mono?: boolean;
}) {
  const unknown = children === null || children === undefined || children === "";
  return (
    <div className="fl-fact">
      <dt>{label}</dt>
      <dd className={join(mono && !unknown && "fl-mono", unknown && "fl-faint")}>
        {unknown ? "—" : children}
      </dd>
    </div>
  );
}

/* --------------------------------------------------- the chrome of a list */

export function Toolbar({ children, end }: { children?: ReactNode; end?: ReactNode }) {
  return (
    <div className="fl-toolbar">
      {children}
      {end && <div className="fl-toolbar-end">{end}</div>}
    </div>
  );
}

/** The box a list is searched with: the mark is inside the field. */
export function Find({ value, onChange, placeholder, title, testId }: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  /**
   * What the search actually looks in, where the placeholder is too short
   * to say it - "hostname, address, machine ID or owner" does not fit in
   * a box but is the difference between searching and guessing.
   */
  title?: string;
  testId?: string;
}) {
  return (
    <span className="fl-find">
      <Icon name="search" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        title={title}
        aria-label={title ?? placeholder}
        data-testid={testId}
      />
    </span>
  );
}

/** A choice of one from a few, as one control rather than a row of buttons. */
export function Seg<T extends string>({ value, onChange, options, label }: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode }[];
  /** What the group chooses between, for anybody who cannot see it. */
  label?: string;
}) {
  return (
    <div className="fl-seg" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={option.value === value ? "fl-on" : undefined}
          aria-pressed={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/** The sizes a list offers. One set for the whole panel. */
export const PAGE_SIZES = [25, 50, 100, 200] as const;

/** The numbers a pager shows: the first, the last, and the ones around. */
export function pageNumbers(current: number, pages: number, around = 2): (number | "gap")[] {
  if (pages < 1) return [];
  const wanted = new Set<number>([1, pages]);
  for (let n = current - around; n <= current + around; n++) {
    if (n >= 1 && n <= pages) wanted.add(n);
  }
  const out: (number | "gap")[] = [];
  let previous = 0;
  for (const n of [...wanted].sort((a, b) => a - b)) {
    if (previous && n - previous > 1) out.push("gap");
    out.push(n);
    previous = n;
  }
  return out;
}

/** Walking a list too long to draw. The toolbar takes this in its `end`. */
export function Pager({ page, size, total, onPage, onSize, sizes = PAGE_SIZES }: {
  /** One-based. */
  page: number;
  size: number;
  total: number;
  onPage: (page: number) => void;
  onSize: (size: number) => void;
  sizes?: readonly number[];
}) {
  const t = useT();
  const pages = Math.max(1, Math.ceil(total / Math.max(1, size)));
  return (
    <>
      <label className="fl-rows">
        {t("Rows per page")}
        <select
          value={size}
          onChange={(event) => { onSize(Number(event.target.value)); onPage(1); }}
          data-testid="page-size"
        >
          {sizes.map((one) => <option key={one} value={one}>{one}</option>)}
        </select>
      </label>
      <span className="fl-note" data-testid="page-of">
        {total > 0
          ? t("{n} of {total}", { n: `${(page - 1) * size + 1}-${Math.min(page * size, total)}`, total })
          : t("{n} of {total}", { n: 0, total: 0 })}
      </span>
      {pages > 1 && (
        <nav className="fl-pager" aria-label={t("Pages")}>
          <button type="button" className="fl-quiet" disabled={page <= 1}
                  onClick={() => onPage(page - 1)} data-testid="page-previous" aria-label={t("Previous")}>‹</button>
          {pageNumbers(page, pages).map((one, index) => one === "gap" ? (
            <span key={`gap-${index}`} className="fl-pager-gap" aria-hidden="true">…</span>
          ) : (
            <button key={one} type="button" className={one === page ? "fl-on" : "fl-quiet"}
                    aria-current={one === page ? "page" : undefined}
                    onClick={() => onPage(one)} data-testid={`page-${one}`}>{one}</button>
          ))}
          <button type="button" className="fl-quiet" disabled={page >= pages}
                  onClick={() => onPage(page + 1)} data-testid="page-next" aria-label={t("Next")}>›</button>
        </nav>
      )}
    </>
  );
}

/* --------------------------------------------------------------- chart */

export type Series = { name: string; tone: Tone; values: number[] };

/**
 * Hours along the bottom, counts up the side, the series stacked, and the
 * tallest column's reading in a bubble over it.
 *
 * It is drawn rather than charted: a panel that pulls a charting library
 * in for a dozen bars pays for it on every screen. Every column carries
 * its own reading as a title, which is what a reader actually asks of a
 * bar, and the axis says what the heights mean.
 */
export function Chart({ labels, series, everyLabel = 3, height = 160, shape = "bars", max, format, testId }: {
  labels: string[];
  series: Series[];
  /** Draw one label in every n, so they do not run together. */
  everyLabel?: number;
  /** What it draws at where its container cannot be measured. */
  height?: number;
  /**
   * The ceiling of the scale, where the measure has one.
   *
   * A percentage drawn to its own highest reading says a host at 4% is
   * as loaded as one at 99%. Given a ceiling, the drawing says what the
   * number means.
   */
  max?: number;
  /** How a reading is written on the axis and in the header: bytes, ms. */
  format?: (value: number) => string;
  /**
   * Counts in a period are columns; a level over time is a line, filled
   * when it is the only series and bare when several share the frame.
   */
  shape?: "bars" | "area" | "line";
  testId?: string;
}) {
  const t = useT();
  const mine = useId().replace(/:/g, "");
  const [at, setAt] = useState<number | null>(null);
  /* The drawing fills the container it was given and stands on its
     floor. Drawn at a fixed height it hung from the top of a card twice
     as tall and left a hole under it - which is what the owner means by
     a chart drawn from the top rather than from the bottom. The height
     passed in is what it falls back to where nothing can be measured. */
  const box = useRef<HTMLDivElement | null>(null);
  const [tall, setTall] = useState(height);
  useEffect(() => {
    const where = box.current;
    if (!where || typeof ResizeObserver === "undefined") return;
    const watch = new ResizeObserver(() => {
      const measured = where.clientHeight;
      if (measured > 60) setTall(measured);
    });
    watch.observe(where);
    return () => watch.disconnect();
  }, []);
  const columns = Math.max(1, labels.length);
  const totals = labels.map((_, i) => series.reduce((sum, one) => sum + (one.values[i] ?? 0), 0));
  const top = Math.max(1, max ?? 0, ...(max === undefined ? totals : []));
  const W = 600;
  const padLeft = 26;
  const padBottom = 16;
  const plotW = W - padLeft;
  const plotH = tall - padBottom;
  const step = plotW / columns;
  const y = (value: number) => plotH - (value / top) * (plotH - 4);
  const x = (i: number) => padLeft + step * (i + 0.5);
  const read = at !== null && at >= 0 && at < columns ? at : null;

  const hover = (event: ReactPointerEvent<SVGRectElement> | ReactMouseEvent<SVGRectElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    if (box.width <= 0) return;
    const inside = ((event.clientX - box.left) / box.width) * W - padLeft;
    setAt(Math.min(columns - 1, Math.max(0, Math.floor(inside / step))));
  };

  return (
    <figure className="fl-chart" data-testid={testId}>
      <div className="fl-chart-top">
        <figcaption className="fl-chart-legend">
          {series.map((one) => (
            <span key={one.name}><i className={join("fl-chart-key", toneClass(one.tone))} />{one.name}</span>
          ))}
        </figcaption>
        {/* The reading under the pointer belongs here and not in a bubble
            over the drawing: a bubble on the tallest column covers the
            numbers it is there to explain. The owner said so on 16.10. */}
        <div className="fl-chart-read" data-testid="chart-read" aria-live="polite">
          {read === null ? (
            <span className="fl-faint">{t("Point at the chart for a reading")}</span>
          ) : (
            <>
              <b>{labels[read]}</b>
              {series.map((one) => (
                <em key={one.name} className={toneClass(one.tone)}>
                  {one.name} {(format ?? ((n: number) => String(n)))(one.values[read] ?? 0)}
                </em>
              ))}
            </>
          )}
        </div>
      </div>

      <div className="fl-chart-plot" ref={box}>
        <svg viewBox={`0 0 ${W} ${tall}`} preserveAspectRatio="none" style={{ height: tall }} role="img"
             onPointerLeave={() => setAt(null)}>
          {[0, 0.5, 1].map((share) => (
            <g key={share}>
              <line className="fl-chart-rule" x1={padLeft} x2={W} y1={y(top * share)} y2={y(top * share)} />
              <text className="fl-chart-scale" x="0" y={y(top * share) + 3}>{(format ?? ((n: number) => String(Math.round(n))))(top * share)}</text>
            </g>
          ))}

          {shape === "bars" && labels.map((label, i) => {
            let base = 0;
            const width = Math.max(1, step - (columns > 40 ? 1.5 : 5));
            return (
              <g key={i}>
                <title>{`${label} · ${totals[i]}`}</title>
                {series.map((one) => {
                  const value = one.values[i] ?? 0;
                  if (value === 0) return null;
                  const tall = (value / top) * (plotH - 4);
                  base += tall;
                  return (
                    <rect
                      key={one.name}
                      className={join("fl-chart-bar", toneClass(one.tone))}
                      x={x(i) - width / 2}
                      y={plotH - base}
                      width={width}
                      height={tall}
                      rx={Math.min(width / 2, 2)}
                      opacity={read === null || read === i ? 1 : 0.45}
                    />
                  );
                })}
              </g>
            );
          })}

          {shape !== "bars" && series.map((one) => {
            const points = labels.map((_, i) => `${x(i)},${y(one.values[i] ?? 0)}`).join(" ");
            const fade = `${mine}-${one.name.replace(/\W/g, "")}`;
            return (
              <g key={one.name} className={toneClass(one.tone)} style={{ color: "var(--tone)" }}>
                {/* The gradient takes its colour where it is written, not
                    where it is used, so it lives inside its own series. */}
                <defs>
                  <linearGradient id={fade} x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="currentColor" stopOpacity="0.38" />
                    <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
                  </linearGradient>
                </defs>
                {shape === "area" && (
                  <polygon
                    className="fl-chart-area"
                    points={`${padLeft},${plotH} ${points} ${W},${plotH}`}
                    fill={`url(#${fade})`}
                  />
                )}
                <polyline className="fl-chart-line" points={points} vectorEffect="non-scaling-stroke" />
              </g>
            );
          })}

          {read !== null && (
            <>
              <line className="fl-chart-cross" x1={x(read)} x2={x(read)} y1="0" y2={plotH} />
              {shape !== "bars" && series.map((one) => (
                <circle key={one.name} className={join("fl-chart-knot", toneClass(one.tone))}
                        cx={x(read)} cy={y(one.values[read] ?? 0)} r="3" vectorEffect="non-scaling-stroke" />
              ))}
            </>
          )}

          {labels.map((label, i) => (
            i % everyLabel === 0
              ? <text key={i} className="fl-chart-axis" x={x(i)} y={tall - 3} textAnchor="middle">{label}</text>
              : null
          ))}

          {/* One pane takes the pointer, so every column answers rather
              than only the places a bar happens to be drawn. */}
          <rect className="fl-chart-hit" x={padLeft} y="0" width={plotW} height={plotH}
                data-testid="chart-hit"
                onPointerMove={hover} onMouseMove={hover} />
        </svg>
      </div>
    </figure>
  );
}

/**
 * Where a number has been lately, in the space of a line of text.
 *
 * It carries no axis and no reading: it is there to say rising, falling
 * or flat, which is the one thing a headline figure cannot say by
 * itself. Anything a reader would want to read off goes in a Chart.
 */
export function Spark({ values, tone }: { values: number[]; tone?: Tone }) {
  const mine = useId().replace(/:/g, "");
  if (values.length < 2) return null;
  const W = 120;
  const H = 32;
  const top = Math.max(1, ...values);
  const low = Math.min(...values, 0);
  const span = Math.max(1, top - low);
  const at = (value: number, i: number) =>
    `${(i / (values.length - 1)) * W},${H - ((value - low) / span) * (H - 3) - 1.5}`;
  const line = values.map(at).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className={toneClass(tone)}
         style={{ color: "var(--tone, var(--accent))" }} aria-hidden="true">
      <defs>
        <linearGradient id={mine} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="currentColor" stopOpacity="0.3" />
          <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon className="fl-chart-area" points={`0,${H} ${line} ${W},${H}`} fill={`url(#${mine})`} />
      <polyline className="fl-chart-line" points={line} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/**
 * A share as a percentage, which never rounds to all or to none.
 *
 * Ninety-nine point seven per cent of the fleet checked, drawn as 100%,
 * reads as "everything was checked" - and the three hosts nobody could
 * judge are the ones the reader was looking for. A share that is not
 * whole keeps a tenth rather than borrowing one.
 */
function share100(share: number, sign = true): string {
  const whole = share * 100;
  const rounded = Math.round(whole);
  const honest = (rounded === 100 && whole < 100) || (rounded === 0 && whole > 0)
    ? whole.toFixed(1)
    : String(rounded);
  return sign ? `${honest}%` : honest;
}

/* ---------------------------------------------------------------- ring */

/**
 * One share of a whole, read at a glance, with what it is made of beside
 * it. A share nobody could take draws no arc at all rather than an arc of
 * nothing, which would read as a share of none.
 */
export function Ring({ share, label, tone = "accent", legend }: {
  /** 0..1, or undefined when nobody could take it. */
  share?: number;
  label: ReactNode;
  tone?: Tone;
  legend?: { label: ReactNode; value: ReactNode; tone?: Tone }[];
}) {
  const known = share !== undefined && Number.isFinite(share);
  const size = 150;
  const stroke = 15;
  const radius = (size - stroke) / 2;
  const round = 2 * Math.PI * radius;
  const filled = known ? Math.min(1, Math.max(0, share)) : 0;
  return (
    <div className="fl-ring">
      <div className={join("fl-ring-plot", toneClass(tone))}>
        <svg viewBox={`0 0 ${size} ${size}`} role="img" aria-hidden="true">
          <circle className="fl-ring-track" cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} />
          {known && (
            <circle
              className="fl-ring-arc"
              cx={size / 2}
              cy={size / 2}
              r={radius}
              strokeWidth={stroke}
              strokeDasharray={`${round * filled} ${round}`}
            />
          )}
        </svg>
        <div className="fl-ring-face">
          <span className="fl-ring-value">{known ? share100(filled) : "—"}</span>
          <span className="fl-ring-label">{label}</span>
        </div>
      </div>
      {legend && legend.length > 0 && (
        <dl className="fl-ring-legend">
          {legend.map((one, index) => (
            <div className={join("fl-ring-legend-row", toneClass(one.tone ?? tone))} key={index}>
              <i className="fl-ring-key" />
              <dt className="fl-truncate">{one.label}</dt>
              <dd><b>{one.value}</b></dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/* ----------------------------------------------------------- the form */

/** The fields of a form, in columns that fold into one when narrow. */
export function Fields({ children }: { children: ReactNode }) {
  return <div className="fl-fields">{children}</div>;
}

export function Field({ label, hint, wide = false, children }: {
  label: ReactNode;
  hint?: ReactNode;
  /** A field that needs the whole width: a path, a reason, a list. */
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <label className={join("fl-field", wide && "fl-wide")}>
      <span className="fl-field-label">{label}</span>
      {children}
      {hint && <span className="fl-field-hint">{hint}</span>}
    </label>
  );
}

/** A checkbox with its sentence; the box lines up with the first line. */
export function Check({ checked, onChange, disabled, children, title, testId }: {
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  children: ReactNode;
  /** The longer sentence the short label stands for, under the pointer. */
  title?: string;
  testId?: string;
}) {
  return (
    <label className="fl-check" title={title}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
        data-testid={testId}
      />
      <span>{children}</span>
    </label>
  );
}

/** The buttons of a form or a card, the one that does the thing first. */
export function Actions({ children, right = false }: { children: ReactNode; right?: boolean }) {
  return <div className={join("fl-actions", right && "fl-right")}>{children}</div>;
}

/** A line the reader has to take account of before going on. */
export function Banner({ tone = "warn", children, actions }: {
  tone?: Tone;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className={join("fl-banner", toneClass(tone))} role="status">
      <span className="fl-banner-text">{children}</span>
      {actions && <div className="fl-actions">{actions}</div>}
    </div>
  );
}

/* ---------------------------------------------------------- the tabs */

/**
 * The tabs of a screen that holds several of one kind of thing.
 *
 * They are tabs and not a second navigation: the rail says where in the
 * panel the reader is, and these say which part of this screen they are
 * reading. A screen with more than about seven wants a rail of its own.
 */
export function Tabs<T extends string>({ value, onChange, tabs }: {
  value: T;
  onChange: (value: T) => void;
  tabs: { value: T; label: ReactNode; count?: number }[];
}) {
  return (
    <div className="fl-tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          role="tab"
          aria-selected={tab.value === value}
          className={tab.value === value ? "fl-tab fl-on" : "fl-tab"}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {tab.count !== undefined && <span className="fl-tab-count">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------------------------------- the dialog */

/**
 * A question that has to be answered before anything else happens.
 *
 * It is for a decision and for what the decision has to carry - the
 * reason that goes into the trail, the name typed out to show the right
 * machine was meant. It is not for a form somebody might want to read
 * the screen behind while filling in: that belongs on the page.
 */
export function Modal({ title, children, onClose, actions }: {
  title: ReactNode;
  children: ReactNode;
  onClose: () => void;
  actions: ReactNode;
}) {
  return (
    <div
      className="fl-modal-backdrop"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <section className="fl-modal" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined}>
        <h2 className="fl-modal-title">{title}</h2>
        <div className="fl-modal-body">{children}</div>
        <div className="fl-actions fl-right">{actions}</div>
      </section>
    </div>
  );
}


/* ------------------------------------------------------------ the file */

/**
 * A list, taken away as a file.
 *
 * The address it asks for is the list's own with the screen's filter on
 * it, so what is saved is what is on the screen rather than the first
 * page of everything. It goes through the panel's own fetch because a
 * bare <a download> drops the bearer token and comes back a refusal.
 */
export function Download({ path, params, label, disabled = false, fileName }: {
  /** The address of the list, without a query: /api/v1/hosts. */
  path: string;
  /** The filter as the server reads it; the keys of a page are dropped. */
  params?: URLSearchParams;
  label?: string;
  disabled?: boolean;
  /** When the server names no file of its own and it is not a CSV. */
  fileName?: string;
}) {
  const t = useT();
  const toast = useToast();
  const [working, setWorking] = useState(false);
  const take = async () => {
    setWorking(true);
    try {
      const response = await fetchWithCredentials(exportAddress(path, params));
      if (!response.ok) {
        let detail = response.statusText;
        try { detail = ((await response.json()) as { detail?: string }).detail ?? detail; } catch { /* a proxy's page, not the API's answer */ }
        throw new Error(detail);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = response.headers.get("Content-Disposition")
        ? exportFileName(response.headers.get("Content-Disposition"))
        : fileName ?? exportFileName(null);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      toast.error(t("The export failed: {message}", { message: error instanceof Error ? error.message : String(error) }));
    } finally {
      setWorking(false);
    }
  };
  return (
    <button type="button" className="fl-quiet fl-small" onClick={take} disabled={disabled || working} data-testid="export-csv">
      {working ? t("Exporting…") : (label ?? t("Export CSV"))}
    </button>
  );
}

/* ------------------------------------------------------------ the arcs */

/**
 * One measure across a handful of things, as rings inside one another.
 *
 * Five hosts' memory in the room a single figure would take. Beyond
 * about six it stops being readable and the answer is a Bars.
 */
export function Arcs({ items, label }: {
  items: { label: ReactNode; share: number; tone?: Tone }[];
  label?: ReactNode;
}) {
  const size = 170;
  const stroke = 11;
  const gap = 5;
  const shown = items.slice(0, 6);
  return (
    <div className="fl-arcs">
      <div className="fl-arcs-plot">
        <svg viewBox={`0 0 ${size} ${size}`} role="img" aria-hidden="true">
          {shown.map((one, index) => {
            const radius = (size - stroke) / 2 - index * (stroke + gap);
            if (radius <= stroke) return null;
            const round = 2 * Math.PI * radius;
            const filled = Math.min(1, Math.max(0, one.share));
            return (
              <g key={index} className={toneClass(one.tone ?? "accent")}>
                <circle className="fl-arcs-track" cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} />
                <circle
                  className="fl-arcs-arc"
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  strokeWidth={stroke}
                  strokeDasharray={`${round * filled} ${round}`}
                />
              </g>
            );
          })}
        </svg>
      </div>
      <dl className="fl-ring-legend">
        {label && <span className="fl-subhead">{label}</span>}
        {shown.map((one, index) => (
          <div className={join("fl-ring-legend-row", toneClass(one.tone ?? "accent"))} key={index}>
            <i className="fl-ring-key" />
            <dt className="fl-truncate">{one.label}</dt>
            <dd><b>{Math.round(Math.min(1, Math.max(0, one.share)) * 100)}%</b></dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/* ----------------------------------------------------------- the tiles */

/** A fleet of things, every one of them the same shape and the same size. */
export function Tiles({ children }: { children: ReactNode }) {
  return <div className="fl-tiles">{children}</div>;
}

/**
 * One thing in that fleet.
 *
 * Its name, how it is going, up to three measurements and where it has
 * been. `silent` is for a thing that has not answered: it says so on
 * itself, in its own corner, while every other tile goes on working.
 * That is the difference between a fleet with one quiet host and a
 * screen that looks broken.
 */
export function Tile({ name, sub, state, figures, spark, silent, to, testId }: {
  name: ReactNode;
  sub?: ReactNode;
  /** The pill in the corner: what condition this one is in. */
  state?: ReactNode;
  figures?: { label: ReactNode; value: ReactNode | null | undefined; tone?: Tone }[];
  spark?: number[];
  /** What it has not been able to tell us, in the reader's words. */
  silent?: ReactNode;
  to?: string;
  testId?: string;
}) {
  const body = (
    <>
      <div className="fl-tile-top">
        <span className="fl-tile-names">
          <span className="fl-tile-name">{name}</span>
          {sub && <span className="fl-tile-sub">{sub}</span>}
        </span>
        {state}
      </div>
      {figures && figures.length > 0 && (
        <div className="fl-tile-figs">
          {figures.slice(0, 3).map((one, index) => (
            <span className={join("fl-tile-fig", toneClass(one.value === null || one.value === undefined ? "unknown" : one.tone))} key={index}>
              <span className="fl-tile-fig-label">{one.label}</span>
              <span className="fl-tile-fig-value">
                {one.value === null || one.value === undefined ? "—" : one.value}
              </span>
            </span>
          ))}
        </div>
      )}
      {silent && <span className={join("fl-tile-veil", toneClass("warn"))}>{silent}</span>}
      {!silent && spark && spark.length > 1 && (
        <div className="fl-tile-spark" aria-hidden="true"><Spark values={spark} /></div>
      )}
    </>
  );
  const className = join("fl-tile", silent ? "fl-tile-mute" : undefined);
  const id = testId ?? undefined;
  return to
    ? <Link to={to} className={className} data-testid={id}>{body}</Link>
    : <div className={className} data-testid={id}>{body}</div>;
}

/* --------------------------------------------------------- the squares */

/**
 * The whole fleet's condition in one block: a square per thing.
 *
 * It answers "is anything wrong" before a number can be read, and it
 * stays readable at a thousand hosts where a table of a thousand rows
 * does not. The tally under it is the part a reader quotes.
 */
export function Squares({ items, tally, testId }: {
  items: { key: string; tone?: Tone; title?: string; to?: string }[];
  tally?: { label: ReactNode; value: ReactNode; tone?: Tone }[];
  testId?: string;
}) {
  return (
    <div className="fl-squares" data-testid={testId}>
      <div className="fl-squares-grid">
        {items.map((one) => (
          one.to
            ? <Link key={one.key} to={one.to} className={join("fl-square", toneClass(one.tone ?? "unknown"))} title={one.title} />
            : <span key={one.key} className={join("fl-square", toneClass(one.tone ?? "unknown"))} title={one.title} />
        ))}
      </div>
      {tally && tally.length > 0 && (
        <div className="fl-quiet-row">
          {tally.map((one, index) => (
            <span className={join("fl-quiet-item", toneClass(one.tone))} key={index}>
              <b>{one.value}</b>{one.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------ the feed */

/** What has happened, newest first. Give the card `flush` for this. */
export function Feed({ children }: { children: ReactNode }) {
  return <div className="fl-feed">{children}</div>;
}

export function FeedRow({ icon, tone, what, who, when, to }: {
  icon?: IconName;
  tone?: Tone;
  what: ReactNode;
  /** Who or what it happened to, under the sentence. */
  who?: ReactNode;
  when?: ReactNode;
  to?: string;
}) {
  const body = (
    <>
      <span className={join("fl-feed-mark", toneClass(tone ?? "neutral"))} aria-hidden="true">
        <Icon name={icon ?? "help"} />
      </span>
      <span className="fl-feed-text">
        <span className="fl-feed-what">{what}</span>
        {who && <span className="fl-feed-who">{who}</span>}
      </span>
      {when && <span className="fl-feed-when">{when}</span>}
    </>
  );
  return to ? <Link to={to} className="fl-feed-row">{body}</Link> : <div className="fl-feed-row">{body}</div>;
}

/* ----------------------------------------------------------- the needs */

/**
 * The things waiting on a person, as rows that lead to them.
 *
 * A count nobody could take is an em dash and says unknown; a count at
 * zero does not belong on the list at all, and the caller drops it
 * before it reaches here.
 */
export function Needs({ items }: {
  items: {
    label: ReactNode;
    /** undefined is "nobody knows"; a boolean is a yes or a no. */
    value?: number | string | boolean;
    tone?: Tone;
    /** Nothing to answer here - a nought, a no - so it wears no state. */
    quiet?: boolean;
    to?: string;
  }[];
}) {
  const t = useT();
  return (
    <div className="fl-needs">
      {items.map((one, index) => {
        const unknown = one.value === undefined || one.value === null;
        const shown = typeof one.value === "boolean" ? (one.value ? t("yes") : t("no")) : one.value;
        const body = (
          <>
            <span className="fl-needs-label">{one.label}</span>
            {unknown && <span className="fl-faint fl-small">{t("not counted")}</span>}
            <span className="fl-needs-count">{unknown ? "—" : shown}</span>
          </>
        );
        const className = join(
          "fl-needs-row",
          toneClass(unknown ? "unknown" : one.quiet ? "neutral" : one.tone),
        );
        return one.to
          ? <Link key={index} to={one.to} className={className}>{body}</Link>
          : <div key={index} className={className}>{body}</div>;
      })}
    </div>
  );
}

/* ------------------------------------------------------------ the bones */

/**
 * The shape of what has not arrived yet.
 *
 * A screen that says "Loading…" tells the reader nothing about whether
 * they are in the right place; a shape the size of the thing coming
 * tells them they are, and stops the page jumping when it lands.
 */
export function Bone({ height = 14, width }: { height?: number; width?: string | number }) {
  return <span className="fl-bone" style={{ display: "block", height, width: width ?? "100%" }} aria-hidden="true" />;
}

export function Bones({ rows = 3, height = 14 }: { rows?: number; height?: number }) {
  const t = useT();
  return (
    <div className="fl-bones" role="status" aria-label={t("Loading…")}>
      {Array.from({ length: rows }, (_, index) => (
        <Bone key={index} height={height} width={index === rows - 1 ? "60%" : "100%"} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------- the pie */

/**
 * How a whole divides, as a ring of slices with the total inside it.
 *
 * This is the fleet's condition in one widget: every state is a slice,
 * and what nobody has heard from is a slice like any other rather than
 * an absence. A ring says one share of a whole; this says what the
 * whole is made of, and the two are not the same question.
 */
export function Pie({ slices, total, label, hole = 0.62, testId }: {
  slices: { label: ReactNode; value: number; tone?: Tone; to?: string }[];
  /** What goes in the middle; the sum of the slices when not given. */
  total?: ReactNode;
  label?: ReactNode;
  /** 0 is a pie, 0.62 the ring every board in the look draws. */
  hole?: number;
  testId?: string;
}) {
  const t = useT();
  const size = 170;
  const drawn = slices.filter((one) => one.value > 0);
  const sum = drawn.reduce((into, one) => into + one.value, 0);
  const radius = size / 2 - 4;
  const inner = radius * hole;
  const middle = (radius + inner) / 2;
  const width = radius - inner;
  const round = 2 * Math.PI * middle;

  let before = 0;
  return (
    <div className="fl-pie" data-testid={testId}>
      <div className="fl-pie-plot">
        <svg viewBox={`0 0 ${size} ${size}`} role="img" aria-hidden="true">
          <circle className="fl-pie-track" cx={size / 2} cy={size / 2} r={middle} strokeWidth={width} />
          {sum > 0 && drawn.map((one, index) => {
            const share = one.value / sum;
            /* Each slice is the same circle, dashed to its own length
               and turned to where the one before it ended. Drawn this
               way there is no arc arithmetic to get wrong, and the
               gap between slices is a dash rather than a shape. */
            const turn = before * 360;
            before += share;
            return (
              <circle
                key={index}
                className={join("fl-pie-slice", toneClass(one.tone))}
                cx={size / 2}
                cy={size / 2}
                r={middle}
                strokeWidth={width}
                strokeDasharray={`${Math.max(0, round * share - 2)} ${round}`}
                transform={`rotate(${turn} ${size / 2} ${size / 2})`}
              >
                <title>{`${one.value}`}</title>
              </circle>
            );
          })}
        </svg>
        <div className="fl-pie-face">
          <span className="fl-pie-total">{total ?? (sum > 0 ? sum : "—")}</span>
          {label && <span className="fl-pie-label">{label}</span>}
        </div>
      </div>
      <dl className="fl-ring-legend">
        {slices.map((one, index) => {
          const body = (
            <>
              <i className="fl-ring-key" />
              <dt className="fl-truncate">{one.label}</dt>
              <dd><b>{one.value}</b> <span className="fl-faint">{sum > 0 ? t("{n}%", { n: share100(one.value / sum, false) }) : ""}</span></dd>
            </>
          );
          const className = join("fl-ring-legend-row", toneClass(one.tone));
          return one.to
            ? <Link key={index} to={one.to} className={className}>{body}</Link>
            : <div key={index} className={className}>{body}</div>;
        })}
      </dl>
    </div>
  );
}

/* ----------------------------------------------------- list furniture */

/**
 * How many rows a list shows at once. One control, so the same words and
 * the same sizes appear wherever a list is long enough to need them.
 */
export function RowsPerPage({ size, onSize, sizes = PAGE_SIZES, testId }: {
  size: number;
  onSize: (size: number) => void;
  sizes?: readonly number[];
  testId?: string;
}) {
  const t = useT();
  return (
    <label className="fl-rows">
      {t("Rows per page")}
      <select value={size} onChange={(event) => onSize(Number(event.target.value))} data-testid={testId ?? "page-size"}>
        {sizes.map((one) => <option key={one} value={one}>{one}</option>)}
      </select>
    </label>
  );
}

/**
 * A row of shortcuts that set something rather than choose between
 * states: "the last hour", "the last day". None of them is ever the one
 * that is on, which is what separates this from a Seg.
 */
export function Presets({ options, label }: {
  options: { label: ReactNode; onPick: () => void }[];
  label?: string;
}) {
  return (
    <div className="fl-seg" role="group" aria-label={label}>
      {options.map((one, index) => (
        <button key={index} type="button" onClick={one.onPick}>{one.label}</button>
      ))}
    </div>
  );
}

/* --------------------------------------------------------- the button */

/**
 * A thing to press, and which kind it is.
 *
 * The stylesheet makes a bare button inside a screen the filled one,
 * which is right for the one action a card is for and wrong for the
 * three beside it. Every screen was reaching for a class to say so; this
 * says it in the kit instead, and a screen that writes `kind` cannot get
 * the appearance of a button wrong.
 */
export function Button({ kind = "do", onClick, disabled, title, icon, children, testId, type = "button" }: {
  /** `do` is the one action; `quiet` stands beside it; `word` is a link
      in a sentence; `danger` is the one that cannot be undone. */
  kind?: "do" | "quiet" | "plain" | "word" | "danger";
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  icon?: IconName;
  children: ReactNode;
  testId?: string;
  type?: "button" | "submit";
}) {
  const className = kind === "do" ? undefined
    : kind === "danger" ? "fl-danger"
    : `fl-${kind}`;
  return (
    <button type={type} className={className} onClick={onClick} disabled={disabled} title={title} data-testid={testId}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

/* -------------------------------------------------------- the readout */

/**
 * Something the reader is meant to copy: a command, a configuration, a
 * fingerprint, a key.
 *
 * It is read-only, it keeps its own line breaks, it scrolls rather than
 * wrapping a command across two lines, and the way to take it is beside
 * it rather than somewhere else on the screen. A screen that put one of
 * these in a text field gave its label two controls.
 */
export function Readout({ label, value, note, lines, highlight, wrap = false, atLine, testId }: {
  label?: ReactNode;
  value: string;
  note?: ReactNode;
  /** How tall before it scrolls; the default suits a command or two. */
  lines?: number;
  /**
   * What the reader is looking for, marked where it occurs.
   *
   * A search over a log that can only say which line matched, and not
   * where in it, makes the reader do the finding twice.
   */
  highlight?: string;
  /** Fold a long line instead of scrolling it sideways. */
  wrap?: boolean;
  /**
   * Which line the reader is standing on, counting from 0.
   *
   * What is sought is marked on that line apart from everywhere else,
   * and the line is brought into view. A search over a thousand lines
   * that can only say "match 7 of 40" leaves the finding to the reader,
   * which is the work the search was for.
   */
  atLine?: number;
  testId?: string;
}) {
  const t = useT();
  const toast = useToast();
  const here = useRef<HTMLElement | null>(null);
  // Brought into view when the line the reader stands on changes, and not
  // on every line a live stream appends: a view being followed is not
  // pulled back to a match the reader has already read.
  useEffect(() => {
    // Guarded: a window without the call (an old browser, a test) must
    // still show the mark rather than lose the whole readout to a throw.
    here.current?.scrollIntoView?.({ block: "nearest" });
  }, [atLine, highlight]);
  const take = async () => {
    const { copyToClipboard } = await import("../lib/clipboard");
    const done = await copyToClipboard(value);
    if (done) toast.success(t("Copied."));
    else toast.error(t("The browser would not take it; copy it by hand."));
  };
  return (
    <div className="fl-readout" data-testid={testId}>
      {(label || note) && (
        <div className="fl-readout-head">
          {label && <span className="fl-readout-label">{label}</span>}
          <button type="button" className="fl-plain" onClick={take} data-testid={testId ? `${testId}-copy` : undefined}>
            <Icon name="copy" />
            {t("Copy")}
          </button>
        </div>
      )}
      <pre
        className={join("fl-readout-body", wrap && "fl-readout-wrap")}
        style={lines ? { maxHeight: `${lines * 1.5}em` } : undefined}
      >
        {marked(value, highlight, atLine, here)}
      </pre>
      {note && <span className="fl-field-hint">{note}</span>}
    </div>
  );
}

/** The text, with every occurrence of what is sought marked in it. */
function marked(
  value: string,
  needle?: string,
  atLine?: number,
  here?: { current: HTMLElement | null },
): ReactNode {
  const what = needle?.trim() ?? "";
  if (what === "") return value;
  const seek = what.toLowerCase();
  const lines = value.split("\n");
  const out: ReactNode[] = [];
  let any = false;
  lines.forEach((line, index) => {
    const tail = index < lines.length - 1 ? "\n" : "";
    const now = atLine !== undefined && index === atLine;
    const lower = line.toLowerCase();
    const pieces: ReactNode[] = [];
    let from = 0;
    for (;;) {
      const found = lower.indexOf(seek, from);
      if (found < 0) break;
      if (found > from) pieces.push(line.slice(from, found));
      pieces.push(
        <mark key={found} className={now ? "fl-mark-now" : undefined}>
          {line.slice(found, found + what.length)}
        </mark>,
      );
      from = found + what.length;
    }
    if (pieces.length === 0) {
      out.push(line + tail);
      return;
    }
    any = true;
    if (from < line.length) pieces.push(line.slice(from));
    pieces.push(tail);
    out.push(
      <span
        key={index}
        data-here={now ? "" : undefined}
        ref={now && here ? (node) => { here.current = node; } : undefined}
      >
        {pieces}
      </span>,
    );
  });
  if (!any) return value;
  return out;
}

/* --------------------------------------------------------- the choice */

/**
 * One of several, each with its own sentence underneath.
 *
 * A Seg is for a choice the reader makes often and changes back; this is
 * for one they make once and have to understand first - which address
 * the fleet reaches the panel on, which route an agent takes.
 */
export function Choice<T extends string>({ value, onChange, options, label, name }: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode; hint?: ReactNode; disabled?: boolean }[];
  label?: ReactNode;
  /** What groups these for the browser; one per screen is enough. */
  name: string;
}) {
  return (
    <div className="fl-choice" role="radiogroup" aria-label={typeof label === "string" ? label : undefined}>
      {label && <span className="fl-field-label">{label}</span>}
      {options.map((one) => (
        <label className={join("fl-choice-one", one.disabled && "fl-off")} key={one.value}>
          <input
            type="radio"
            name={name}
            value={one.value}
            checked={one.value === value}
            disabled={one.disabled}
            onChange={() => onChange(one.value)}
          />
          <span className="fl-choice-text">
            <span className="fl-choice-name">{one.label}</span>
            {one.hint && <span className="fl-field-hint">{one.hint}</span>}
          </span>
        </label>
      ))}
    </div>
  );
}

/* --------------------------------------------------------- the guard */

/**
 * A control that exists only where the order would be taken.
 *
 * Every screen that can change something wrote this for itself - eight
 * copies by the time anybody counted - and each one made the same three
 * decisions slightly differently. They are the product's, not a screen's:
 *
 * - While the answer is on its way, nothing is drawn. A control that
 *   appears and then goes is worse than one that arrives late.
 * - Refused with a reason the reader can act on - a permission they
 *   could be given, a state the host is in - the control stays, shut,
 *   and the reason stands beside it. Hiding it teaches nobody anything.
 * - Refused with nothing to say, it is not drawn. An operator should not
 *   be shown a door that will never open.
 */
export function Guard({ verdict, children, testId }: {
  verdict: { allowed: boolean; known: boolean; pending: boolean; reason?: string; missing_permission?: string };
  /** Drawn where the order would be taken; `shut` where it would not. */
  children: (shut: boolean) => ReactNode;
  testId?: string;
}) {
  const t = useT();
  if (verdict.pending) return null;
  if (verdict.allowed) return <>{children(false)}</>;
  const why = verdict.reason
    || (verdict.missing_permission ? t("needs {permission}", { permission: verdict.missing_permission }) : "");
  if (!why) return null;
  return (
    <div className="fl-guard" data-testid={testId}>
      {children(true)}
      <span className="fl-note">{why}</span>
    </div>
  );
}

/* -------------------------------------------------------- shown once */

/**
 * A value the server will not say twice: a token, a password it chose, a
 * one-time secret.
 *
 * It is the thing worst to get wrong, so it is one piece rather than one
 * per screen: it says plainly that this is the only showing, it offers
 * the one way to take it, and closing it is the reader saying they have.
 * The value never goes into an address and never into a log.
 */
export function ShownOnce({ label, value, note, onClose, testId }: {
  label: ReactNode;
  value: string;
  note?: ReactNode;
  onClose: () => void;
  testId?: string;
}) {
  const t = useT();
  return (
    <div className={join("fl-shownonce", toneClass("warn"))} role="status" data-testid={testId}>
      <div className="fl-shownonce-head">
        <span className="fl-shownonce-label">{label}</span>
        <button type="button" className="fl-plain" onClick={onClose} data-testid={testId ? `${testId}-close` : undefined}>
          {t("I have it")}
        </button>
      </div>
      <Readout value={value} label={t("The value")} testId={testId ? `${testId}-value` : undefined} />
      <span className="fl-note">
        {note ?? t("This is the only time the panel shows it: it keeps a digest and nothing else.")}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------- paper */

/**
 * Print what is on the screen.
 *
 * The panel's own themes are dark, and a dark screen on paper is either
 * a wasted cartridge or text nobody can read. The reader's theme is put
 * aside for the length of the printing and given straight back: the
 * stylesheet decides nothing about colour here, which is the rule, and
 * the sheet comes out as a document rather than as a photograph of a
 * screen.
 */
export function printPage() {
  const root = document.documentElement;
  const was = root.dataset.theme;
  root.dataset.theme = "latte";
  const back = () => {
    if (was === undefined) delete root.dataset.theme;
    else root.dataset.theme = was;
    window.removeEventListener("afterprint", back);
  };
  window.addEventListener("afterprint", back);
  try {
    window.print();
  } finally {
    // A browser that never fires afterprint - and a test - still gets
    // its theme back.
    if (typeof window.onafterprint === "undefined") back();
  }
}
