import { Children, isValidElement, useState, type CSSProperties, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Icon, type IconName } from "../components/icons";
import { pageTitle, useDocumentTitle } from "../lib/title";
import { useT } from "../i18n";

/**
 * The kit: every surface, every rhythm and every piece of chrome the panel
 * is allowed to draw.
 *
 * Written on 15.10 to replace markup that had been assembled screen by
 * screen over months. The rule that matters is not which element a piece
 * produces but that there is exactly one piece for each job: one page
 * head, one panel, one grid, one measurement, one table, one field. A
 * screen composes them and owns no appearance of its own, so changing how
 * the product looks is changing this file and nothing else.
 *
 * Every class here begins with `ui-`. Nothing outside this file writes one
 * that is not a tone, and nothing in it writes a class that is not one -
 * which is what lets the stylesheet be read as a list of what exists
 * rather than as a history of what was needed once.
 */

export type Tone = "ok" | "warn" | "error" | "info" | "unknown" | "neutral" | "accent";
export type Span = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12;

const join = (...parts: (string | false | undefined | null)[]) => parts.filter(Boolean).join(" ");

/**
 * How a thing is going, as the one class that says it.
 *
 * A tone sets two custom properties and the text colour, and every piece
 * of the kit reads those rather than carrying a rule per tone: `.ui-pill`
 * is one rule, not seven. A word the kit does not know is neutral, never
 * a class the stylesheet has never heard of.
 */
const TONES = new Set(["ok", "warn", "error", "info", "unknown", "neutral", "accent"]);
export function toneClass(name?: string | null): string {
  return `ui-${name && TONES.has(name) ? name : "neutral"}`;
}

/* ---------------------------------------------------------------- page */

/** A link on the way to the current page, shown above the title. */
export type Crumb = { label: string; to: string };

/**
 * The head of a screen: what it is, one line on what it answers, and the
 * actions that belong to the whole of it. The long explanation goes behind
 * the mark, because a paragraph at the top of a screen is read once and
 * then skipped for ever.
 */
export function PageHead({
  title, lead, description, actions, help, mark, icon, breadcrumb,
}: {
  title: ReactNode;
  /** One line, at most about eighty characters: what this screen is for. */
  lead?: ReactNode;
  /** The name this had in the markup it replaces. */
  description?: ReactNode;
  actions?: ReactNode;
  help?: ReactNode;
  mark?: ReactNode;
  /** The mark of the section; without it the head takes the one of its route. */
  icon?: IconName;
  breadcrumb?: Crumb[];
}) {
  const t = useT();
  const [helpOpen, setHelpOpen] = useState(false);
  const location = useLocation();
  const name = icon ?? iconForPath(location.pathname);
  const words = lead ?? description;
  // The tab is named after the page.
  useDocumentTitle(typeof title === "string" && title.trim() !== "" ? pageTitle(title) : undefined);
  return (
    <header className="ui-pagehead">
      <div className="ui-pagehead-row">
        {mark ?? (name && <span className="ui-pagehead-mark" aria-hidden="true"><Icon name={name} /></span>)}
        <div className="ui-pagehead-text">
          {breadcrumb && breadcrumb.length > 0 && (
            <nav className="ui-crumbs">
              {breadcrumb.map((crumb) => <Link key={crumb.to} to={crumb.to}>{crumb.label}</Link>)}
            </nav>
          )}
          <h1 className="ui-pagehead-title">
            {title}
            {help && (
              <button
                type="button"
                className="ui-helpmark"
                aria-expanded={helpOpen}
                title={t("What this screen is for")}
                onClick={() => setHelpOpen(!helpOpen)}
                data-testid="page-help-toggle"
              >
                <Icon name="help" />
              </button>
            )}
          </h1>
          {words && <p className="ui-pagehead-lead">{words}</p>}
          {help && helpOpen && <div className="ui-help" data-testid="page-help">{help}</div>}
        </div>
        {actions && <div className="ui-pagehead-actions">{actions}</div>}
      </div>
    </header>
  );
}

/**
 * The head of a section inside a page: a title, one line about it, the rest
 * behind the mark, and the actions on the right.
 *
 * The same object as PageHead and deliberately a smaller one. A page has a
 * head; a tab of a page has this.
 */
export function SectionHead({
  title, description, help, actions, mark,
}: {
  title: ReactNode;
  description?: ReactNode;
  help?: ReactNode;
  actions?: ReactNode;
  mark?: ReactNode;
}) {
  const t = useT();
  const [helpOpen, setHelpOpen] = useState(false);
  return (
    <>
      <div className="ui-sectionhead">
        {mark && <span className="ui-sectionhead-mark" aria-hidden="true">{mark}</span>}
        <div className="ui-sectionhead-text">
          <h2 className="ui-sectionhead-title">
            {title}
            {help && (
              <button
                type="button"
                className="ui-helpmark"
                aria-expanded={helpOpen}
                title={t("What this screen is for")}
                onClick={() => setHelpOpen(!helpOpen)}
                data-testid="section-help-toggle"
              >
                <Icon name="help" />
              </button>
            )}
          </h2>
          {description && <p className="ui-lede">{description}</p>}
        </div>
        {actions && <div className="ui-sectionhead-actions">{actions}</div>}
      </div>
      {help && helpOpen && <div className="ui-help" data-testid="section-help">{help}</div>}
    </>
  );
}

/* The mark of a section, by the first segment of its address: the same
   icon the navigation shows, so the head and the sidebar agree. */
const SECTION_ICONS: Record<string, IconName> = {
  dashboard: "dashboard", hosts: "hosts", jobs: "jobs", bulk: "bulk", campaigns: "campaigns",
  security: "security", vulnerabilities: "vulnerabilities", certificates: "certificates",
  secrets: "secrets", backups: "backups", monitoring: "monitoring", directory: "directory",
  access: "access", audit: "audit",
  groups: "groups", tags: "groups", teams: "accounts", profile: "accounts",
  relays: "relays", reports: "audit", readiness: "overview", policies: "security",
  notifications: "notifications", unresolved: "jobs", reads: "reads", budgets: "overview",
  settings: "settings", status: "settings", setup: "settings", support: "logs",
};

function iconForPath(pathname: string): IconName | undefined {
  const [, first, second] = pathname.split("/");
  if (first === "hosts" && second === "new") return "add-host";
  return SECTION_ICONS[first ?? ""];
}

/* ---------------------------------------------------------------- grid */

/**
 * The twelve-column grid everything stands on. A child says how many
 * columns it takes; the ladder in the stylesheet decides what that means
 * on a phone.
 */
export function Grid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={join("ui-grid", className)}>{children}</div>;
}

export function Col({ span = 12, children, style }: { span?: Span; children: ReactNode; style?: CSSProperties }) {
  return <div className={`ui-col ui-col-${span}`} style={style}>{children}</div>;
}

/** Blocks side by side, in as many columns as the width allows. */
export function Cols({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return <div className={join("ui-cols", wide && "ui-wide")}>{children}</div>;
}

/** A column of blocks, at the rhythm of the page. */
export function Stack({ children, gap = "m", className }: { children: ReactNode; gap?: "s" | "m" | "l"; className?: string }) {
  return <div className={join(gap === "s" ? "ui-stack-s" : gap === "l" ? "ui-stack-l" : "ui-stack", className)}>{children}</div>;
}

/* --------------------------------------------------------------- panel */

/**
 * The one surface. A title that labels rather than shouts, one place for
 * the controls that belong to this panel, a body, and a foot for what is
 * said after the content.
 *
 * `flush` is for a body that is a table: the table reaches the panel's own
 * edges instead of floating inside a margin.
 */
export function Panel({
  title, note, description, actions, children, foot, footer, flush = false, className, tone: state,
}: {
  title?: ReactNode;
  note?: ReactNode;
  /** The name this had in the markup it replaces. */
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  foot?: ReactNode;
  footer?: ReactNode;
  flush?: boolean;
  className?: string;
  tone?: Tone;
}) {
  const words = note ?? description;
  const below = foot ?? footer;
  return (
    <section className={join("ui-panel", state && toneClass(state), className)}>
      {(title || words || actions) && (
        <div className="ui-panel-head">
          <div className="ui-panel-headtext">
            {title && <h2 className="ui-panel-title">{title}</h2>}
            {words && <p className="ui-panel-note">{words}</p>}
          </div>
          {actions && <div className="ui-panel-actions">{actions}</div>}
        </div>
      )}
      {children !== undefined && children !== null && children !== false && (
        <div className={join("ui-panel-body", flush && "ui-flush")}>{children}</div>
      )}
      {below && <div className="ui-panel-foot">{below}</div>}
    </section>
  );
}

/* --------------------------------------------------------- measurement */

/**
 * A number somebody reads from across the room.
 *
 * Two rules are the component's and not the caller's. A value nobody knows
 * is an em dash and the word unknown - never a nought, because a fleet
 * nobody has asked and a fleet with nothing wrong are different answers.
 * And a state colours the figure, never the box: a row of tiles with two
 * of them framed in red stops being a row.
 */
export function Stat({
  label, value, unit, tone: state, mark, icon, note, hint, delta, size = "l",
  plain = false, hero = false, to, span, testId,
}: {
  label: ReactNode;
  /** null and undefined are both "nobody knows". */
  value: ReactNode | null | undefined;
  unit?: string;
  tone?: Tone;
  mark?: ReactNode;
  /** The mark above the number, as the name of an icon. */
  icon?: IconName;
  note?: ReactNode;
  /** The name this had in the markup it replaces. */
  hint?: ReactNode;
  delta?: { text: string; good?: boolean; direction?: "up" | "down" };
  size?: "s" | "m" | "l" | "xl";
  /** Inside a panel, where a second box would only add lines. */
  plain?: boolean;
  /** The one filled tile. It wears the accent, which carries no state. */
  hero?: boolean;
  to?: string;
  span?: Span;
  testId?: string;
}) {
  const t = useT();
  const unknown = value === null || value === undefined;
  const shown = unknown ? "unknown" : state;
  const words = note ?? hint;
  const classes = join(
    "ui-stat", `ui-stat-${size}`, plain && "ui-stat-plain", hero && "ui-stat-hero",
    span && `ui-col-${span}`, shown && toneClass(shown),
  );
  const body = (
    <>
      {(mark || icon) && (
        <span className="ui-stat-mark" aria-hidden="true">{mark ?? (icon && <Icon name={icon} />)}</span>
      )}
      <div className={join("ui-stat-value", typeof value === "string" && value.length > 8 && "ui-stat-phrase")}>
        {unknown ? <span className="ui-stat-dash" title={t("unknown")}>—</span> : value}
        {!unknown && unit && <span className="ui-stat-unit">{unit}</span>}
      </div>
      <div className="ui-stat-foot">
        <span className="ui-stat-label">{label}</span>
        {delta && !unknown && (
          <span className={join("ui-stat-delta", delta.good === false ? "ui-bad" : "ui-good")}>
            {delta.text}
            {delta.direction && <span aria-hidden="true">{delta.direction === "up" ? " ↑" : " ↓"}</span>}
          </span>
        )}
      </div>
      {words && <p className="ui-stat-note">{words}</p>}
    </>
  );
  const id = testId ?? (typeof label === "string" ? `stat-${label}` : undefined);
  if (to) return <Link to={to} className={join(classes, "ui-stat-link")} data-testid={id} data-state={shown ?? "none"}>{body}</Link>;
  return <div className={classes} data-testid={id} data-state={shown ?? "none"}>{body}</div>;
}

/**
 * The row of measurements.
 *
 * `foldZeros` is for a grid whose panel promises to show what needs doing:
 * a tile at zero becomes a word under the row, so the tiles are the things
 * that are actually there. Unknown is not zero and keeps its tile.
 */
export function Stats({
  children, compact = false, foldZeros = false,
}: {
  children: ReactNode;
  compact?: boolean;
  foldZeros?: boolean;
}) {
  const classes = join("ui-stats", compact && "ui-compact");
  if (!foldZeros) return <div className={classes}>{children}</div>;

  const tiles: ReactNode[] = [];
  const folded: { label: ReactNode; to?: string }[] = [];
  Children.forEach(children, (child) => {
    if (!isValidElement<{ value?: unknown; label?: ReactNode; to?: string }>(child)) {
      tiles.push(child);
      return;
    }
    if (child.props.value === 0) {
      folded.push({ label: child.props.label, to: child.props.to });
      return;
    }
    tiles.push(child);
  });

  return (
    <>
      {tiles.length > 0 && <div className={classes}>{tiles}</div>}
      {folded.length > 0 && (
        <div className="ui-stats-folded" data-testid="stats-folded">
          {folded.map((one, index) => {
            const body = <><span className="ui-stats-folded-value">0</span>{one.label}</>;
            return one.to
              ? <Link key={index} to={one.to} className="ui-stats-folded-item">{body}</Link>
              : <span key={index} className="ui-stats-folded-item">{body}</span>;
          })}
        </div>
      )}
    </>
  );
}

/* --------------------------------------------------------------- table */

export type Column<Row> = {
  /** Distinguishes the column; also the key React draws the cells by. */
  key?: string;
  /** What stands in the header. A column with no head still needs its key. */
  head?: ReactNode;
  /** What the cell draws. */
  cell: (row: Row) => ReactNode;
  /**
   * The column that names the row. Exactly one should carry it: a row whose
   * first cell is a <th> is a row a screen reader can read back.
   */
  rowHeader?: boolean;
  /** A column of figures is read down, so it is aligned right. */
  numeric?: boolean;
  /** The buttons at the end of a row. */
  actions?: boolean;
  /** Prose that squeezes the useful columns on a narrow screen. */
  wideOnly?: boolean;
  /** The same thing, said the way the kit says it. */
  minor?: boolean;
};

/**
 * One table for the whole panel. It scrolls inside its own holder rather
 * than widening the page, its head is a label and not a headline, and a
 * row shows data: whatever can be done to it lives where the row leads.
 */
export function DataTable<Row>({
  columns, rows, keyOf, rowKey, rowTestId, empty, bodyTestId, onRow, rowClass,
}: {
  columns: Column<Row>[];
  rows: Row[];
  keyOf?: (row: Row, index: number) => string;
  rowKey?: (row: Row) => string;
  rowTestId?: (row: Row) => string;
  empty?: ReactNode;
  bodyTestId?: string;
  onRow?: (row: Row) => void;
  rowClass?: (row: Row) => string | undefined;
}) {
  if (rows.length === 0 && empty !== undefined) return <Empty>{empty}</Empty>;
  const key = (row: Row, index: number) => (rowKey ? rowKey(row) : keyOf ? keyOf(row, index) : String(index));
  const classOf = (column: Column<Row>) => join(
    column.numeric && "ui-numeric",
    column.actions && "ui-actioncell",
    (column.minor || column.wideOnly) && "ui-minor",
  ) || undefined;

  return (
    <div className="ui-table-holder">
      <table className="ui-table">
        <thead>
          <tr>
            {columns.map((column, i) => (
              <th key={column.key ?? i} scope="col" className={classOf(column)}>{column.head}</th>
            ))}
          </tr>
        </thead>
        <tbody data-testid={bodyTestId}>
          {rows.map((row, index) => (
            <tr
              key={key(row, index)}
              data-testid={rowTestId?.(row)}
              className={rowClass?.(row)}
              onClick={onRow ? () => onRow(row) : undefined}
            >
              {columns.map((column, i) =>
                column.rowHeader ? (
                  <th key={column.key ?? i} scope="row" className={classOf(column)}>{column.cell(row)}</th>
                ) : (
                  <td key={column.key ?? i} className={classOf(column)}>{column.cell(row)}</td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A table that cannot widen its panel: it scrolls inside it instead. */
export function TableHolder({ children }: { children: ReactNode }) {
  return <div className="ui-table-holder">{children}</div>;
}

/* ------------------------------------------------------------- walking */

/**
 * The page sizes a list offers. One set for the whole panel: a screen that
 * invents its own is a screen that answers "how many rows" differently from
 * the one beside it.
 */
export const PAGE_SIZES = [25, 50, 100, 200] as const;

/**
 * The numbers a pager shows: the first, the last, the ones around the
 * current, and a gap where it skipped.
 */
export function pageNumbers(current: number, pages: number, around = 2): (number | "gap")[] {
  if (pages < 1) return [];
  const wanted = new Set<number>([1, pages]);
  for (let n = current - around; n <= current + around; n++) {
    if (n >= 1 && n <= pages) wanted.add(n);
  }
  const ordered = [...wanted].sort((a, b) => a - b);
  const out: (number | "gap")[] = [];
  let previous = 0;
  for (const n of ordered) {
    if (previous && n - previous > 1) out.push("gap");
    out.push(n);
    previous = n;
  }
  return out;
}

/**
 * Walking a list too long to draw: the rows per page, where in the whole the
 * page is, and the way to another one. The toolbar of a list takes this in
 * its `end`.
 */
export function Pager({
  page, size, total, onPage, onSize, sizes = PAGE_SIZES,
}: {
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
      <label className="ui-rows">
        {t("Rows per page")}
        <select
          value={size}
          onChange={(event) => { onSize(Number(event.target.value)); onPage(1); }}
          data-testid="page-size"
        >
          {sizes.map((one) => <option key={one} value={one}>{one}</option>)}
        </select>
      </label>
      <span data-testid="page-of">
        {total > 0
          ? t("{n} of {total}", {
              n: `${(page - 1) * size + 1}-${Math.min(page * size, total)}`,
              total,
            })
          : t("{n} of {total}", { n: 0, total: 0 })}
      </span>
      {pages > 1 && (
        <nav className="ui-pager ui-segmented" aria-label={t("Pages")}>
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => onPage(page - 1)}
            data-testid="page-previous"
            aria-label={t("Previous")}
          >
            ‹
          </button>
          {pageNumbers(page, pages).map((one, index) =>
            one === "gap" ? (
              /* The gap is not a button and is hidden from a screen reader:
                 the numbers either side of it are the ones to press. */
              <span key={`gap-${index}`} className="ui-pager-gap" aria-hidden="true">…</span>
            ) : (
              <button
                key={one}
                type="button"
                className={one === page ? "ui-active" : ""}
                aria-current={one === page ? "page" : undefined}
                onClick={() => onPage(one)}
                data-testid={`page-${one}`}
              >
                {one}
              </button>
            ),
          )}
          <button
            type="button"
            disabled={page >= pages}
            onClick={() => onPage(page + 1)}
            data-testid="page-next"
            aria-label={t("Next")}
          >
            ›
          </button>
        </nav>
      )}
    </>
  );
}

/* ---------------------------------------------------------- the small */

/** The row of filters, searches and actions above a list. */
export function Toolbar({ children, end }: { children?: ReactNode; end?: ReactNode }) {
  return (
    <div className="ui-toolbar">
      {children}
      {end && <div className="ui-toolbar-end">{end}</div>}
    </div>
  );
}

/**
 * The filters a list keeps out of the way until somebody wants them.
 *
 * `active` is the page's own answer to "is any of these set?", and when it
 * is true the block opens and stays open: a filter that is narrowing the
 * list must be visible, or the reader sees a short list and no reason for
 * it. Hiding the controls is allowed; hiding the fact that they are
 * working is not.
 */
export function MoreFilters({
  active, count, children,
}: {
  active: boolean;
  count?: number;
  children: ReactNode;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const shown = open || active;
  return (
    <>
      <button
        type="button"
        className={join("ui-btn-secondary", shown && "ui-open")}
        aria-expanded={shown}
        onClick={() => setOpen(!shown)}
        data-testid="more-filters"
      >
        {shown ? t("Fewer filters") : t("More filters")}
        {!shown && count ? <span className="ui-pill ui-warn">{count}</span> : null}
      </button>
      {shown && <div className="ui-filters-row" data-testid="more-filters-row">{children}</div>}
    </>
  );
}

export function Facts({ children }: { children: ReactNode }) {
  return <dl className="ui-facts">{children}</dl>;
}

export function Fact({ label, hint, wide = false, children }: {
  label: ReactNode;
  /** What the value means, on hover; a sentence does not belong in the list. */
  hint?: string;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={join("ui-fact", wide && "ui-wide")}>
      <dt className="ui-fact-label" title={hint}>{label}</dt>
      <dd className="ui-fact-value">{children}</dd>
    </div>
  );
}

export function Pill({ tone: state = "neutral", children, title }: { tone?: Tone | string; children: ReactNode; title?: string }) {
  return <span className={join("ui-pill", toneClass(state))} title={title}>{children}</span>;
}

/** A word that belongs to a thing: a tag, a kind, a qualifier. */
export function Tag({ mono = false, children }: { mono?: boolean; children: ReactNode }) {
  return <span className={join("ui-tag", mono && "ui-mono")}>{children}</span>;
}

/** The state of a connection, as a dot in the colours of the badge. */
export function Dot({ state }: { state?: string | null }) {
  const kind = state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={join("ui-dot", toneClass(kind))} title={state ?? undefined} />;
}

/**
 * An empty list says so in one sentence and, where one exists, offers the
 * action that fills it. A blank panel looks like a page that did not load.
 */
export function Empty({ children, action }: { children: ReactNode; action?: ReactNode }) {
  if (!action) return <p className="ui-empty">{children}</p>;
  return (
    <div className="ui-empty">
      <p>{children}</p>
      <div className="ui-actions">{action}</div>
    </div>
  );
}

/** A line the reader has to take account of before going on. */
export function Banner({ tone: state = "warn", children }: { tone?: Tone; children: ReactNode }) {
  return <div className={join("ui-banner", toneClass(state))}>{children}</div>;
}

export function Bar({ share, tone: state = "info", label }: { share: number; tone?: Tone | string; label?: ReactNode }) {
  return (
    <span className="ui-bar" title={typeof label === "string" ? label : undefined}>
      <span
        className={join("ui-bar-fill", toneClass(state))}
        style={{ width: `${Math.round(Math.min(1, Math.max(0, share)) * 100)}%` }}
      />
    </span>
  );
}

/**
 * A label, a bar and a number in three tracks of one grid. The bar can
 * never run under the words, which is what made the fleet composition
 * unreadable: the two were layered and the text sat on the colour.
 */
export function BarList({
  items,
}: {
  items: { label: ReactNode; value: number; tone?: Tone | string }[];
}) {
  const top = Math.max(1, ...items.map((item) => item.value));
  return (
    <dl className="ui-barlist">
      {items.map((item, i) => (
        <div className="ui-barlist-row" key={i}>
          <dt>{item.label}</dt>
          <dd><Bar share={item.value / top} tone={item.tone} /></dd>
          <dd className="ui-numeric">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Actions({ children, right = false }: { children: ReactNode; right?: boolean }) {
  return <div className={join("ui-actions", right && "ui-right")}>{children}</div>;
}

export function Field({ label, hint, wide = false, children }: {
  label: ReactNode;
  hint?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <label className={join("ui-field", wide && "ui-wide")}>
      <span className="ui-field-label">{label}</span>
      {children}
      {hint && <span className="ui-field-hint">{hint}</span>}
    </label>
  );
}

/** The fields of a form, in columns that fold into one on a narrow screen. */
export function Fields({ children }: { children: ReactNode }) {
  return <div className="ui-fields">{children}</div>;
}

/* ------------------------------------------------- the zones of a page */

/**
 * The answer the page exists to give, in one line and without a border.
 *
 * A screen that opens with sixteen bordered boxes of equal weight has no
 * entry point: the eye has nowhere to land and every box asks to be read.
 * This is the one thing that is read first, so it is the one thing that is
 * not in a box.
 */
export function Verdict({
  tone: state, headline, children, actions,
}: {
  tone?: Tone;
  /** The sentence or the number that answers the page's question. */
  headline: ReactNode;
  /** The few facts that qualify it; three or four, not a list. */
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className={join("ui-verdict", state && toneClass(state))} data-testid="verdict">
      <div className="ui-verdict-row">
        <p className="ui-verdict-headline">{headline}</p>
        {actions && <div className="ui-verdict-actions">{actions}</div>}
      </div>
      {children && <div className="ui-verdict-facts">{children}</div>}
    </section>
  );
}

/**
 * What the reader has to do something about. The zone draws nothing at all
 * when it is empty, which is the point: an empty heading reads as a thing
 * the page is still loading.
 */
export function Attention({ title, children }: { title: ReactNode; children?: ReactNode }) {
  const count = Children.toArray(children).filter(Boolean).length;
  if (count === 0) return null;
  return (
    <section className="ui-attention" data-testid="needs-attention">
      <h2 className="ui-attention-title">{title}</h2>
      <div className="ui-stack-s">{children}</div>
    </section>
  );
}
