import type { CSSProperties, ReactNode } from "react";

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
 * Every class here begins with `ui-`. Nothing outside this file writes one,
 * and nothing in it writes a class that is not one - which is what lets the
 * stylesheet be read as a list of what exists rather than as a history of
 * what was needed once.
 */

type Tone = "ok" | "warn" | "error" | "info" | "unknown" | "neutral";
type Columns = 1 | 2 | 3 | 4 | 6 | 8 | 9 | 12;

const join = (...parts: (string | false | undefined)[]) => parts.filter(Boolean).join(" ");

/* ---------------------------------------------------------------- page */

/**
 * The head of a screen: what it is, one line on what it answers, and the
 * actions that belong to the whole of it. The long explanation goes behind
 * the mark, because a paragraph at the top of a screen is read once and
 * then skipped for ever.
 */
export function PageHead({
  title, lead, actions, help, mark,
}: {
  title: ReactNode;
  lead?: ReactNode;
  actions?: ReactNode;
  help?: ReactNode;
  mark?: ReactNode;
}) {
  return (
    <header className="ui-pagehead">
      {mark && <span className="ui-pagehead-mark">{mark}</span>}
      <div className="ui-pagehead-text">
        <h1 className="ui-pagehead-title">{title}</h1>
        {lead && <p className="ui-pagehead-lead">{lead}</p>}
      </div>
      {actions && <div className="ui-pagehead-actions">{actions}</div>}
      {help && <details className="ui-pagehead-help"><summary>?</summary><div>{help}</div></details>}
    </header>
  );
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

export function Col({ span = 12, children, style }: { span?: Columns; children: ReactNode; style?: CSSProperties }) {
  return <div className={`ui-col ui-col-${span}`} style={style}>{children}</div>;
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
  title, note, actions, children, foot, flush = false, className, tone,
}: {
  title?: ReactNode;
  note?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  foot?: ReactNode;
  flush?: boolean;
  className?: string;
  tone?: Tone;
}) {
  return (
    <section className={join("ui-panel", tone && `ui-panel-${tone}`, className)}>
      {(title || actions) && (
        <div className="ui-panel-head">
          <div className="ui-panel-headtext">
            {title && <h2 className="ui-panel-title">{title}</h2>}
            {note && <p className="ui-panel-note">{note}</p>}
          </div>
          {actions && <div className="ui-panel-actions">{actions}</div>}
        </div>
      )}
      <div className={join("ui-panel-body", flush && "ui-flush")}>{children}</div>
      {foot && <div className="ui-panel-foot">{foot}</div>}
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
  label, value, unit, tone, mark, note, delta, size = "l",
}: {
  label: ReactNode;
  /** null and undefined are both "nobody knows". */
  value: ReactNode | null | undefined;
  unit?: string;
  tone?: Tone;
  mark?: ReactNode;
  note?: ReactNode;
  delta?: { text: string; good: boolean };
  size?: "m" | "l" | "xl";
}) {
  const unknown = value === null || value === undefined;
  return (
    <div
      className={join("ui-stat", `ui-stat-${size}`, unknown ? "ui-stat-unknown" : tone && `ui-stat-${tone}`)}
      data-testid={typeof label === "string" ? `stat-${label}` : undefined}
    >
      {mark && <span className="ui-stat-mark">{mark}</span>}
      <div className="ui-stat-value">
        {unknown ? <span className="ui-stat-dash">—</span> : value}
        {!unknown && unit && <span className="ui-stat-unit">{unit}</span>}
      </div>
      <div className="ui-stat-foot">
        <span className="ui-stat-label">{label}</span>
        {delta && !unknown && (
          <span className={join("ui-stat-delta", delta.good ? "ui-good" : "ui-bad")}>{delta.text}</span>
        )}
      </div>
      {note && <p className="ui-stat-note">{note}</p>}
    </div>
  );
}

/* --------------------------------------------------------------- table */

export type Column<Row> = {
  /** The heading, and the key of the column. */
  head: ReactNode;
  /** What the cell draws. */
  cell: (row: Row) => ReactNode;
  /** A column of figures is read down, so it is aligned right. */
  numeric?: boolean;
  /** A column that may be dropped on a narrow screen. */
  secondary?: boolean;
};

/**
 * One table for the whole panel. It scrolls inside its own holder rather
 * than widening the page, its head is a label and not a headline, and a
 * row shows data: whatever can be done to it lives where the row leads.
 */
export function DataTable<Row>({
  columns, rows, keyOf, empty, onRow, rowClass,
}: {
  columns: Column<Row>[];
  rows: Row[];
  keyOf: (row: Row, index: number) => string;
  empty?: ReactNode;
  onRow?: (row: Row) => void;
  rowClass?: (row: Row) => string | undefined;
}) {
  if (rows.length === 0) return <Empty>{empty ?? "Nothing here."}</Empty>;
  return (
    <div className="ui-table-holder">
      <table className="ui-table">
        <thead>
          <tr>
            {columns.map((column, i) => (
              <th
                key={i}
                scope="col"
                className={join(column.numeric && "ui-numeric", column.secondary && "ui-secondary")}
              >
                {column.head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={keyOf(row, index)}
              className={rowClass?.(row)}
              onClick={onRow ? () => onRow(row) : undefined}
            >
              {columns.map((column, i) => (
                <td key={i} className={join(column.numeric && "ui-numeric", column.secondary && "ui-secondary")}>
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------------------------------------------------- the small */

export function Toolbar({ children, end }: { children?: ReactNode; end?: ReactNode }) {
  return (
    <div className="ui-toolbar">
      {children}
      {end && <div className="ui-toolbar-end">{end}</div>}
    </div>
  );
}

export function Facts({ children }: { children: ReactNode }) {
  return <dl className="ui-facts">{children}</dl>;
}

export function Fact({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="ui-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export function Pill({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`ui-pill ui-pill-${tone}`}>{children}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="ui-empty">{children}</p>;
}

export function Bar({ share, tone = "info", label }: { share: number; tone?: Tone; label?: ReactNode }) {
  return (
    <span className="ui-bar" title={typeof label === "string" ? label : undefined}>
      <span className={`ui-bar-fill ui-bar-${tone}`} style={{ width: `${Math.round(Math.min(1, Math.max(0, share)) * 100)}%` }} />
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
  items: { label: ReactNode; value: number; tone?: Tone }[];
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

export function Actions({ children }: { children: ReactNode }) {
  return <div className="ui-actions">{children}</div>;
}

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="ui-field">
      <span className="ui-field-label">{label}</span>
      {children}
      {hint && <span className="ui-field-hint">{hint}</span>}
    </label>
  );
}

export function Fields({ children }: { children: ReactNode }) {
  return <div className="ui-fields">{children}</div>;
}
