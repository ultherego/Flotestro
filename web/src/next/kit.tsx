import type { CSSProperties, ReactNode } from "react";
import { Link } from "react-router-dom";
import { Icon, type IconName } from "../components/icons";
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
export function Head({ title, lead, actions }: {
  title: ReactNode;
  lead?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="fl-head">
      <div className="fl-head-text">
        <h1 className="fl-head-title">{title}</h1>
        {lead && <p className="fl-head-lead">{lead}</p>}
      </div>
      {actions && <div className="fl-head-actions">{actions}</div>}
    </header>
  );
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
export function Card({ title, note, tools, children, foot, flush = false, span }: {
  title?: ReactNode;
  note?: ReactNode;
  tools?: ReactNode;
  children?: ReactNode;
  foot?: ReactNode;
  /** For a body that is a table or a toolbar: it reaches the edges. */
  flush?: boolean;
  span?: Span;
}) {
  const card = (
    <section className={join("fl-card", flush && "fl-flush")}>
      {(title || tools) && (
        <div className="fl-card-head">
          {title && <h2 className="fl-card-title">{title}</h2>}
          {tools && <div className="fl-card-tools">{tools}</div>}
          {note && <p className="fl-card-note">{note}</p>}
        </div>
      )}
      {children !== undefined && children !== null && children !== false && (
        <div className="fl-card-body">{children}</div>
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
  label, value, unit, tone, icon, note, delta, hero = false, to, testId,
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

export function Tag({ children }: { children: ReactNode }) {
  return <span className="fl-tag">{children}</span>;
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

export function Note({ children }: { children: ReactNode }) {
  return <p className="fl-note">{children}</p>;
}

/**
 * An empty list says so in one sentence and, where one exists, offers the
 * action that fills it. A blank card looks like a page that did not load.
 */
export function Empty({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="fl-empty">
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
  head?: ReactNode;
  cell: (row: Row) => ReactNode;
  /** Numbers are read down a column, so they line up on their digits. */
  num?: boolean;
  /** The buttons at the end of a row. */
  actions?: boolean;
  /** What a narrow screen may do without. */
  minor?: boolean;
};

/**
 * One table for the whole panel. It scrolls inside its own card rather
 * than widening the page, its head stays in view while it does, and a row
 * shows data: whatever can be done to it lives where the row leads.
 */
export function Table<Row>({ columns, rows, keyOf, empty, rowTestId, testId }: {
  columns: Column<Row>[];
  rows: Row[];
  keyOf: (row: Row, index: number) => string;
  empty?: ReactNode;
  rowTestId?: (row: Row) => string;
  testId?: string;
}) {
  if (rows.length === 0 && empty !== undefined) return <Empty>{empty}</Empty>;
  const classOf = (column: Column<Row>) =>
    join(column.num && "fl-num", column.actions && "fl-cell-actions", column.minor && "fl-minor") || undefined;
  return (
    <div className="fl-tablewrap">
      <table className="fl-table" data-testid={testId}>
        <thead>
          <tr>{columns.map((column) => (
            <th key={column.key} scope="col" className={classOf(column)}>{column.head}</th>
          ))}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={keyOf(row, index)} data-testid={rowTestId?.(row)}>
              {columns.map((column) => (
                <td key={column.key} className={classOf(column)}>{column.cell(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
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
export function Bars({ items }: { items: { label: ReactNode; value: number; tone?: Tone | string }[] }) {
  const top = Math.max(1, ...items.map((item) => item.value));
  return (
    <dl className="fl-bars">
      {items.map((item, index) => (
        <div className="fl-bars-row" key={index}>
          <dt>{item.label}</dt>
          <dd><Bar share={item.value / top} tone={item.tone ?? "accent"} /></dd>
          <dd className="fl-bars-count">{item.value}</dd>
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

export function Fact({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="fl-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
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
export function Find({ value, onChange, placeholder, testId }: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  testId?: string;
}) {
  return (
    <span className="fl-find">
      <Icon name="search" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        data-testid={testId}
        aria-label={placeholder}
      />
    </span>
  );
}

/** A choice of one from a few, as one control rather than a row of buttons. */
export function Seg<T extends string>({ value, onChange, options }: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode }[];
}) {
  return (
    <div className="fl-seg">
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
export function Chart({ labels, series, everyLabel = 3, height = 150 }: {
  labels: string[];
  series: Series[];
  /** Draw one label in every n, so they do not run together. */
  everyLabel?: number;
  height?: number;
}) {
  const columns = labels.length;
  const totals = labels.map((_, i) => series.reduce((sum, one) => sum + (one.values[i] ?? 0), 0));
  const top = Math.max(1, ...totals);
  const peak = totals.indexOf(Math.max(...totals));
  const width = 100;
  const gap = columns > 40 ? 0.3 : 0.9;
  const barWidth = Math.max(0.6, width / Math.max(1, columns) - gap);
  const round = Math.min(barWidth / 2, 2);
  return (
    <figure className="fl-chart">
      <div className="fl-chart-scale" style={{ height }} aria-hidden="true">
        <span>{top}</span><span>{Math.round(top / 2)}</span><span>0</span>
      </div>
      <div className="fl-chart-plot">
        <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" style={{ height }}>
          {[0, 0.5, 1].map((at) => (
            <line key={at} className="fl-chart-rule" x1="0" x2={width} y1={height - at * height} y2={height - at * height} />
          ))}
          {labels.map((label, i) => {
            let bottom = 0;
            return (
              <g key={i}>
                <title>{`${label} · ${totals[i]}`}</title>
                {series.map((one) => {
                  const value = one.values[i] ?? 0;
                  const tall = (value / top) * (height - 2);
                  const y = height - bottom - tall;
                  bottom += tall;
                  return value === 0 ? null : (
                    <rect
                      key={one.name}
                      className={join("fl-chart-bar", toneClass(one.tone))}
                      x={i * (barWidth + gap)}
                      y={y}
                      width={barWidth}
                      height={tall}
                      rx={round}
                    />
                  );
                })}
              </g>
            );
          })}
        </svg>
        {totals[peak] > 0 && (
          <span
            className="fl-chart-bubble"
            style={{
              left: `${((peak + 0.5) / Math.max(1, columns)) * 100}%`,
              top: `${(1 - totals[peak] / top) * height - 6}px`,
            }}
          >
            {totals[peak]}
          </span>
        )}
      </div>
      <div className="fl-chart-axis">
        {labels.map((label, i) => <span key={i}>{i % everyLabel === 0 ? label : ""}</span>)}
      </div>
      <figcaption className="fl-chart-legend">
        {series.map((one) => (
          <span key={one.name}><i className={join("fl-chart-key", toneClass(one.tone))} />{one.name}</span>
        ))}
      </figcaption>
    </figure>
  );
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
  const size = 132;
  const stroke = 13;
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
          <span className="fl-ring-value">{known ? `${Math.round(filled * 100)}%` : "—"}</span>
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
