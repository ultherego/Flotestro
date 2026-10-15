import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useT } from "../i18n";

/** The tone of a segment or a bar; it is a state colour, never the accent. */
export type WidgetTone = "ok" | "warn" | "error" | "unknown" | "info" | "neutral";

export type Segment = {
  label: string;
  value: number | undefined;
  tone: WidgetTone;
  /** The page that lists exactly these; the segment becomes a link. */
  to?: string;
};

/**
 * The states of a set of things, with their counts.
 *
 * A state with nothing in it takes no width. It used to take a slot of its
 * own - `flex: var(--share) 1 96px`, so the 96px basis decided the width and
 * not the share - and on the fleet dashboard five empty states were holding
 * 45 % of the bar while four hosts held the rest. A bar whose segments do not
 * stand for their magnitudes is not a weak chart; it is a chart that is wrong
 * about the one thing a bar says.
 *
 * So the empty states move below the bar, named, in small type, where a zero
 * reads as a word rather than as an area. They are still there - an operator
 * who wants to know that nothing is quarantined still reads it - and they are
 * still counted, which is what the browser suite asks of this component.
 *
 * When one state holds everything, there is no bar at all: a one-segment bar
 * chart is a stat tile with extra steps, so the count is simply shown.
 *
 * Unknown is not zero. A segment with no value at all keeps its own mark and
 * is never folded in with the empty ones.
 *
 * And it is not only the mark. A bar divides a width between the states, so
 * it says "this is the whole and these are its parts" - which it cannot say
 * when one of the states was never counted: the denominator is the counted
 * ones alone, so every share is a share of the rest. The bar used to keep
 * that to itself and leave the uncounted state as a dash in small type among
 * the zeros. It is said in words now, under the bar, in the one case it is
 * true - the state that was not counted is named there.
 */
export function StatusBar({ segments, compact = false }: { segments: Segment[]; compact?: boolean }) {
  const t = useT();
  const counted = segments.filter((segment) => segment.value !== undefined && segment.value > 0);
  // The three kinds are told apart by the value and nothing else: a count, a
  // nothing, and a number that was never taken.
  const quiet = segments.filter((segment) => segment.value !== undefined && segment.value <= 0);
  const uncounted = segments.filter((segment) => segment.value === undefined);
  const total = counted.reduce((sum, segment) => sum + (segment.value ?? 0), 0);

  const draw = (segment: Segment, className: string, style?: React.CSSProperties) => {
    const body = (
      <>
        <span className="status-bar-value" data-testid="status-bar-value">
          {segment.value === undefined ? "\u2014" : segment.value}
        </span>
        <span className="status-bar-label">{segment.label}</span>
      </>
    );
    return segment.to
      ? (
        <Link key={segment.label} role="listitem" className={className} style={style}
          to={segment.to} title={segment.label}>{body}</Link>
      )
      : (
        <div key={segment.label} role="listitem" className={className} style={style}
          title={segment.label}>{body}</div>
      );
  };

  return (
    <div className={compact ? "status-bar-group compact" : "status-bar-group"}
      role="list" data-testid="status-bar">
      {counted.length === 1 && draw(counted[0], `status-bar-hero ${counted[0].tone}`)}
      {counted.length > 1 && (
        <div className="status-bar">
          {counted.map((segment) => draw(
            segment,
            `status-bar-segment ${segment.tone}`,
            { "--share": (segment.value ?? 0) / total } as React.CSSProperties,
          ))}
        </div>
      )}
      {quiet.length > 0 && (
        <div className="status-bar-quiet">
          {quiet.map((segment) => draw(segment, `status-bar-quiet-item ${segment.tone} zero`))}
        </div>
      )}
      {uncounted.length > 0 && (
        <div className="status-bar-uncounted" data-testid="status-bar-uncounted">
          <span className="status-bar-uncounted-note">
            {counted.length > 0
              ? t("Not counted, so what is above is a share of the rest:")
              : t("Not counted:")}
          </span>
          {uncounted.map((segment) => draw(segment, `status-bar-quiet-item ${segment.tone} unset`))}
        </div>
      )}
    </div>
  );
}

/**
 * A set of counts that are not parts of one whole.
 *
 * "19 security findings, 341 failed jobs, 6 unknown checks" are three
 * different things; adding them up means nothing, so a bar that divides a
 * width between them is the wrong form however honest its proportions are.
 * Drawn as one on 12.10 it put "19 S…" and "6 U" in slivers - and the code
 * already carried the admission, a comment explaining that labels longer
 * than a dozen characters are cut off, with the names shortened to fit.
 * The names were bent to the form. This is the form the names asked for.
 *
 * The counts that are at zero go under the row as words, the way they do in
 * StatusBar, because a zero is news as a word and noise as an area.
 */
export function CountRow({ counts }: { counts: Segment[] }) {
  const t = useT();
  const present = counts.filter((count) => count.value !== undefined && count.value > 0);
  const quiet = counts.filter((count) => count.value !== undefined && count.value <= 0);
  // A count nobody took does not belong under a row of zeros, here either:
  // these counts are of different things, so the only reading of a dash among
  // them is "there is none", which is the one thing it does not mean.
  const uncounted = counts.filter((count) => count.value === undefined);

  const draw = (count: Segment, className: string) => {
    const body = (
      <>
        <span className="status-bar-value" data-testid="status-bar-value">
          {count.value === undefined ? "\u2014" : count.value}
        </span>
        <span className="status-bar-label">{count.label}</span>
      </>
    );
    return count.to
      ? <Link key={count.label} role="listitem" className={className} to={count.to}>{body}</Link>
      : <div key={count.label} role="listitem" className={className}>{body}</div>;
  };

  return (
    <div className="status-bar-group" role="list" data-testid="status-bar">
      {present.length > 0 && (
        <div className="count-row">
          {present.map((count) => draw(count, `count-tile ${count.tone}`))}
        </div>
      )}
      {quiet.length > 0 && (
        <div className="status-bar-quiet">
          {quiet.map((count) => draw(count, `status-bar-quiet-item ${count.tone} zero`))}
        </div>
      )}
      {uncounted.length > 0 && (
        <div className="status-bar-uncounted" data-testid="status-bar-uncounted">
          <span className="status-bar-uncounted-note">{t("Not counted:")}</span>
          {uncounted.map((count) => draw(count, `status-bar-quiet-item ${count.tone} unset`))}
        </div>
      )}
    </div>
  );
}

export type Bar = { label: string; value: number; tone?: WidgetTone | "accent" };
export type BarSeries = { name: string; tone: WidgetTone | "accent"; values: number[] };

/**
 * A bar chart over categories or hours, as plain SVG. Several series stack
 * on one bar.
 */
export function BarChart({
  labels, series, height = 160, everyLabel = 1,
}: {
  labels: string[];
  series: BarSeries[];
  height?: number;
  /** Draw every n-th label, for hours that would otherwise overlap. */
  everyLabel?: number;
}) {
  const width = 600;
  const pad = { top: 8, right: 8, bottom: 22, left: 34 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const totals = labels.map((_, i) => series.reduce((sum, s) => sum + (s.values[i] ?? 0), 0));
  const max = Math.max(1, ...totals);
  const step = niceStep(max);
  const top = Math.ceil(max / step) * step;
  const slot = innerW / Math.max(1, labels.length);
  const barW = Math.max(2, slot * 0.68);
  const y = (value: number) => pad.top + innerH - (value / top) * innerH;
  const ticks: number[] = [];
  for (let v = 0; v <= top; v += step) ticks.push(v);
  return (
    <>
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img">
        {ticks.map((v) => (
          <g key={v}>
            <line className="grid" x1={pad.left} x2={width - pad.right} y1={y(v)} y2={y(v)} />
            <text x={pad.left - 6} y={y(v) + 4} textAnchor="end">{v}</text>
          </g>
        ))}
        <line className="axis" x1={pad.left} x2={width - pad.right} y1={y(0)} y2={y(0)} />
        {labels.map((label, i) => {
          let base = 0;
          const x = pad.left + i * slot + (slot - barW) / 2;
          return (
            <g key={label + i}>
              {series.map((s) => {
                const value = s.values[i] ?? 0;
                if (value <= 0) return null;
                const y1 = y(base + value);
                const h = y(base) - y1;
                base += value;
                return <rect key={s.name} className={`bar ${s.tone}`} x={x} y={y1} width={barW} height={h} />;
              })}
              {i % everyLabel === 0 && (
                <text x={x + barW / 2} y={height - 6} textAnchor="middle">{label}</text>
              )}
            </g>
          );
        })}
      </svg>
      {series.length > 1 && (
        <ul className="chart-legend">
          {series.map((s) => <li key={s.name}><span className={`swatch ${s.tone}`} />{s.name}</li>)}
        </ul>
      )}
    </>
  );
}

/** The colour token of a tone, for the parts of a chart that take an inline colour. */
const TONE_VAR: Record<WidgetTone | "accent", string> = {
  ok: "--ok", warn: "--warn", error: "--error", unknown: "--unknown", info: "--blue",
  neutral: "--text-faint", accent: "--accent",
};

/** One label on the time axis: where it sits, and the instant it reads. */
type AxisTick = { at: number; iso: string };

export type AreaSeries = {
  name: string;
  tone: WidgetTone | "accent";
  /** One value per time; an undefined one is a gap, not a zero. */
  values: (number | undefined)[];
  /** Draw the line only, without the fill under it, for a series read against another. */
  line?: boolean;
};

/**
 * A time series as plain SVG: time on the x axis, one or more series as a
 * line with a soft fill under it, a faint grid and the values on the y axis.
 */
export function AreaChart({
  times, series, height = 160, max, format = (value) => String(value), label = shortTime, peak,
}: {
  /** The instants of the points, one per index of every series; they set the x coordinate. */
  times: string[];
  series: AreaSeries[];
  height?: number;
  /** The top of the y axis: a fixed one for a share (100), the largest value otherwise. */
  max?: number;
  /** How a value on the y axis reads. */
  format?: (value: number) => string;
  /** How an instant on the x axis reads. */
  label?: (iso: string) => string;
  /** The peak within each step, drawn as a thin dashed line in the tone of the first series. */
  peak?: (number | undefined)[];
}) {
  const width = 600;
  const pad = { top: 8, right: 10, bottom: 22, left: 48 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const count = times.length;
  const highest = Math.max(
    0,
    ...series.flatMap((s) => s.values.filter((v): v is number => v !== undefined)),
    ...(peak ?? []).filter((v): v is number => v !== undefined),
  );
  // A fixed top keeps a share on the same scale on every host; a top from
  // the data rounds up to a tick, so the largest value is not on the edge.
  const ceiling = max !== undefined && max > 0 ? max : undefined;
  const step = ceiling !== undefined ? ceiling / 4 : niceStep(Math.max(1, highest));
  const top = ceiling ?? Math.max(step, Math.ceil(highest / step) * step);
  // The x coordinate is the instant, not the position in the array. Drawn by
  // index, an hour with no readings takes the width of one sample and a hole
  // in the data disappears into a smooth line.
  const stamps = times.map((iso) => Date.parse(iso));
  const first = stamps[0];
  const span = count > 1 ? stamps[count - 1] - first : 0;
  const timed = span > 0 && stamps.every((stamp) => Number.isFinite(stamp));
  const x = (i: number) =>
    count < 2 ? pad.left + innerW / 2
      : timed ? pad.left + ((stamps[i] - first) / span) * innerW
        : pad.left + (i / (count - 1)) * innerW;
  const y = (value: number) => pad.top + innerH - (Math.min(value, top) / top) * innerH;
  const ticks: number[] = [];
  for (let v = 0; v <= top + step / 1000; v += step) ticks.push(v);
  // Five labels evenly spaced along the axis. On a timed axis they are five
  // instants, which is not the same as five points once there are holes.
  const labelAt = count > 1 ? [0, 1, 2, 3, 4].map((k) => Math.round((k * (count - 1)) / 4)) : [0];
  const labels: (AxisTick | undefined)[] = timed
    ? [0, 1, 2, 3, 4].map((k) => ({
      at: pad.left + (k / 4) * innerW,
      iso: new Date(first + (k / 4) * span).toISOString(),
    }))
    : labelAt.map((i) => (times[i] === undefined ? undefined : { at: x(i), iso: times[i] }));

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img">
      {ticks.map((v) => (
        <g key={v}>
          <line className="grid" x1={pad.left} x2={width - pad.right} y1={y(v)} y2={y(v)} />
          <text x={pad.left - 6} y={y(v) + 4} textAnchor="end">{format(v)}</text>
        </g>
      ))}
      <line className="axis" x1={pad.left} x2={width - pad.right} y1={y(0)} y2={y(0)} />
      {/* The band under a line fades out downwards instead of sitting at one
          flat wash. A constant fill competes with the gridlines at the
          bottom of the chart and makes two overlapping series unreadable
          where they cross; a fade keeps the weight at the line, which is
          the part being read. One gradient per tone, named after it, so
          two series of the same tone share one definition. */}
      <defs>
        {Array.from(new Set(series.map((s) => s.tone))).map((tone) => (
          <linearGradient key={tone} id={`area-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={`var(${TONE_VAR[tone]})`} stopOpacity={0.28} />
            <stop offset="100%" stopColor={`var(${TONE_VAR[tone]})`} stopOpacity={0.02} />
          </linearGradient>
        ))}
      </defs>
      {series.map((s) => {
        const colour = `var(${TONE_VAR[s.tone]})`;
        return (
          <g key={s.name}>
            {!s.line && runs(s.values).map((run, k) => (
              <path
                key={k}
                className="area"
                style={{ fill: `url(#area-${s.tone})` }}
                d={`${runPath(run, x, y)} L${x(run[run.length - 1].i).toFixed(1)},${y(0).toFixed(1)} L${x(run[0].i).toFixed(1)},${y(0).toFixed(1)} Z`}
              />
            ))}
            {runs(s.values).map((run, k) => (
              run.length === 1
                ? <circle key={k} cx={x(run[0].i)} cy={y(run[0].value)} r={2} style={{ fill: colour }} />
                : <path key={k} className="line" vectorEffect="non-scaling-stroke" style={{ stroke: colour }} d={runPath(run, x, y)} />
            ))}
          </g>
        );
      })}
      {peak && series[0] && runs(peak).map((run, k) => (
        <path
          key={k}
          className="line"
          vectorEffect="non-scaling-stroke"
          style={{ stroke: `var(${TONE_VAR[series[0].tone]})` }}
          strokeWidth={1}
          strokeDasharray="4 3"
          d={runPath(run, x, y)}
        />
      ))}
      {labels.map((tick, k) => tick !== undefined && (
        <text key={k} x={tick.at} y={height - 6} textAnchor={k === 0 ? "start" : k === labels.length - 1 ? "end" : "middle"}>
          {label(tick.iso)}
        </text>
      ))}
    </svg>
  );
}

type Run = { i: number; value: number }[];

/** The stretches of a series between its gaps, each drawn as one line. */
function runs(values: (number | undefined)[]): Run[] {
  const out: Run[] = [];
  let current: Run = [];
  values.forEach((value, i) => {
    if (value === undefined) {
      if (current.length) out.push(current);
      current = [];
    } else {
      current.push({ i, value });
    }
  });
  if (current.length) out.push(current);
  return out;
}

function runPath(run: Run, x: (i: number) => number, y: (value: number) => number): string {
  return run.map((p, k) => `${k === 0 ? "M" : "L"}${x(p.i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
}

function shortTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** The names of the series under a chart, each with its swatch; a dashed one is a peak line. */
export function ChartLegend({ items }: { items: { name: string; tone: WidgetTone | "accent"; dashed?: boolean }[] }) {
  return (
    <ul className="chart-legend">
      {items.map((item) => (
        <li key={item.name}>
          <span
            className="swatch"
            style={{ "--swatch": `var(${TONE_VAR[item.tone]})`, opacity: item.dashed ? 0.55 : 1 } as React.CSSProperties}
          />
          {item.name}
        </li>
      ))}
    </ul>
  );
}

/**
 * A breakdown of a whole by category: label, proportional bar and count,
 * for the composition of the fleet beside its list.
 */
export function Breakdown({ items, tone = "info" }: { items: { label: ReactNode; value: number; tone?: WidgetTone }[]; tone?: WidgetTone }) {
  const max = Math.max(1, ...items.map((item) => item.value));
  return (
    <dl className="breakdown">
      {items.map((item, i) => (
        <BreakdownRow key={i} label={item.label} value={item.value} share={item.value / max} tone={item.tone ?? tone} />
      ))}
    </dl>
  );
}

function BreakdownRow({ label, value, share, tone }: { label: ReactNode; value: number; share: number; tone: WidgetTone }) {
  return (
    <>
      <dt>{label}</dt>
      <dd><div className="breakdown-bar"><div className={`breakdown-fill ${tone}`} style={{ width: `${Math.round(share * 100)}%` }} /></div></dd>
      <dd className="breakdown-count">{value}</dd>
    </>
  );
}

/** A number with its share of a whole, for a table cell. */
export function Meter({ value, max, tone = "info", text }: { value: number; max: number; tone?: WidgetTone; text?: ReactNode }) {
  const share = max > 0 ? Math.min(1, value / max) : 0;
  return (
    <span className="meter">
      <span className="meter-track"><span className={`meter-fill ${tone}`} style={{ width: `${Math.round(share * 100)}%` }} /></span>
      <span className="meter-value">{text ?? value}</span>
    </span>
  );
}

function niceStep(max: number): number {
  const raw = max / 4;
  const power = Math.pow(10, Math.floor(Math.log10(Math.max(1, raw))));
  const unit = raw / power;
  const nice = unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 5 ? 5 : 10;
  return nice * power;
}
