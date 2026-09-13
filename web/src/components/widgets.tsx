import type { ReactNode } from "react";
import { Link } from "react-router-dom";

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
 * A row of coloured segments, one per state, with the count in large
 * type: the condition of the fleet at one glance. Zero is shown, not
 * hidden - the absence of a state is information too - and an undefined
 * count is a dash, because unknown is never zero.
 */
export function StatusBar({ segments, compact = false }: { segments: Segment[]; compact?: boolean }) {
  const total = segments.reduce((sum, segment) => sum + (segment.value ?? 0), 0);
  return (
    <div className={compact ? "status-bar compact" : "status-bar"} role="list">
      {segments.map((segment) => {
        const value = segment.value;
        const zero = !value;
        const share = total > 0 && value ? Math.max(1, (value / total) * 6) : 1;
        const className = ["status-bar-segment", segment.tone, zero ? "zero" : ""].join(" ").trim();
        const style = { "--share": share } as React.CSSProperties;
        const body = (
          <>
            <span className="status-bar-value">{value === undefined ? "—" : value}</span>
            <span className="status-bar-label">{segment.label}</span>
          </>
        );
        return segment.to
          ? <Link key={segment.label} role="listitem" className={className} style={style} to={segment.to}>{body}</Link>
          : <div key={segment.label} role="listitem" className={className} style={style}>{body}</div>;
      })}
    </div>
  );
}

export type Bar = { label: string; value: number; tone?: WidgetTone | "accent" };
export type BarSeries = { name: string; tone: WidgetTone | "accent"; values: number[] };

/**
 * A bar chart over categories or hours, as plain SVG. Several series
 * stack on one bar. The height is given in the viewBox, so the chart
 * scales with its widget.
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
