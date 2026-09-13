import type { CSSProperties } from "react";

/**
 * The brand: a spine and three bars on a 24-unit grid. The spine on the
 * left is the control plane; the three bars beside it are hosts, drawn as
 * separate blocks with a gap from the spine because the fleet is many
 * machines under one plane, not one machine. The bars shorten downwards,
 * so the whole reads as an "F" and as a flow leaving the spine. Filled
 * shapes, no strokes: they stay crisp at 16 px in a browser tab.
 *
 * The favicon and the packaging logo in web/public repeat these shapes on
 * a 64-unit grid; a change here has to be carried there by hand.
 */
const SPINE = { x: 2, y: 2, width: 5, height: 20 };
const BARS = [
  { x: 10, y: 2, width: 12, height: 4 },
  { x: 10, y: 10, width: 9, height: 4 },
  { x: 10, y: 18, width: 6, height: 4 },
];
const CORNER = 1.5;

/**
 * The mark alone, in the colour of the text around it. With `accent` the
 * spine takes the theme accent and the bars stay in currentColor; without
 * it the mark is one colour, for a tile that already carries the accent.
 * The mark is decorative wherever it appears - a title or a label always
 * stands next to it - so it is hidden from assistive technology.
 */
export function LogoMark({ size = 24, className, accent = false }: {
  size?: number;
  className?: string;
  accent?: boolean;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      className={className}
      aria-hidden="true"
      focusable="false"
      style={{ display: "block", flex: "none" }}
    >
      <rect {...SPINE} rx={CORNER} fill={accent ? "var(--accent)" : "currentColor"} />
      {BARS.map((bar) => <rect key={bar.y} {...bar} rx={CORNER} fill="currentColor" />)}
    </svg>
  );
}

/**
 * The mark with the name beside it. The name is ordinary text in the
 * panel's font, not outlines, so it needs no font of its own and follows
 * the text colour; its size and spacing follow the mark, so one `size`
 * scales the whole lock-up.
 */
export function Logo({ size = 32, className }: { size?: number; className?: string }) {
  const style: CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    gap: Math.round(size * 0.3),
    color: "inherit",
  };
  const word: CSSProperties = {
    fontWeight: 600,
    fontSize: Math.round(size * 0.58),
    letterSpacing: "-0.02em",
    lineHeight: 1,
    whiteSpace: "nowrap",
  };
  return (
    <span className={className} style={style}>
      <LogoMark size={size} accent />
      <span style={word}>Flotestro</span>
    </span>
  );
}
