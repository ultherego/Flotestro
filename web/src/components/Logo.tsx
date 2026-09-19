import type { CSSProperties } from "react";

/**
 * The brand: an "F" for the control plane with a cable leaving its bars to
 * three hosts, each in its own colour - a fleet is many machines under one
 * plane, not one machine.
 */
const PLANE =
  "M36 31h60a10 10 0 0 1 10 10v6a10 10 0 0 1-10 10H62v14h25a10 10 0 0 1 10 10v5a10 10 0 0 1-10 10H62v16H36z";
const CABLE = "M96 44h16v59H52M87 83.5h25";
const PORTS = [
  { cx: 96, cy: 44 },
  { cx: 87, cy: 83.5 },
  { cx: 52, cy: 104 },
];
const HOSTS = [
  { cy: 44, fill: "#a6e3a1" },
  { cy: 83.5, fill: "#89b4fa" },
  { cy: 103, fill: "#cba6f7" },
];

/**
 * The mark alone.
 */
export function LogoMark({ size = 24, className, accent = false, ground = "var(--bg-panel)" }: {
  size?: number;
  className?: string;
  accent?: boolean;
  /** The colour behind the mark: the ports and the host rings are cut in it. */
  ground?: string;
}) {
  const ink = accent ? "var(--accent)" : "currentColor";
  return (
    <svg
      width={size}
      height={size}
      viewBox="28 24 96 96"
      className={className}
      aria-hidden="true"
      focusable="false"
      style={{ display: "block", flex: "none" }}
    >
      <path d={PLANE} fill={ink} />
      {PORTS.map((port) => <circle key={port.cy} {...port} r={4} fill={ground} />)}
      <path d={CABLE} fill="none" stroke={ink} strokeWidth={5} strokeLinecap="round" strokeLinejoin="round" />
      {HOSTS.map((host) => (
        <circle key={host.cy} cx={112} cy={host.cy} r={7} fill={host.fill} stroke={ground} strokeWidth={4} />
      ))}
    </svg>
  );
}

/**
 * The mark with the name beside it.
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
