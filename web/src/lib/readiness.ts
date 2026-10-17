/**
 * What the head of the readiness screen has to say about a fleet.
 *
 * The case worth holding is the third one: no gaps found and hosts that have
 * reported no adapter at all. A fleet whose hosts said nothing is not a fleet
 * without gaps, and a screen that showed a green zero there would be the
 * "unknown is not zero" fault committed by the panel itself, about the very
 * thing it exists to surface.
 */
export type ReadinessVerdict = "ok" | "unknown" | "attention";

export function readinessVerdict(data: {
  silent: number;
  unorderable: number;
  gaps: { nowhere: boolean }[];
}): ReadinessVerdict {
  if (data.unorderable > 0 || data.gaps.some((gap) => gap.nowhere)) return "attention";
  if (data.silent > 0) return "unknown";
  return data.gaps.length > 0 ? "attention" : "ok";
}
