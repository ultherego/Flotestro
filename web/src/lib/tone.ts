/**
 * How a thing is going, as the one word every screen says it with.
 *
 * A tone is not a colour: the screens name the state and the stylesheet
 * decides what it looks like, so "warn" means the same thing on a tile, a
 * pill, a bar and a chart. It lives here rather than in a kit because the
 * helpers that work a state out - a campaign's, a policy verdict's - are
 * not part of any one panel's appearance.
 */
export type Tone = "ok" | "warn" | "error" | "info" | "unknown" | "neutral" | "accent";

/**
 * The tone of a state that was worked out rather than chosen: a campaign's
 * outcome, a policy verdict. "accent" is the panel's own emphasis and is
 * never something a state means, so it is not one of these.
 */
export type StateTone = Exclude<Tone, "accent">;

/**
 * The class that carries a tone.
 *
 * A tone sets two custom properties and the text colour, and every piece
 * of a kit reads those rather than carrying a rule per tone: one rule,
 * not seven. A word no tone answers to is neutral, never a class the
 * stylesheet has never heard of.
 */
const TONES = new Set(["ok", "warn", "error", "info", "unknown", "neutral", "accent"]);
export function toneClass(name?: string | null): string {
  return `ui-${name && TONES.has(name) ? name : "neutral"}`;
}
