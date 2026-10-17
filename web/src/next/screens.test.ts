import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/**
 * The rule that makes forty screens one panel.
 *
 * The owner asked for it in as many words: *„aby były jakieś klasy i
 * funkcje z których można dziedziczyć aby nie było tak że wszystkie
 * podstrony są układane ręcznie"*. A screen composes the kit and owns no
 * appearance of its own - no layout, no spacing, no colour. Said in a
 * review it lasts a week; said here it lasts.
 *
 * What a screen may still write is a word's own class - faint, small,
 * mono - and the kinds of button the stylesheet names. Everything that
 * puts things in places is a component.
 */

const SCREENS = join(__dirname, "screens");

/** Every screen of the new panel, by path, including the host's modules. */
function screens(): { name: string; text: string }[] {
  const out: { name: string; text: string }[] = [];
  const walk = (dir: string, prefix: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) { walk(path, `${prefix}${entry.name}/`); continue; }
      if (!entry.name.endsWith(".tsx") || entry.name.endsWith(".test.tsx")) continue;
      out.push({ name: prefix + entry.name, text: readFileSync(path, "utf8") });
    }
  };
  walk(SCREENS, "");
  return out;
}

/**
 * The classes a screen may name: a word's own appearance, a kind of
 * button, and the three state words. Not one of them puts anything
 * anywhere.
 */
const ALLOWED = new Set([
  // how a word reads
  "fl-faint", "fl-small", "fl-mono", "fl-nowrap", "fl-truncate", "fl-note", "fl-subhead",
  // what a thing is doing
  "fl-ok", "fl-warn", "fl-error", "fl-unknown", "fl-info", "fl-neutral", "fl-accent",
  // which kind of button
  "fl-quiet", "fl-plain", "fl-word", "fl-danger", "fl-btn",
]);

describe("a screen of the new panel", () => {
  it("never writes a layout, a spacing or a colour of its own", () => {
    const offenders: string[] = [];
    for (const screen of screens()) {
      for (const [index, line] of screen.text.split("\n").entries()) {
        for (const found of line.matchAll(/className=\{?["`]([^"`]*)["`]/g)) {
          for (const name of found[1].split(/\s+/).filter(Boolean)) {
            if (!name.startsWith("fl-")) continue;
            if (ALLOWED.has(name)) continue;
            offenders.push(`${screen.name}:${index + 1} ${name}`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * One tile of a row wears the accent, and one only.
   *
   * It says "this is what the screen is about", and two of them are two
   * answers to one question. The count is per row of tiles rather than
   * per file, because a screen that serves a list and one thing draws
   * two rows and each is entitled to its own.
   */
  it("gives the accent to one tile of a row, because a row answers one question", () => {
    const offenders: string[] = [];
    for (const screen of screens()) {
      for (const row of screen.text.split("<Kpis>").slice(1)) {
        const tiles = row.split("</Kpis>")[0];
        const heroes = tiles.match(/\bhero\b/g) ?? [];
        if (heroes.length > 1) offenders.push(`${screen.name}: a row with ${heroes.length}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * A link inside the new panel stays inside it.
   *
   * One that does not throws the reader into the panel being replaced,
   * losing the shell, the rail and whatever they were in the middle of.
   * Nine of them were found by hand; this finds the tenth. A deliberate
   * way out is an <a href>, which says it is leaving.
   */
  /**
   * While the rewrite stood at /next this read "no link leaves /next",
   * and it caught a screen sending the reader back into the panel being
   * replaced every few days. The panel took the root on 16.10 and there
   * is no second panel to fall into, so what is left to guard is the way
   * out of the panel altogether: a bare <a href> to one of its own
   * addresses reloads the whole application where a router link would
   * not, and that is a page flash nobody asked for.
   */
  it("goes to its own addresses through the router, not through the browser", () => {
    const places = "hosts|jobs|campaigns|policies|groups|relays|secrets|vulnerabilities"
      + "|reads|bulk|audit|tags|teams|access|settings|security|backups|certificates"
      + "|monitoring|notifications|directory|status|support|reports|budgets|readiness|unresolved";
    const out = new RegExp(`<a[^>]*href=\\{?["\`]/(?:${places})(?:[/?"\`]|$)`);
    const offenders: string[] = [];
    for (const screen of screens()) {
      for (const [index, line] of screen.text.split("\n").entries()) {
        if (out.test(line)) offenders.push(`${screen.name}:${index + 1}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("never carries an inline style, which no theme can follow", () => {
    const offenders: string[] = [];
    for (const screen of screens()) {
      for (const [index, line] of screen.text.split("\n").entries()) {
        if (/\sstyle=\{/.test(line)) offenders.push(`${screen.name}:${index + 1}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("names no colour, so every theme comes out right", () => {
    const offenders: string[] = [];
    for (const screen of screens()) {
      for (const [index, line] of screen.text.split("\n").entries()) {
        // A hex, or a token of the stylesheet reached for by hand.
        if (/#[0-9a-fA-F]{3,8}\b/.test(line) && !/\/\//.test(line.split("#")[0].slice(-2))) {
          offenders.push(`${screen.name}:${index + 1} ${line.trim().slice(0, 60)}`);
        }
        if (/var\(--/.test(line)) offenders.push(`${screen.name}:${index + 1} token`);
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * One heading, drawn by the shell out of one table. A screen that
   * drew its own would be the first of forty shapes of heading, and a
   * place with no entry in the table would open with no name and no
   * answer to "what is this screen for".
   */
  it("has a name and an explanation in the one table that holds them", () => {
    const panel = readFileSync(join(__dirname, "Panel.tsx"), "utf8");
    const about = readFileSync(join(SCREENS, "about.tsx"), "utf8");
    const places = new Set(
      [...panel.matchAll(/path="\/?([a-z-]*)/g)]
        .map((found) => (found[1] === "" ? "dashboard" : found[1])),
    );
    const files = new Map(screens().map((one) => [one.name, one.text]));
    const named = (place: string) => {
      if (new RegExp(`\\b${place}:`).test(about)) return true;
      // Or the screen carries its own frame, with both a name and the
      // paragraph behind the question mark.
      const route = new RegExp(`path="/${place === "dashboard" ? "" : place}[^"]*" element=\\{<(\\w+)`);
      const found = panel.match(route);
      const text = found ? files.get(`${found[1]}.tsx`) : undefined;
      return text !== undefined && /<Screen\b/.test(text) && /\bhelp=/.test(text) && /\btitle=/.test(text);
    };
    const missing = [...places].filter((place) => !named(place));
    expect(missing).toEqual([]);
  });
});

/**
 * A notice is not a container somebody arranges.
 *
 * A cell of the board is a whole row tall whatever it holds, so one line
 * of warning in a cell opens the screen with a hand's width of empty
 * floor under it - and an arrangement that hid that container would have
 * hidden the warning. Twelve screens did this. The board takes notices
 * above the grid instead, through its own `notices`.
 */
describe("what is never a container", () => {
  it("keeps notices off the board", () => {
    const offenders: string[] = [];
    for (const { name, text } of screens()) {
      for (const one of text.matchAll(/\{ key: "(notices?|problem|banner|warning)",[^}]*\bheight:/g)) {
        offenders.push(`${name}: ${one[1]}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

/**
 * A form is never a container of the board.
 *
 * This is the fault the owner named on 17.10, in his own words: pressing
 * "Create identity" opened a form inside a container headed "Who may sign
 * in", and from there nobody knows what is going on. It was on nineteen
 * screens - a filter, a wizard step, a twenty-seven-field declaration -
 * because the board treats a form and a reading as the same rectangle.
 *
 * A reading goes in a `Card` on the board. A decision goes in a `Form`,
 * which is not a board container and never carries somebody else's title.
 */
describe("what may stand on a board", () => {
  /**
   * The twenty places where it is still true, on 17.10, and a ratchet.
   *
   * The list may only shrink. A screen converted to the pattern takes its
   * line out; a screen that puts a new form on a board fails here the day
   * it is written. Leaving the test simply red while the panel is
   * converted would have meant a red suite for everybody for days, and a
   * red suite nobody can fix is a suite people learn to ignore.
   *
   * What this cannot see: a container whose form is inside a component it
   * calls - `set: <SetSettings host={host} />`. Those are on the list in
   * DESIGN-UI.md, found by walking the running panel, and they are the
   * reason this number is not the whole of the work.
   */
  /**
   * How many such cards each screen still has. The number may only fall:
   * a screen that gains one fails here, and a screen that loses its last
   * comes off the list. Counted rather than named, because several of
   * these titles are expressions and a name would be the fragile part.
   */
  const stillWrong: Record<string, number> = {
  };

  /** Each `<Card …>` of a file, from its opening tag to its own close. */
  function cards(text: string): string[] {
    const out: string[] = [];
    for (const open of text.matchAll(/<Card\b/g)) {
      let depth = 0;
      let i = open.index ?? 0;
      const from = i;
      while (i < text.length) {
        if (text.startsWith("<Card", i)) { depth += 1; i += 5; continue; }
        if (text.startsWith("</Card>", i)) {
          depth -= 1; i += 7;
          if (depth === 0) { out.push(text.slice(from, i)); break; }
          continue;
        }
        if (text.startsWith("/>", i) && depth === 1) { out.push(text.slice(from, i + 2)); break; }
        i += 1;
      }
    }
    return out;
  }

  it("holds nothing somebody has to fill in", () => {
    const tally: Record<string, number> = {};
    for (const { name, text } of screens()) {
      const n = cards(text).filter((card) => /<(input|textarea|Field\b|Fields\b)/.test(card)).length;
      if (n > 0) tally[name] = n;
    }
    const worse = Object.entries(tally)
      .filter(([name, n]) => n > (stillWrong[name] ?? 0))
      .map(([name, n]) => `${name}: ${n} (was ${stillWrong[name] ?? 0})`);
    expect(worse).toEqual([]);
    // And the ratchet: a screen that no longer has any comes off the list.
    const stale = Object.entries(stillWrong)
      .filter(([name, n]) => (tally[name] ?? 0) < n)
      .map(([name, n]) => `${name}: now ${tally[name] ?? 0}, listed as ${n}`);
    expect(stale).toEqual([]);
  });
});
