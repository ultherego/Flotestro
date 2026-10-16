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
      [...panel.matchAll(/path="\/next\/?([a-z-]*)/g)]
        .map((found) => (found[1] === "" ? "dashboard" : found[1])),
    );
    const files = new Map(screens().map((one) => [one.name, one.text]));
    const named = (place: string) => {
      if (new RegExp(`\\b${place}:`).test(about)) return true;
      // Or the screen carries its own frame, with both a name and the
      // paragraph behind the question mark.
      const route = new RegExp(`path="/next/${place === "dashboard" ? "" : place}[^"]*" element=\\{<(\\w+)`);
      const found = panel.match(route);
      const text = found ? files.get(`${found[1]}.tsx`) : undefined;
      return text !== undefined && /<Screen\b/.test(text) && /\bhelp=/.test(text) && /\btitle=/.test(text);
    };
    const missing = [...places].filter((place) => !named(place));
    expect(missing).toEqual([]);
  });
});
