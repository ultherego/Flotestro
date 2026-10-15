import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * A class name in the markup with no rule in the stylesheets draws nothing.
 *
 * The screen of unconfirmed operations was built that way and the owner said
 * what it looked like: "wygląda jak pisana w html a nie profesjonalnym
 * produkcie". The table carried className="data" and the labels className=
 * "muted", and neither name existed in any stylesheet - so the browser drew
 * the browser's defaults and the screen stood out from every other one.
 *
 * Typescript cannot catch this: a class name is a string. So it is read off
 * the sources here.
 */

const SRC = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * The ones that were already like this when the check was written. The list
 * may only shrink: a name added to the markup without a rule fails, and a
 * name here that has since been given a rule fails too, so the list cannot
 * quietly become a place to put new ones.
 *
 * It is empty as of 15.10. The eighteen it held were three different things.
 * Five carried their appearance in a `style={{...}}` beside the name, which
 * is the same defect with the evidence attached; those declarations moved
 * into the stylesheet. Six named nothing at all and nothing selected them -
 * `plan-arch`, `plan-blocked`, `plan-changes`, `plan-toggle`, `host-select`,
 * `action-guard-notice` - and a name that draws nothing and says nothing to
 * anybody is noise in the markup, so they are gone from it. The rest were
 * given the rule they were always meant to have, `no-print` and
 * `report-print-head` among them: those two had their rules all along, in a
 * template literal in Reports.tsx, which this check could not read until it
 * read the sources as well as the stylesheets.
 */
const INHERITED: string[] = [];

function sources(dir: string, match: RegExp): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry === "node_modules") continue;
      out.push(...sources(path, match));
      continue;
    }
    if (match.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

/**
 * Every rule the panel ships, wherever it is written.
 *
 * Most are in the stylesheets. A page that prints as a document carries its
 * own, in a template literal it injects into a <style> element - and a rule
 * there is a rule: reading only the .css files, this check called those
 * classes unstyled and kept two of them on an exceptions list for weeks.
 */
function everyRule(): string {
  const stylesheets = sources(SRC, /\.css$/).map((path) => readFileSync(path, "utf8"));
  const injected: string[] = [];
  for (const path of sources(SRC, /\.tsx$/)) {
    const text = readFileSync(path, "utf8");
    // A template literal holding something that looks like a rule block.
    for (const found of text.matchAll(/`([^`]*\{[^`]*\})`/g)) {
      if (/^[\s\S]*\.[a-zA-Z][\w-]*[\s\S]*\{/.test(found[1])) injected.push(found[1]);
    }
  }
  return [...stylesheets, ...injected].join("\n");
}

/**
 * A name the markup can produce, and nothing else.
 *
 * A template literal is read by standing every value its holes can take in
 * turn and keeping the names that come out whole. A hole whose values
 * cannot be read off the source - a variable, a call - stands as UNKNOWN,
 * and any name it touches is dropped rather than guessed at: `ui-pill-`
 * followed by a tone is not a name, but the `ui-pill` before it is.
 *
 * This was the hole the check had. It read className="..." and nothing
 * else, so six names written as `` className={`ui-bar-fill ${tone}`} ``
 * never reached it and had no rule in any stylesheet for weeks.
 */
const UNKNOWN = "\u0000";

/** The holes of a template, split off from the text around them. */
function pieces(template: string): { text: string[]; holes: string[] } {
  const text: string[] = [];
  const holes: string[] = [];
  let at = 0;
  let plain = "";
  while (at < template.length) {
    if (template.startsWith("${", at)) {
      let depth = 1;
      let quote = "";
      let i = at + 2;
      for (; i < template.length && depth > 0; i++) {
        const c = template[i];
        if (quote) {
          if (c === "\\") i++;
          else if (c === quote) quote = "";
        } else if (c === '"' || c === "'" || c === "`") quote = c;
        else if (c === "{") depth++;
        else if (c === "}") depth--;
      }
      text.push(plain);
      plain = "";
      holes.push(template.slice(at + 2, i - 1));
      at = i;
      continue;
    }
    plain += template[at++];
  }
  text.push(plain);
  return { text, holes };
}

/**
 * What a hole can put in the markup.
 *
 * The strings an expression names are its candidates, except those being
 * compared against - `state === "failed" ? "error" : "ok"` says nothing
 * about a class called failed. UNKNOWN is always among them, because the
 * expression may just as well return something this cannot see.
 */
function values(expression: string): string[] {
  const compared = expression
    .replace(/[!=]==?\s*(["'])(?:\\.|(?!\1).)*\1/g, " ")
    .replace(/(["'])(?:\\.|(?!\1).)*\1\s*[!=]==?/g, " ");
  const literals = [...compared.matchAll(/(["'])((?:\\.|(?!\1).)*)\1/g)].map((m) => m[2]);
  return [...new Set([...literals, UNKNOWN])];
}

/** Every string the template can produce, up to a sane number of them. */
function outcomes(template: string): string[] {
  const { text, holes } = pieces(template);
  let out = [text[0]];
  holes.forEach((hole, i) => {
    const next: string[] = [];
    for (const so_far of out) for (const value of values(hole)) next.push(so_far + value + text[i + 1]);
    out = next.slice(0, 64);
  });
  return out;
}

/** The class names a source file writes, each with the file it is in. */
function namesWritten(text: string): string[] {
  const names: string[] = [];
  for (const m of text.matchAll(/className="([^"{}]+)"/g)) names.push(...m[1].split(/\s+/));
  for (const m of text.matchAll(/className=\{`((?:[^`\\]|\\.)*)`\}/g)) {
    for (const outcome of outcomes(m[1])) names.push(...outcome.split(/\s+/));
  }
  return names.filter((name) => name && !name.includes(UNKNOWN));
}

describe("the class names the panel's markup uses", () => {
  const styles = everyRule();
  const defined = new Set([...styles.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]));
  const used = new Map<string, string[]>();
  for (const path of sources(SRC, /\.tsx$/)) {
    for (const token of namesWritten(readFileSync(path, "utf8"))) {
      used.set(token, [...(used.get(token) ?? []), path.slice(SRC.length + 1)]);
    }
  }

  it("were found at all", () => {
    expect(defined.size).toBeGreaterThan(100);
    expect(used.size).toBeGreaterThan(100);
  });

  it("each have a rule in a stylesheet", () => {
    const missing = [...used.entries()]
      .filter(([name]) => !defined.has(name) && !INHERITED.includes(name))
      .map(([name, where]) => `${name} (${where[0]})`)
      .sort();
    expect(missing).toEqual([]);
  });

  it("have no name on the inherited list that has since been given a rule", () => {
    // Otherwise the list keeps names that are no longer exceptions, and the
    // next reader cannot tell which of them still matter.
    expect(INHERITED.filter((name) => defined.has(name))).toEqual([]);
  });

  it("have no name on the inherited list that the markup no longer uses", () => {
    expect(INHERITED.filter((name) => !used.has(name))).toEqual([]);
  });

  /*
   * CSS multi-column fills one column to the bottom and starts the next, so
   * it has no idea what a tile is: on a wide screen the head of a tile sat
   * in one column and its body and its button in the next. That is why
   * Masonry was taken out of this panel, and `.parts { columns: 380px }`
   * survived that removal and did it again on the settings screen on 15.10,
   * in front of the owner. A grid of tracks is the form; this refuses the
   * other one rather than trusting anybody to remember.
   */
  /*
   * The whole of the appearance is one namespace. The screens had grown
   * three vocabularies for one job - card-, hm-section- and ui-panel- for
   * the same box - and a rule outside the kit's namespace is how a fourth
   * starts. The reset and the tokens style elements and nothing else, so
   * every class selector in the stylesheets is the kit's.
   */
  it("are written in the kit's namespace and no other", () => {
    const outside = new Set<string>();
    for (const path of sources(SRC, /\.css$/)) {
      for (const line of readFileSync(path, "utf8").split("\n")) {
        const [head, brace] = [line.split("{")[0], line.includes("{")];
        if (!brace) continue;
        for (const found of head.matchAll(/\.([a-zA-Z][\w-]*)/g)) {
          if (!found[1].startsWith("ui-")) outside.add(found[1]);
        }
      }
    }
    expect([...outside].sort()).toEqual([]);
  });

  it("lay tiles out in a grid, never in CSS columns", () => {
    const offenders: string[] = [];
    for (const path of sources(SRC, /\.css$/)) {
      const text = readFileSync(path, "utf8");
      text.split("\n").forEach((line, index) => {
        if (/^\s*(columns|column-count|column-width)\s*:/.test(line)) {
          offenders.push(`${path.slice(SRC.length + 1)}:${index + 1} ${line.trim()}`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });
});
