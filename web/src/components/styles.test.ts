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
 */
const INHERITED = [
  "action-guard", "action-guard-denied", "action-guard-hint", "action-guard-notice",
  "column-chooser", "fp-host-tags", "hm-notes", "hm-panel-row", "host-picker-kind",
  "host-select", "no-print", "plan-arch", "plan-blocked", "plan-changes", "plan-toggle",
  "prose", "report-print-head", "title",
];

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

describe("the class names the panel's markup uses", () => {
  const styles = sources(SRC, /\.css$/).map((path) => readFileSync(path, "utf8")).join("\n");
  const defined = new Set([...styles.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]));
  const used = new Map<string, string[]>();
  for (const path of sources(SRC, /\.tsx$/)) {
    const text = readFileSync(path, "utf8");
    // The literal form only: a name built at runtime is a condition over
    // names that appear literally somewhere else.
    for (const m of text.matchAll(/className="([^"{}]+)"/g)) {
      for (const token of m[1].split(/\s+/).filter(Boolean)) {
        used.set(token, [...(used.get(token) ?? []), path.slice(SRC.length + 1)]);
      }
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
});
