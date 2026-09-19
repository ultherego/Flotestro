import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { pl } from "./pl";

/**
 * The translation catalogue is keyed by the English source strings, so a
 * string added to a screen without a Polish line falls back to English
 * quietly.
 */

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

type Usage = { key: string; file: string; line: number };
type Extraction = {
  keys: Usage[];
  /** Calls whose first argument is not a string literal, as file:line. */
  nonLiteral: string[];
  files: number;
};

/**
 * Every . ts and . tsx source under a directory.
 */
function sourceFiles(dir: string): string[] {
  if (dir === join(SRC, "i18n")) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      out.push(...sourceFiles(path));
      continue;
    }
    if (!/\.tsx?$/.test(entry)) continue;
    if (/\.test\.tsx?$/.test(entry)) continue;
    out.push(path);
  }
  return out;
}

/** The string a JS literal denotes, escapes resolved. */
function unquote(literal: string): string {
  const body = literal.slice(1, -1);
  const escapes: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0" };
  return body.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_match, code: string) => {
    if (code.startsWith("u{")) return String.fromCodePoint(parseInt(code.slice(2, -1), 16));
    if (code.startsWith("u") || code.startsWith("x")) return String.fromCharCode(parseInt(code.slice(1), 16));
    return escapes[code] ?? code;
  });
}

/**
 * Extracts the t() keys of one source text.
 */
export function extractKeys(text: string, file: string): Extraction {
  const keys: Usage[] = [];
  const nonLiteral: string[] = [];
  const literal = /\bt\(\s*("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')/g;
  const anyCall = /\bt\(\s*(?=\S)/g;
  const lineOf = (index: number) => text.slice(0, index).split("\n").length;
  const literalStarts = new Set<number>();
  for (const match of text.matchAll(literal)) {
    literalStarts.add(match.index ?? 0);
    keys.push({ key: unquote(match[1]), file, line: lineOf(match.index ?? 0) });
  }
  for (const match of text.matchAll(anyCall)) {
    const index = match.index ?? 0;
    if (literalStarts.has(index)) continue;
    // A closing parenthesis right away is a call with no key at all,
    // which does not translate anything; it is not reported.
    if (text[index + match[0].length] === ")") continue;
    nonLiteral.push(`${file}:${lineOf(index)}`);
  }
  return { keys, nonLiteral, files: 1 };
}

function extractAll(): Extraction {
  const result: Extraction = { keys: [], nonLiteral: [], files: 0 };
  for (const path of sourceFiles(SRC)) {
    const one = extractKeys(readFileSync(path, "utf8"), relative(SRC, path));
    result.keys.push(...one.keys);
    result.nonLiteral.push(...one.nonLiteral);
    result.files += 1;
  }
  return result;
}

describe("the key extractor", () => {
  it("reads both quote styles and resolves escapes", () => {
    const text = [
      `const a = t("Hosts");`,
      `const b = t('Add host', { n: 1 });`,
      `const c = t("There is no module named \\"{segment}\\".");`,
      `const d = t(`,
      `  "Split over lines"`,
      `);`,
      `const e = text.split("x").at(0);`,
    ].join("\n");
    const { keys, nonLiteral } = extractKeys(text, "sample.tsx");
    expect(keys.map((usage) => usage.key)).toEqual([
      "Hosts",
      "Add host",
      'There is no module named "{segment}".',
      "Split over lines",
    ]);
    expect(keys[1].line).toBe(2);
    expect(nonLiteral).toEqual([]);
  });

  it("reports a key that is not a literal instead of guessing it", () => {
    const text = `t(stateName(state))\nt(item.label)\nt(\`Hello \${name}\`)`;
    const { keys, nonLiteral } = extractKeys(text, "sample.tsx");
    expect(keys).toEqual([]);
    expect(nonLiteral).toEqual(["sample.tsx:1", "sample.tsx:2", "sample.tsx:3"]);
  });
});

describe("the Polish catalogue", () => {
  const extraction = extractAll();
  const used = new Set(extraction.keys.map((usage) => usage.key));

  it("sees the sources", () => {
    expect(extraction.files).toBeGreaterThan(10);
    expect(used.size).toBeGreaterThan(100);
  });

  it("has every literal key the screens use", () => {
    const missing = [...used].filter((key) => !(key in pl)).sort();
    const where = missing.map((key) => {
      const usage = extraction.keys.find((entry) => entry.key === key);
      return `  ${JSON.stringify(key)}  (${usage?.file}:${usage?.line})`;
    });
    expect(missing, `keys without a Polish line:\n${where.join("\n")}`).toEqual([]);
  });

  it("keeps the placeholders of every key in its translation", () => {
    const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
    const broken = Object.entries(pl)
      .filter(([key, value]) => placeholders(key).join(",") !== placeholders(value).join(","))
      .map(([key]) => key);
    expect(broken, "translations whose {placeholders} differ from the key").toEqual([]);
  });

  it("has no empty translation", () => {
    const empty = Object.entries(pl).filter(([, value]) => value.trim() === "").map(([key]) => key);
    expect(empty).toEqual([]);
  });

  // The two reports below are advisory: a catalogue line may serve a key
  // that reaches t() through a table, and a table-driven call is a design
  // choice, not a defect.
  it("reports catalogue lines no literal key uses (advisory)", () => {
    const unused = Object.keys(pl).filter((key) => !used.has(key)).sort();
    if (unused.length > 0) {
      console.warn(
        `${unused.length} catalogue lines are not used by a literal t() key; they may be reached through tables:\n`
        + unused.slice(0, 40).map((key) => `  ${JSON.stringify(key)}`).join("\n")
        + (unused.length > 40 ? `\n  … and ${unused.length - 40} more` : ""),
      );
    }
    expect(true).toBe(true);
  });

  it("reports files that pass a non-literal key to t() (advisory)", () => {
    if (extraction.nonLiteral.length > 0) {
      console.warn(
        `${extraction.nonLiteral.length} t() calls take their key from an expression and are not checked:\n`
        + extraction.nonLiteral.map((place) => `  ${place}`).join("\n"),
      );
    }
    expect(true).toBe(true);
  });
});
