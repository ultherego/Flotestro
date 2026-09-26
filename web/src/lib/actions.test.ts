import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { allowanceOf, type HostActions } from "./actions";
import { ACTION_TYPES } from "../generated/actions";

/**
 * Every control the panel guards names an operation of the catalogue, and a
 * name the catalogue does not have is not an error on the screen: the control
 * is simply not drawn. A rename in Go would take a button away silently, so
 * the names are pinned here.
 *
 * They used to be pinned by reading the Go sources with regular expressions -
 * three files, three patterns, and a silent pass the moment any of them was
 * written differently. The catalogue is generated now
 * (cmd/tools/contractgen), and a Go test fails when the generated file and the
 * registry disagree, so this side has one thing to read and no parser.
 */

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

type Usage = { action: string; file: string; line: number };

/** Every .ts and .tsx source of the panel, tests aside. */
function sourceFiles(dir: string): string[] {
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

/** The action="..." props of one source text, with the line they stand on. */
export function extractActions(text: string, file: string): Usage[] {
  const out: Usage[] = [];
  const prop = /\baction="([^"\n]*)"/g;
  for (const match of text.matchAll(prop)) {
    out.push({
      action: match[1],
      file,
      line: text.slice(0, match.index ?? 0).split("\n").length,
    });
  }
  return out;
}

function panelActions(): Usage[] {
  const out: Usage[] = [];
  for (const path of sourceFiles(SRC)) {
    out.push(...extractActions(readFileSync(path, "utf8"), relative(SRC, path)));
  }
  return out;
}

/**
 * The catalogue GET /hosts/{id}/actions serves: the operations that have a
 * spec, and the lifecycle orders judged after them. Both come from the
 * generated file, which a Go test holds to the registry.
 */
function catalogue(): Set<string> {
  return new Set<string>(ACTION_TYPES);
}

describe("the action names of the panel", () => {
  it("reads a prop and the line it stands on", () => {
    const text = 'x\n<ActionGuard action="unit.restart" host={id}>\n';
    expect(extractActions(text, "x.tsx")).toEqual([{ action: "unit.restart", file: "x.tsx", line: 2 }]);
    expect(extractActions("const action = \"x\";", "x.tsx")).toEqual([]);
  });

  /* A generated file that came back empty would let every check below pass on
     an empty set, so both ends are counted first. */
  it("finds the catalogue and the panel's names at all", () => {
    expect(catalogue().size).toBeGreaterThan(100);
    expect(new Set(panelActions().map((usage) => usage.action)).size).toBeGreaterThan(50);
  });

  it("names only operations the API serves", () => {
    const served = catalogue();
    const strangers = panelActions().filter((usage) => !served.has(usage.action));
    // A name the catalogue does not carry hides its control instead of
    // failing it, so the failure has to happen here.
    expect(strangers.map((usage) => `${usage.action} (${usage.file}:${usage.line})`)).toEqual([]);
  });

  it("hides a control whose name the catalogue lost", () => {
    const data: HostActions = {
      items: [{ action: "unit.restart", permission: "unit.restart", mutating: true, risk: "medium", allowed: true }],
      version: 1,
    };
    const state = { isPending: false, isError: false };
    expect(allowanceOf(data, state, "unit.restart").allowed).toBe(true);
    const renamed = allowanceOf(data, state, "unit.restart.now");
    expect(renamed.allowed).toBe(false);
    expect(renamed.reason_code).toBe("unknown_action");
  });
});
