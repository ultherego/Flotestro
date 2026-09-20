import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { allowanceOf, type HostActions } from "./actions";

/**
 * Every control the panel guards names an operation of the catalogue, and a
 * name the catalogue does not have is not an error on the screen: the control
 * is simply not drawn. A rename in Go would take a button away silently, so
 * the names are pinned here - against the Go sources themselves rather than
 * against a copy of them, which would drift the same way.
 */

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = join(SRC, "..", "..");

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

/** The ActionType constants of a Go file, by their name. */
export function actionConstants(go: string): Map<string, string> {
  const constants = new Map<string, string>();
  const declaration = /\b(Action[A-Za-z0-9]*)\s+ActionType\s*=\s*"([^"]+)"/g;
  for (const match of go.matchAll(declaration)) constants.set(match[1], match[2]);
  return constants;
}

/** The body of a Go map or slice literal opened by this line. */
function literalBody(go: string, opening: string): string {
  const start = go.indexOf(opening);
  if (start < 0) throw new Error(`the Go sources no longer contain ${opening}`);
  const end = go.indexOf("\n}\n", start);
  if (end < 0) throw new Error(`${opening} is not closed the way this test reads it`);
  return go.slice(start + opening.length, end);
}

/**
 * The catalogue GET /hosts/{id}/actions serves: the operations that have a
 * spec, and the lifecycle orders judged after them.
 */
function catalogue(): Set<string> {
  const opspec = readFileSync(join(ROOT, "internal/opspec/opspec.go"), "utf8");
  const constants = actionConstants(opspec);
  const specs = literalBody(opspec, "var actionSpecs = map[ActionType]actionSpec{");
  const served = new Set<string>();
  for (const match of specs.matchAll(/^\t(Action[A-Za-z0-9]*):/gm)) {
    const name = constants.get(match[1]);
    // A key this test cannot resolve means the parsing below has drifted
    // from the Go sources, and a silent pass would be worse than a failure.
    if (!name) throw new Error(`actionSpecs names ${match[1]}, which declares no ActionType`);
    served.add(name);
  }
  const lifecycle = readFileSync(join(ROOT, "internal/adminapi/actions.go"), "utf8");
  for (const match of literalBody(lifecycle, "var hostLifecycleActions = []lifecycleAction{")
    .matchAll(/\bAction:\s*"([^"]+)"/g)) {
    served.add(match[1]);
  }
  return served;
}

describe("the action names of the panel", () => {
  it("reads a prop and the line it stands on", () => {
    const text = 'x\n<ActionGuard action="unit.restart" host={id}>\n';
    expect(extractActions(text, "x.tsx")).toEqual([{ action: "unit.restart", file: "x.tsx", line: 2 }]);
    expect(extractActions("const action = \"x\";", "x.tsx")).toEqual([]);
  });

  it("reads the ActionType constants of a Go file", () => {
    const go = '\tActionUnitStart   ActionType = "unit.start"\n\tActionUnitStop ActionType = "unit.stop"\n';
    expect([...actionConstants(go)]).toEqual([["ActionUnitStart", "unit.start"], ["ActionUnitStop", "unit.stop"]]);
  });

  /* The parsers above read the Go sources, so a change of shape there would
     leave them with nothing and every check below would pass on an empty
     set. Both ends are counted first. */
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
