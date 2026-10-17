import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The shared components are shared, which means they do not know about the
 * screens that use them. Two of them read the host module registry out of
 * pages/host, so a component could not be used without a page and a change to
 * a screen reached into everything: the registry moved to lib/ and this keeps
 * it from coming back.
 */

const COMPONENTS = dirname(fileURLToPath(import.meta.url));

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      out.push(...sources(path));
      continue;
    }
    if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

describe("the boundaries of the panel", () => {
  /**
   * A shared component may not reach into a screen.
   *
   * Until 17.10 this read "a component may not import a page", and it was
   * guarding the line between the shared parts and the panel being
   * replaced. That panel is gone; the line it was drawn along has not
   * moved, only its far side is now `src/next/screens`. A component that
   * imports a screen is a component that belongs in that screen.
   */
  it("has components that do not reach into a screen", () => {
    const crossings: string[] = [];
    const files = sources(COMPONENTS);
    // A run that found no component at all would pass having checked nothing.
    expect(files.length).toBeGreaterThan(5);
    for (const path of files) {
      const text = readFileSync(path, "utf8");
      for (const match of text.matchAll(/from\s+"([^"]*(?:pages|next\/screens)\/[^"]*)"/g)) {
        crossings.push(`${relative(COMPONENTS, path)} imports ${match[1]}`);
      }
    }
    expect(crossings).toEqual([]);
  });
});
