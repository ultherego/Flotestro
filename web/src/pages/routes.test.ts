import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Every page the router can reach opens with a header: the mark of the section,
 * the title, one line of description, the actions on the right. Thirty-seven
 * pages carry one because somebody went through them one at a time on 13.10,
 * and nothing was watching afterwards - a page added tomorrow would simply not
 * have it, and the panel would be back to each screen starting its own way.
 *
 * It reads App.tsx and the page sources rather than a list kept here, for the
 * reason the list would be wrong: a copy of the routes is a second description
 * of the routes, edited once.
 *
 * What it checks is that the page's module renders a header, not which of its
 * components does - several pages are a thin router over a list component that
 * holds the header, and following that would need a parser rather than a read.
 * A page with no header anywhere in it is what this catches.
 */

const PAGES = dirname(fileURLToPath(import.meta.url));
const SRC = dirname(PAGES);
const app = readFileSync(join(SRC, "App.tsx"), "utf8");

/**
 * The components the routes name, with the ones nested under another route left
 * out: those sit inside a layout, and the layout is the page.
 */
function routedComponents(source: string): string[] {
  const routes = source.slice(source.indexOf("<Routes>"), source.lastIndexOf("</Routes>"));
  const names: string[] = [];
  let depth = 0;
  for (const line of routes.split("\n")) {
    const element = line.match(/element=\{<([A-Z][A-Za-z0-9]*)/);
    // The element is taken out before the tag is read: element={<HostLayout />}
    // carries a "/>" of its own, and a route that opens a block would be read
    // as one that closes itself - which is how its twenty-four nested tabs came
    // out of this parser as pages in their own right.
    const tag = line.replace(/element=\{[^}]*\}/g, "");
    if (element && depth === 0) names.push(element[1]);
    if (tag.includes("</Route>")) depth--;
    if (/<Route\b/.test(tag) && !/\/>/.test(tag)) depth++;
  }
  return [...new Set(names)];
}

/** Where App.tsx imports a component from, and under which name it is exported. */
function importOf(source: string, name: string): { from: string; exported: string } | undefined {
  const named = source.match(
    new RegExp(`import\\s*\\{([^}]*?\\b(?:(\\w+)\\s+as\\s+)?${name}\\b[^}]*)\\}\\s*from\\s*"(\\.[^"]+)"`),
  );
  if (named) return { from: named[3], exported: named[2] ?? name };
  const direct = source.match(new RegExp(`import\\s+${name}\\s+from\\s*"(\\.[^"]+)"`));
  return direct ? { from: direct[1], exported: name } : undefined;
}

describe("the pages the router can reach", () => {
  const routed = routedComponents(app);

  it("are found in App.tsx at all", () => {
    // A run that matched nothing would pass having checked nothing.
    expect(routed.length).toBeGreaterThan(25);
  });

  it("each open with a header", () => {
    const without: string[] = [];
    for (const name of routed) {
      const where = importOf(app, name);
      // A component declared in App.tsx itself is the shell, not a page.
      if (!where) continue;
      const file = join(SRC, `${where.from.replace(/^\.\//, "")}.tsx`);
      const source = readFileSync(file, "utf8");
      if (!new RegExp(`\\b${where.exported}\\b`).test(source)) {
        without.push(`${name}: ${where.from} exports no ${where.exported}`);
        continue;
      }
      // PageHeader for an ordinary page; the host section's header is its
      // context bar, which carries the connection state and the freshness of
      // the data as well as the name - the one section whose header is not the
      // same component, and deliberately.
      if (!/PageHeader|ContextBar/.test(source)) without.push(`${name} (${where.from})`);
    }
    expect(without).toEqual([]);
  });
});
