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

/**
 * The whole of one JSX element, from its name to the ">" that ends its opening
 * tag, with nested braces counted.
 *
 * Needed because an attribute holds expressions with their own braces and
 * their own ">" - an arrow function, a nested element - and a scan that stops
 * at the first ">" reads half a tag. A hand-rolled scan over these files
 * reported pages that do not exist before this counted properly.
 */
function openingTag(source: string, name: string, from = 0): string | undefined {
  const start = source.indexOf(`<${name}`, from);
  if (start < 0) return undefined;
  let depth = 0;
  for (let i = start; i < source.length; i++) {
    const c = source[i];
    if (c === "{") depth++;
    else if (c === "}") depth--;
    else if (c === ">" && depth === 0) return source.slice(start, i + 1);
  }
  return undefined;
}

/** The icons the page header can resolve, read out of the component itself. */
function sectionIcons(): Set<string> {
  const layout = readFileSync(join(SRC, "components/layout.tsx"), "utf8");
  const table = layout.slice(layout.indexOf("const SECTION_ICONS"), layout.indexOf("function iconForPath"));
  return new Set([...table.matchAll(/(\w[\w-]*)\s*:\s*"[\w-]+"/g)].map((m) => m[1]));
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
      // A route that only forwards draws nothing, so there is no header to
      // ask for: the screens that moved into the settings area keep their old
      // addresses answering, and those answers are a <Navigate>.
      if (/Redirect$/.test(where.exported)) continue;
      // PageHeader for an ordinary page; the host section's header is its
      // context bar, which carries the connection state and the freshness of
      // the data as well as the name - the one section whose header is not the
      // same component, and deliberately.
      if (!/PageHeader|ContextBar/.test(source)) without.push(`${name} (${where.from})`);
    }
    expect(without).toEqual([]);
  });

  /**
   * The explanation belongs behind the mark beside the title, not under it.
   * A paragraph is read once and then takes the top of the page every time
   * after that, which is the owner's complaint about this panel in his own
   * words: a wall of text under the tab's title.
   */
  it("each keep their explanation behind the mark beside the title", () => {
    const without: string[] = [];
    for (const name of routed) {
      const where = importOf(app, name);
      if (!where) continue;
      const file = join(SRC, `${where.from.replace(/^\.\//, "")}.tsx`);
      const source = readFileSync(file, "utf8");
      const tag = openingTag(source, "PageHeader");
      // A page under a layout carries no header of its own; the header test
      // above is what says which pages those are.
      if (!tag) continue;
      if (!/\bhelp=\{/.test(tag)) without.push(`${name} (${where.from})`);
    }
    expect(without).toEqual([]);
  });

  /**
   * And every tab's title carries the mark of its section. The header takes it
   * from the first segment of the address, so a page whose section is not in
   * that table shows a title with nothing beside it.
   */
  it("each carry the icon of their section", () => {
    const icons = sectionIcons();
    expect(icons.size).toBeGreaterThan(10);
    const routes = app.slice(app.indexOf("<Routes>"), app.lastIndexOf("</Routes>"));
    const without: string[] = [];
    let depth = 0;
    for (const line of routes.split("\n")) {
      const path = line.match(/<Route\s+path="([^"]*)"/);
      const tag = line.replace(/element=\{[^}]*\}/g, "");
      if (path && depth === 0) {
        const first = path[1].split("/")[1] ?? "";
        // The catch-all and the landing page are not sections.
        if (first !== "" && first !== "*" && !icons.has(first)) without.push(path[1]);
      }
      if (tag.includes("</Route>")) depth--;
      if (/<Route\b/.test(tag) && !/\/>/.test(tag)) depth++;
    }
    expect([...new Set(without)]).toEqual([]);
  });
});
