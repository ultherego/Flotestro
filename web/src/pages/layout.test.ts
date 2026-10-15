import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/**
 * One shape for a screen, held to by a parser rather than by memory.
 *
 * The owner, on 15.10, after three screens in a row: *"caly UI ma byc spojny a
 * tu kazda podstrona zyje wlasnym zyciem... nie trzymaja sie te
 * kontenery/tabele zadnych norm"*. He was right, and the reason is that the
 * norm was written in a skill and in review comments, which is to say nowhere
 * a mistake can be caught. Thirty-eight pages followed it and seven did not,
 * and the difference is visible as soon as two of them are open side by side:
 * a table in a padded card body sits with a margin around it, the same table
 * in a flush card does not.
 *
 * The norm:
 *
 *   <Card flush title=…>        a data table lives in a card, and the card is
 *     <Toolbar end={count}>…    flush, so the table meets its edges
 *     <table>…</table>          the controls above it, in the toolbar
 *   </Card>
 *
 * and spacing comes from the stylesheet. A page that sets a margin or a
 * padding in a style attribute is a page deciding for itself what the gap
 * between two things is, which is how thirty-odd screens drift apart.
 *
 * This reads the JSX tree with the TypeScript parser, not the text: "is this
 * table inside a flush Card" is a question about nesting, and a regular
 * expression that answers it is answering a different question.
 *
 * What it does not see: a table in a component that some other file places
 * inside a card. Following that would need the whole program rather than one
 * file, so those are passed over in silence rather than reported as tables
 * standing on the page - a check that cries wolf is turned off within a week.
 */

const PAGES = dirname(fileURLToPath(import.meta.url));

/** Every page source, the tests and the barrel files aside. */
function pageSources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      out.push(...pageSources(path));
      continue;
    }
    if (entry.endsWith(".tsx") && !entry.endsWith(".test.tsx")) out.push(path);
  }
  return out;
}

function parse(path: string): ts.SourceFile {
  return ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
}

/** The tag of a JSX element, as written. */
function tagOf(node: ts.Node): string {
  if (ts.isJsxElement(node)) return node.openingElement.tagName.getText();
  if (ts.isJsxSelfClosingElement(node)) return node.tagName.getText();
  return "";
}

function hasAttribute(node: ts.JsxElement | ts.JsxSelfClosingElement, name: string): boolean {
  const opening = ts.isJsxElement(node) ? node.openingElement : node;
  return opening.attributes.properties.some(
    (property) => ts.isJsxAttribute(property) && property.name.getText() === name,
  );
}

/** The literal class names of an element, where they are written literally. */
function classesOf(node: ts.Node): string[] {
  if (!ts.isJsxElement(node) && !ts.isJsxSelfClosingElement(node)) return [];
  const opening = ts.isJsxElement(node) ? node.openingElement : node;
  for (const property of opening.attributes.properties) {
    if (!ts.isJsxAttribute(property) || property.name.getText() !== "className") continue;
    const value = property.initializer;
    if (value && ts.isStringLiteral(value)) return value.text.split(/\s+/);
  }
  return [];
}

/**
 * A tile of a board is the other container the panel has, and a table inside
 * one is already in a header-and-body shape: `.part` is the card of a board.
 */
function isTile(node: ts.Node): boolean {
  return classesOf(node).includes("part") || classesOf(node).includes("part-body");
}

/** Kept for the next rule that needs to know what a card or a tile is. */
void hasAttribute;
void isTile;

/** Walks the tree with the stack of enclosing JSX tags. */
function walk(node: ts.Node, stack: ts.Node[], visit: (node: ts.Node, stack: ts.Node[]) => void) {
  visit(node, stack);
  const next = ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) ? [...stack, node] : stack;
  ts.forEachChild(node, (child) => walk(child, next, visit));
}

/**
 * The screens that still write a table of their own.
 *
 * Forty-five of them did on 15.10, with 283 header cells typed out one at a
 * time - the same object spelled forty-five ways, which is what the owner was
 * looking at when he said the tables keep to no norm. `DataTable` is that
 * object; this list is what has not moved onto it yet.
 *
 * It may only shrink. A screen that moves must leave it, and a new screen may
 * not enter it, so the panel cannot grow a forty-sixth spelling while the
 * forty-five are being worked through.
 */
const WRITE_THEIR_OWN_TABLE = [
  "Access.tsx",
  "AddHost.tsx",
  "Audit.tsx",
  "Backups.tsx",
  "Budgets.tsx",
  "Bulk.tsx",
  "Campaign.tsx",
  "Campaigns.tsx",
  "CertificateAuthority.tsx",
  "Certificates.tsx",
  "Dashboard.tsx",
  "Directory.tsx",
  "Groups.tsx",
  "Hosts.tsx",
  "HostsMetadata.tsx",
  "Job.tsx",
  "Jobs.tsx",
  "Monitoring.tsx",
  "Notifications.tsx",
  "Policies.tsx",
  "Policy.tsx",
  "Profile.tsx",
  "Readiness.tsx",
  "Reads.tsx",
  "Relays.tsx",
  "Reports.tsx",
  "Schedules.tsx",
  "Secret.tsx",
  "Secrets.tsx",
  "Security.tsx",
  "Status.tsx",
  "Support.tsx",
  "Tags.tsx",
  "Teams.tsx",
  "Unresolved.tsx",
  "Vulnerabilities.tsx",
  "Vulnerability.tsx",
  "directory/Health.tsx",
  "directory/HostGroups.tsx",
  "directory/Hosts.tsx",
  "directory/Services.tsx",
  "directory/SshKeys.tsx",
  "directory/Users.tsx",
  "host/shared.tsx",
];

describe("the shape of a screen", () => {
  const pages = pageSources(PAGES);

  it("reads the pages at all", () => {
    expect(pages.length).toBeGreaterThan(30);
  });

  /*
   * Where a table sits in a card, the stylesheet decides how it meets the
   * card's edges - not the page. Half the screens had their table in a flush
   * card and half in a padded body beside a sentence, so the same kind of
   * list was inset on one screen and not on the next. Rather than rewrite
   * twelve call sites and wait for the thirteenth, the rule is in one place
   * and this is what says it is still there.
   */
  it("lets the stylesheet decide how a table meets its card", () => {
    const stylesheet = readFileSync(join(dirname(PAGES), "styles.css"), "utf8");
    expect(stylesheet).toMatch(/\.card-body:not\(\.flush\) > table/);
    expect(stylesheet).toMatch(/\.card-body:not\(\.flush\) > \* > table/);
  });

  it("draws its tables with the panel's own table, or is on the list of those that do not yet", () => {
    const writing: string[] = [];
    for (const path of pages) {
      const source = parse(path);
      let found = false;
      walk(source, [], (node) => { if (tagOf(node) === "table") found = true; });
      if (found) writing.push(path.slice(PAGES.length + 1));
    }
    const notListed = writing.filter((one) => !WRITE_THEIR_OWN_TABLE.includes(one));
    expect(notListed, "a new screen writing its own table instead of using DataTable").toEqual([]);
    // And the list may only shrink: a screen that has moved to DataTable has
    // to leave it, or the list stops meaning anything.
    const moved = WRITE_THEIR_OWN_TABLE.filter((one) => !writing.includes(one));
    expect(moved, "these no longer write their own table and belong off the list").toEqual([]);
  });

  it("never sets a table's own margins from a page", () => {
    const offenders: string[] = [];
    for (const path of pages) {
      const source = parse(path);
      walk(source, [], (node, stack) => {
        if (tagOf(node) !== "table") return;
        const element = node as ts.JsxElement;
        const opening = element.openingElement;
        const styled = opening.attributes.properties.some(
          (property) => ts.isJsxAttribute(property) && property.name.getText() === "style",
        );
        if (styled) {
          offenders.push(`${path.slice(PAGES.length + 1)}:${
            source.getLineAndCharacterOfPosition(node.getStart()).line + 1} a table with a style of its own`);
        }
        void stack;
      });
    }
    expect(offenders).toEqual([]);
  });

  it("leaves the spacing between things to the stylesheet", () => {
    const offenders: string[] = [];
    for (const path of pages) {
      const source = parse(path);
      walk(source, [], (node) => {
        if (!ts.isJsxAttribute(node) || node.name.getText() !== "style") return;
        const text = node.getText();
        if (!/\b(margin|padding)/.test(text)) return;
        offenders.push(`${path.slice(PAGES.length + 1)}:${
          source.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${text.replace(/\s+/g, " ").slice(0, 70)}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});
