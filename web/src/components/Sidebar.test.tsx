import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { badgeFor, type BadgeCounts } from "./Sidebar";
import { pl } from "../i18n/pl";

/**
 * The badges in the navigation are two agreements the type checker cannot
 * see: the address in the switch has to be an address the navigation lists,
 * and the title reaches t() through a variable, so the catalogue check of
 * the screens cannot see it either. A typo in either costs nothing visible -
 * the badge simply never appears, or appears in English.
 */

const HERE = dirname(fileURLToPath(import.meta.url));

/** The addresses badgeFor answers for, read off its own switch. */
function badgedAddresses(): string[] {
  const source = readFileSync(join(HERE, "Sidebar.tsx"), "utf8");
  const body = source.slice(source.indexOf("export function badgeFor"));
  return [...body.slice(0, body.indexOf("\n}")).matchAll(/case "([^"]+)":/g)].map((match) => match[1]);
}

/** Every address the navigation lists, read off the application's faces. */
function navigableAddresses(): string[] {
  const source = readFileSync(join(HERE, "..", "lib", "navigation.ts"), "utf8");
  return [...source.matchAll(/\bto: "([^"]+)"/g)].map((match) => match[1]);
}

describe("the navigation badges", () => {
  const addresses = badgedAddresses();

  it("reads the switch", () => {
    expect(addresses.length).toBeGreaterThan(3);
    expect(addresses).toContain("/unresolved");
  });

  it("badges only addresses the navigation lists", () => {
    const listed = new Set(navigableAddresses());
    expect(addresses.filter((address) => !listed.has(address))).toEqual([]);
  });

  it("has a Polish line for every title", () => {
    // Every counter at one, so each case returns rather than falling out on
    // a zero; the titles are what is under test.
    const counts: BadgeCounts = {
      jobs_awaiting_approval: 1,
      campaigns_awaiting_approval: 1,
      campaigns_manual_gate: 1,
      alerts_firing: 1,
      hosts_drifted: 1,
      operations_unconfirmed: 1,
    };
    const missing: string[] = [];
    for (const address of addresses) {
      const badge = badgeFor(address, counts);
      expect(badge, `${address} has every counter set and still shows no badge`).toBeDefined();
      if (badge && !(badge.title in pl)) missing.push(`${address}: ${badge.title}`);
    }
    expect(missing, "badge titles without a Polish line").toEqual([]);
  });

  it("counts the operations nobody could confirm", () => {
    expect(badgeFor("/unresolved", { operations_unconfirmed: 4 })?.count).toBe(4);
    // Nothing waiting is no badge, not a zero: the sidebar is a list of
    // places, and a zero beside every one of them says nothing.
    expect(badgeFor("/unresolved", { operations_unconfirmed: 0 })).toBeUndefined();
    expect(badgeFor("/unresolved", {})).toBeUndefined();
    expect(badgeFor("/unresolved", undefined)).toBeUndefined();
  });
});
