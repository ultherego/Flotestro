import { expect, test, type Page } from "@playwright/test";
import { absent, expectHealthy, fleetHosts, navigation, openHostList, trail, watchErrors, type Host } from "./fleet";

/**
 * The host list and the host workspace.
 */

let hosts: Host[] = [];

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
});

test.describe("host list", () => {
  test("shows every host the API lists", async ({ page }) => {
    const { errors } = watchErrors(page);
    const table = await openHostList(page);
    for (const host of hosts.slice(0, 50)) {
      await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
    }
    // The count in the bar of the card is the total the database counted;
    // the one at the foot counts the rows actually loaded, and on a fleet
    // that fits in one page the two agree.
    await expect(countInBar(page)).toHaveText(`${hosts.length} hosts`);
    await expectHealthy(page, errors);
  });

  test("the search box narrows the list by a hostname fragment", async ({ page }) => {
    const table = await openHostList(page);
    const rows = table.locator("tbody tr");
    await expect(rows).toHaveCount(Math.min(hosts.length, 100));

    // A fragment that names some hosts but not all of them, when the
    // fleet allows it: the whole name otherwise.
    const target = hosts[0];
    const fragment = distinctiveFragment(target.hostname, hosts.map((host) => host.hostname));
    const expected = hosts.filter((host) => host.hostname.toLowerCase().includes(fragment.toLowerCase()));

    const search = page.getByTestId("search");
    await search.fill(fragment);
    // The filter runs on the server after a pause.
    if (hosts.length > 1) await expect.poll(() => rows.count()).toBeLessThan(hosts.length);
    for (const host of expected) {
      await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
    }
    expect(await rows.count()).toBeGreaterThanOrEqual(expected.length);

    await search.fill("no-such-host-" + Date.now());
    await expect(page.getByText("No host matches the filters.")).toBeVisible();

    await search.fill("");
    await expect(rows).toHaveCount(Math.min(hosts.length, 100));
  });

  test("the reboot filter keeps the hosts the server says need one", async ({ page, request }) => {
    // The server is the reference: the list must show exactly the hosts the
    // API answers with for the same filter, not what a first page happens to
    // carry.
    const response = await request.get("/api/v1/hosts?limit=200&reboot_required=true");
    expect(response.ok(), `GET /api/v1/hosts?reboot_required=true answered ${response.status()}`).toBeTruthy();
    const needing = ((await response.json()) as { items: Host[] }).items;

    const table = await openHostList(page);
    const rows = table.locator("tbody tr");
    // The reboot filter is one of the folded ones: the bar keeps the few a
    // list is usually narrowed by and the rest wait behind a button.
    await page.getByTestId("more-filters").click();
    await page.getByTestId("filter-reboot").selectOption("true");
    if (needing.length === 0) {
      await expect(page.getByText("No host matches the filters.")).toBeVisible();
    } else {
      await expect(rows).toHaveCount(Math.min(needing.length, 100));
      for (const host of needing.slice(0, 50)) {
        await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
      }
    }
    // The count in the bar follows the filter, like the rows do.
    await expect(countInBar(page)).toHaveText(`${needing.length} hosts`);

    await page.getByTestId("filter-reboot").selectOption("");
    await expect(rows).toHaveCount(Math.min(hosts.length, 100));
  });

  test("the owner and the management address stand in their own columns", async ({ page }) => {
    const table = await openHostList(page);
    // The address is a column of its own on every screen; a sortable
    // heading carries a button with an arrow, so the heading is found by
    // its text rather than by its whole accessible name.
    await expect(table.locator("thead th", { hasText: heading("Address") })).toBeVisible();
    // The owner is empty on most fleets, so its column starts folded
    // away: the chooser offers it unticked, and ticking it adds the
    // column with the owner, or a dash, in every row.
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toHaveCount(0);
    await page.getByTestId("hosts-columns").click();
    const chooser = page.locator(".fl-columns-list");
    const owner = chooser.getByRole("checkbox", { name: "Owner" });
    await expect(owner).not.toBeChecked();
    await owner.check();
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toBeVisible();
    const row = table.locator("tbody tr").first();
    await expect(row.getByTestId("host-owner")).toHaveText(/\S/);
    const address = row.getByTestId("host-address");
    // An address comes with its origin as a chip; a missing one says the
    // address is unknown rather than leaving the cell blank.
    await expect(address).toBeVisible();
    const chip = (await address.locator(".fl-pill").first().textContent())?.trim() ?? "";
    expect(["session", "agent", "manual", "unknown"]).toContain(chip);
    /* The kit's chooser has no reset: a column is put away by the same
       tick that brought it, which is the one control the panel offers and
       therefore the one this holds to. */
    await owner.uncheck();
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toHaveCount(0);
  });

  test("ticked hosts open the bulk workspace as its targets", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    // The checkboxes exist for whoever can read campaigns; without that
    // right there is no workspace to open and the test has nothing to do.
    const whoami = await request.get("/api/v1/whoami");
    const granted = ((await whoami.json()) as { permissions: string[] }).permissions;
    test.skip(!granted.includes("campaign.read"), absent("the token cannot read campaigns; no selection is offered"));

    const table = await openHostList(page);
    const chosen = hosts.slice(0, 2);
    for (const host of chosen) {
      await table.getByRole("checkbox", { name: `select ${host.hostname}` }).check();
    }
    // What is offered for the ticked rows stands at the foot of the card
    // the rows are in, and says how many it would reach.
    const foot = page.locator(".fl-card-foot").filter({ hasText: `${chosen.length} selected` });
    await expect(foot).toBeVisible();
    await foot.getByTestId("open-bulk").click();

    // The workspace opens on those hosts by identifier, and says so.
    await expect(page).toHaveURL(/\/bulk\?/);
    const url = new URL(page.url());
    expect(url.searchParams.getAll("host_id").sort()).toEqual(chosen.map((host) => host.id).sort());
    await expect(page.locator(".fl-head-title").first()).not.toBeEmpty();
    await expectHealthy(page, errors);
  });
});

test.describe("host workspace", () => {
  test("clicking a host opens it and the rail switches to the host's modules", async ({ page }) => {
    const { errors } = watchErrors(page);
    const table = await openHostList(page);
    const host = hosts[0];
    await table.getByRole("link", { name: host.hostname, exact: true }).click();

    // The list leads to the machine itself; the overview is the module it
    // opens on, and the address of a machine with no module named is the
    // machine's own.
    await expect(page).toHaveURL(new RegExp(`/hosts/${host.id}$`));
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);

    // The top bar names the host between the section and the module.
    await expect(trail(page)).toContainText(host.hostname);
    await expect(trail(page)).toContainText("Overview");

    // The rail shows the modules of this host under their headings, with
    // the way back above them; the fleet's places are gone.
    const nav = navigation(page);
    await expect(nav.getByRole("link", { name: "All hosts" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "System" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Overview", exact: true })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Dashboard", exact: true })).toHaveCount(0);

    /* The tab title is not held to here. The panel being replaced wrote
       the machine into document.title; this one does not write a title at
       all, so there is nothing to hold to and saying so is better than an
       assertion that would pass over an empty claim. */
    await expectHealthy(page, errors);
  });

  test("every module in the rail opens, and one the host cannot back says why", async ({ page }) => {
    const { errors } = watchErrors(page);
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);

    const nav = navigation(page);
    const open = nav.locator("a.fl-navitem:not(.fl-back)");
    await expect(open.first()).toBeVisible();

    const modules: { name: string; href: string }[] = [];
    for (const link of await open.all()) {
      const href = await link.getAttribute("href");
      const name = (await link.locator(".fl-navitem-label").textContent())?.trim() ?? "";
      if (href && href !== "/hosts") modules.push({ name, href });
    }
    expect(modules.length).toBeGreaterThan(10);
    expect(modules.map((module) => module.name)).toContain("Jobs");

    /* A module the host has no backing for is not left out and not turned
       into a page of refusals: it stays on the rail, dimmed, not a link,
       and its title says why. That is where the sentence lives now. */
    for (const off of await nav.locator("span.fl-navitem.fl-off").all()) {
      const name = (await off.locator(".fl-navitem-label").textContent())?.trim() ?? "";
      await expect(off, `${name} is dimmed without a reason`).toHaveAttribute("title", /\S/);
    }

    for (const module of modules) {
      await test.step(module.name, async () => {
        await nav.locator(`a[href="${module.href}"]`).click();
        await expect(page).toHaveURL(new RegExp(`${module.href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
        // The trail keeps the host and names the module.
        await expect(trail(page)).toContainText(host.hostname);
        await expect(trail(page)).toContainText(module.name);
        // The module settled: it drew something of the panel's own - a
        // container, an honest empty state, a banner - rather than
        // nothing or an error.
        const settled = page.locator(".fl-card, .fl-form, .fl-empty, .fl-banner, .fl-kpi");
        await expect(settled.first(), `${module.name} drew nothing`).toBeVisible();
        await expectHealthy(page, errors);
      });
    }
  });
});

/** The count the card's own bar carries: the fleet's total, not the page's. */
function countInBar(page: Page) {
  return page.locator(".fl-toolbar-end .fl-note").filter({ hasText: /^\d+ hosts$/ });
}

/** A table heading by its label, with or without the arrow of a sortable column after it. */
function heading(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[⇅▲▼↑↓↕]?$`);
}

/**
 * The shortest prefix of a hostname that does not name every host in the
 * fleet, so the filter demonstrably leaves rows out.
 */
function distinctiveFragment(hostname: string, all: string[]): string {
  for (let length = 3; length < hostname.length; length += 1) {
    const prefix = hostname.slice(0, length);
    // A prefix that reads as hex could also match a machine ID.
    if (/^[0-9a-f]+$/i.test(prefix)) continue;
    const matching = all.filter((name) => name.toLowerCase().includes(prefix.toLowerCase()));
    if (matching.length < all.length) return prefix;
  }
  return hostname;
}
