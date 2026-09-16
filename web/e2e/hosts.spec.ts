import { expect, test } from "@playwright/test";
import { expectHealthy, fleetHosts, navigation, openHostList, watchErrors, type Host } from "./fleet";

/**
 * The host list and the host workspace. The fleet is read through the
 * API first, so the assertions compare the screen with what the server
 * knows rather than with names hard-coded for one laboratory.
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
    // The count in the toolbar is the total the database counted.
    await expect(page.getByText(new RegExp(`^${hosts.length} hosts$`))).toBeVisible();
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

    // The box is short and says what it searches on hover and to the
    // screen reader; the label is that sentence.
    const search = page.getByRole("textbox", { name: "Search hostname, address, machine ID or owner" });
    await search.fill(fragment);
    // The filter runs on the server after a pause. The search also reads
    // addresses, machine IDs and owners, so the list may keep a row the
    // hostname alone would not explain; it must keep every matching name
    // and drop at least one host.
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
    // The server is the reference: the list must show exactly the hosts
    // the API answers with for the same filter, not what a first page
    // happens to carry.
    const response = await request.get("/api/v1/hosts?limit=200&reboot_required=true");
    expect(response.ok(), `GET /api/v1/hosts?reboot_required=true answered ${response.status()}`).toBeTruthy();
    const needing = ((await response.json()) as { items: Host[] }).items;

    const table = await openHostList(page);
    const rows = table.locator("tbody tr");
    await page.getByTestId("filter-reboot").selectOption("true");
    if (needing.length === 0) {
      await expect(page.getByText("No host matches the filters.")).toBeVisible();
    } else {
      await expect(rows).toHaveCount(Math.min(needing.length, 100));
      for (const host of needing.slice(0, 50)) {
        await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
      }
    }
    // The count in the toolbar follows the filter, like the rows do.
    await expect(page.getByText(new RegExp(`^${needing.length} hosts$`))).toBeVisible();

    await page.getByTestId("filter-reboot").selectOption("");
    await expect(rows).toHaveCount(Math.min(hosts.length, 100));
  });

  test("the owner and the management address stand in their own columns", async ({ page }) => {
    const table = await openHostList(page);
    // The address is a column of its own on every screen; a sortable
    // heading carries a button with an arrow, so the heading is found by
    // its text rather than by its whole accessible name.
    await expect(table.locator("thead th", { hasText: heading("Address") })).toBeVisible();
    // The owner is empty on most fleets, so its column stays off the
    // screen until chosen: the chooser offers it unticked, and ticking it
    // adds the column with the owner, or a dash, in every row.
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toHaveCount(0);
    await page.getByTestId("column-chooser").click();
    const owner = page.getByRole("group", { name: "Columns" }).getByRole("checkbox", { name: "Owner" });
    await expect(owner).not.toBeChecked();
    await owner.check();
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toBeVisible();
    await page.keyboard.press("Escape");
    const row = table.locator("tbody tr").first();
    await expect(row.getByTestId("host-owner")).toHaveText(/\S/);
    const address = row.getByTestId("host-address");
    // An address comes with its origin as a chip; a missing one says so.
    await expect(address.locator(".badge").first()).toBeVisible();
    const chip = (await address.locator(".badge").first().textContent())?.trim() ?? "";
    expect(["session", "agent", "manual", "unknown"]).toContain(chip);
    // The reset puts the column away again.
    await page.getByTestId("column-chooser").click();
    await page.getByTestId("reset-columns").click();
    await expect(table.locator("thead th", { hasText: heading("Owner") })).toHaveCount(0);
  });

  test("ticked hosts open the bulk workspace as its targets", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    // The checkboxes exist for whoever can read campaigns; without that
    // right there is no workspace to open and the test has nothing to do.
    const whoami = await request.get("/api/v1/whoami");
    const permissions = ((await whoami.json()) as { permissions: string[] }).permissions;
    test.skip(!permissions.includes("campaign.read"), "the token cannot read campaigns; no selection is offered");

    const table = await openHostList(page);
    const chosen = hosts.slice(0, 2);
    for (const host of chosen) {
      await table.getByRole("checkbox", { name: `select ${host.hostname}` }).check();
    }
    const bar = page.getByTestId("selection-bar");
    await expect(bar).toBeVisible();
    await expect(bar).toContainText(`${chosen.length} selected`);
    await bar.getByRole("button", { name: `Open in Bulk workspace (${chosen.length})` }).click();

    // The workspace opens on those hosts by identifier, and says so.
    await expect(page).toHaveURL(/\/bulk\?/);
    const url = new URL(page.url());
    expect(url.searchParams.getAll("host_id")).toEqual(chosen.map((host) => host.id));
    await expect(page.locator(".page-header").getByRole("heading", { name: "Bulk Workspace" })).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("host workspace", () => {
  test("clicking a host opens its overview and the sidebar switches to the host face", async ({ page }) => {
    const { errors } = watchErrors(page);
    const table = await openHostList(page);
    const host = hosts[0];
    await table.getByRole("link", { name: host.hostname, exact: true }).click();

    await expect(page).toHaveURL(new RegExp(`/hosts/${host.id}/overview$`));
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview" })).toBeVisible();

    // The top bar names the host between the section and the module.
    const trail = page.getByRole("navigation", { name: "Breadcrumb" });
    await expect(trail).toContainText(host.hostname);
    await expect(trail).toContainText("Overview");

    // The sidebar shows the modules of this host under their headings,
    // with the way back to the list above them; the fleet items are gone.
    const nav = navigation(page);
    await expect(nav.getByRole("link", { name: "All hosts" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "System" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Overview", exact: true })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Dashboard", exact: true })).toHaveCount(0);

    // The tab title carries the machine.
    await expect(page).toHaveTitle(new RegExp(`^${host.hostname}`));
    await expectHealthy(page, errors);
  });

  test("every module in the sidebar opens, and an unavailable one says why", async ({ page }) => {
    const { errors } = watchErrors(page);
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview" })).toBeVisible();

    const nav = navigation(page);
    const links = nav.locator("a.sidebar-item:not(.sidebar-back)");
    await expect(links.first()).toBeVisible();

    const modules: { name: string; href: string; unavailable: string | null }[] = [];
    for (const link of await links.all()) {
      const href = await link.getAttribute("href");
      const name = (await link.textContent())?.trim() ?? "";
      if (!href || href === "/hosts") continue;
      const dimmed = (await link.getAttribute("class"))?.split(/\s+/).includes("unavailable") ?? false;
      modules.push({ name, href, unavailable: dimmed ? await link.getAttribute("title") : null });
    }
    expect(modules.length).toBeGreaterThan(10);
    expect(modules.map((module) => module.name)).toContain("Jobs");

    for (const module of modules) {
      await test.step(module.unavailable ? `${module.name} (unavailable)` : module.name, async () => {
        await nav.getByRole("link", { name: module.name, exact: true }).click();
        await expect(page).toHaveURL(new RegExp(`${module.href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
        // The trail keeps the host and names the module.
        const trail = page.getByRole("navigation", { name: "Breadcrumb" });
        await expect(trail).toContainText(host.hostname);
        await expect(trail).toContainText(module.name);

        if (module.unavailable) {
          // The route stays and the reason is on the page: a vanished
          // module would look like a missing feature.
          const notice = page.getByText(`${module.name} is not available on this host: ${module.unavailable}.`);
          await expect(notice).toBeVisible();
          await expect(page.locator(".hm-header")).toHaveCount(0);
        } else {
          // A module with backing shows its header, or an honest empty
          // state while the host has not reported it yet.
          const header = page.locator(".hm-header").getByRole("heading", { name: module.name, exact: true });
          await expect(header.or(page.locator(".empty")).first()).toBeVisible();
        }
        await expectHealthy(page, errors);
      });
    }
  });
});

/** A table heading by its label, with or without the arrow of a sortable column after it. */
function heading(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[⇅▲▼]?$`);
}

/**
 * The shortest prefix of a hostname that does not name every host in the
 * fleet, so the filter demonstrably leaves rows out. With a fleet of one,
 * or hosts that share the name up to the end, the whole name is used.
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
