import { expect, test } from "@playwright/test";
import { expectHealthy, navigation, openAccountMenu, watchErrors } from "./fleet";

/**
 * The shell of the panel: the dashboard, every place the sidebar leads
 * to, and the settings of the person at the screen. None of it changes
 * the fleet.
 */

test.describe("dashboard", () => {
  test("renders the status bars with numbers", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/dashboard");
    await expect(page.locator(".page-header").getByRole("heading", { name: "Fleet dashboard" })).toBeVisible();

    const bars = page.getByTestId("status-bar");
    await expect(bars).toHaveCount(2);

    // The availability bar counts hosts; every segment settles on a
    // number once the summary and the activity have arrived. A dash
    // would mean a count the server did not answer.
    const availability = bars.first();
    const values = availability.getByTestId("status-bar-value");
    await expect(values).toHaveCount(6);
    for (const value of await values.all()) {
      await expect(value).toHaveText(/^\d+$/);
    }
    // The online segment links to the filtered host list.
    const online = availability.getByRole("listitem").filter({ hasText: "Online" });
    await expect(online).toBeVisible();
    await expect(online).toHaveAttribute("href", /connection_state=online/);

    // The problems bar has its own numbers; a segment fed by a module the
    // token may not read shows a dash, which is also a valid answer.
    const problems = bars.nth(1);
    await expect(problems.getByTestId("status-bar-value")).toHaveCount(5);
    for (const value of await problems.getByTestId("status-bar-value").all()) {
      await expect(value).toHaveText(/^(\d+|—)$/);
    }

    await expectHealthy(page, errors);
  });
});

test.describe("navigation", () => {
  test("every sidebar item leads to a page with a header and no error", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/dashboard");
    const links = navigation(page).getByRole("link");
    await expect(links.first()).toBeVisible();

    // The targets are read first: the sidebar re-renders on every
    // navigation, and a locator held across it would go stale. The name
    // is the label alone: an item may carry a badge with the count of
    // what waits behind it, and the count moves while the fleet works.
    const items: { name: string; href: string }[] = [];
    for (const link of await links.all()) {
      const href = await link.getAttribute("href");
      const name = (await link.locator(".sidebar-item-label").textContent())?.trim() ?? "";
      if (href) items.push({ name, href });
    }
    expect(items.length).toBeGreaterThanOrEqual(4);
    expect(items.map((item) => item.href)).toContain("/hosts");

    for (const item of items) {
      await test.step(`${item.name} (${item.href})`, async () => {
        await navigation(page).locator(`a[href="${item.href}"]`).click();
        await expect(page).toHaveURL(new RegExp(`${item.href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\?|$)`));
        const header = page.locator(".page-header, .hm-header").first();
        await expect(header).toBeVisible();
        await expect(header.getByRole("heading").first()).not.toBeEmpty();
        // The trail in the top bar names the section as the sidebar does.
        await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText(item.name);
        await expectHealthy(page, errors);
      });
    }
  });
});

test.describe("account menu", () => {
  test("the theme switch changes data-theme on the root element", async ({ page }) => {
    await page.goto("/dashboard");
    const html = page.locator("html");
    const before = await html.getAttribute("data-theme");
    expect(["mocha-peach", "mocha-green", "latte"]).toContain(before);

    const menu = await openAccountMenu(page);
    const themes = menu.getByRole("group", { name: "Theme" });
    await themes.getByRole("button", { name: "Latte" }).click();
    await expect(html).toHaveAttribute("data-theme", "latte");
    await expect(themes.getByRole("button", { name: "Latte" })).toHaveAttribute("aria-pressed", "true");

    await themes.getByRole("button", { name: "Green" }).click();
    await expect(html).toHaveAttribute("data-theme", "mocha-green");

    // The choice survives a reload: the inline script reads it before
    // React mounts.
    await page.reload();
    await expect(html).toHaveAttribute("data-theme", "mocha-green");
  });

  test("the text size switch changes data-scale on the root element", async ({ page }) => {
    await page.goto("/dashboard");
    const html = page.locator("html");
    await expect(html).toHaveAttribute("data-scale", "normal");

    const menu = await openAccountMenu(page);
    const sizes = menu.getByRole("group", { name: "Text size" });
    await sizes.getByRole("button", { name: "A+", exact: true }).click();
    await expect(html).toHaveAttribute("data-scale", "large");

    await sizes.getByRole("button", { name: "A-", exact: true }).click();
    await expect(html).toHaveAttribute("data-scale", "small");

    await page.reload();
    await expect(html).toHaveAttribute("data-scale", "small");
  });

  test("the menu closes on Escape", async ({ page }) => {
    await page.goto("/dashboard");
    const menu = await openAccountMenu(page);
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
  });
});

test.describe("command palette", () => {
  test("Ctrl+K opens the palette with the search focused and the places of the panel", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("button", { name: "Search the panel" })).toBeVisible();
    await page.keyboard.press("Control+k");

    const search = page.getByRole("textbox", { name: "Search the panel" });
    await expect(search).toBeVisible();
    await expect(search).toBeFocused();
    // Empty, the palette lists the places of the panel and nothing else:
    // the hosts stand in the selector beside it. Every row is a "Go to",
    // and the host list is among them for whoever may see the sidebar.
    const list = page.getByRole("listbox", { name: "Results" });
    await expect(list).toBeVisible();
    const rows = list.getByRole("option");
    await expect(rows.first()).toBeVisible();
    await expect(list.locator("[role='option']:not([data-kind='command'])")).toHaveCount(0);
    for (const row of await rows.all()) {
      await expect(row).toContainText(/^Go to /);
    }
    await expect(rows.filter({ hasText: /^Go to Hosts\b/ })).toHaveCount(1);

    await page.keyboard.press("Escape");
    await expect(search).toBeHidden();
  });
});

test.describe("host selector", () => {
  test("Ctrl+Shift+K opens the selector with the filter focused and the hosts listed", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("button", { name: "Select a host" })).toBeVisible();
    await page.keyboard.press("Control+Shift+k");

    const filter = page.getByRole("textbox", { name: "Select a host" });
    await expect(filter).toBeVisible();
    await expect(filter).toBeFocused();
    // The selector must not have opened the palette as well: Ctrl+K
    // without Shift is the palette's, and the two share the key.
    await expect(page.getByRole("textbox", { name: "Search the panel" })).toHaveCount(0);
    const list = page.getByRole("listbox", { name: "Hosts" });
    await expect(list).toBeVisible();
    // The list fills once the hosts arrive, every row a host; a fleet
    // with no host would say so instead of staying blank.
    await expect(list.getByRole("option").first().or(page.getByText("No host is enrolled yet"))).toBeVisible();
    for (const row of await list.getByRole("option").all()) {
      await expect(row).toHaveAttribute("data-kind", "hosts");
    }

    await page.keyboard.press("Escape");
    await expect(filter).toBeHidden();
  });
});
