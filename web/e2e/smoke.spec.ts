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
    // navigation, and a locator held across it would go stale.
    const items: { name: string; href: string }[] = [];
    for (const link of await links.all()) {
      const href = await link.getAttribute("href");
      const name = (await link.textContent())?.trim() ?? "";
      if (href) items.push({ name, href });
    }
    expect(items.length).toBeGreaterThanOrEqual(4);
    expect(items.map((item) => item.href)).toContain("/hosts");

    for (const item of items) {
      await test.step(`${item.name} (${item.href})`, async () => {
        await navigation(page).getByRole("link", { name: item.name, exact: true }).click();
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

test.describe("host picker", () => {
  test("Ctrl+K opens the picker with the filter focused", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("button", { name: "Search hosts" })).toBeVisible();
    await page.keyboard.press("Control+k");

    const filter = page.getByRole("textbox", { name: "Filter hosts" });
    await expect(filter).toBeVisible();
    await expect(filter).toBeFocused();
    const list = page.getByRole("listbox", { name: "Hosts" });
    await expect(list).toBeVisible();
    // The list fills once the hosts arrive; a fleet with no host would
    // say so instead of staying blank.
    await expect(list.getByRole("option").first().or(page.getByText("No host matches the filter."))).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(filter).toBeHidden();
  });
});
