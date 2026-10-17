import { expect, test } from "@playwright/test";
import { card, expectHealthy, head, navigation, openUserMenu, trail, watchErrors } from "./fleet";

/**
 * The shell of the panel: the dashboard, every place the rail leads to,
 * and the settings of the person at the screen.
 */

test.describe("dashboard", () => {
  test("answers what needs a person, then counts what was found", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/dashboard");
    await expect(head(page, "Fleet dashboard")).toBeVisible();

    /* The verdict used to be a sentence across the top. It is two figures
       now, and they are the same answer said in the shape the rest of the
       panel says figures in: what waits on a person, and what the fleet
       found by itself. A figure nobody could take is a dash and says
       "unknown" in its label - never a nought. */
    for (const label of ["Waiting on a person", "Found on the hosts"]) {
      const kpi = page.getByTestId(`kpi-${label}`);
      await expect(kpi).toBeVisible();
      const value = kpi.locator(".fl-kpi-value");
      await expect(value).toHaveText(/^\d+$|^—$/);
      if ((await value.textContent())?.trim() === "—") {
        await expect(kpi.locator(".fl-kpi-label")).toHaveText(`${label}: unknown`);
      }
    }

    // What needs a person, listed. Either nothing does and the card says
    // so in a sentence, or every row carries a count - and a count the
    // server could not take is a dash, which is not a count of zero.
    const needs = card(page, "What needs you");
    await expect(needs).toBeVisible();
    const rows = needs.locator(".fl-needs-row");
    await expect(
      rows.first().or(needs.getByText("Nothing waits and nothing is wrong.")).first(),
    ).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row.locator(".fl-needs-count")).toHaveText(/^(\d+|—)$/);
    }

    // The availability band counts hosts: every segment it draws settles
    // on a number, and what is at zero or was never counted stands under
    // the band in words rather than as a sliver nobody can read.
    const availability = page.getByTestId("availability");
    await expect(availability).toBeVisible();
    const segments = availability.locator(".fl-band-value");
    const quiet = availability.locator(".fl-quiet-item");
    expect((await segments.count()) + (await quiet.count()), "the band named no state at all").toBe(6);
    for (const value of await segments.all()) {
      await expect(value).toHaveText(/^\d+$/);
    }
    // The online segment leads to the host list narrowed to it.
    const online = availability.getByRole("listitem").filter({ hasText: "Online" });
    if (await online.count() > 0) {
      await expect(online).toHaveAttribute("href", /connection_state=online/);
    }

    // The lists the dashboard keeps. Each says what is in it, in its own
    // words, whether or not it holds anything.
    const failures = card(page, "Recent failures");
    await expect(
      failures.locator(".fl-feed-row").first().or(failures.getByText("No failed operations.")).first(),
    ).toBeVisible();

    await expectHealthy(page, errors);
  });
});

test.describe("navigation", () => {
  test("every rail item leads to a page with a heading and no error", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/dashboard");
    const links = navigation(page).locator("a.fl-navitem:not(.fl-back)");
    await expect(links.first()).toBeVisible();

    // The targets are read first: the rail re-renders on every
    // navigation, and a locator held across it would go stale.
    const items: { name: string; href: string }[] = [];
    for (const link of await links.all()) {
      const href = await link.getAttribute("href");
      const name = (await link.locator(".fl-navitem-label").textContent())?.trim() ?? "";
      if (href) items.push({ name, href });
    }
    expect(items.length).toBeGreaterThanOrEqual(4);
    expect(items.map((item) => item.href)).toContain("/hosts");

    for (const item of items) {
      await test.step(`${item.name} (${item.href})`, async () => {
        await navigation(page).locator(`a[href="${item.href}"]`).click();
        await expect(page).toHaveURL(new RegExp(`${item.href.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(\\?|$)`));
        /* Every screen has a heading and no screen can leave it out.
           What it says is the screen's own name, which is not always the
           short word the rail uses for it - the rail says "Dashboard"
           and the screen is called "Fleet dashboard", the rail says
           "Directory" and the screen "Identity directory" - so what is
           held to is that there is a name, that the trail says where the
           reader is, and that the rail marks the place they are standing
           in. */
        const title = page.locator(".fl-head-title").first();
        await expect(title).toBeVisible();
        await expect(title).not.toBeEmpty();
        await expect(trail(page)).not.toBeEmpty();
        await expect(navigation(page).locator(`a[href="${item.href}"]`)).toHaveClass(/fl-on/);
        await expectHealthy(page, errors);
      });
    }
  });
});

test.describe("the person at the screen", () => {
  test("the theme switch changes data-theme on the root element", async ({ page }) => {
    await page.goto("/dashboard");
    const html = page.locator("html");
    const before = await html.getAttribute("data-theme");
    expect(["mocha-peach", "mocha-green", "latte"]).toContain(before);

    const menu = await openUserMenu(page);
    await menu.getByTestId("theme-latte").click();
    await expect(html).toHaveAttribute("data-theme", "latte");
    await expect(menu.getByTestId("theme-latte")).toHaveClass(/fl-on/);

    await menu.getByTestId("theme-mocha-green").click();
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

    const menu = await openUserMenu(page);
    await menu.getByTestId("scale-large").click();
    await expect(html).toHaveAttribute("data-scale", "large");

    await menu.getByTestId("scale-small").click();
    await expect(html).toHaveAttribute("data-scale", "small");

    await page.reload();
    await expect(html).toHaveAttribute("data-scale", "small");
  });

  test("the menu closes on Escape", async ({ page }) => {
    await page.goto("/dashboard");
    const menu = await openUserMenu(page);
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
  });
});

test.describe("the finder", () => {
  test("Ctrl+K opens it with the box focused, and a place is found by its name", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.getByTestId("open-finder")).toBeVisible();
    await page.keyboard.press("Control+k");

    const finder = page.getByTestId("finder");
    await expect(finder).toBeVisible();
    const field = page.getByTestId("finder-field");
    await expect(field).toBeFocused();

    /* With nothing typed the finder is this browser's own list of
       machines and says what it is for; it no longer prints the whole
       panel's worth of places over a reader who has not asked for one.
       A name typed into it finds the place it names. */
    await field.fill("Hosts");
    const place = page.getByTestId("finder-place:/hosts");
    await expect(place).toBeVisible();
    await expect(place).toContainText("Hosts");
    await expect(place.getByText("place", { exact: true })).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(finder).toHaveCount(0);
  });

  test("the finder opens a place and lands on it", async ({ page }) => {
    await page.goto("/dashboard");
    await page.keyboard.press("Control+k");
    await page.getByTestId("finder-field").fill("Jobs");
    await page.getByTestId("finder-place:/jobs").click();
    await expect(page).toHaveURL(/\/jobs$/);
    await expect(page.getByTestId("finder")).toHaveCount(0);
  });
});

test.describe("host selector", () => {
  test("the selector in the bar lists the fleet and opens a machine", async ({ page }) => {
    await page.goto("/dashboard");
    const open = page.getByTestId("host-select");
    await expect(open).toBeVisible();
    await open.click();

    const menu = page.getByTestId("host-select-open");
    await expect(menu).toBeVisible();
    const field = page.getByTestId("host-select-field");
    await expect(field).toBeFocused();
    // The selector lists machines and nothing else: it must not have
    // opened the finder, which reaches everything.
    await expect(page.getByTestId("finder")).toHaveCount(0);

    // The list fills once the hosts arrive, every row a machine; a fleet
    // with no host would say so instead of staying blank.
    const rows = menu.locator(".fl-pick-open");
    await expect(
      rows.first().or(menu.getByText("No machine answers to that.")).first(),
    ).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row).toHaveAttribute("data-testid", /^pick-/);
    }

    await page.keyboard.press("Escape");
    await expect(menu).toHaveCount(0);
  });
});
