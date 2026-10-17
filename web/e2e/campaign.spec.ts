import { expect, test } from "@playwright/test";
import { absent, card, expectHealthy, fleetHosts, head, watchErrors, type Host } from "./fleet";

/**
 * The Bulk workspace up to the preview: an operation is chosen, the scope is
 * narrowed to one site, and the eligibility step shows which hosts would
 * take part.
 */

let hosts: Host[] = [];

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
});

test("the Bulk workspace previews a unit restart scoped to one site without creating a campaign", async ({ page }) => {
  const { errors } = watchErrors(page);
  const site = process.env.FLOTESTRO_SITE ?? hosts[0].site;
  const inSite = hosts.filter((host) => host.site === site);
  expect(inSite.length, `no host in site ${site}`).toBeGreaterThan(0);

  // Any write to the campaigns API would be a change of the fleet.
  const writes: string[] = [];
  page.on("request", (request) => {
    if (request.method() !== "GET" && request.url().includes("/api/v1/")) writes.push(`${request.method()} ${request.url()}`);
  });

  await page.goto("/bulk");
  await expect(head(page, "Bulk")).toBeVisible();
  const noEngine = page.getByText("the backend has no campaign engine");
  const steps = card(page, "The steps");
  await expect(steps.or(noEngine).first()).toBeVisible();
  test.skip(await noEngine.count() > 0, absent("this installation has no campaign engine; the wizard is not offered"));

  // Step 1: the order.
  const scope = page.locator(".fl-card").filter({ hasText: /^1\. Scope/ }).first();
  await expect(scope).toBeVisible();
  const next = page.getByTestId("step-next");
  /* A step the order is not ready for is no longer a disabled tab with
     the reason inside it: the tabs stay walkable and the reason stands
     once under them, which is the same sentence in one place. */
  await expect(next).toBeDisabled();
  await expect(next).toHaveAttribute("title", /pick an operation and name the campaign/);
  await expect(steps).toContainText("Before going on: pick an operation and name the campaign.");

  await page.getByTestId("order-name").fill("e2e preview only");
  const operation = page.getByTestId("order-action");
  await expect(operation.locator("option[value='unit.restart']")).toHaveCount(1);
  await operation.selectOption("unit.restart");
  // The field is found by its label: the form no longer suggests a unit
  // name, because a unit is called whatever its host calls it.
  await page.locator("label.fl-field").filter({ hasText: /^Unit/ }).locator("input").first()
    .fill("cron.service");

  // The bar over the wizard pins the order for the whole of it.
  const bar = page.locator(".fl-card").filter({ hasText: "What is being ordered" }).first();
  await expect(bar).toContainText("e2e preview only");
  await expect(bar).toContainText("unit.restart");

  await expect(next).toBeEnabled();
  await next.click();

  // Step 2: the site.
  await expect(page.locator(".fl-card").filter({ hasText: /^2\. Targets/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "by site, environment and OS" })).toHaveAttribute("aria-pressed", "true");
  const siteField = page.getByTestId("target-site");
  await siteField.fill(site);
  const matched = page.getByTestId("matched");
  await expect(matched).toBeVisible();
  // The previous answer stays on the screen while the narrowed preview
  // loads, so the count is polled until it fits the site.
  await expect.poll(async () => matchedCount(await matched.textContent()), {
    message: "the preview cannot match more hosts than the site holds",
  }).toBeLessThanOrEqual(inSite.length);
  const count = matchedCount(await matched.textContent());
  expect(count).toBeGreaterThan(0);
  // The sample under the count names hosts of the site.
  const step = page.locator(".fl-card").filter({ hasText: /^2\. Targets/ }).first();
  const sample = (await step.textContent()) ?? "";
  expect(inSite.some((host) => sample.includes(host.hostname)), `the targets step names no host of ${site}`).toBe(true);
  await expect(page.getByTestId("scope-targets")).toHaveText(/^\d+$/);

  // Step 3: eligibility. Every host of the site with systemd can restart
  // a unit; a host without it stays on the list with its reason.
  await expect(page.getByTestId("step-next")).toBeEnabled();
  await page.getByTestId("step-next").click();
  await expect(page.locator(".fl-card").filter({ hasText: /^3\. Eligibility/ }).first()).toBeVisible();

  // Back leads to the targets with the site still typed, and the tab of
  // the third step brings the operator forward again.
  await page.getByTestId("step-back").click();
  await expect(page.locator(".fl-card").filter({ hasText: /^2\. Targets/ }).first()).toBeVisible();
  await expect(siteField).toHaveValue(site);
  await page.getByRole("tab", { name: "3. Eligibility" }).click();
  await expect(page.locator(".fl-card").filter({ hasText: /^3\. Eligibility/ }).first()).toBeVisible();

  const table = page.getByTestId("eligibility");
  const eligibleRow = table.locator("tbody tr").filter({ has: page.locator(".fl-pill.fl-ok", { hasText: "eligible" }) });
  await expect(eligibleRow).toHaveCount(1);
  const eligibleCount = Number((await eligibleRow.getByRole("cell").nth(1).textContent())?.trim());
  expect(eligibleCount).toBeGreaterThan(0);
  expect(eligibleCount).toBeLessThanOrEqual(count);
  // A host without systemd cannot restart a unit, so the eligible count is
  // bounded by the adapters the API reports, when it reports them.
  if (inSite.some((host) => host.capabilities?.length)) {
    const capable = inSite.filter((host) => host.capabilities?.some((item) => item.name === "systemd" && item.available)).length;
    const unknownRow = table.locator("tbody tr").filter({ has: page.locator(".fl-pill", { hasText: "adapter unknown" }) });
    const unknown = (await unknownRow.count()) > 0
      ? Number((await unknownRow.first().getByRole("cell").nth(1).textContent())?.trim())
      : 0;
    expect(eligibleCount).toBeLessThanOrEqual(capable + unknown);
  }
  if (eligibleCount < count) {
    // Somebody is left out; the reason stands next to the count.
    await expect(table.locator("tbody tr").filter({ has: page.locator(".fl-pill.fl-error, .fl-pill.fl-warn") }).first()).toBeVisible();
  }
  await expect(page.getByTestId("scope-targets")).toHaveText(String(eligibleCount));

  // The wizard goes no further: the rollout, the window and the order are
  // not touched.
  await expect(page.getByTestId("step-next")).toBeEnabled();
  await expect(page.getByRole("tab", { name: "6. Create" })).toBeVisible();
  await expect(page.locator(".fl-card").filter({ hasText: /^6\. Create/ })).toHaveCount(0);
  expect(writes, "the preview must not write anything").toEqual([]);
  await expectHealthy(page, errors);
});

test("the operations that cannot run as a campaign are listed with their reasons", async ({ page }) => {
  await page.goto("/bulk");
  const noEngine = page.getByText("the backend has no campaign engine");
  const steps = card(page, "The steps");
  await expect(steps.or(noEngine).first()).toBeVisible();
  test.skip(await noEngine.count() > 0, absent("this installation has no campaign engine; the wizard is not offered"));

  // The list waits for the operation catalogue; a catalogue in which
  // every mutating operation runs as a campaign draws no list at all.
  await expect(page.getByTestId("order-action").locator("option")).not.toHaveCount(1);
  const open = page.getByTestId("show-refusals");
  test.skip((await open.count()) === 0, absent("every mutating operation of this installation runs as a campaign"));
  await expect(open).toContainText("cannot run as a campaign");
  await open.click();

  const rows = page.getByTestId("bulk-refusals").locator("tbody tr");
  expect(await rows.count()).toBeGreaterThan(0);
  for (const row of await rows.all()) {
    await expect(row.getByRole("cell").nth(1)).not.toBeEmpty();
  }
});

/** The number in "The selector matches N hosts". */
function matchedCount(text: string | null): number {
  const match = /The selector matches (\d+) hosts/.exec(text ?? "");
  return match ? Number(match[1]) : 0;
}
