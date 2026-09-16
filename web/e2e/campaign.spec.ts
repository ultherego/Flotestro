import { expect, test } from "@playwright/test";
import { expectHealthy, fleetHosts, watchErrors, type Host } from "./fleet";

/**
 * The Bulk workspace up to the preview: an operation is chosen, the scope
 * is narrowed to one site, and the eligibility step shows which hosts
 * would take part. The wizard stops there: no campaign is created, so
 * the fleet is left as it was.
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
  await expect(page.locator(".page-header").getByRole("heading", { name: "Bulk Workspace" })).toBeVisible();
  const noEngine = page.getByText("the backend has no campaign engine");
  const scope = page.getByRole("heading", { name: "1. Scope" });
  await expect(scope.or(noEngine).first()).toBeVisible();
  test.skip(await noEngine.isVisible(), "this installation has no campaign engine; the wizard is not offered");

  // Step 1: the order. The second step stays shut until the order is
  // complete: the pill above and the button at the end of the step are
  // both off, and both say why.
  const steps = page.locator(".bulk-steps");
  const targetsStep = steps.getByRole("button", { name: /Targets/ });
  await expect(targetsStep).toBeDisabled();
  await expect(targetsStep).toContainText("pick an operation, name the campaign and give it a valid payload");
  const next = (title: string) => page.getByRole("button", { name: `Next: ${title}`, exact: true });
  await expect(next("Targets")).toBeDisabled();
  await expect(page.getByText("Before going on: pick an operation, name the campaign and give it a valid payload.")).toBeVisible();

  await page.getByPlaceholder("campaign name").fill("e2e preview only");
  // The select is found through its field: a wrapping label lends the
  // control the text of the chosen option, so its accessible name moves.
  const operation = page.locator("label.field").filter({ hasText: /^Operation/ }).locator("select");
  await expect(operation.locator("option[value='unit.restart']")).toHaveCount(1);
  await operation.selectOption("unit.restart");
  await page.getByPlaceholder("unit, e.g. cron.service").fill("cron.service");

  // The scope bar pins the order for the whole wizard.
  const scopeBar = page.locator(".scope-bar");
  await expect(scopeBar).toContainText("e2e preview only");
  await expect(scopeBar).toContainText("unit.restart");

  await expect(targetsStep).toBeEnabled();
  await expect(next("Targets")).toBeEnabled();
  await next("Targets").click();

  // Step 2: the site. The hosts are chosen by their filters, the way the
  // step starts in; the count comes from the database and the sample
  // names the hosts.
  await expect(page.getByRole("heading", { name: "2. Targets" })).toBeVisible();
  await expect(page.getByRole("radio", { name: "by site, environment and OS" })).toBeChecked();
  const siteField = page.locator("label.field").filter({ hasText: /^Site/ }).locator("input");
  await siteField.fill(site);
  const matched = page.getByText(/The selector matches \d+ hosts/);
  await expect(matched).toBeVisible();
  // The previous answer stays on the screen while the narrowed preview
  // loads, so the count is polled until it fits the site.
  await expect.poll(async () => matchedCount(await matched.textContent()), {
    message: "the preview cannot match more hosts than the site holds",
  }).toBeLessThanOrEqual(inSite.length);
  const count = matchedCount(await matched.textContent());
  expect(count).toBeGreaterThan(0);
  // The sample under the count names hosts of the site.
  const sample = (await page.locator(".card-foot .source").first().textContent()) ?? "";
  expect(inSite.some((host) => sample.includes(host.hostname)), `the sample "${sample}" names no host of ${site}`).toBe(true);
  await expect(scopeBar).toContainText("targets:");

  // Step 3: eligibility. Every host of the site with systemd can restart
  // a unit; a host without it stays on the list with its reason.
  const eligibilityStep = steps.getByRole("button", { name: /Eligibility/ });
  await expect(eligibilityStep).toBeEnabled();
  await next("Eligibility").click();
  await expect(page.getByRole("heading", { name: "3. Eligibility" })).toBeVisible();

  // Back leads to the targets with the site still typed, and the pill
  // of the third step brings the operator forward again.
  await page.getByRole("button", { name: "Back", exact: true }).click();
  await expect(page.getByRole("heading", { name: "2. Targets" })).toBeVisible();
  await expect(siteField).toHaveValue(site);
  await eligibilityStep.click();
  await expect(page.getByRole("heading", { name: "3. Eligibility" })).toBeVisible();

  const eligibleRow = page.getByRole("row").filter({ has: page.locator(".badge.ok", { hasText: "eligible" }) });
  await expect(eligibleRow).toHaveCount(1);
  const eligibleCount = Number((await eligibleRow.getByRole("cell").nth(1).textContent())?.trim());
  expect(eligibleCount).toBeGreaterThan(0);
  expect(eligibleCount).toBeLessThanOrEqual(count);
  // A host without systemd cannot restart a unit, so the eligible count
  // is bounded by the adapters the API reports, when it reports them.
  if (inSite.some((host) => host.capabilities?.length)) {
    const capable = inSite.filter((host) => host.capabilities?.some((item) => item.name === "systemd" && item.available)).length;
    expect(eligibleCount).toBeLessThanOrEqual(capable);
  }
  if (eligibleCount < count) {
    // Somebody is left out; the reason stands next to the count.
    await expect(page.getByRole("row").filter({ has: page.locator(".badge.error, .badge.warn") }).first()).toBeVisible();
  }
  await expect(scopeBar).toContainText(`targets: ${eligibleCount}`);

  // The wizard goes no further: the rollout, the window and the order
  // are not touched. The next step is offered, the create step is not
  // opened.
  await expect(next("Rollout")).toBeEnabled();
  await expect(steps.getByRole("button", { name: /Create/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "6. Create" })).toHaveCount(0);
  expect(writes, "the preview must not write anything").toEqual([]);
  await expectHealthy(page, errors);
});

test("the operations that cannot run as a campaign are listed with their reasons", async ({ page }) => {
  await page.goto("/bulk");
  const noEngine = page.getByText("the backend has no campaign engine");
  const scope = page.getByRole("heading", { name: "1. Scope" });
  await expect(scope.or(noEngine).first()).toBeVisible();
  test.skip(await noEngine.isVisible(), "this installation has no campaign engine; the wizard is not offered");

  const refusals = page.locator("details").filter({ hasText: "cannot run as a campaign" });
  // The list waits for the operation catalogue; a catalogue in which
  // every mutating operation runs as a campaign draws no list at all.
  await expect(page.locator("label.field").filter({ hasText: /^Operation/ }).locator("option")).not.toHaveCount(1);
  test.skip((await refusals.count()) === 0, "every mutating operation of this installation runs as a campaign");
  await refusals.locator("summary").click();
  const rows = refusals.getByRole("row").filter({ has: page.locator("td") });
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
