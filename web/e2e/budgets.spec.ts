import { expect, test, type APIRequestContext, type Locator, type Page } from "@playwright/test";
import { expectHealthy, permissions, watchErrors } from "./fleet";

/**
 * The budgets page: the capacity of the fleet, the sites and the backup
 * backends, and the editor of one capacity.
 *
 * The rows are compared with what the API answers rather than with the
 * numbers of the lab: the tokens held change with every task. One test
 * leaves a mark and takes it back: it raises the capacity of one budget by
 * a token through the editor and restores the original through the API,
 * with the tag of the record, the way the editor writes it. A token that
 * may not read the budgets skips with the permission it would need.
 */

type Holder = { owner: string; claimant: string; class: string; tokens: number; since: string };
type Budget = {
  key: string; capacity: number; used: number; claimants: number; waiting_jobs: number;
  waiting_targets: number; holders: Holder[]; by_class: Record<string, number>;
};
type Limit = { key: string; capacity: number; note: string; updated_at: string };

let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  granted = await permissions(request);
});

/** The page header of a fleet page, with its title. */
function header(page: Page, title: string) {
  return page.locator(".page-header").getByRole("heading", { name: title });
}

/** A whole-text match: "Capacity" must not find "Capacity of the fleet". */
function exact(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

/** The card of a fleet page by its title. */
function card(page: Page, title: string) {
  return page.locator(".card").filter({ has: page.locator(".card-title", { hasText: exact(title) }) });
}

/** Every value of a status bar has settled on a number. */
async function expectCounted(bar: Locator, count: number) {
  const values = bar.getByTestId("status-bar-value");
  await expect(values).toHaveCount(count);
  for (const value of await values.all()) {
    await expect(value).toHaveText(/^\d+$/);
  }
}

/** The budgets as the API lists them; an installation without them answers 501. */
async function budgets(request: APIRequestContext): Promise<Budget[] | null> {
  const response = await request.get("/api/v1/budgets");
  if (response.status() === 501) return null;
  expect(response.ok(), `GET /api/v1/budgets answered ${response.status()}`).toBeTruthy();
  return ((await response.json()) as { items: Budget[] }).items;
}

/** One configured budget with the tag of its version. */
async function limitOf(request: APIRequestContext, key: string): Promise<{ limit: Limit; etag: string }> {
  const response = await request.get(`/api/v1/budgets/${encodeURIComponent(key)}`);
  expect(response.ok(), `GET /api/v1/budgets/${key} answered ${response.status()}`).toBeTruthy();
  return { limit: (await response.json()) as Limit, etag: response.headers()["etag"] ?? "" };
}

/** Writes a budget back on the version named by the tag, as the editor does. */
async function restore(request: APIRequestContext, key: string, capacity: number, note: string) {
  const { etag } = await limitOf(request, key);
  const response = await request.put(`/api/v1/budgets/${encodeURIComponent(key)}`, {
    headers: etag ? { "If-Match": etag } : {},
    data: { capacity, note },
  });
  expect(response.ok(), `PUT /api/v1/budgets/${key} answered ${response.status()}`).toBeTruthy();
}

/** The row of a budget in the table, found by its key. */
function rowOf(page: Page, key: string) {
  return page.locator("tr[data-testid='budget-row']").filter({ has: page.locator("td .mono", { hasText: exact(key) }) });
}

test.describe("budgets", () => {
  test("the sidebar leads to the page and the table agrees with the API", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), "the token may not read the budgets (budget.read)");
    const { errors } = watchErrors(page);
    const items = await budgets(request);

    await page.goto("/dashboard");
    await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Budgets" }).click();
    await expect(page).toHaveURL(/\/budgets$/);
    await expect(header(page, "Budgets")).toBeVisible();

    if (items === null) {
      await expect(page.getByText("Budgets are disabled in this installation.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }

    const capacity = card(page, "Capacity");
    await expect(capacity).toContainText(`${items.length} budgets`);
    await expectCounted(capacity.getByTestId("status-bar"), 4);
    await expect(card(page, "By family")).toBeVisible();
    // The four classes of work, always drawn with their tokens in use and
    // their promotion age as a hint.
    const classes = card(page, "By class");
    for (const name of ["incident", "interactive", "maintenance", "background"]) {
      await expect(classes).toContainText(name);
    }
    await expect(classes).toContainText("2 minutes");

    if (items.length === 0) {
      await expect(page.getByText("No budget is configured.", { exact: true })).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }

    const table = page.locator("table").first();
    for (const column of ["Key", "Capacity", "In use", "Held by", "Claimants", "Share per claimant", "Waiting jobs", "Waiting hosts"]) {
      await expect(table.getByRole("columnheader", { name: exact(column) })).toBeVisible();
    }
    await expect(table.locator("tr[data-testid='budget-row']")).toHaveCount(items.length);
    for (const item of items) {
      const row = rowOf(page, item.key);
      await expect(row).toHaveCount(1);
      // The capacity is a policy and does not move under the test; the
      // tokens in use do, so only their shape is checked.
      await expect(row.getByRole("cell").nth(1)).toHaveText(String(item.capacity));
      await expect(row.locator(".meter-value")).toHaveText(new RegExp(`^\\d+ / ${item.capacity}$`));
      // The holders come and go with the tokens: the cell either names
      // nobody or names holders, each with its class and its tokens.
      const holders = row.getByRole("cell").nth(3);
      await expect(holders).toHaveText(/nobody|tokens/);
      for (const holder of await holders.getByTestId("budget-holder").all()) {
        await expect(holder).toContainText(/\d+ tokens/);
        await expect(holder.locator(".badge")).toHaveCount(1);
      }
      // A pattern row is the default of its family and says so.
      const pattern = item.key.split(":")[1] === "*";
      await expect(row.locator(".badge", { hasText: "default" })).toHaveCount(pattern ? 1 : 0);
    }

    // The status bar counts the keys of the table; the tokens in use may
    // have moved since the API answered, so the other segments are only
    // numbers, checked above.
    await expect(capacity.getByTestId("status-bar-value").nth(0)).toHaveText(String(items.length));

    // A count of waiting jobs leads to the queue, a count of waiting
    // campaign hosts to the campaigns.
    const waiting = items.find((item) => item.waiting_jobs > 0);
    if (waiting) {
      const link = rowOf(page, waiting.key).getByRole("cell").nth(6).getByRole("link", { name: /^\d+$/ });
      await expect(link).toHaveAttribute("href", "/jobs?state=queued");
    }
    const held = items.find((item) => item.waiting_targets > 0);
    if (held) {
      const link = rowOf(page, held.key).getByRole("cell").nth(7).getByRole("link", { name: /^\d+$/ });
      await expect(link).toHaveAttribute("href", "/campaigns");
    }
    await expectHealthy(page, errors);
  });

  test("the editor is offered only with the right to write", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), "the token may not read the budgets (budget.read)");
    const items = (await budgets(request)) ?? [];
    test.skip(items.length === 0, "no budget is configured in this installation");

    await page.goto("/budgets");
    await expect(header(page, "Budgets")).toBeVisible();
    const buttons = page.locator("table").first().getByRole("button", { name: "Edit" });
    await expect(buttons).toHaveCount(granted.has("budget.write") ? items.length : 0);
  });

  test("a capacity changed in the editor reaches the API and is restored", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), "the token may not read the budgets (budget.read)");
    test.skip(!granted.has("budget.write"), "the token may not change a budget (budget.write)");
    const items = (await budgets(request)) ?? [];
    test.skip(items.length === 0, "no budget is configured in this installation");
    const { errors } = watchErrors(page);

    // A site's own key is the narrowest scope the right can be held in,
    // so it is the one most tokens may write; the fleet-wide keys are the
    // fallback.
    const chosen = items.find((item) => {
      const [family, scope] = item.key.split(":");
      return family === "site" && scope !== "*";
    }) ?? items[0];
    const original = await limitOf(request, chosen.key);
    const raised = original.limit.capacity + 1;
    const stamp = Date.now().toString(36);

    try {
      await page.goto("/budgets");
      await expect(header(page, "Budgets")).toBeVisible();
      const row = rowOf(page, chosen.key);
      await row.getByRole("button", { name: "Edit" }).click();
      const editor = page.locator(`tr[data-testid='budget-editor'][data-key='${chosen.key}']`);
      await expect(editor).toBeVisible();
      // The note of the last change is the starting point of this one.
      await expect(editor.getByLabel("Note", { exact: true })).toHaveValue(original.limit.note);
      // Nothing changed yet: nothing to save.
      await expect(editor.getByRole("button", { name: "Save" })).toBeDisabled();

      await editor.getByLabel("Capacity", { exact: true }).fill(String(raised));
      await editor.getByLabel("Note", { exact: true }).fill(`e2e ${stamp}`);
      await editor.getByRole("button", { name: "Save" }).click();

      // The editor closes and the row shows the new capacity.
      await expect(editor).toHaveCount(0);
      await expect(row.getByRole("cell").nth(1)).toHaveText(String(raised));
      const written = await limitOf(request, chosen.key);
      expect(written.limit.capacity).toBe(raised);
      expect(written.limit.note).toBe(`e2e ${stamp}`);
      // The change is a new version of the record.
      expect(written.etag).not.toBe(original.etag);
      await expectHealthy(page, errors);
    } finally {
      await restore(request, chosen.key, original.limit.capacity, original.limit.note);
    }
    const back = await limitOf(request, chosen.key);
    expect(back.limit.capacity).toBe(original.limit.capacity);
    expect(back.limit.note).toBe(original.limit.note);
  });
});
