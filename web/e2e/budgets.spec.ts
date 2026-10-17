import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { absent, card, expectHealthy, head, permissions, watchErrors } from "./fleet";

/**
 * The budgets page: the capacity of the fleet, the sites and the backup
 * backends, and the editor of one capacity.
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

/** A table heading by its label, with or without the arrow of a sortable column. */
function heading(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[⇅▲▼↑↓↕]?$`);
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
  return page.getByTestId("budgets").locator("tbody tr").filter({ has: page.getByTestId(`pick-${key}`) });
}

test.describe("budgets", () => {
  test("the settings lead to the page and the table agrees with the API", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), absent("the token may not read the budgets (budget.read)"));
    const { errors } = watchErrors(page);
    const items = await budgets(request);

    /* The budgets are a screen of their own again rather than a tab of
       the settings. The settings still name the section and lead to it,
       which is the way a reader gets there, so that is the way in here. */
    await page.goto("/settings");
    await page.getByRole("tab", { name: "Budgets" }).click();
    await expect(page).toHaveURL(/\/settings\?tab=budgets$/);
    await page.getByTestId("settings-open-section").click();
    await expect(page).toHaveURL(/\/budgets$/);
    await expect(head(page, "Budgets")).toBeVisible();

    if (items === null) {
      await expect(page.getByText("Budgets are disabled in this installation.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }

    // The four headline figures of the screen; a figure nobody could take
    // is a dash and says unknown rather than a nought.
    for (const id of ["kpi-keys", "kpi-saturated", "kpi-waiting-jobs", "kpi-waiting-hosts"]) {
      await expect(page.getByTestId(id).locator(".fl-kpi-value")).toHaveText(/^\d+$|^—$/);
    }
    await expect(page.getByTestId("kpi-keys").locator(".fl-kpi-value")).toHaveText(String(items.length));
    await expect(card(page, "Capacity").getByTestId("budget-states")).toBeVisible();
    await expect(card(page, "By family")).toBeVisible();
    // The four classes of work, always drawn with their tokens in use.
    const classes = card(page, "By class");
    for (const name of ["incident", "interactive", "maintenance", "background"]) {
      await expect(classes).toContainText(name);
    }

    if (items.length === 0) {
      await expect(page.getByText("No budget is configured.", { exact: true })).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }

    const table = page.getByTestId("budgets");
    for (const column of ["Key", "Capacity", "In use", "Held by", "Claimants", "Share per claimant", "Waiting jobs", "Waiting hosts"]) {
      await expect(table.locator("thead th", { hasText: heading(column) })).toBeVisible();
    }
    await expect(table.locator("tbody tr")).toHaveCount(items.length);
    for (const item of items) {
      const row = rowOf(page, item.key);
      await expect(row).toHaveCount(1);
      // The capacity is a policy and does not move under the test; the
      // tokens in use do, so only their shape is checked.
      await expect(row.getByRole("cell").nth(1)).toHaveText(String(item.capacity));
      await expect(row.locator(".fl-meter-value")).toHaveText(new RegExp(`^\\d+ / ${item.capacity}$`));
      // The holders come and go with the tokens: the cell either names
      // nobody or names holders, each with its class and its tokens.
      const holders = row.getByRole("cell").nth(3);
      await expect(holders).toHaveText(/nobody|tokens/);
      // A pattern row is the default of its family and says so.
      const pattern = item.key.split(":")[1] === "*";
      await expect(row.locator(".fl-pill", { hasText: "default" })).toHaveCount(pattern ? 1 : 0);
    }

    // A count of waiting jobs leads to the queue, a count of waiting
    // campaign hosts to the campaigns.
    const waiting = items.find((item) => item.waiting_jobs > 0);
    if (waiting) {
      await expect(rowOf(page, waiting.key).getByRole("cell").nth(6).getByRole("link"))
        .toHaveAttribute("href", "/jobs?state=queued");
    }
    const held = items.find((item) => item.waiting_targets > 0);
    if (held) {
      await expect(rowOf(page, held.key).getByRole("cell").nth(7).getByRole("link"))
        .toHaveAttribute("href", "/campaigns");
    }
    await expectHealthy(page, errors);
  });

  test("the editor is offered only with the right to write", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), absent("the token may not read the budgets (budget.read)"));
    const items = (await budgets(request)) ?? [];
    test.skip(items.length === 0, absent("no budget is configured in this installation"));

    await page.goto("/budgets");
    await expect(head(page, "Budgets")).toBeVisible();
    /* A row no longer carries an Edit button of its own: a key is picked
       and its own container holds everything about it, the editor
       included. What is held to is the same - the editor is there for
       whoever may write and is replaced by the reason for whoever may
       not. */
    await page.getByTestId(`pick-${items[0].key}`).click();
    // The container the key opens into: the one that holds the editor, or
    // the sentence that stands in its place.
    const detail = page.locator(".fl-card").filter({ hasText: "Share per claimant" })
      .filter({ hasNot: page.getByTestId("budgets") });
    await expect(detail).toHaveCount(1);
    if (granted.has("budget.write")) {
      await expect(detail.getByTestId("capacity-save")).toBeVisible();
    } else {
      await expect(detail.getByTestId("capacity-save")).toHaveCount(0);
      await expect(detail).toContainText("You may not change this budget");
    }
  });

  test("a capacity changed in the editor reaches the API and is restored", async ({ page, request }) => {
    test.skip(!granted.has("budget.read"), absent("the token may not read the budgets (budget.read)"));
    test.skip(!granted.has("budget.write"), absent("the token may not change a budget (budget.write)"));
    const items = (await budgets(request)) ?? [];
    test.skip(items.length === 0, absent("no budget is configured in this installation"));
    const { errors } = watchErrors(page);

    // A site's own key is the narrowest scope the right can be held in, so
    // it is the one most tokens may write; the fleet-wide keys are the
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
      await expect(head(page, "Budgets")).toBeVisible();
      await page.getByTestId(`pick-${chosen.key}`).click();
      const capacity = page.getByTestId("capacity");
      const note = page.getByTestId("capacity-note");
      await expect(capacity).toHaveValue(String(original.limit.capacity));
      // The note of the last change is the starting point of this one.
      await expect(note).toHaveValue(original.limit.note);
      // Nothing changed yet: nothing to save.
      await expect(page.getByTestId("capacity-save")).toBeDisabled();

      await capacity.fill(String(raised));
      await note.fill(`e2e ${stamp}`);
      await page.getByTestId("capacity-save").click();

      // The row shows the new capacity once the write is through.
      await expect(rowOf(page, chosen.key).getByRole("cell").nth(1)).toHaveText(String(raised));
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
