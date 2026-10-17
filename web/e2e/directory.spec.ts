import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { absent, card, expectHealthy, head, permissions, watchErrors } from "./fleet";

/**
 * The identity directory page, one tab at a time.
 */

type Status = { configured: boolean; reachable?: boolean; principal?: string };
type Items<T> = { items: T[] };

let status: Status = { configured: false };
let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  const response = await request.get("/api/v1/identity/status");
  expect(response.ok(), `GET /api/v1/identity/status answered ${response.status()}`).toBeTruthy();
  status = (await response.json()) as Status;
  granted = await permissions(request);
});

test.beforeEach(() => {
  test.skip(!status.configured || !status.reachable, absent("this installation has no directory connection"));
  test.skip(!granted.has("identity.read"), absent("the token may not read the directory (identity.read)"));
});

/** Opens the directory page and switches to the named tab. */
async function openTab(page: Page, name: string) {
  await page.goto("/directory");
  await expect(head(page, "Identity directory")).toBeVisible();
  const tab = page.getByRole("tab", { name, exact: true });
  await tab.click();
  await expect(tab).toHaveAttribute("aria-selected", "true");
}

/** A directory collection as the API lists it. */
async function collection<T>(request: APIRequestContext, path: string): Promise<T[]> {
  const response = await request.get(path);
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  return ((await response.json()) as Items<T>).items;
}

/** The tab settled: its table is there, or the sentence that says it is empty. */
async function expectSettled(page: Page, testId: string, empty: RegExp) {
  await expect(page.getByTestId(testId).or(page.getByText(empty)).first()).toBeVisible();
}

test("users are listed one row per account", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const users = await collection<{ uid: string }>(request, "/api/v1/identity/users");
  await openTab(page, "Users");
  if (users.length === 0) {
    await expect(page.getByText("The directory holds no accounts.")).toBeVisible();
  } else {
    const table = page.getByTestId("accounts");
    await expect(table.locator("tbody tr")).toHaveCount(users.length);
    await expect(table.locator(`[data-testid="pick-${users[0].uid}"]`)).toBeVisible();
  }
  await expect(card(page, "Preserved accounts")).toBeVisible();
  await expect(card(page, "Recent changes")).toBeVisible();
  await expectHealthy(page, errors);
});

test("groups are listed with their members", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const groups = await collection<{ name: string }>(request, "/api/v1/identity/groups");
  await openTab(page, "Groups");
  await expectSettled(page, "groups", /^No groups\.$/);
  if (groups.length > 0) {
    await expect(page.getByTestId("groups")).toContainText(groups[0].name);
  }
  await expectHealthy(page, errors);
});

test("HBAC rules are listed with the simulation below them", async ({ page }) => {
  test.skip(!granted.has("identity.policy.read"), absent("the token may not read the access rules (identity.policy.read)"));
  const { errors } = watchErrors(page);
  await openTab(page, "HBAC rules");
  await expectSettled(page, "hbac", /^No rules\.$/);
  await expect(card(page, "Simulate access")).toBeVisible();
  await expectHealthy(page, errors);
});

test("sudo rules are listed", async ({ page }) => {
  test.skip(!granted.has("identity.policy.read"), absent("the token may not read the sudo rules (identity.policy.read)"));
  const { errors } = watchErrors(page);
  await openTab(page, "sudo rules");
  await expectSettled(page, "sudo", /^No sudo rules\.$/);
  await expectHealthy(page, errors);
});

test("hosts show the enrolled directory entries", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const hosts = await collection<{ fqdn: string; enrolled: boolean }>(request, "/api/v1/identity/hosts");
  await openTab(page, "Hosts");
  await expectSettled(page, "directory-hosts", /^The directory has no host entries\.$/);
  const enrolled = hosts.find((host) => host.enrolled) ?? hosts[0];
  if (enrolled) {
    const row = page.getByTestId("directory-hosts").locator("tbody tr").filter({ hasText: enrolled.fqdn });
    await expect(row.first()).toBeVisible();
    // The fleet column settles on a link or on the fact that the host is
    // not in the fleet; "Checking…" is neither.
    await expect(row.first().getByText("Checking…")).toHaveCount(0);
  }
  await expectHealthy(page, errors);
});

test("host groups are listed with their hosts", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const groups = await collection<{ name: string }>(request, "/api/v1/identity/host-groups");
  await openTab(page, "Host groups");
  await expectSettled(page, "host-groups", /^The directory has no host groups\.$/);
  if (groups.length > 0) {
    await expect(page.getByTestId("host-groups")).toContainText(groups[0].name);
  }
  await expectHealthy(page, errors);
});

test("SSH keys split the accounts by whether they have one", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const users = await collection<{ uid: string; ssh_key_fingerprints?: string[] }>(request, "/api/v1/identity/users");
  await openTab(page, "SSH keys");
  await expect(card(page, "Accounts with keys")).toBeVisible();
  await expect(card(page, "Accounts without keys")).toBeVisible();
  /* The split used to be said in a sentence over the two tables; it is a
     ring with its own legend now, and the legend carries the same two
     counts plus the keys themselves. */
  const withKeys = users.filter((user) => (user.ssh_key_fingerprints ?? []).length > 0).length;
  const keys = users.reduce((sum, user) => sum + (user.ssh_key_fingerprints ?? []).length, 0);
  const legend = page.locator(".fl-ring, .fl-card").filter({ hasText: "Keys on record" }).first();
  await expect(legend).toContainText(String(withKeys));
  await expect(legend).toContainText(String(keys));
  await expectHealthy(page, errors);
});

test("services are listed read-only", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "Services");
  await expectSettled(page, "services", /^The directory has no service principals the panel can read\.$/);
  await expect(page.getByTestId("service-filter")).toBeVisible();
  await expectHealthy(page, errors);
});

test("DNS shows the zones and the records of the first one", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "DNS");
  await expect(page.getByTestId("zone")).toBeVisible();
  await expectSettled(page, "dns-records", /^This zone has no records the panel can read\.$/);
  await expectHealthy(page, errors);
});

test("integration health names the connector and the fleet half", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "Integration health");
  await expect(card(page, "Connector")).toBeVisible();
  await expect(card(page, "Keytab")).toBeVisible();
  await expect(card(page, "Hosts offline from the directory")).toBeVisible();
  if (status.principal) {
    await expect(page.getByText(status.principal, { exact: true }).first()).toBeVisible();
  }
  await expectHealthy(page, errors);
});
