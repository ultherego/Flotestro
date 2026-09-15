import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { expectHealthy, permissions, watchErrors } from "./fleet";

/**
 * The identity directory page, one tab at a time. Every tab is opened and
 * what it renders is compared with what the API answers for the same
 * resource; nothing is ordered, approved or written. The whole file skips
 * on an installation without a directory connection: the tabs would only
 * show the notice saying so.
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
  test.skip(!status.configured || !status.reachable, "this installation has no directory connection");
  test.skip(!granted.has("identity.read"), "the token may not read the directory (identity.read)");
});

/** The page header of the directory page. */
function header(page: Page) {
  return page.locator(".page-header").getByRole("heading", { name: "Identity directory" });
}

/** Opens the directory page and switches to the named tab. */
async function openTab(page: Page, name: string) {
  await page.goto("/directory");
  await expect(header(page)).toBeVisible();
  const tabs = page.locator(".tabs").first();
  await tabs.getByRole("button", { name, exact: true }).click();
  await expect(tabs.getByRole("button", { name, exact: true })).toHaveClass(/active/);
}

/** A directory collection as the API lists it. */
async function collection<T>(request: APIRequestContext, path: string): Promise<T[]> {
  const response = await request.get(path);
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  return ((await response.json()) as Items<T>).items;
}

/** The tab has settled: its table is there, or the sentence that says it is empty. */
async function expectSettled(page: Page, empty: RegExp) {
  const table = page.locator(".card table").first();
  await expect(table.or(page.getByText(empty)).first()).toBeVisible();
}

test("users are listed one row per account", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const users = await collection<{ uid: string }>(request, "/api/v1/identity/users");
  await openTab(page, "Users");
  if (users.length === 0) {
    await expect(page.getByText("No accounts.")).toBeVisible();
  } else {
    const table = page.locator(".card table").first();
    await expect(table.locator("tbody tr")).toHaveCount(users.length);
    await expect(table.getByRole("cell", { name: users[0].uid, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("heading", { name: "Preserved accounts" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recent changes" })).toBeVisible();
  await expectHealthy(page, errors);
});

test("groups are listed with their members", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const groups = await collection<{ name: string }>(request, "/api/v1/identity/groups");
  await openTab(page, "Groups");
  await expectSettled(page, /^No groups\.$/);
  if (groups.length > 0) {
    await expect(page.getByRole("cell", { name: groups[0].name, exact: true })).toBeVisible();
  }
  await expectHealthy(page, errors);
});

test("HBAC rules are listed with the simulation below them", async ({ page }) => {
  test.skip(!granted.has("identity.policy.read"), "the token may not read the access rules (identity.policy.read)");
  const { errors } = watchErrors(page);
  await openTab(page, "HBAC rules");
  await expectSettled(page, /^No rules\.$/);
  await expect(page.getByRole("heading", { name: "Simulate access" })).toBeVisible();
  await expectHealthy(page, errors);
});

test("sudo rules are listed", async ({ page }) => {
  test.skip(!granted.has("identity.policy.read"), "the token may not read the sudo rules (identity.policy.read)");
  const { errors } = watchErrors(page);
  await openTab(page, "sudo rules");
  await expectSettled(page, /^No sudo rules\.$/);
  await expectHealthy(page, errors);
});

test("hosts show the enrolled directory entries", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const hosts = await collection<{ fqdn: string; enrolled: boolean }>(request, "/api/v1/identity/hosts");
  await openTab(page, "Hosts");
  await expectSettled(page, /^The directory has no host entries\.$/);
  const enrolled = hosts.find((host) => host.enrolled) ?? hosts[0];
  if (enrolled) {
    const row = page.getByRole("row").filter({ hasText: enrolled.fqdn });
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
  await expectSettled(page, /^The directory has no host groups\.$/);
  if (groups.length > 0) {
    await expect(page.getByRole("cell", { name: groups[0].name, exact: true })).toBeVisible();
  }
  await expectHealthy(page, errors);
});

test("SSH keys split the accounts by whether they have one", async ({ page, request }) => {
  const { errors } = watchErrors(page);
  const users = await collection<{ uid: string; ssh_key_fingerprints?: string[] }>(request, "/api/v1/identity/users");
  await openTab(page, "SSH keys");
  await expect(page.getByRole("heading", { name: "Accounts with keys" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Accounts without keys" })).toBeVisible();
  const withKeys = users.filter((user) => (user.ssh_key_fingerprints ?? []).length > 0).length;
  await expect(page.getByText(new RegExp(`^\\d+ keys on ${withKeys} accounts$`))).toBeVisible();
  await expectHealthy(page, errors);
});

test("services are listed read-only", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "Services");
  await expectSettled(page, /^The directory has no service principals the panel can read\.$/);
  await expect(page.getByPlaceholder("filter by principal or host")).toBeVisible();
  await expectHealthy(page, errors);
});

test("DNS shows the zones and the records of the first one", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "DNS");
  await expect(page.locator(".toolbar select").first()).toBeVisible();
  await expectSettled(page, /^This zone has no records the panel can read\.$/);
  await expectHealthy(page, errors);
});

test("integration health names the connector and the fleet half", async ({ page }) => {
  const { errors } = watchErrors(page);
  await openTab(page, "Integration health");
  await expect(page.getByRole("heading", { name: "Connector" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Keytab" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Hosts offline from the directory" })).toBeVisible();
  if (status.principal) {
    await expect(page.getByText(status.principal, { exact: true }).first()).toBeVisible();
  }
  await expectHealthy(page, errors);
});
