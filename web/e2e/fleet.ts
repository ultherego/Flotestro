import { expect, type APIRequestContext, type Page } from "@playwright/test";

/** The fields of a host the tests read; the API returns more. */
export type Host = {
  id: string;
  hostname: string;
  site: string;
  environment: string;
  os_family?: string;
  connection_state: "online" | "offline" | "stale" | "unknown";
  pending_updates: number | null;
  capabilities?: { name: string; available: boolean }[];
};

/**
 * The hosts the token may see, straight from the API. The tests do not
 * assume the names of the lab machines: what the list shows is compared
 * with what the API returns, so the same tests run against any fleet.
 */
export async function fleetHosts(request: APIRequestContext): Promise<Host[]> {
  const response = await request.get("/api/v1/hosts?limit=200");
  expect(response.ok(), `GET /api/v1/hosts answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { items: Host[] };
  return body.items;
}

/** A host with a working adapter of the given name, or undefined. */
export function hostWith(hosts: Host[], capability: string): Host | undefined {
  return hosts.find((host) => host.capabilities?.some((item) => item.name === capability && item.available));
}

/**
 * Collects the uncaught exceptions of the page. A React error boundary
 * would print "Error:", but an exception in an event handler only reaches
 * the console; both are failures of the screen, so both are watched.
 */
export function watchErrors(page: Page): { errors: string[] } {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  return { errors };
}

/** The page shows no error box and threw nothing. */
export async function expectHealthy(page: Page, errors: string[]) {
  await expect(page.locator(".page-error")).toHaveCount(0);
  await expect(page.getByText(/^Error:/)).toHaveCount(0);
  expect(errors, "uncaught exceptions on the page").toEqual([]);
}

/** The sidebar navigation, as the screen reader names it. */
export function navigation(page: Page) {
  return page.getByRole("navigation", { name: "Main navigation" });
}

/** Opens the account menu of the top bar and returns its dialog. */
export async function openAccountMenu(page: Page) {
  await page.getByRole("button", { name: "Account menu" }).click();
  const menu = page.getByRole("dialog", { name: "Account menu" });
  await expect(menu).toBeVisible();
  return menu;
}

/** Opens the host list and waits for its rows. */
export async function openHostList(page: Page) {
  await page.goto("/hosts");
  await expect(page.locator(".page-header").getByRole("heading", { name: "Hosts" })).toBeVisible();
  const table = page.locator("table").first();
  await expect(table).toBeVisible();
  return table;
}
