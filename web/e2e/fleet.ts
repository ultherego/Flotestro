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

/**
 * The permissions of the token, as the panel reads them to show or hide a
 * section. A test of a gated page skips without the permission instead of
 * failing on the refusal the page would show.
 */
export async function permissions(request: APIRequestContext): Promise<Set<string>> {
  const response = await request.get("/api/v1/whoami");
  expect(response.ok(), `GET /api/v1/whoami answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { permissions?: string[] };
  return new Set(body.permissions ?? []);
}

/** The hosts the API lists as online; a read from a host needs one. */
export function onlineHosts(hosts: Host[]): Host[] {
  return hosts.filter((host) => host.connection_state === "online");
}

/** An online host with a working adapter of the given name, or undefined. */
export function onlineHostWith(hosts: Host[], capability: string): Host | undefined {
  return hostWith(onlineHosts(hosts), capability);
}

/**
 * Opens a module of the host workspace and waits for it to settle: the
 * module header when the host backs it, or the notice saying why it does
 * not. The notice is returned so the test can skip with the reason.
 */
export async function openModule(page: Page, host: Host, segment: string, name: string): Promise<string | null> {
  await page.goto(`/hosts/${host.id}/${segment}`);
  const header = page.locator(".hm-header").getByRole("heading", { name, exact: true });
  const notice = page.getByText(`${name} is not available on this host:`);
  await expect(header.or(notice).first()).toBeVisible();
  return (await notice.isVisible()) ? await notice.textContent() : null;
}

/** The state of a job, as the API records it. */
export async function jobState(request: APIRequestContext, id: string): Promise<string> {
  const response = await request.get(`/api/v1/jobs/${id}`);
  expect(response.ok(), `GET /api/v1/jobs/${id} answered ${response.status()}`).toBeTruthy();
  const job = (await response.json()) as { state: string };
  return job.state;
}

/** The tags of a host, straight from the API. */
export async function hostTags(request: APIRequestContext, id: string): Promise<string[]> {
  const response = await request.get(`/api/v1/hosts/${id}`);
  expect(response.ok(), `GET /api/v1/hosts/${id} answered ${response.status()}`).toBeTruthy();
  const host = (await response.json()) as { tags?: string[] };
  return host.tags ?? [];
}

/** Replaces the tags of a host; the whole list, as the API takes it. */
export async function setHostTags(request: APIRequestContext, id: string, tags: string[]) {
  const response = await request.put(`/api/v1/hosts/${id}/tags`, { data: { tags } });
  expect(response.ok(), `PUT /api/v1/hosts/${id}/tags answered ${response.status()}`).toBeTruthy();
}
