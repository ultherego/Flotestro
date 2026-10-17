import { expect, type APIRequestContext, type Locator, type Page } from "@playwright/test";

/** The fields of a host the tests read; the API returns more. */
export type Host = {
  id: string;
  hostname: string;
  site: string;
  environment: string;
  os_family?: string;
  connection_state: "online" | "offline" | "stale" | "unknown";
  pending_updates: number | null;
  pending_security_updates: number | null;
  capabilities?: { name: string; available: boolean }[];
};

/**
 * The hosts the token may see, straight from the API.
 */
export async function fleetHosts(request: APIRequestContext): Promise<Host[]> {
  const response = await request.get("/api/v1/hosts?limit=200");
  expect(response.ok(), `GET /api/v1/hosts answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { items: Host[] };
  return body.items;
}

/**
 * The reason a skipped test gives, in the form the gate reads. A skip that
 * does not say which kind of skip it is fails the whole run - the same
 * contract the Go suite keeps with absent(), notApplicable() and waived().
 *
 * The reason is carried in double quotes, so a double quote inside it would
 * end the field early; they become single quotes rather than being escaped,
 * because the gate's parser reads the plain form and nothing else.
 */
function skipReason(fields: string, reason: string): string {
  return `FLOTESTRO-SKIP ${fields} reason="${reason.replace(/"/g, "'")}"`;
}

/** The scenario did not run and nothing stands in for it: a failed run. */
export function absent(reason: string): string {
  return skipReason("class=absent", reason);
}

/** It does not apply here, and this names the host where it does run. */
export function notApplicable(runsOn: string, reason: string): string {
  return skipReason(`class=not_applicable runs_on=${runsOn}`, reason);
}

/** Let through until a date, by a named waiver, with evidence in its place. */
export function waived(waiver: string, until: string, evidence: string, reason: string): string {
  return skipReason(`class=waived waiver=${waiver} until=${until} evidence=${evidence}`, reason);
}

/** A host with a working adapter of the given name, or undefined. */
export function hostWith(hosts: Host[], capability: string): Host | undefined {
  return hosts.find((host) => host.capabilities?.some((item) => item.name === capability && item.available));
}

/**
 * Collects the uncaught exceptions of the page.
 */
export function watchErrors(page: Page): { errors: string[] } {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  return { errors };
}

/**
 * The page shows no error box and threw nothing.
 *
 * The box is the kit's own `Problem`, which is what every screen of the
 * panel puts a failed read into; there is no second shape of error box to
 * look for, and a screen that invented one would be caught by the kit's
 * own test rather than here.
 */
export async function expectHealthy(page: Page, errors: string[]) {
  await expect(page.locator(".fl-problem")).toHaveCount(0);
  await expect(page.getByText(/^Error:/)).toHaveCount(0);
  expect(errors, "uncaught exceptions on the page").toEqual([]);
}

/** The rail of the shell, as the screen reader names it. */
export function navigation(page: Page) {
  return page.getByRole("navigation", { name: "Main navigation" });
}

/** The trail across the top bar, as the screen reader names it. */
export function trail(page: Page) {
  return page.getByRole("navigation", { name: "Breadcrumb" });
}

/** A whole-text match: "Hosts" must not find "Hosts by state". */
export function exact(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

/**
 * The heading of a screen.
 *
 * Every screen of the panel is drawn in one frame, so there is one place
 * its name can be: the shell's own head above the containers. A screen
 * that can explain itself carries the mark that opens the explanation
 * inside the heading, so the name is matched with or without it.
 */
export function head(page: Page, title: string) {
  const escaped = title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return page.locator(".fl-head-title").filter({ hasText: new RegExp(`^${escaped}\\s*\\??$`) });
}

/** A container of a screen by the name in its head. */
export function card(page: Page, title: string) {
  return page.locator(".fl-card").filter({ has: page.locator(".fl-card-title", { hasText: exact(title) }) });
}

/**
 * A form of a screen by its title.
 *
 * A form is not a container: it stands on a face of its own, with its name
 * in `.fl-form-title` and its buttons in `.fl-form-foot`.
 */
export function formOf(page: Page, title: string) {
  return page.locator("form.fl-form").filter({ has: page.locator(".fl-form-title", { hasText: exact(title) }) });
}

/** Opens the user menu at the foot of the rail and returns it. */
export async function openUserMenu(page: Page) {
  await page.getByTestId("user").click();
  const menu = page.getByTestId("user-menu");
  await expect(menu).toBeVisible();
  return menu;
}

/** Opens the host list and waits for its rows. */
export async function openHostList(page: Page) {
  await page.goto("/hosts");
  await expect(head(page, "Hosts")).toBeVisible();
  const table = page.getByTestId("hosts");
  await expect(table).toBeVisible();
  return table;
}

/**
 * Opens a module of the host workspace and waits for it to settle.
 *
 * The panel being replaced turned a module the host does not back into a
 * page of its own saying so; this one draws the module either way and
 * says why on the rail instead, dimmed and with the reason in its title.
 * So the reason is read off the rail, and the caller skips on it exactly
 * as it used to - what changed is where the sentence lives, not whether
 * the panel says it.
 */
export async function openModule(
  page: Page, host: Host, segment: string, name: string, tab?: string,
): Promise<string | null> {
  /* A module's content is behind sub-tabs kept in the address, so a reader
     following a link lands on one; the first tab is what a bare address
     opens, and `tab` names any other. */
  await page.goto(`/hosts/${host.id}/${segment}${tab ? `?tab=${tab}` : ""}`);
  // The machine's own head carries its name whichever module is open; it
  // is the one thing on the page that means "this host has loaded".
  await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname, { timeout: 30_000 });
  const off = navigation(page).locator("span.fl-navitem.fl-off").filter({
    has: page.locator(".fl-navitem-label", { hasText: exact(name) }),
  });
  if (await off.count() === 0) return null;
  const reason = await off.first().getAttribute("title");
  return `${name} is not available on this host: ${reason ?? "no reason given"}`;
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

/**
 * The permissions of the token, as the panel reads them to show or hide a
 * section.
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
 * Every value of a band has settled on a number.
 *
 * The band draws what is counted as segments and what is at zero or
 * uncounted as words under it, so the count of segments is not the count
 * of things measured; what is checked is that every segment carries a
 * number and that the band is there at all.
 */
export async function expectBanded(band: Locator) {
  await expect(band).toBeVisible();
  const values = band.locator(".fl-band-value");
  const quiet = band.locator(".fl-quiet-item");
  expect((await values.count()) + (await quiet.count()), "the band drew no segment at all").toBeGreaterThan(0);
  for (const value of await values.all()) {
    await expect(value).toHaveText(/^\d+$/);
  }
}

/**
 * Opens a sub-tab of the screen by its name, as a reader clicking it would,
 * and waits for it to be the selected one.
 */
export async function openTab(page: Page, name: string | RegExp) {
  const tab = page.getByRole("tab", { name, exact: typeof name === "string" });
  await tab.click();
  await expect(tab).toHaveAttribute("aria-selected", "true");
}
