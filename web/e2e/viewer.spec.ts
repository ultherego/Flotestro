import { expect, test, type APIRequestContext, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { expectHealthy, fleetHosts, jobState, onlineHostWith, openModule, permissions, watchErrors, type Host } from "./fleet";

/**
 * What a viewer sees.
 */

const SEGMENTS = [
  "overview", "system", "packages", "services", "processes", "schedules", "kernel", "time", "power", "policies",
  "network", "dns", "firewall", "ssh", "storage", "files", "backups", "containers", "compose", "security",
  "certificates", "identity", "logs", "monitoring", "jobs", "audit",
];

let hosts: Host[] = [];
let granted = new Set<string>();
let viewerToken = "";
let viewer: BrowserContext | null = null;

/** A token for a fresh viewer of the host's site and environment. */
async function createViewer(request: APIRequestContext, host: Host): Promise<string> {
  const response = await request.post("/api/v1/principals", {
    data: {
      subject: `viewer-e2e-${Date.now()}`,
      roles: [{ role: "viewer", site: host.site, environment: host.environment }],
      issue_token: true,
      reason: "viewer prepared for a browser test of the action guard",
    },
  });
  expect(response.ok(), `POST /api/v1/principals answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { token?: string };
  expect(body.token, "the principal was created without a token").toBeTruthy();
  return body.token as string;
}

/** A browser context signed in as the viewer, next to the suite's session. */
async function viewerContext(browser: Browser, baseURL: string | undefined): Promise<BrowserContext> {
  if (viewer) return viewer;
  viewer = await browser.newContext({
    baseURL,
    extraHTTPHeaders: { Authorization: `Bearer ${viewerToken}` },
    viewport: { width: 1600, height: 1000 },
    locale: "en-US",
  });
  return viewer;
}

/** The section of the unit list on the Services page. */
function unitList(page: Page) {
  return page.locator(".hm-section").filter({ has: page.locator(".hm-section-head h3", { hasText: /^All units$/ }) });
}

/** The job identifier of the next operation the page orders. */
function nextJob(page: Page, hostID: string): Promise<string> {
  return page
    .waitForResponse((response) => response.url().endsWith(`/api/v1/hosts/${hostID}/operations`) && response.request().method() === "POST")
    .then(async (response) => {
      expect(response.ok(), `POST /operations answered ${response.status()}`).toBeTruthy();
      return ((await response.json()) as { id: string }).id;
    });
}

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
  granted = await permissions(request);
  if (granted.has("principal.manage")) {
    viewerToken = await createViewer(request, onlineHostWith(hosts, "systemd") ?? hosts[0]);
  }
});

test.afterAll(async () => {
  await viewer?.close();
  viewer = null;
});

test.describe("a viewer sees no mutating control", () => {
  test("the Services page shows Restart to the administrator and not to the viewer", async ({ page, request, browser, baseURL }) => {
    test.skip(!granted.has("principal.manage"), "the token may not create a viewer (principal.manage)");
    test.skip(!granted.has("unit.restart") || !granted.has("job.create"), "the token may not restart a unit itself (unit.restart, job.create)");
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, "no online host reports systemd");
    const target = host as Host;
    test.slow();

    // The administrator's session: the unit list is read once, and its
    // rows carry the restart button.
    const missing = await openModule(page, target, "services", "Services");
    test.skip(missing !== null, missing ?? "");
    const list = unitList(page);
    const filter = list.getByPlaceholder("Filter by name");
    const unread = list.getByText("This host has not been read yet.");
    await expect(filter.or(unread).first()).toBeVisible();
    if (await unread.isVisible()) {
      const ordered = nextJob(page, target.id);
      await page.locator(".hm-header").getByRole("button", { name: "Read from host" }).click();
      const job = await ordered;
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(state !== "succeeded", `${target.hostname} did not answer the unit listing: ${state}`);
      await expect(filter).toBeVisible({ timeout: 60_000 });
    }
    await expect(list.locator("tbody tr").first()).toBeVisible();
    await expect(list.getByRole("button", { name: "Restart" }).first()).toBeVisible();
    await expect(page.getByTestId("module-read-only")).toHaveCount(0);

    // The viewer's session on the same page: the same rows, no button
    // that would order anything, and the line that says why.
    const context = await viewerContext(browser, baseURL);
    const other = await context.newPage();
    const { errors } = watchErrors(other);
    await other.goto(`/hosts/${target.id}/services`);
    await expect(other.locator(".hm-header").getByRole("heading", { name: "Services", exact: true })).toBeVisible();
    const viewerList = unitList(other);
    await expect(viewerList.locator("tbody tr").first()).toBeVisible();
    const notice = other.getByTestId("module-read-only");
    await expect(notice).toBeVisible();
    await expect(notice).toContainText("changing it needs the permission");
    await expect(notice).toContainText("unit.restart");
    await expect(other.getByRole("button", { name: "Restart" })).toHaveCount(0);
    await expect(other.getByRole("button", { name: "Stop" })).toHaveCount(0);
    await expect(other.getByRole("button", { name: "Mask" })).toHaveCount(0);
    // The one read of the page stays on the screen for the viewer, held
    // back and explained: a page whose only button is gone reads as broken.
    const read = other.locator(".hm-header").getByRole("button", { name: "Read from host" });
    await expect(read).toBeVisible();
    await expect(read).toBeDisabled();
    await expect(other.locator(".hm-header .action-guard-denied")).toHaveAttribute("title", /permission/);
    await expectHealthy(other, errors);
    await other.close();
  });

  test("the preview refuses the viewer every change, and the order is refused all the same", async ({ playwright, baseURL }) => {
    test.skip(!granted.has("principal.manage"), "the token may not create a viewer (principal.manage)");
    const host = onlineHostWith(hosts, "systemd") ?? hosts[0];
    const api = await playwright.request.newContext({ baseURL, extraHTTPHeaders: { Authorization: `Bearer ${viewerToken}` } });
    try {
      const response = await api.get(`/api/v1/hosts/${host.id}/actions`);
      expect(response.ok(), `GET /actions answered ${response.status()}`).toBeTruthy();
      const body = (await response.json()) as { items: { action: string; mutating: boolean; allowed: boolean; reason_code?: string }[] };
      expect(body.items.length).toBeGreaterThan(0);
      for (const item of body.items) {
        if (item.mutating) expect(item.allowed, `${item.action} is allowed to a viewer`).toBe(false);
      }
      const restart = body.items.find((item) => item.action === "unit.restart");
      expect(restart?.reason_code).toBe("permission_denied");
      // The guard is a courtesy; the gate is the order's own.
      const order = await api.post(`/api/v1/hosts/${host.id}/operations`, {
        data: { action: "unit.restart", payload: { unit: { unit: "cron.service" } } },
      });
      expect(order.status()).toBe(403);
    } finally {
      await api.dispose();
    }
  });

  test("every module page renders for the viewer", async ({ browser, baseURL }) => {
    test.skip(!granted.has("principal.manage"), "the token may not create a viewer (principal.manage)");
    const host = onlineHostWith(hosts, "systemd") ?? hosts[0];
    test.slow();
    const context = await viewerContext(browser, baseURL);
    const other = await context.newPage();
    const { errors } = watchErrors(other);
    for (const segment of SEGMENTS) {
      await other.goto(`/hosts/${host.id}/${segment}`);
      // A module header, the notice of a module the host does not back, or
      // the refusal of a record the viewer may not read: any of them is a
      // page that settled rather than crashed.
      const settled = other.locator(".hm-header .hm-title").or(other.locator(".empty")).or(other.getByText(/is not available on/));
      await expect(settled.first(), `${segment} did not settle`).toBeVisible();
      await expectHealthy(other, errors);
    }
    await other.close();
  });
});
