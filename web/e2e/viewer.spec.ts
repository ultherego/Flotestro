import { expect, test, type APIRequestContext, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { absent, expectHealthy, fleetHosts, jobState, onlineHostWith, openModule, permissions, watchErrors, type Host } from "./fleet";

/**
 * What a viewer sees.
 */

const SEGMENTS = [
  "overview", "system", "packages", "services", "processes", "schedules", "kernel", "time", "power", "policies",
  "network", "dns", "firewall", "ssh", "storage", "files", "backups", "containers", "compose", "security",
  "certificates", "accounts", "identity", "logs", "monitoring", "jobs", "audit",
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
      // The team is said in words: the panel refuses a grant that leaves it out,
      // because a team omitted by accident would widen the binding in silence.
      roles: [{
        role: "viewer", site: host.site, environment: host.environment,
        team_scope: { mode: "any" },
      }],
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

/** The unit listing of the Services module. */
function units(page: Page) {
  return page.getByTestId("units");
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
    test.skip(!granted.has("principal.manage"), absent("the token may not create a viewer (principal.manage)"));
    test.skip(!granted.has("unit.restart") || !granted.has("job.create"), absent("the token may not restart a unit itself (unit.restart, job.create)"));
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, absent("no online host reports systemd"));
    const target = host as Host;
    test.slow();

    // The administrator's session: the unit list is read once, and its
    // rows carry the restart button.
    const missing = await openModule(page, target, "services", "Services");
    test.skip(missing !== null, absent(missing ?? ""));
    const unread = page.getByText("This host has not been read yet.");
    await expect(units(page).or(unread).first()).toBeVisible();
    if (await unread.isVisible()) {
      const ordered = nextJob(page, target.id);
      await page.getByTestId("read-units").click();
      const job = await ordered;
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(state !== "succeeded", absent(`${target.hostname} did not answer the unit listing: ${state}`));
      await expect(units(page)).toBeVisible({ timeout: 60_000 });
    }
    await expect(units(page).locator("tbody tr").first()).toBeVisible();
    await expect(units(page).getByRole("button", { name: "Restart" }).first()).toBeVisible();
    await expect(page.getByText("You can read this module; changing it")).toHaveCount(0);

    // The viewer's session on the same page: the same rows, no button
    // that would order anything, and the line that says why.
    const context = await viewerContext(browser, baseURL);
    const other = await context.newPage();
    const { errors } = watchErrors(other);
    await other.goto(`/hosts/${target.id}/services`);
    await expect(other.locator(".fl-head-title").first()).toContainText(target.hostname);
    await expect(units(other).locator("tbody tr").first()).toBeVisible();

    /* The panel being replaced held a refused control on the screen,
       greyed, with the reason on hover. This one takes it away and says
       once, above the module, what may and may not be done here - which
       is the same claim in one place instead of on every button. */
    const notice = other.locator(".fl-banner").filter({ hasText: "You can read this module" });
    await expect(notice).toBeVisible();
    await expect(notice).toContainText("changing it");
    await expect(notice).toContainText("unit.restart");
    await expect(other.getByRole("button", { name: "Restart" })).toHaveCount(0);
    await expect(other.getByRole("button", { name: "Stop" })).toHaveCount(0);
    await expect(other.getByRole("button", { name: "Mask" })).toHaveCount(0);
    await expectHealthy(other, errors);
    await other.close();
  });

  test("the preview refuses the viewer every change, and the order is refused all the same", async ({ playwright, baseURL }) => {
    test.skip(!granted.has("principal.manage"), absent("the token may not create a viewer (principal.manage)"));
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
    test.skip(!granted.has("principal.manage"), absent("the token may not create a viewer (principal.manage)"));
    const host = onlineHostWith(hosts, "systemd") ?? hosts[0];
    test.slow();
    const context = await viewerContext(browser, baseURL);
    const other = await context.newPage();
    const { errors } = watchErrors(other);
    for (const segment of SEGMENTS) {
      await other.goto(`/hosts/${host.id}/${segment}`);
      // A container of the module, an honest empty state, or the banner
      // that says what the viewer may not do: any of them is a page that
      // settled rather than crashed.
      const settled = other.locator(".fl-card, .fl-empty, .fl-kpi, .fl-banner");
      await expect(settled.first(), `${segment} did not settle`).toBeVisible();
      await expectHealthy(other, errors);
    }
    await other.close();
  });
});
