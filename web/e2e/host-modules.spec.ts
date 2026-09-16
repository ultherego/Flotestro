import { expect, test, type Page } from "@playwright/test";
import {
  expectHealthy, fleetHosts, jobState, onlineHostWith, openModule, permissions, watchErrors, type Host,
} from "./fleet";

/**
 * The host modules that read from the host on request: services,
 * schedules, processes and logs, with a look at the security and SSH
 * pages. Every read here is a diagnostic - a unit detail, a preview of a
 * cron expression, a process snapshot, a page of the journal - and the
 * one job that outlives its screen, the journal follow, is canceled
 * before the test ends. Nothing is changed on any host.
 *
 * A read needs a host that answers: a test picks an online host with the
 * adapter it needs and skips, with the reason, when the lab has none.
 */

let hosts: Host[] = [];
let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
  granted = await permissions(request);
});

/**
 * The cron unit of a family: Debian and Ubuntu ship cron.service, the Red
 * Hat family crond.service. Another family gets the journal daemon, which
 * every systemd host has, so the detail read still has a unit to answer
 * with.
 */
function cronUnit(host: Host): string {
  if (host.os_family === "debian") return "cron.service";
  if (host.os_family === "rhel") return "crond.service";
  return "systemd-journald.service";
}

/** A whole-text match: "Read" must not find "Reading". */
function exact(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

/** A titled section of a module page. */
function section(page: Page, title: string) {
  return page.locator(".hm-section").filter({ has: page.locator(".hm-section-head h3", { hasText: exact(title) }) });
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

test.describe("services", () => {
  test("the detail of the cron unit opens from the address with its facts and its journal", async ({ page }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, "no online host reports systemd");
    const target = host as Host;
    const unit = cronUnit(target);
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "services", "Services");
    test.skip(missing !== null, missing ?? "");
    await expect(page.locator(".hm-header .hm-lede")).toContainText("systemd units");
    await expect(section(page, "Unit states").getByTestId("status-bar")).toBeVisible();
    await expect(section(page, "Failed units")).toBeVisible();

    // A unit named in the address is opened: the detail is its own read,
    // whether or not the full list has been read yet.
    const ordered = nextJob(page, target.id);
    await page.goto(`/hosts/${target.id}/services?unit=${encodeURIComponent(unit)}`);
    await ordered;
    const detail = page.getByTestId("unit-detail");
    const refused = page.locator(".hm-message.error");
    await expect(detail.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.isVisible()) test.skip(true, `${target.hostname} answered the detail read of ${unit} with: ${await refused.textContent()}`);

    const fact = (label: string) => detail.locator(".hm-fact").filter({ has: page.locator("dt", { hasText: exact(label) }) }).locator("dd");
    await expect(fact("Unit file")).toContainText(unit);
    await expect(fact("State").locator(".badge").first()).toHaveText(/^(active|inactive|failed|activating|deactivating)$/);
    await expect(fact("On boot")).not.toBeEmpty();
    for (const heading of ["Drop-ins", "Last journal lines"]) {
      await expect(detail.locator(".widget-subhead", { hasText: heading })).toBeVisible();
    }
    // The journal continues on the Logs page from where the detail ended.
    await expect(detail.getByRole("link", { name: "Follow in Logs" })).toHaveAttribute("href", new RegExp(`/logs\\?unit=${encodeURIComponent(unit).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    await expect(detail.getByRole("button", { name: "Read again" })).toBeEnabled();
    await expectHealthy(page, errors);
  });

  test("the full list is read from the host, filtered by name, and offers reset-failed on a failed unit", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, "no online host reports systemd");
    const target = host as Host;
    const unit = cronUnit(target);
    test.slow();

    const missing = await openModule(page, target, "services", "Services");
    test.skip(missing !== null, missing ?? "");
    const all = section(page, "All units");
    const filter = all.getByPlaceholder("Filter by name");
    const unread = all.getByText("This host has not been read yet.");
    await expect(filter.or(unread).first()).toBeVisible();

    if (await unread.isVisible()) {
      // The list is read on request; the page picks the new module up on
      // its next refresh, which is due within half a minute.
      const ordered = nextJob(page, target.id);
      await page.locator(".hm-header").getByRole("button", { name: "Read from host" }).click();
      const job = await ordered;
      await expect(page.locator(".hm-message")).toContainText(/Job \w+ has been queued|is waiting for approval/);
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(!["succeeded", "failed"].includes(state), `${target.hostname} did not answer the unit listing: ${state}`);
      await expect(filter).toBeVisible({ timeout: 60_000 });
    }

    // Every listed unit has a state badge and an action; the filter keeps
    // the units whose name carries the text.
    const rows = all.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    await expect(all.locator(".hm-foot")).toContainText(/\d+ of \d+ units shown/);
    await filter.fill(unit.replace(/\.service$/, ""));
    await expect(rows.first()).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row.locator("td").first()).toContainText(unit.replace(/\.service$/, ""));
      await expect(row.locator("td").nth(1).locator(".badge")).not.toBeEmpty();
    }
    const cron = rows.filter({ hasText: unit }).first();
    await expect(cron).toBeVisible();
    // An active unit is restarted or stopped, another one started; the
    // reset of the failed record is offered only where there is one.
    const state = (await cron.locator("td").nth(1).textContent())?.trim();
    await expect(cron.getByRole("button", { name: state === "active" ? "Restart" : "Start", exact: true })).toBeVisible();
    await expect(cron.getByRole("button", { name: "Reset failed" })).toHaveCount(state === "failed" ? 1 : 0);

    await filter.fill("");
    const failed = rows.filter({ has: page.locator("td:nth-child(2) .badge.error") });
    if (await failed.count()) {
      await expect(failed.first().getByRole("button", { name: "Reset failed" })).toBeVisible();
    } else {
      test.info().annotations.push({ type: "note", description: `${target.hostname} has no failed unit; the reset-failed button has nothing to stand on` });
    }
    // The failed list beside it shows the same button per failed unit.
    const failedSection = section(page, "Failed units");
    for (const row of await failedSection.locator("tbody tr").all()) {
      await expect(row.getByRole("button", { name: "Reset failed" })).toBeVisible();
    }
  });
});

test.describe("schedules", () => {
  test("the host previews the next runs of a cron expression in its own zone", async ({ page }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    const host = onlineHostWith(hosts, "schedules");
    test.skip(!host, "no online host reports the schedules adapter");
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "schedules", "Schedules");
    test.skip(missing !== null, missing ?? "");
    await expect(section(page, "By kind")).toBeVisible();
    const list = section(page, "Schedules").last();
    await expect(list.locator("tbody tr").first().or(list.locator(".empty"))).toBeVisible();

    // The form opens from the header; the preview is a read the host
    // answers, so the dates come in the host's zone rather than the browser's.
    await page.locator(".hm-header").getByRole("button", { name: "New schedule" }).click();
    const form = section(page, "New schedule");
    await expect(form).toBeVisible();
    const expression = form.getByPlaceholder("Cron expression");
    await expect(expression).toHaveValue("0 3 * * *");
    await expression.fill("30 4 * * 1");

    const posted: string[] = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && request.url().includes("/api/v1/hosts/")) posted.push(request.postData() ?? "");
    });
    const ordered = nextJob(page, target.id);
    await form.getByRole("button", { name: "Preview next runs" }).click();
    await ordered;
    expect(posted.some((body) => body.includes("schedule.preview")), "the preview is ordered as schedule.preview").toBe(true);
    expect(posted.some((body) => body.includes("schedule.ensure")), "nothing is created").toBe(false);

    const note = form.locator(".hm-form-note").filter({ hasText: /Next runs in|does not accept the expression/ });
    const refused = form.locator(".hm-message.error");
    await expect(note.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.isVisible()) test.skip(true, `${target.hostname} refused the preview: ${await refused.textContent()}`);
    await expect(note).toContainText("Next runs in");
    // Three Mondays at half past four, written as the host's wall clock.
    const runs = (await note.locator(".hm-mono").textContent()) ?? "";
    const dates = runs.split(",").map((run) => run.trim()).filter(Boolean);
    expect(dates.length).toBeGreaterThanOrEqual(1);
    for (const run of dates) {
      expect(run).toMatch(/^\d{4}-\d{2}-\d{2} 04:30$/);
      // Parsed and read as a local date: the day of the string, not of any zone.
      expect(new Date(run.replace(" ", "T")).getDay(), `${run} is not a Monday`).toBe(1);
    }
    // The create button stays off: no name and no command were given.
    await expect(form.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
    await expectHealthy(page, errors);
  });
});

test.describe("processes", () => {
  test("the snapshot is read from the host and nests as a tree", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    const host = hosts.find((entry) => entry.connection_state === "online");
    test.skip(!host, "no host is online");
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "processes", "Processes");
    test.skip(missing !== null, missing ?? "");
    await expect(section(page, "Process states").getByTestId("status-bar")).toBeVisible();
    const list = section(page, "Processes").last();
    const filter = list.getByPlaceholder("Filter by command, user, unit or PID");
    const unread = list.getByText("This host has not been read yet.");
    await expect(filter.or(unread).first()).toBeVisible();

    if (await unread.isVisible()) {
      const ordered = nextJob(page, target.id);
      await page.locator(".hm-header").getByRole("button", { name: "Read from host" }).click();
      const job = await ordered;
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(state !== "succeeded", `${target.hostname} did not answer the process read: ${state}`);
      await expect(filter).toBeVisible({ timeout: 60_000 });
    }

    const rows = list.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    const flat = await rows.count();
    expect(flat).toBeGreaterThan(1);
    // The bar has settled on numbers once the snapshot is in.
    for (const value of await section(page, "Process states").getByTestId("status-bar-value").all()) {
      await expect(value).toHaveText(/^\d+$/);
    }
    await expect(section(page, "By user").locator(".breakdown-fill").first()).toBeVisible();

    // The tree nests every child under its parent: a child is indented,
    // a parent carries a fold, and nothing is lost in the nesting.
    await list.getByRole("checkbox", { name: "Tree" }).check();
    await expect(rows).toHaveCount(flat);
    const indents = list.getByTestId("process-indent");
    // A cut-off slice may hold children whose parents were left out, and
    // those stand as roots; a whole host always nests something under
    // its init process.
    const truncated = (await list.locator(".warning").count()) > 0;
    if (!truncated) expect(await indents.count(), "a whole host has at least one parent with a child").toBeGreaterThan(0);
    for (const indent of await indents.all()) {
      expect(Number(await indent.getAttribute("data-depth"))).toBeGreaterThan(0);
    }
    // The fold is a glyph; what it does stands in its title.
    const folds = list.locator("button[title='Hide children']");
    if ((await indents.count()) > 0) expect(await folds.count(), "a child implies a parent with a fold").toBeGreaterThan(0);
    test.skip((await folds.count()) === 0, `${target.hostname} sent a slice with no parent and child together; nothing to fold`);
    // Folding a parent hides its children and the title counts them.
    await folds.first().click();
    await expect(rows).not.toHaveCount(flat);
    const folded = list.locator("button[title^='Show ']").first();
    await expect(folded).toHaveAttribute("title", /^Show \d+ children$/);
    await expect(folded).toHaveAttribute("aria-expanded", "false");
    await folded.click();
    await expect(rows).toHaveCount(flat);

    // The filter keeps the matching processes with the path down to them.
    await filter.fill("1");
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeLessThanOrEqual(flat);
    await expectHealthy(page, errors);
  });
});

test.describe("logs", () => {
  test("a journal read returns lines, and stopping a follow cancels its job", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    test.skip(!granted.has("job.cancel"), "the token may not cancel a job (job.cancel)");
    const host = onlineHostWith(hosts, "journald");
    test.skip(!host, "no online host reports journald");
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "logs", "Logs");
    test.skip(missing !== null, missing ?? "");
    const reading = section(page, "Reading");
    await expect(reading.locator(".badge", { hasText: "nothing read yet" })).toBeVisible();
    // Nothing read means nothing counted: dashes, not zeros.
    for (const value of await section(page, "Lines on screen").getByTestId("status-bar-value").all()) {
      await expect(value).toHaveText("—");
    }

    // A page of the journal, bounded by the line count. The fields carry
    // their label and a hint under it in one label element, so a field
    // is found by the label it starts with.
    const form = section(page, "Read");
    await form.locator("label.hm-field", { hasText: /^Unit/ }).locator("input").fill("");
    await form.locator("label.hm-field", { hasText: /^Lines/ }).locator("input[type=number]").fill("50");
    const ordered = nextJob(page, target.id);
    await form.getByRole("button", { name: "Read", exact: true }).click();
    const readJob = await ordered;
    const output = section(page, "Output");
    const refused = page.locator(".hm-message.error");
    await expect(output.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.isVisible()) test.skip(true, `${target.hostname} refused the journal read: ${await refused.textContent()}`);
    expect(await jobState(request, readJob)).toBe("succeeded");
    // The count beside the title is the number of lines the host gave;
    // the text under it is those lines, one per line.
    const lines = ((await output.locator("pre.hm-log").textContent()) ?? "").split("\n");
    expect(lines.length).toBeGreaterThan(0);
    await expect(output.locator(".hm-count")).toHaveText(String(lines.length));
    await expect(reading.locator(".badge", { hasText: exact("read") })).toBeVisible();
    for (const value of await section(page, "Lines on screen").getByTestId("status-bar-value").all()) {
      await expect(value).toHaveText(/^\d+$|^—$/);
    }

    // The follow holds a process on the host; Stop cancels the job, so
    // the host does not keep the journal open for the rest of the timeout.
    const followed = nextJob(page, target.id);
    await form.getByRole("button", { name: "Follow" }).click();
    const followJob = await followed;
    await expect(section(page, "Live")).toBeVisible();
    await expect(reading.locator(".badge", { hasText: exact("live") })).toBeVisible();
    await expect(form.getByRole("button", { name: "Pause" })).toBeVisible();

    const canceled = page.waitForResponse((response) => response.url().endsWith(`/api/v1/jobs/${followJob}/cancel`));
    await form.getByRole("button", { name: "Stop" }).click();
    expect((await canceled).ok(), "the cancel of the follow job went through").toBeTruthy();
    await expect(section(page, "Live")).toHaveCount(0);
    await expect(form.getByRole("button", { name: "Follow" })).toBeVisible();
    await expect.poll(() => jobState(request, followJob), { timeout: 30_000 }).toBe("canceled");
    await expectHealthy(page, errors);
  });
});

test.describe("security and ssh", () => {
  test("the security page judges the host with dashes until the report is in", async ({ page, request }) => {
    const host = onlineHostWith(hosts, "security") ?? hosts.find((entry) => entry.capabilities?.some((item) => item.name === "security" && item.available));
    test.skip(!host, "no host reports the security adapter");
    const target = host as Host;
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "security", "Security");
    test.skip(missing !== null, missing ?? "");
    await expect(page.locator(".hm-header").getByRole("button", { name: "Scan now" })).toBeVisible();
    await expect(page.getByTestId("module-freshness")).toBeVisible();
    const checks = section(page, "Checks").getByTestId("status-bar");
    await expect(checks.getByTestId("status-bar-value")).toHaveCount(4);

    // The counts of the bar are the counts of the report.
    const report = await request.get(`/api/v1/hosts/${target.id}/security`);
    expect(report.ok(), `GET /api/v1/hosts/${target.id}/security answered ${report.status()}`).toBeTruthy();
    const counts = ((await report.json()) as { counts?: { failed?: number; passed?: number; unknown?: number; not_applicable?: number } }).counts;
    if (counts) {
      const values = checks.getByTestId("status-bar-value");
      await expect(values.nth(0)).toHaveText(String(counts.failed ?? 0));
      await expect(values.nth(1)).toHaveText(String(counts.passed ?? 0));
    }
    for (const title of ["Need action", "Protective state", "Listening sockets", "Findings"]) {
      await expect(section(page, title).first()).toBeVisible();
    }
    await expectHealthy(page, errors);
  });

  test("the ssh page shows the effective configuration and opens the editor without sending anything", async ({ page }) => {
    const host = onlineHostWith(hosts, "sshd") ?? hosts.find((entry) => entry.capabilities?.some((item) => item.name === "sshd" && item.available));
    test.skip(!host, "no host reports the sshd adapter");
    const target = host as Host;
    const { errors } = watchErrors(page);
    const posted: string[] = [];
    page.on("request", (request) => {
      if (request.method() !== "GET" && request.url().includes("/api/v1/")) posted.push(`${request.method()} ${request.url()}`);
    });

    const missing = await openModule(page, target, "ssh", "SSH");
    test.skip(missing !== null, missing ?? "");
    const unreported = page.getByText("This host has not reported its sshd yet.");
    test.skip(await unreported.isVisible(), `${target.hostname} has not reported its sshd yet`);
    await expect(section(page, "Ways in").getByTestId("status-bar-value")).toHaveCount(5);
    for (const title of ["Posture", "Authentication methods", "Host keys", "Managed drop-in"]) {
      await expect(section(page, title).first()).toBeVisible();
    }

    await page.locator(".hm-header").getByRole("button", { name: "Change configuration" }).click();
    const editor = section(page, "Change configuration");
    await expect(editor).toBeVisible();
    await expect(editor.locator("select").first()).toHaveValue("");
    await page.locator(".hm-header").getByRole("button", { name: "Cancel" }).click();
    await expect(editor).toHaveCount(0);
    expect(posted, "opening the editor must not write anything").toEqual([]);
    await expectHealthy(page, errors);
  });
});
