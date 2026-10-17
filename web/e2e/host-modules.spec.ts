import { expect, test, type Page } from "@playwright/test";
import {
  absent, card, expectHealthy, fleetHosts, jobState, onlineHostWith, openModule, openTab, permissions, watchErrors, type Host,
} from "./fleet";

/**
 * The host modules that read from the host on request: services, schedules,
 * processes and logs, with a look at the security and SSH pages.
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
 * Hat family crond.
 */
function cronUnit(host: Host): string {
  if (host.os_family === "debian") return "cron.service";
  if (host.os_family === "rhel") return "crond.service";
  return "systemd-journald.service";
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
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, absent("no online host reports systemd"));
    const target = host as Host;
    const unit = cronUnit(target);
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "services", "Services");
    test.skip(missing !== null, absent(missing ?? ""));
    // The first tab is the state of the units; the list is the second.
    await expect(page.getByTestId("unit-states")).toBeVisible();
    await expect(card(page, "Failed units")).toBeVisible();

    // A unit named in the address is opened: the detail is its own read,
    // whether or not the full list has been read yet.
    const ordered = nextJob(page, target.id);
    await page.goto(`/hosts/${target.id}/services?tab=units&unit=${encodeURIComponent(unit)}`);
    await ordered;
    const detail = page.getByTestId("unit-detail");
    const refused = page.locator(".fl-problem");
    await expect(detail.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.count() > 0) test.skip(true, absent(`${target.hostname} answered the detail read of ${unit} with: ${await refused.first().textContent()}`));

    /* The detail opens under the unit's own row now rather than in a card
       of its own somewhere on the screen; what it says is the same. */
    const fact = (label: string) =>
      detail.locator(".fl-fact").filter({ has: page.locator("dt", { hasText: new RegExp(`^${label}$`) }) }).locator("dd");
    await expect(fact("Unit file")).toContainText(unit.replace(/\.service$/, ""));
    await expect(fact("State").locator(".fl-pill").first()).toHaveText(/^(active|inactive|failed|activating|deactivating)$/);
    await expect(fact("On boot")).not.toBeEmpty();
    // The drop-ins and the last journal lines: both are said, whether or
    // not the host has any of either.
    await expect(
      detail.getByText("No override files.").or(detail.locator(".fl-readout-label").first()).first(),
    ).toBeVisible();
    await expect(
      detail.getByTestId("unit-journal").or(detail.getByText("The journal has nothing for this unit.")).first(),
    ).toBeVisible();
    // The journal continues on the Logs page from where the detail ended.
    await expect(detail.getByRole("link", { name: "Follow in Logs" })).toHaveAttribute(
      "href", new RegExp(`/logs\\?unit=${encodeURIComponent(unit).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    await expect(detail.getByRole("button", { name: "Read again" })).toBeEnabled();
    await expectHealthy(page, errors);
  });

  test("the full list is read from the host, filtered by name, and offers reset-failed on a failed unit", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    const host = onlineHostWith(hosts, "systemd");
    test.skip(!host, absent("no online host reports systemd"));
    const target = host as Host;
    const unit = cronUnit(target);
    test.slow();

    const missing = await openModule(page, target, "services", "Services", "units");
    test.skip(missing !== null, absent(missing ?? ""));
    const all = card(page, "All units");
    const table = page.getByTestId("units");
    const unread = all.getByText("This host has not been read yet.");
    await expect(table.or(unread).first()).toBeVisible();

    if (await unread.count() > 0) {
      // The list is read on request; the page picks the new module up on
      // its next refresh, which is due within half a minute.
      const ordered = nextJob(page, target.id);
      await page.getByTestId("read-units").click();
      const job = await ordered;
      await expect(page.locator(".fl-banner")).toContainText(/queued|waiting for approval/);
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(!["succeeded", "failed"].includes(state), absent(`${target.hostname} did not answer the unit listing: ${state}`));
      await expect(table).toBeVisible({ timeout: 60_000 });
    }

    // Every listed unit has a state badge; the filter keeps the units
    // whose name carries the text.
    const rows = table.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    const filter = page.getByTestId("unit-filter");
    await filter.fill(unit.replace(/\.service$/, ""));
    await expect(rows.first()).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row.locator("td").first()).toContainText(unit.replace(/\.service$/, ""));
    }
    const cron = table.locator(`tr[data-testid="unit-${unit}"]`);
    await expect(cron).toHaveCount(1);
    // An active unit is restarted or stopped, another one started; the
    // reset of the failed record is offered only where there is one.
    const state = (await cron.locator(".fl-pill").first().textContent())?.trim();
    await expect(cron.getByRole("button", { name: state === "active" ? "Restart" : "Start", exact: true })).toBeVisible();
    await expect(cron.getByRole("button", { name: "Reset failed" })).toHaveCount(state === "failed" ? 1 : 0);

    await filter.fill("");
    const failed = rows.filter({ has: page.locator(".fl-pill.fl-error") });
    if (await failed.count()) {
      await expect(failed.first().getByRole("button", { name: "Reset failed" })).toBeVisible();
    } else {
      test.info().annotations.push({ type: "note", description: `${target.hostname} has no failed unit; the reset-failed button has nothing to stand on` });
    }
    // The failed list, on the state tab, shows the same button per failed unit.
    await openTab(page, "State");
    for (const row of await page.getByTestId("failed-units").locator("tbody tr").all()) {
      await expect(row.getByRole("button", { name: "Reset failed" })).toBeVisible();
    }
  });
});

test.describe("schedules", () => {
  test("the host previews the next runs of a cron expression in its own zone", async ({ page }) => {
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    const host = onlineHostWith(hosts, "schedules");
    test.skip(!host, absent("no online host reports the schedules adapter"));
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "schedules", "Schedules");
    test.skip(missing !== null, absent(missing ?? ""));
    await expect(card(page, "By kind")).toBeVisible();
    await openTab(page, "Schedules");
    const list = page.getByTestId("schedules");
    await expect(list.or(card(page, "Schedules").locator(".fl-empty")).first()).toBeVisible();

    // The form opens from the heading; the preview is a read the host
    // answers, so the dates come in the host's zone rather than the
    // browser's. It is a form of its own now, not a card on the list.
    await page.getByTestId("new-schedule").click();
    const form = page.locator("form.fl-form").filter({ has: page.locator(".fl-form-title", { hasText: /^New schedule$/ }) });
    await expect(form).toBeVisible();
    const expression = form.getByTestId("schedule-expression");
    await expect(expression).toHaveValue("0 3 * * *");
    await expression.fill("30 4 * * 1");

    const posted: string[] = [];
    page.on("request", (request) => {
      if (request.method() === "POST" && request.url().includes("/api/v1/hosts/")) posted.push(request.postData() ?? "");
    });
    const ordered = nextJob(page, target.id);
    await form.getByTestId("schedule-preview-ask").click();
    await ordered;
    expect(posted.some((body) => body.includes("schedule.preview")), "the preview is ordered as schedule.preview").toBe(true);
    expect(posted.some((body) => body.includes("schedule.ensure")), "nothing is created").toBe(false);

    const preview = form.getByTestId("schedule-preview");
    const refused = form.locator(".fl-problem");
    await expect(preview.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.count() > 0) test.skip(true, absent(`${target.hostname} refused the preview: ${await refused.first().textContent()}`));
    await expect(preview.locator(".fl-readout-label")).toContainText("Next runs in");
    // Three Mondays at half past four, written as the host's wall clock.
    const runs = (await preview.locator("pre").textContent()) ?? "";
    const dates = runs.split("\n").map((run) => run.trim()).filter(Boolean);
    expect(dates.length).toBeGreaterThanOrEqual(1);
    for (const run of dates) {
      expect(run).toMatch(/^\d{4}-\d{2}-\d{2} 04:30$/);
      // Parsed and read as a local date: the day of the string, not of any zone.
      expect(new Date(run.replace(" ", "T")).getDay(), `${run} is not a Monday`).toBe(1);
    }
    // The create button stays off: no name and no command were given.
    await expect(form.getByTestId("schedule-create")).toBeDisabled();
    await expectHealthy(page, errors);
  });
});

test.describe("processes", () => {
  test("the snapshot is read from the host and nests as a tree", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    const host = hosts.find((entry) => entry.connection_state === "online");
    test.skip(!host, absent("no host is online"));
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "processes", "Processes");
    test.skip(missing !== null, absent(missing ?? ""));
    await expect(page.getByTestId("process-states")).toBeVisible();
    await openTab(page, "List");
    const list = card(page, "Processes");
    const table = page.getByTestId("processes");
    const unread = list.getByText("This host has not been read yet.");
    await expect(table.or(unread).first()).toBeVisible();

    if (await unread.count() > 0) {
      const ordered = nextJob(page, target.id);
      await page.getByTestId("read-processes").click();
      const job = await ordered;
      await expect.poll(() => jobState(request, job), { timeout: 60_000 }).toMatch(/^(succeeded|failed|timed_out|canceled|expired)$/);
      const state = await jobState(request, job);
      test.skip(state !== "succeeded", absent(`${target.hostname} did not answer the process read: ${state}`));
      await expect(table).toBeVisible({ timeout: 60_000 });
    }

    const rows = table.locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    const flat = await rows.count();
    expect(flat).toBeGreaterThan(1);
    // The band has settled on numbers once the snapshot is in; it is on the
    // state tab, the list on the other.
    await openTab(page, "State");
    for (const value of await page.getByTestId("process-states").locator(".fl-band-value").all()) {
      await expect(value).toHaveText(/^\d+$/);
    }
    await expect(card(page, "By user").locator(".fl-bar-fill").first()).toBeVisible();
    await openTab(page, "List");

    // The tree nests every child under its parent: a child is set in, a
    // parent carries a fold, and nothing is lost in the nesting.
    await list.getByRole("checkbox", { name: "Tree" }).check();
    await expect(rows).toHaveCount(flat);
    const indents = table.locator(".fl-indent:not([data-depth='0'])");
    // A cut-off slice may hold children whose parents were left out, and
    // those stand as roots; a whole host always nests something under its
    // init process.
    const truncated = (await page.locator(".fl-banner").count()) > 0;
    if (!truncated) expect(await indents.count(), "a whole host has at least one parent with a child").toBeGreaterThan(0);
    for (const indent of await indents.all()) {
      expect(Number(await indent.getAttribute("data-depth"))).toBeGreaterThan(0);
    }
    // The fold is a glyph; what it does stands in its title.
    const folds = table.locator("button[title='Hide children']");
    if ((await indents.count()) > 0) expect(await folds.count(), "a child implies a parent with a fold").toBeGreaterThan(0);
    test.skip((await folds.count()) === 0, absent(`${target.hostname} sent a slice with no parent and child together; nothing to fold`));
    // Folding a parent hides its children and the title counts them.
    await folds.first().click();
    await expect(rows).not.toHaveCount(flat);
    const folded = table.locator("button[title^='Show ']").first();
    await expect(folded).toHaveAttribute("title", /^Show \d+ children$/);
    await folded.click();
    await expect(rows).toHaveCount(flat);

    // The filter keeps the matching processes with the path down to them.
    await page.getByTestId("process-filter").fill("1");
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeLessThanOrEqual(flat);
    await expectHealthy(page, errors);
  });
});

test.describe("logs", () => {
  test("a journal read returns lines, and stopping a follow cancels its job", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    test.skip(!granted.has("job.cancel"), absent("the token may not cancel a job (job.cancel)"));
    const host = onlineHostWith(hosts, "journald");
    test.skip(!host, absent("no online host reports journald"));
    const target = host as Host;
    test.slow();
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "logs", "Logs");
    test.skip(missing !== null, absent(missing ?? ""));
    /* The tab is the reading and the other is its result: what is being
       read, and the counts, are on Result. Nothing read yet is a pill and
       a band that draws no segment, not a row of noughts. */
    await openTab(page, "Result");
    const reading = card(page, "What is being read");
    await expect(reading.locator(".fl-pill", { hasText: "nothing read yet" })).toBeVisible();
    await expect(page.getByTestId("line-counts").locator(".fl-band-value")).toHaveCount(0);

    // A page of the journal, bounded by the line count: a form on the
    // Reading tab, which hands the reader to Result when it is ordered.
    await openTab(page, "Reading");
    const form = page.getByTestId("read-form");
    await form.getByTestId("unit").fill("");
    await form.getByTestId("line-count").fill("50");
    const ordered = nextJob(page, target.id);
    await form.getByTestId("read").click();
    const readJob = await ordered;
    const output = page.getByTestId("log-output");
    const refused = page.locator(".fl-problem");
    await expect(output.or(refused).first()).toBeVisible({ timeout: 60_000 });
    if (await refused.count() > 0) test.skip(true, absent(`${target.hostname} refused the journal read: ${await refused.first().textContent()}`));
    expect(await jobState(request, readJob)).toBe("succeeded");
    // The note beside the title is the number of lines the host gave; the
    // text under it is those lines, one per line.
    const lines = ((await output.locator("pre").textContent()) ?? "").split("\n");
    expect(lines.length).toBeGreaterThan(0);
    await expect(card(page, "Output").locator(".fl-card-note")).toHaveText(`${lines.length} lines`);
    await expect(reading.locator(".fl-pill", { hasText: /^read$/ })).toBeVisible();

    // The follow holds a process on the host; Stop cancels the job, so
    // the host does not keep the journal open for the rest of the timeout.
    // The read handed the reader to Result; the follow is ordered from the form.
    await openTab(page, "Reading");
    const followed = nextJob(page, target.id);
    await form.getByTestId("follow").click();
    const followJob = await followed;
    await expect(card(page, "Live")).toBeVisible();
    await expect(reading.locator(".fl-pill", { hasText: /^live$/ })).toBeVisible();
    // Pausing and stopping steer what is arriving, so they stand over the
    // output on the Result tab rather than in the form.
    await expect(page.getByTestId("pause")).toBeVisible();

    const canceled = page.waitForResponse((response) => response.url().endsWith(`/api/v1/jobs/${followJob}/cancel`));
    await page.getByTestId("stop").click();
    expect((await canceled).ok(), "the cancel of the follow job went through").toBeTruthy();
    await expect(card(page, "Live")).toHaveCount(0);
    await openTab(page, "Reading");
    await expect(page.getByTestId("read-form").getByTestId("follow")).toBeVisible();
    await expect.poll(() => jobState(request, followJob), { timeout: 30_000 }).toBe("canceled");
    await expectHealthy(page, errors);
  });
});

test.describe("security and ssh", () => {
  test("the security page judges the host with dashes until the report is in", async ({ page, request }) => {
    const host = onlineHostWith(hosts, "security") ?? hosts.find((entry) => entry.capabilities?.some((item) => item.name === "security" && item.available));
    test.skip(!host, absent("no host reports the security adapter"));
    const target = host as Host;
    const { errors } = watchErrors(page);

    const missing = await openModule(page, target, "security", "Security");
    test.skip(missing !== null, absent(missing ?? ""));
    await expect(page.getByTestId("scan")).toBeVisible();
    const checks = page.getByTestId("check-counts");
    await expect(checks).toBeVisible();

    // The counts of the band are the counts of the report.
    const report = await request.get(`/api/v1/hosts/${target.id}/security`);
    expect(report.ok(), `GET /api/v1/hosts/${target.id}/security answered ${report.status()}`).toBeTruthy();
    const counts = ((await report.json()) as { counts?: { failed?: number; passed?: number; unknown?: number; not_applicable?: number } }).counts;
    if (counts) {
      // A count at zero is a word under the band rather than a segment in
      // it, so each one is looked for wherever the band chose to put it.
      for (const [label, value] of [["failed", counts.failed ?? 0], ["passed", counts.passed ?? 0]] as const) {
        await expect(checks, `the band does not count ${label}`).toContainText(String(value));
      }
    }
    for (const title of ["Need action", "Protective state", "Listening sockets", "Findings"]) {
      await expect(card(page, title).first()).toBeVisible();
    }
    await expectHealthy(page, errors);
  });

  test("the ssh page shows the effective configuration and opens the editor without sending anything", async ({ page }) => {
    const host = onlineHostWith(hosts, "sshd") ?? hosts.find((entry) => entry.capabilities?.some((item) => item.name === "sshd" && item.available));
    test.skip(!host, absent("no host reports the sshd adapter"));
    const target = host as Host;
    const { errors } = watchErrors(page);
    const posted: string[] = [];
    page.on("request", (request) => {
      if (request.method() !== "GET" && request.url().includes("/api/v1/")) posted.push(`${request.method()} ${request.url()}`);
    });

    const missing = await openModule(page, target, "ssh", "SSH");
    test.skip(missing !== null, absent(missing ?? ""));
    const unreported = page.getByText("This host has not reported its sshd yet.");
    test.skip(await unreported.count() > 0, absent(`${target.hostname} has not reported its sshd yet`));
    const ways = card(page, "Ways in");
    await expect(ways).toBeVisible();
    for (const label of ["ports", "methods enabled", "methods disabled", "methods unknown", "host keys"]) {
      await expect(ways.locator("dt", { hasText: new RegExp(`^${label}$`) })).toHaveCount(1);
    }
    for (const title of ["Posture", "Authentication methods", "Host keys", "Managed drop-in", "Effective configuration"]) {
      await expect(card(page, title).first()).toBeVisible();
    }

    /* The editor is opened from the posture card - the one it changes -
       and is a form of its own on the Change tab; Cancel leaves it. */
    await page.getByTestId("change-configuration").click();
    const editor = page.getByTestId("ssh-config-form");
    await expect(editor).toBeVisible();
    await expect(editor.locator(".fl-form-title")).toHaveText("Change configuration");
    await editor.getByRole("button", { name: "Cancel" }).click();
    await expect(editor).toHaveCount(0);
    expect(posted, "opening the editor must not write anything").toEqual([]);
    await expectHealthy(page, errors);
  });
});
