import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { expectHealthy, fleetHosts, openModule, permissions, watchErrors, type Host } from "./fleet";

/**
 * The pages that give the operator a working day: the job list and one
 * job, the campaigns and their calendar, the secrets, the access tabs,
 * the audit export, the CVE view, the tag catalogue, the reports, the
 * status and first-run pages, the notification channels, the profile,
 * the command palette, and two faces of a host - its overview and its
 * package table.
 *
 * Every test only reads. Nothing is ordered, saved or confirmed: a
 * button that would change the fleet is looked at, never pressed. A page
 * the token may not see is skipped with the permission it would need, and
 * a fleet without a job, a secret or a package list skips the test that
 * needs one instead of failing on an empty screen.
 */

let hosts: Host[] = [];
let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
  granted = await permissions(request);
});

/** The page header of a fleet page, with its title. */
function header(page: Page, title: string) {
  return page.locator(".page-header").getByRole("heading", { name: title });
}

/** A whole-text match: "Jobs" must not find "Jobs of the host". */
function exact(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

/** The card of a fleet page by its title. */
function card(page: Page, title: string) {
  return page.locator(".card").filter({ has: page.locator(".card-title", { hasText: exact(title) }) });
}

/** A section of the host workspace by its heading. */
function section(page: Page, title: string) {
  return page.locator(".hm-section").filter({ has: page.locator("h3", { hasText: exact(title) }) }).first();
}

/** The items of a collection endpoint, or an empty list when the token may not read it. */
async function items<T>(request: APIRequestContext, path: string): Promise<T[]> {
  const response = await request.get(path);
  if (response.status() === 403) return [];
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { items?: T[] };
  return body.items ?? [];
}

test.describe("jobs", () => {
  test("the job list has a host column, a state filter that can be cleared, and a host chip from a link", async ({ page }) => {
    test.skip(!granted.has("job.read"), "the token may not read jobs (job.read)");
    const { errors } = watchErrors(page);
    await page.goto("/jobs");
    await expect(header(page, "Jobs")).toBeVisible();
    await expect(card(page, "State").getByTestId("status-bar")).toBeVisible();

    // The table or the honest empty state; the host column is a header
    // of its own when there is a table.
    // The job table is the one headed by the operation; the widgets
    // above it are tables of their own.
    const table = page.locator("table:has(th:has-text(\"Operation\"))").first();
    await expect(table.or(page.getByText(exact("No jobs."))).first()).toBeVisible();
    if (await table.isVisible()) {
      await expect(table.locator("th", { hasText: "Host" }).first()).toBeVisible();
      await expect(table.locator("th", { hasText: "Operation" }).first()).toBeVisible();
    }

    // A state chosen in the toolbar goes to the address, and the clear
    // button appears with it.
    const toolbar = page.locator(".toolbar").first();
    await expect(toolbar.getByRole("button", { name: "Clear filters" })).toHaveCount(0);
    await toolbar.locator("select").first().selectOption("succeeded");
    await expect(page).toHaveURL(/[?&]state=succeeded/);
    await expect(toolbar.getByRole("button", { name: "Clear filters" })).toBeVisible();
    await expect(table.locator("tbody tr").first().or(page.locator(".card-body .empty", { hasText: exact("No jobs.") })).first()).toBeVisible();
    await toolbar.getByRole("button", { name: "Clear filters" }).click();
    await expect(page).not.toHaveURL(/[?&]state=/);
    await expect(toolbar.getByRole("button", { name: "Clear filters" })).toHaveCount(0);
    await expect(toolbar.locator("select").first()).toHaveValue("");

    // A host arrives from a link, not from a field: it shows as a chip
    // with a way to take it off.
    const host = hosts[0];
    await page.goto(`/jobs?host_id=${encodeURIComponent(host.id)}`);
    await expect(header(page, "Jobs")).toBeVisible();
    const chip = page.locator(".toolbar .chip", { hasText: `host ${host.id.slice(0, 8)}` });
    await expect(chip).toBeVisible();
    await expect(page.locator(".toolbar").first().getByRole("button", { name: "Clear filters" })).toBeVisible();
    await chip.getByRole("button", { name: "Remove the host filter" }).click();
    await expect(chip).toHaveCount(0);
    await expect(page).not.toHaveURL(/[?&]host_id=/);
    await expectHealthy(page, errors);
  });

  test("the first job opens on its operation with the payload card", async ({ page, request }) => {
    test.skip(!granted.has("job.read"), "the token may not read jobs (job.read)");
    const jobs = await items<{ id: string; action_type: string; state: string }>(request, "/api/v1/jobs?limit=1");
    test.skip(jobs.length === 0, "the fleet has no job yet");
    const job = jobs[0];
    const { errors } = watchErrors(page);

    await page.goto(`/jobs/${job.id}`);
    await expect(page.locator(".page-header").getByRole("heading", { name: job.action_type })).toBeVisible();
    await expect(page.locator(".page-header .breadcrumb").getByRole("link", { name: "Jobs" })).toBeVisible();
    await expect(card(page, "Job")).toBeVisible();
    await expect(card(page, "Decision and result")).toBeVisible();
    // The payload is the order as the host receives it; the hash of the
    // job stands beside it.
    const payload = card(page, "Payload");
    await expect(payload).toBeVisible();
    await expect(payload.locator("pre").first()).toBeVisible();
    await expect(card(page, "Decision and result")).toContainText("Payload hash");
    await expectHealthy(page, errors);
  });
});

test.describe("campaigns", () => {
  test("the campaign list filters by state and operation and links to the schedules", async ({ page, request }) => {
    test.skip(!granted.has("campaign.read"), "the token may not read campaigns (campaign.read)");
    const { errors } = watchErrors(page);
    const campaigns = await items<{ id: string; name: string }>(request, "/api/v1/campaigns?limit=200");

    await page.goto("/campaigns");
    await expect(header(page, "Campaigns")).toBeVisible();
    await expect(card(page, "State").getByTestId("status-bar")).toBeVisible();
    await expect(card(page, "Outcomes")).toBeVisible();

    const list = card(page, "List");
    await expect(list).toBeVisible();
    const toolbar = list.locator(".toolbar").first();
    const state = toolbar.locator("select").first();
    const operation = toolbar.locator("select").nth(1);
    await expect(state.locator("option").first()).toHaveText("state: any");
    await expect(operation.locator("option").first()).toHaveText("operation: any");
    await expect(toolbar.getByPlaceholder("Requested by")).toBeVisible();
    if (campaigns.length === 0) {
      await expect(list.locator(".empty-state")).toBeVisible();
    } else {
      await expect(list.locator("tbody tr").first()).toBeVisible();
    }

    // A state that no campaign is likely to be in: the list narrows on
    // the server and either shows rows of that state or says there is
    // nothing, with a way back.
    const narrowed = page.waitForResponse((response) => response.url().includes("/api/v1/campaigns?") && response.url().includes("state=canceled"));
    await state.selectOption("canceled");
    expect((await narrowed).ok()).toBeTruthy();
    await expect(list.locator("tbody tr").first().or(list.getByRole("button", { name: "Clear the filters" })).first()).toBeVisible();
    await state.selectOption("");

    // The schedules are one link away in the header.
    const schedules = page.locator(".page-header").getByRole("link", { name: "Schedules" });
    await expect(schedules).toHaveAttribute("href", "/campaigns/schedules");
    await schedules.click();
    await expect(page).toHaveURL(/\/campaigns\/schedules$/);
    await expect(header(page, "Scheduled campaigns")).toBeVisible();
    await expectHealthy(page, errors);
  });

  test("the maintenance calendar draws the seven weekdays of a month", async ({ page }) => {
    test.skip(!granted.has("campaign.read"), "the token may not read campaigns (campaign.read)");
    const { errors } = watchErrors(page);
    await page.goto("/campaigns/schedules");
    await expect(header(page, "Scheduled campaigns")).toBeVisible();

    const schedules = card(page, "Schedules");
    await expect(schedules).toBeVisible();
    await expect(schedules.locator("tbody tr").first().or(schedules.locator(".empty, .empty-state").first()).first()).toBeVisible();

    const calendar = card(page, "Maintenance calendar");
    await expect(calendar).toBeVisible();
    for (const day of ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]) {
      await expect(calendar.locator(".source", { hasText: exact(day) })).toHaveCount(1);
    }
    // A month grid has at least four weeks of seven days behind the
    // labels, and the month it draws is named between its two arrows.
    const cells = calendar.locator(".card-body > div > div");
    await expect(cells.nth(7 + 27)).toBeVisible();
    await expect(calendar.locator(".card-actions .mono")).toHaveText(/^\d{4}-\d{2}$/);
    await expect(calendar.locator(".card-actions").getByRole("button", { name: "Next month" })).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("secrets", () => {
  test("the store has a search box and opens the first secret on its metadata", async ({ page, request }) => {
    test.skip(!granted.has("secret.read"), "the token may not read secrets (secret.read)");
    const { errors } = watchErrors(page);
    const secrets = await items<{ name: string; current_version?: number }>(request, "/api/v1/secrets");

    await page.goto("/secrets");
    await expect(header(page, "Secrets")).toBeVisible();
    await expect(card(page, "Store")).toContainText(`${secrets.length} secrets`);
    await expect(card(page, "By creator")).toBeVisible();
    const search = page.getByPlaceholder("Search by name or description");
    await expect(search).toBeVisible();

    if (secrets.length === 0) {
      await expect(page.getByText("No secrets are stored in this installation.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }
    const table = page.locator("table").first();
    await expect(table.locator("tbody tr")).toHaveCount(secrets.length);

    // A name nobody has narrows the list to nothing; the box empty lists
    // them all again.
    await search.fill("no-such-secret-" + Date.now());
    await expect(page.getByText("No secret matches the search.")).toBeVisible();
    await search.fill("");
    await expect(table.locator("tbody tr")).toHaveCount(secrets.length);

    // The first secret: its metadata, its reference, its versions - and
    // never its value.
    const first = secrets[0];
    await table.getByRole("link", { name: first.name, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/secrets/${encodeURIComponent(first.name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`));
    await expect(header(page, first.name)).toBeVisible();
    await expect(page.locator(".page-header .breadcrumb").getByRole("link", { name: "Secrets" })).toBeVisible();
    await expect(card(page, "Secret")).toContainText("the value is not here and cannot be read back");
    await expect(card(page, "Reference")).toBeVisible();
    await expect(card(page, "Versions")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("access", () => {
  test("the identities and roles tabs open from the address and the roles come as a matrix", async ({ page }) => {
    test.skip(!granted.has("principal.manage"), "the token may not manage access (principal.manage)");
    const { errors } = watchErrors(page);

    await page.goto("/access?tab=identities");
    await expect(header(page, "Access")).toBeVisible();
    const tabs = page.locator(".tabs").first();
    await expect(tabs.getByRole("button", { name: "Identities" })).toHaveClass(/active/);
    await expect(tabs.getByRole("button", { name: "Group mappings" })).not.toHaveClass(/active/);
    const identities = card(page, "Identities");
    await expect(identities).toBeVisible();
    await expect(identities.getByPlaceholder("subject, name or identifier")).toBeVisible();
    // The token itself is an identity, so the table is never empty.
    await expect(identities.locator("tbody tr").first()).toBeVisible();
    await expect(identities.locator("th", { hasText: "Roles and scopes" }).first()).toBeVisible();

    await page.goto("/access?tab=roles");
    await expect(tabs.getByRole("button", { name: "Roles" })).toHaveClass(/active/);
    const roles = card(page, "Roles");
    await expect(roles).toBeVisible();
    const matrix = roles.locator("table");
    await expect(matrix.locator("th", { hasText: "Permission" }).first()).toBeVisible();
    // A permission is a row, a role is a column: at least two roles and
    // one permission ticked "yes".
    expect(await matrix.locator("thead th").count()).toBeGreaterThanOrEqual(3);
    await expect(matrix.locator("tbody tr").first()).toBeVisible();
    await expect(matrix.locator("tbody .badge.ok", { hasText: exact("yes") }).first()).toBeVisible();
    await expect(roles).toContainText(/\d+ permissions/);

    // The search narrows the rows in the browser.
    await roles.getByPlaceholder("permission, e.g. job.create").fill("job.");
    for (const cell of await matrix.locator("tbody tr td:first-child").all()) {
      await expect(cell).toContainText("job.");
    }
    // The tab click writes the address like the address wrote the tab.
    await tabs.getByRole("button", { name: "Identities" }).click();
    await expect(page).toHaveURL(/[?&]tab=identities/);
    await expectHealthy(page, errors);
  });
});

test.describe("audit", () => {
  test("the events card offers the signed export", async ({ page }) => {
    test.skip(!granted.has("audit.read"), "the token may not read the audit trail (audit.read)");
    const { errors } = watchErrors(page);
    await page.goto("/audit");
    await expect(header(page, "Audit")).toBeVisible();
    const events = card(page, "Events");
    await expect(events).toBeVisible();
    await expect(events.locator(".card-actions").getByRole("button", { name: "Export", exact: true })).toBeVisible();
    await expect(events.locator(".card-actions").getByRole("button", { name: "Export", exact: true })).toBeEnabled();
    await expect(events).toContainText("hash chain");
    await expectHealthy(page, errors);
  });
});

test.describe("vulnerabilities", () => {
  test("the CVE view is chosen by the address and the toggle shows it", async ({ page }) => {
    test.skip(!granted.has("vulnerability.read"), "the token may not read vulnerabilities (vulnerability.read)");
    const { errors } = watchErrors(page);
    await page.goto("/vulnerabilities?view=cves");
    await expect(header(page, "Vulnerabilities")).toBeVisible();

    const toggle = page.getByTestId("view-toggle");
    await expect(toggle.getByRole("button", { name: "By CVE" })).toHaveClass(/active/);
    await expect(toggle.getByRole("button", { name: "By host" })).not.toHaveClass(/active/);
    const table = card(page, "By CVE");
    await expect(table).toBeVisible();
    await expect(table.getByPlaceholder("CVE number or package name")).toBeVisible();
    await expect(table.locator("tbody tr").first().or(table.locator(".empty").first()).first()).toBeVisible();

    // The other way round: the toggle writes the address.
    await toggle.getByRole("button", { name: "By host" }).click();
    await expect(page).not.toHaveURL(/[?&]view=cves/);
    await expect(toggle.getByRole("button", { name: "By host" })).toHaveClass(/active/);
    await expect(card(page, "Hosts")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("tags", () => {
  test("the catalogue counts the tags the API lists and filters them", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    const tags = await items<{ tag: string; hosts: number }>(request, "/api/v1/tags");

    await page.goto("/tags");
    await expect(header(page, "Tags")).toBeVisible();
    await expect(card(page, "Catalogue")).toContainText(`${tags.length} tags on the hosts you may read`);
    await expect(card(page, "By key")).toBeVisible();
    const filter = page.getByPlaceholder("Filter tags");
    await expect(filter).toBeVisible();

    if (tags.length === 0) {
      await expect(page.getByText("No host you may read carries a tag.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }
    const table = page.locator("table").first();
    await expect(table.locator("tbody tr")).toHaveCount(tags.length);
    await expect(table.getByRole("columnheader", { name: "Hosts" })).toBeVisible();
    await filter.fill("no-such-tag-" + Date.now());
    await expect(page.getByText("No tag matches the filter.")).toBeVisible();
    await filter.fill("");
    await expect(table.locator("tbody tr")).toHaveCount(tags.length);
    await expectHealthy(page, errors);
  });
});

test.describe("reports", () => {
  test("every report is a card with its own CSV export", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/reports");
    await expect(header(page, "Reports")).toBeVisible();
    await expect(page.getByRole("group", { name: "Period" })).toBeVisible();
    await expect(page.getByRole("group", { name: "Period" }).locator("button.active")).toHaveCount(1);

    // The campaigns report needs the right to read campaigns; the other
    // two come with the hosts.
    const titles = granted.has("campaign.read") ? ["Patch status", "Campaigns", "Compliance"] : ["Patch status", "Compliance"];
    await expect(page.locator(".widgets > .card")).toHaveCount(titles.length);
    for (const title of titles) {
      const report = card(page, title);
      await expect(report).toBeVisible();
      // The compliance report carries one export per section; the first
      // stands for the card.
      await expect(report.locator(".card-actions").getByTestId("export-csv").first()).toBeVisible();
      await expect(report.locator(".card-actions").getByTestId("export-csv").first()).toHaveText(/Export .*CSV/);
    }
    // The patch report has settled: a table of hosts, or the reason it
    // could not be drawn.
    const patch = card(page, "Patch status");
    await expect(patch.locator("table").first().or(patch.locator(".empty, .page-error, .fp-note").first()).first()).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("status", () => {
  test("the panel judges itself and says what it is built from", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), "the token may not read the status (settings.read)");
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/status");
    expect(response.ok(), `GET /api/v1/status answered ${response.status()}`).toBeTruthy();
    const status = (await response.json()) as { ok: boolean; unknown: number; blocks: Record<string, unknown> };

    await page.goto("/status");
    await expect(header(page, "Status")).toBeVisible();
    const verdict = page.locator(".card").filter({ has: page.locator("dt", { hasText: exact("Verdict") }) }).first();
    await expect(verdict).toBeVisible();
    await expect(verdict.locator(".badge").first()).toHaveText(status.ok ? "every judged part is fine" : "a part of the panel is not fine");
    await expect(verdict.locator("dt", { hasText: exact("Not judged") })).toBeVisible();
    await expect(verdict.locator("dt", { hasText: exact("Last refresh") })).toBeVisible();

    if (status.blocks.build) {
      await expect(card(page, "About")).toBeVisible();
      await expect(card(page, "About").locator("dt").first()).toBeVisible();
    }
    await expect(page.locator(".page-header").getByRole("link", { name: "OpenAPI" })).toHaveAttribute("href", "/api/v1/openapi.json");
    await expectHealthy(page, errors);
  });
});

test.describe("setup", () => {
  test("the first-run checklist has a card for every step the server counts", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), "the token may not read the checklist (settings.read)");
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/setup");
    expect(response.ok(), `GET /api/v1/setup answered ${response.status()}`).toBeTruthy();
    const checklist = (await response.json()) as { steps: { key: string; state: string }[]; done: number; total: number; complete: boolean };
    expect(checklist.steps, "the checklist names ten steps").toHaveLength(10);

    await page.goto("/setup");
    await expect(header(page, "First run")).toBeVisible();
    const cards = page.locator(".stack > .card");
    // The summary card and one card per step, numbered in order.
    await expect(cards).toHaveCount(1 + checklist.steps.length);
    await expect(cards.first()).toContainText(checklist.complete ? "Every required step is done" : `${checklist.done} of ${checklist.total} required steps done`);
    for (let index = 0; index < checklist.steps.length; index += 1) {
      const step = cards.nth(index + 1);
      await expect(step.locator(".card-title")).toContainText(`${index + 1}.`);
      await expect(step.locator(".card-title .badge")).toHaveText(/^(Done|To do|Warning|Optional)$/);
    }
    // The first step left is the one highlighted; none when all is done.
    const undone = checklist.steps.findIndex((step) => step.state === "undone");
    await expect(page.locator(".stack > .card.warn")).toHaveCount(undone === -1 ? 0 : 1);
    await expectHealthy(page, errors);
  });
});

test.describe("notifications", () => {
  test("the channels card lists the channels or says nobody is told", async ({ page, request }) => {
    test.skip(!granted.has("notification.read"), "the token may not read notifications (notification.read)");
    const { errors } = watchErrors(page);
    const channels = await items<{ id: string; name: string }>(request, "/api/v1/notifications/channels");

    await page.goto("/notifications");
    await expect(header(page, "Notifications")).toBeVisible();
    const list = card(page, "Channels");
    await expect(list).toBeVisible();
    if (channels.length === 0) {
      await expect(list.locator(".empty-state")).toContainText("No channels");
    } else {
      await expect(list.locator("tbody tr")).toHaveCount(channels.length);
      for (const channel of channels) {
        await expect(list.locator("tbody tr").filter({ hasText: channel.name })).not.toHaveCount(0);
      }
    }
    // Whoever manages the channels sees the button; the others see only
    // the list.
    const newChannel = page.getByRole("button", { name: "New channel" });
    if (granted.has("notification.manage")) {
      await expect(newChannel.first()).toBeVisible();
    } else {
      await expect(newChannel).toHaveCount(0);
    }
    // The log became a queue: a delivery is a durable row with a state,
    // and the card says so.
    await expect(card(page, "Delivery queue")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("profile", () => {
  test("the preferences form shows the zone, the page size and the landing page", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/profile");
    await expect(header(page, "Profile")).toBeVisible();
    await expect(card(page, "Identity")).toBeVisible();
    await expect(card(page, "Permissions")).toBeVisible();

    const preferences = card(page, "Preferences");
    await expect(preferences).toBeVisible();
    await expect(preferences.getByTestId("preference-time-zone")).toBeVisible();
    await expect(preferences.getByTestId("preference-page-size")).toBeVisible();
    await expect(preferences.getByTestId("preference-landing-page")).toBeVisible();
    await expect(preferences.getByRole("group", { name: "Language" })).toBeVisible();
    await expect(preferences.locator(".card-foot").getByRole("button", { name: "Save" })).toBeVisible();
    // Nothing is typed, nothing is saved: the form is looked at only.
    await expectHealthy(page, errors);
  });
});

test.describe("command palette", () => {
  test("Control+K opens the palette, a hostname prefix finds the host, Escape closes it", async ({ page }) => {
    const { errors } = watchErrors(page);
    const host = hosts[0];
    await page.goto("/hosts");
    await expect(header(page, "Hosts")).toBeVisible();

    const popover = page.locator(".host-picker-popover");
    await expect(popover).toHaveCount(0);
    await page.keyboard.press("Control+k");
    await expect(popover).toBeVisible();
    const input = popover.getByRole("textbox", { name: "Search the panel" });
    await expect(input).toBeFocused();

    // A prefix of at least two characters is a query of the fleet.
    await input.fill(host.hostname.slice(0, Math.max(2, Math.min(4, host.hostname.length))));
    const row = popover.getByRole("option").filter({ has: page.locator(".host-picker-name", { hasText: exact(host.hostname) }) });
    await expect(row.first()).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(popover).toHaveCount(0);
    await expect(page).toHaveURL(/\/hosts$/);
    await expectHealthy(page, errors);
  });
});

test.describe("host workspace", () => {
  test("the overview keeps the notes, the failure domain and the quarantine door", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    const response = await request.get(`/api/v1/hosts/${host.id}`);
    expect(response.ok(), `GET /api/v1/hosts/${host.id} answered ${response.status()}`).toBeTruthy();
    const detail = (await response.json()) as { failure_domain?: string | null; lifecycle_state?: string };

    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview", exact: true })).toBeVisible();

    // The failure domain is a fact of the system card: the domain, or
    // the badge that says the host is not placed.
    const system = section(page, "System");
    const domain = system.locator(".hm-fact").filter({ has: page.locator("dt", { hasText: exact("Failure domain") }) });
    await expect(domain).toBeVisible();
    if (detail.failure_domain) {
      await expect(domain.locator("dd")).toContainText(detail.failure_domain);
    } else {
      await expect(domain.locator("dd .badge", { hasText: "not placed" })).toBeVisible();
    }

    const notes = section(page, "Notes");
    await expect(notes).toBeVisible();
    await expect(notes.locator(".hm-section-desc")).toContainText("audit trail");

    // The quarantine button is looked at, never pressed: the door stands
    // for whoever may quarantine a live host, and is absent otherwise.
    const lifecycle = section(page, "Lifecycle");
    await expect(lifecycle).toBeVisible();
    const alive = detail.lifecycle_state !== "retired" && detail.lifecycle_state !== "retiring";
    const quarantine = lifecycle.getByRole("button", { name: "Quarantine host…" });
    if (alive && detail.lifecycle_state !== "quarantined" && granted.has("host.quarantine")) {
      await expect(quarantine).toBeVisible();
      await expect(quarantine).toHaveClass(/hm-danger/);
    } else {
      await expect(quarantine).toHaveCount(0);
    }
    await expectHealthy(page, errors);
  });

  test("the packages tab shows the installed packages with a search box", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    const notice = await openModule(page, host, "packages", "Packages");
    test.skip(notice !== null, notice ?? undefined);
    const list = await request.get(`/api/v1/hosts/${host.id}/packages`);
    test.skip(list.status() === 403, "the token may not read the package list (packages.read)");
    expect(list.ok(), `GET /api/v1/hosts/${host.id}/packages answered ${list.status()}`).toBeTruthy();
    const packages = (await list.json()) as { items: { name: string }[] };

    await expect(section(page, "Updates")).toBeVisible();
    await expect(section(page, "Sources")).toBeVisible();
    const installed = section(page, "Installed packages");
    await expect(installed).toBeVisible();
    test.skip(packages.items.length === 0, "the panel has not read the package list of this host yet");

    // The tools stand in the heading: the search, the filter, the order.
    const search = installed.getByPlaceholder("Search packages");
    await expect(search).toBeVisible();
    await expect(installed.locator(".hm-count")).toHaveText(String(packages.items.length));
    const table = installed.locator("table").first();
    await expect(table.locator("th", { hasText: "Package" }).first()).toBeVisible();
    await expect(table.locator("th", { hasText: "Held" }).first()).toBeVisible();
    await expect(table.locator("tbody tr:not(.spacer)").first()).toBeVisible();

    // The search narrows in the browser; the count follows it.
    const first = packages.items[0].name;
    await search.fill(first);
    await expect(table.getByRole("button", { name: first, exact: true }).first()).toBeVisible();
    await search.fill("no-such-package-" + Date.now());
    await expect(installed.getByText("No package matches.")).toBeVisible();
    await search.fill("");
    await expect(installed.locator(".hm-count")).toHaveText(String(packages.items.length));
    await expectHealthy(page, errors);
  });
});
