import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  absent, card, exact, expectHealthy, fleetHosts, formOf, head, openModule, openTab, permissions, watchErrors, type Host,
} from "./fleet";

/**
 * The pages that give the operator a working day: the job list and one job,
 * the campaigns and their calendar, the secrets, the access screen, the
 * audit export, the CVE view, the tag catalogue, the reports, the status
 * and the first-run checklist.
 */

let hosts: Host[] = [];
let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
  granted = await permissions(request);
});

/** The items of a collection endpoint, or an empty list when the token may not read it. */
async function items<T>(request: APIRequestContext, path: string): Promise<T[]> {
  const response = await request.get(path);
  if (response.status() === 403) return [];
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { items?: T[] };
  return body.items ?? [];
}

test.describe("jobs", () => {
  test("the list is counted, filtered by state in the address, and takes a host from a link", async ({ page }) => {
    test.skip(!granted.has("job.read"), absent("the token may not read jobs (job.read)"));
    const { errors } = watchErrors(page);
    await page.goto("/jobs");
    await expect(head(page, "Jobs")).toBeVisible();

    // The table or the honest empty state; the host column is a header of
    // its own when there is a table.
    const table = page.getByTestId("jobs");
    await expect(table.or(card(page, "Jobs").getByText("No jobs.")).first()).toBeVisible();
    if (await table.count() > 0) {
      await expect(table.locator("th", { hasText: "Host" }).first()).toBeVisible();
      await expect(table.locator("th", { hasText: "Operation" }).first()).toBeVisible();
    }

    // A state chosen in the bar goes to the address, and the clear button
    // appears with it.
    const jobs = card(page, "Jobs");
    await expect(jobs.getByTestId("clear")).toHaveCount(0);
    await jobs.getByTestId("state").selectOption("succeeded");
    await expect(page).toHaveURL(/[?&]state=succeeded/);
    await expect(jobs.getByTestId("clear")).toBeVisible();
    await jobs.getByTestId("clear").click();
    await expect(page).not.toHaveURL(/[?&]state=/);
    await expect(jobs.getByTestId("clear")).toHaveCount(0);
    await expect(jobs.getByTestId("state")).toHaveValue("");

    // A host arrives from a link, not from a field: it shows as a chip
    // with a way to take it off.
    const host = hosts[0];
    await page.goto(`/jobs?host_id=${encodeURIComponent(host.id)}`);
    await expect(head(page, "Jobs")).toBeVisible();
    const chip = card(page, "Jobs").locator(".fl-tag", { hasText: `host ${host.id.slice(0, 8)}` });
    await expect(chip).toBeVisible();
    await expect(card(page, "Jobs").getByTestId("clear")).toBeVisible();
    await chip.getByRole("button", { name: "Remove the host filter" }).click();
    await expect(chip).toHaveCount(0);
    await expect(page).not.toHaveURL(/[?&]host_id=/);

    // What the list is made of - the states, the day, the operations - is
    // the second reading, not a row of containers over the list.
    await openTab(page, "Statistics");
    await expect(card(page, "State").getByTestId("job-states")).toBeVisible();
    await expectHealthy(page, errors);
  });

  test("the first job opens on its operation with the payload card", async ({ page, request }) => {
    test.skip(!granted.has("job.read"), absent("the token may not read jobs (job.read)"));
    const jobs = await items<{ id: string; action_type: string; state: string }>(request, "/api/v1/jobs?limit=1");
    test.skip(jobs.length === 0, absent("the fleet has no job yet"));
    const job = jobs[0];
    const { errors } = watchErrors(page);

    await page.goto(`/jobs/${job.id}`);
    // One job names itself rather than the section it is in, so it draws
    // its own heading and the operation is what it says.
    await expect(head(page, job.action_type)).toBeVisible();
    // The job is read in four tabs; the order, with the payload as the host
    // receives it, is the first.
    await expect(card(page, "The order")).toBeVisible();
    const payload = card(page, "Payload");
    await expect(payload).toBeVisible();
    await expect(payload.locator("pre").first()).toBeVisible();
    // The decision and the hash of the job that stands beside the payload
    // are the second.
    await openTab(page, "Result");
    await expect(card(page, "Decision and result")).toBeVisible();
    await expect(card(page, "Decision and result")).toContainText("Payload hash");
    await expectHealthy(page, errors);
  });
});

test.describe("campaigns", () => {
  test("the campaign list filters by state on the server", async ({ page, request }) => {
    test.skip(!granted.has("campaign.read"), absent("the token may not read campaigns (campaign.read)"));
    const { errors } = watchErrors(page);
    const campaigns = await items<{ id: string; name: string }>(request, "/api/v1/campaigns?limit=200");

    await page.goto("/campaigns");
    await expect(head(page, "Campaigns")).toBeVisible();

    const list = card(page, "Campaigns");
    await expect(list).toBeVisible();
    await expect(list.getByTestId("state").locator("option").first()).toHaveText("state: any");
    await expect(list.getByTestId("requester")).toBeVisible();
    await expect(list.getByTestId("action")).toBeVisible();
    if (campaigns.length === 0) {
      await expect(list.locator(".fl-empty")).toBeVisible();
    } else {
      await expect(list.locator("tbody tr").first()).toBeVisible();
    }

    // A state that no campaign is likely to be in: the list narrows on the
    // server, the address carries it, and either rows of that state come
    // back or the list says there is nothing.
    const narrowed = page.waitForResponse((response) => response.url().includes("/api/v1/campaigns?") && response.url().includes("state=canceled"));
    await list.getByTestId("state").selectOption("canceled");
    expect((await narrowed).ok()).toBeTruthy();
    await expect(page).toHaveURL(/[?&]state=canceled/);
    await expect(list.locator("tbody tr").first().or(list.locator(".fl-empty")).first()).toBeVisible();
    await list.getByTestId("state").selectOption("");

    // The counts by state are the second reading, over the same filter.
    await openTab(page, "Summary");
    await expect(card(page, "State").getByTestId("campaign-states")).toBeVisible();
    await expectHealthy(page, errors);
  });

  test("the maintenance calendar draws the seven weekdays of a month", async ({ page }) => {
    test.skip(!granted.has("campaign.read"), absent("the token may not read campaigns (campaign.read)"));
    const { errors } = watchErrors(page);
    /* The scheduled campaigns are reached by their address: the campaign
       list no longer carries a link to them. */
    await page.goto("/campaigns/schedules");
    await expect(head(page, "Scheduled campaigns")).toBeVisible();

    const schedules = card(page, "Schedules");
    await expect(schedules).toBeVisible();
    await expect(
      page.getByTestId("schedules").or(schedules.locator(".fl-empty")).first(),
    ).toBeVisible();

    // The calendar is the second reading of the screen, the schedules the first.
    await openTab(page, "Calendar");
    const calendar = card(page, "Maintenance calendar");
    await expect(calendar).toBeVisible();
    const month = page.getByTestId("calendar");
    for (const day of ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]) {
      await expect(month.locator("thead th", { hasText: exact(day) })).toHaveCount(1);
    }
    // A month is at least four weeks of seven days, and the month it draws
    // is named between its two arrows.
    expect(await month.locator("tbody tr").count()).toBeGreaterThanOrEqual(4);
    await expect(calendar.getByTestId("calendar-month")).toHaveText(/^\d{4}-\d{2}$/);
    await expect(calendar.getByRole("group", { name: "Which month" })
      .getByRole("button", { name: "Next month" })).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("secrets", () => {
  test("the store has a search box and opens the first secret on its metadata", async ({ page, request }) => {
    test.skip(!granted.has("secret.read"), absent("the token may not read secrets (secret.read)"));
    const { errors } = watchErrors(page);
    const secrets = await items<{ name: string; current_version?: number }>(request, "/api/v1/secrets");

    await page.goto("/secrets");
    await expect(head(page, "Secrets")).toBeVisible();
    await expect(card(page, "Store").getByTestId("secrets-band")).toBeVisible();
    await expect(card(page, "By creator")).toBeVisible();
    const search = page.getByTestId("secrets-search");
    await expect(search).toBeVisible();

    if (secrets.length === 0) {
      await expect(page.getByText("No secrets are stored in this installation.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }
    const table = page.getByTestId("secrets-table");
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
    await expect(card(page, "Secret")).toContainText("cannot be read back");
    await expect(card(page, "Reference")).toBeVisible();
    // The versions are the second reading of one secret.
    await openTab(page, "Versions");
    await expect(card(page, "Versions")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("access", () => {
  test("the identities are listed and the roles come as a matrix", async ({ page }) => {
    test.skip(!granted.has("principal.manage"), absent("the token may not manage access (principal.manage)"));
    const { errors } = watchErrors(page);

    /* Access is one screen of containers again rather than tabs of the
       settings: the identities, the role catalogue and the review are all
       on it. The old address /access is the one it answers to. */
    await page.goto("/access");
    await expect(head(page, "Users and access")).toBeVisible();
    await expect(formOf(page, "Find somebody").getByTestId("filter-subject")).toBeVisible();
    // The token itself is an identity, so the list is never empty.
    const identities = page.getByTestId("access-rows");
    await expect(identities.locator("tbody tr").first()).toBeVisible();
    await expect(identities.locator("th", { hasText: "Roles and scopes" }).first()).toBeVisible();

    // The catalogue of permissions is a reading of its own, the last tab.
    await openTab(page, "Permissions");
    const roles = card(page, "What a role may be given");
    await expect(roles).toBeVisible();
    const matrix = page.getByTestId("permission-catalogue");
    await expect(matrix.locator("th", { hasText: "Permission" }).first()).toBeVisible();
    // A permission is a row, a role is a column: at least two roles and
    // one permission ticked "yes".
    expect(await matrix.locator("thead th").count()).toBeGreaterThanOrEqual(3);
    await expect(matrix.locator("tbody tr").first()).toBeVisible();
    await expect(matrix.locator("tbody .fl-pill.fl-ok", { hasText: exact("yes") }).first()).toBeVisible();
    await expect(roles).toContainText(/\d+ permissions/);

    // The search narrows the rows in the browser.
    await roles.getByTestId("permission-search").fill("job.");
    for (const cell of await matrix.locator("tbody tr td:first-child").all()) {
      await expect(cell).toContainText("job.");
    }
    await openTab(page, "Roles");
    await expect(card(page, "Roles of this installation")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("audit", () => {
  test("the trail offers the signed export", async ({ page }) => {
    test.skip(!granted.has("audit.read"), absent("the token may not read the audit trail (audit.read)"));
    const { errors } = watchErrors(page);
    await page.goto("/audit");
    await expect(head(page, "Audit")).toBeVisible();
    /* The export belongs to the whole screen rather than to the list, so
       it stands in the heading beside the title; what it is stays said on
       the list it exports. */
    const exporter = page.getByTestId("export");
    await expect(exporter).toBeVisible();
    await expect(exporter).toBeEnabled();
    await expect(card(page, "Events")).toContainText("hash chain");
    await expectHealthy(page, errors);
  });
});

test.describe("vulnerabilities", () => {
  test("the CVE view is chosen by the address and the toggle shows it", async ({ page }) => {
    test.skip(!granted.has("vulnerability.read"), absent("the token may not read vulnerabilities (vulnerability.read)"));
    const { errors } = watchErrors(page);
    await page.goto("/vulnerabilities?view=cves");
    await expect(head(page, "Vulnerabilities")).toBeVisible();

    const table = card(page, "By CVE");
    await expect(table).toBeVisible();
    await expect(table.getByRole("button", { name: "By CVE" })).toHaveAttribute("aria-pressed", "true");
    await expect(table.getByRole("button", { name: "By host" })).toHaveAttribute("aria-pressed", "false");
    await expect(table.getByTestId("search")).toHaveAttribute("placeholder", "CVE number or package name");
    await expect(
      page.getByTestId("cves").or(table.locator(".fl-empty")).first(),
    ).toBeVisible();

    // The other way round: the toggle writes the address.
    await table.getByRole("button", { name: "By host" }).click();
    await expect(page).not.toHaveURL(/[?&]view=cves/);
    const byHost = card(page, "By host");
    await expect(byHost.getByRole("button", { name: "By host" })).toHaveAttribute("aria-pressed", "true");
    await expectHealthy(page, errors);
  });
});

test.describe("tags", () => {
  test("the catalogue counts the tags the API lists and filters them", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    const tags = await items<{ tag: string; hosts: number }>(request, "/api/v1/tags");

    await page.goto("/tags");
    await expect(head(page, "Tags")).toBeVisible();
    const filter = page.getByTestId("tag-search");
    await expect(filter).toBeVisible();

    // How the tags are written, and the keys with the most values, are the
    // second reading; the list of tags is the first.
    const keys = async () => {
      await openTab(page, "Keys");
      await expect(card(page, "How the tags are written").getByTestId("tag-shape")).toBeVisible();
      await expect(card(page, "By key")).toBeVisible();
    };

    const catalogue = card(page, "Tags");
    if (tags.length === 0) {
      await expect(catalogue).toContainText("No host you may read carries a tag.");
      await keys();
      await expectHealthy(page, errors);
      return;
    }
    const table = catalogue.locator("table");
    await expect(table.locator("tbody tr")).toHaveCount(tags.length);
    await expect(table.locator("thead th", { hasText: /^Hosts/ })).toBeVisible();
    await filter.fill("no-such-tag-" + Date.now());
    await expect(catalogue).toContainText("No tag matches this.");
    await filter.fill("");
    await expect(table.locator("tbody tr")).toHaveCount(tags.length);
    await keys();
    await expectHealthy(page, errors);
  });
});

test.describe("reports", () => {
  test("every report is a container with its own CSV export", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/reports");
    await expect(head(page, "Reports")).toBeVisible();
    const period = page.getByRole("group", { name: "Period" });
    await expect(period).toBeVisible();
    await expect(period.locator("button[aria-pressed='true']")).toHaveCount(1);

    // One report at a time, each on a tab of its own; the campaigns report
    // needs the right to read campaigns, so that tab is not offered without
    // it. The tab and the container it opens are named differently.
    const reports = granted.has("campaign.read")
      ? [["Patching", "Patch status"], ["Campaigns", "Campaigns"], ["Compliance", "Compliance"]]
      : [["Patching", "Patch status"], ["Compliance", "Compliance"]];
    for (const [tab, title] of reports) {
      await openTab(page, tab);
      const report = card(page, title);
      await expect(report, `no container for ${title}`).toHaveCount(1);
      // The compliance report carries one export per section; the first
      // stands for the container.
      await expect(report.getByTestId("export-csv").first()).toBeVisible();
    }
    // The patch report has settled: a table of hosts, or the reason it
    // could not be drawn.
    await openTab(page, "Patching");
    const patch = card(page, "Patch status");
    await expect(
      page.getByTestId("patch-hosts").or(patch.locator(".fl-empty, .fl-problem, .fl-note").first()).first(),
    ).toBeVisible();
    await expectHealthy(page, errors);
  });
});

/* The names the status screen gives the server's blocks. Kept here so the
   test addresses what a reader sees rather than the key behind it. */
const BLOCK_TITLES: Record<string, string> = {
  database: "Database", replicas: "Replicas", crypto: "Cryptographic state", migrations: "Schema",
  outbox: "Durable trail", scheduler: "Scheduler", sessions: "Sessions", relays: "Relays",
  directory: "Directory connector", vulnerability_feeds: "Vulnerability feeds",
  certificates: "Certificates", monitoring: "Monitoring", housekeeping: "Housekeeping",
};

function blockTitle(name: string): string {
  return BLOCK_TITLES[name] ?? name;
}

/** The word the panel reads a verdict as. */
function verdictWord(tone: string): string {
  return tone === "ok" ? "fine" : tone === "warn" ? "attention" : tone === "error" ? "not fine" : "unknown";
}

test.describe("status", () => {
  test("the panel judges itself and says what it is built from", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), absent("the token may not read the status (settings.read)"));
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/status");
    expect(response.ok(), `GET /api/v1/status answered ${response.status()}`).toBeTruthy();
    const status = (await response.json()) as { ok: boolean; unknown: number; blocks: Record<string, unknown> };

    await page.goto("/status");
    await expect(head(page, "Status")).toBeVisible();

    /* The verdict used to be one sentence. It is four figures now, and
       the one claim the sentence carried - that unknown is counted apart
       from fine - is the figure that says so. */
    const judged = Number((await page.getByTestId("kpi-judged").locator(".fl-kpi-value").textContent())?.trim());
    const notJudged = Number((await page.getByTestId("kpi-unknown").locator(".fl-kpi-value").textContent())?.trim());
    const blocks = Object.keys(status.blocks).filter((name) => name !== "build");
    expect(notJudged).toBe(status.unknown);
    expect(judged + notJudged).toBe(blocks.length);
    await expect(page.getByTestId("kpi-unknown")).toContainText("unknown is not the same as fine");

    // Every part is on the Components tab, each one carrying the word its
    // verdict reads as - and unknown is not fine.
    await openTab(page, "Components");
    for (const [name, block] of Object.entries(status.blocks)) {
      if (name === "build") continue;
      const judgedBlock = block as { ok: boolean | null; attention?: string };
      const tone = judgedBlock.ok === null ? "unknown" : !judgedBlock.ok ? "error" : judgedBlock.attention ? "warn" : "ok";
      const part = card(page, blockTitle(name));
      if (await part.count() === 0) continue;
      await expect(part.locator(".fl-card-tools .fl-pill")).toHaveText(verdictWord(tone));
    }

    if (status.blocks.build) {
      await expect(card(page, "About").locator("dt").first()).toBeVisible();
    }

    await expect(page.getByRole("link", { name: "OpenAPI" })).toHaveAttribute("href", /openapi\.json$/);
    await expectHealthy(page, errors);
  });
});

test.describe("unresolved operations", () => {
  // The screen went out and the first person to open it got "Error: internal
  // error": the query named a column the jobs table does not have, and
  // nothing in the suite had ever run it. The Go side now calls the route, and
  // this opens the page the way a person does.
  test("the page answers, counts the two questions apart, and rules on a row", async ({ page, request }) => {
    test.skip(!granted.has("job.read"), absent("the token may not read jobs (job.read)"));
    const { errors } = watchErrors(page);

    const response = await request.get("/api/v1/unresolved");
    expect(response.ok(), `GET /api/v1/unresolved answered ${response.status()}`).toBeTruthy();
    const answer = (await response.json()) as {
      counts: { outcome_unknown_operations: number; applied_unverified_operations: number };
      items: { attempt_id: string }[];
    };

    await page.goto("/unresolved");
    await expect(head(page, "Needs confirmation")).toBeVisible();
    // The failure this test exists for showed as the page's error box, not as
    // a console error, so it is named here on its own.
    await expect(page.locator(".fl-problem")).toHaveCount(0);

    // The two uncertainties are counted apart on purpose: one total reads the
    // same for one host with forty of these and forty hosts with one each.
    await expect(page.getByTestId("count-outcome_unknown").locator(".fl-kpi-value"))
      .toHaveText(String(answer.counts.outcome_unknown_operations));
    await expect(page.getByTestId("count-applied_unverified").locator(".fl-kpi-value"))
      .toHaveText(String(answer.counts.applied_unverified_operations));

    /* The badge the rail used to carry for this queue is gone: the new
       rail draws no counts, so that claim is not made here any more. */

    if (answer.items.length === 0) {
      await expectHealthy(page, errors);
      return;
    }

    /* The ruling is a dialog now rather than a second row under the one
       it rules on. What it refuses is the same: a ruling with no basis. */
    const first = answer.items[0];
    await page.getByTestId(`rule-${first.attempt_id}`).click();
    const ruling = page.getByRole("dialog", { name: "Rule on this operation" });
    await expect(ruling).toBeVisible();
    await expect(ruling.getByTestId("ruling-save")).toBeDisabled();
    await ruling.getByRole("button", { name: "Cancel" }).click();
    await expect(ruling).toHaveCount(0);

    await expectHealthy(page, errors);
  });

  test("the filter narrows the list without narrowing its counts", async ({ page, request }) => {
    test.skip(!granted.has("job.read"), absent("the token may not read jobs (job.read)"));
    const { errors } = watchErrors(page);

    const response = await request.get("/api/v1/unresolved");
    expect(response.ok(), `GET /api/v1/unresolved answered ${response.status()}`).toBeTruthy();
    const counts = ((await response.json()) as {
      counts: { outcome_unknown_operations: number };
    }).counts;

    await page.goto("/unresolved");
    /* The counts stand above the list as figures and the filter in the
       bar of the list, rather than both beside the title. The claim is
       the one that mattered: a list narrowed to one question keeps the
       whole fleet's counts, so nobody can filter until the fleet looks
       settled. */
    const list = card(page, "Unconfirmed operations");
    await expect(list).toBeVisible();

    // Choosing one question narrows the list to it - each question is a tab
    // now, rather than a switch in the bar of the list - and the counts
    // stay the whole fleet's. A list that narrowed its own counter would
    // let an operator filter until the fleet looked settled.
    await openTab(page, "Did it hold?");
    await expect(page.getByTestId("count-outcome_unknown").locator(".fl-kpi-value"))
      .toHaveText(String(counts.outcome_unknown_operations));
    for (const question of await list.locator("tbody tr td:nth-child(3)").allTextContents()) {
      expect(question.trim(), "the list filtered to one question shows the other").toBe("Did it hold?");
    }

    await openTab(page, "All");
    await expectHealthy(page, errors);
  });
});

test.describe("setup", () => {
  test("the first-run checklist has a row for every step the server counts", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), absent("the token may not read the checklist (settings.read)"));
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/setup");
    expect(response.ok(), `GET /api/v1/setup answered ${response.status()}`).toBeTruthy();
    const checklist = (await response.json()) as { steps: { key: string; state: string; path: string }[]; done: number; total: number; complete: boolean };
    // How many steps there are and what they are called is the server's
    // contract, pinned once in tests/integration/setup_test.go. This test is
    // about the page showing whatever the server sends, so it holds no copy of
    // the number. Emptiness is still a fault, because every assertion below
    // would pass over a checklist with nothing in it.
    expect(checklist.steps.length, "the checklist named no steps at all").toBeGreaterThan(0);

    await page.goto("/setup");
    await expect(head(page, "First run")).toBeVisible();
    // The summary container says how far the list has got.
    // The screen counts the steps that can be done: a warning is advice and never
    // finishes, so it is not one of the steps left (20.10).
    const required = checklist.total - checklist.steps.filter((step) => step.state === "warning").length;
    await expect(card(page, checklist.complete ? "Every required step is done" : `${checklist.done} of ${required} required steps done`)).toBeVisible();
    // The steps are rows of one table, in order, each with its state in a
    // word; twelve containers were not a list a reader could take in.
    const rows = page.getByTestId("setup-steps").locator("tbody tr");
    await expect(rows).toHaveCount(checklist.steps.length);
    for (let index = 0; index < checklist.steps.length; index += 1) {
      const step = checklist.steps[index];
      const row = page.getByTestId(`step-${step.key}`);
      await expect(row.getByRole("cell").first()).toContainText(`${index + 1}.`);
      // The state is the second cell; the first may carry the mark of the next step.
      await expect(row.getByRole("cell").nth(1).locator(".fl-pill")).toHaveText(/^(Done|To do|Warning|Optional)$/);
      // Which row is which step is read off the page, not off a table kept
      // here: the row carries a link to the page the server named for that
      // step, and a step dealt with on this screen says "here" instead.
      if (step.path === "/setup") {
        await expect(page.getByTestId(`go-${step.key}`)).toHaveCount(0);
        await expect(row).toContainText("here");
      } else {
        await expect(page.getByTestId(`go-${step.key}`)).toHaveCount(1);
      }
    }
    /* The step to do next is said in a word rather than in a coloured
       frame: the kit colours a state, never a container. */
    const undone = checklist.steps.findIndex((step) => step.state === "undone");
    await expect(page.locator("[data-testid='setup-steps'] .fl-pill", { hasText: "do this next" }))
      .toHaveCount(undone === -1 ? 0 : 1);
    await expectHealthy(page, errors);
  });
});

test.describe("notifications", () => {
  test("the channels container lists the channels or says nobody is told", async ({ page, request }) => {
    test.skip(!granted.has("notification.read"), absent("the token may not read notifications (notification.read)"));
    const { errors } = watchErrors(page);
    const channels = await items<{ id: string; name: string }>(request, "/api/v1/notifications/channels");

    /* The channels have a screen of their own again; the settings name
       the section and lead here. */
    await page.goto("/notifications");
    await expect(head(page, "Notifications")).toBeVisible();
    const list = card(page, "Channels");
    await expect(list).toBeVisible();
    if (channels.length === 0) {
      await expect(list.locator(".fl-empty")).toContainText("No channels");
    } else {
      await expect(page.getByTestId("channels").locator("tbody tr")).toHaveCount(channels.length);
      for (const channel of channels) {
        await expect(page.getByTestId("channels").locator("tbody tr").filter({ hasText: channel.name })).not.toHaveCount(0);
      }
    }
    // Whoever manages the channels sees the button; the others see only
    // the list.
    const newChannel = page.getByTestId("new-channel").or(page.getByTestId("new-channel-empty"));
    if (granted.has("notification.manage")) {
      await expect(newChannel.first()).toBeVisible();
    } else {
      await expect(newChannel).toHaveCount(0);
    }
    // The log became a queue: a delivery is a durable row with a state,
    // and the container says so. The queue is a tab of its own.
    await openTab(page, "Queue");
    await expect(card(page, "Delivery queue")).toBeVisible();
    await expect(card(page, "What the queue is made of").getByTestId("queue-states")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("profile", () => {
  test("the preferences form shows the zone, the page size and the landing page", async ({ page }) => {
    const { errors } = watchErrors(page);
    await page.goto("/profile");
    await expect(head(page, "My settings")).toBeVisible();
    // Who the reader is and what they may do are two tabs; the account is
    // the first, and the permissions the fourth.
    await expect(card(page, "Who you are signed in as")).toBeVisible();
    await openTab(page, "Permissions");
    await expect(card(page, "What you may do")).toBeVisible();

    // The preferences are decisions, so they are forms on the Appearance
    // tab - the look, and how the panel reads - not containers.
    await openTab(page, "Appearance");
    const preferences = formOf(page, "How the panel reads to you");
    await expect(preferences).toBeVisible();
    await expect(preferences.getByTestId("zone")).toBeVisible();
    await expect(preferences.getByTestId("page-size-preference")).toBeVisible();
    await expect(preferences.getByTestId("landing")).toBeVisible();
    await expect(preferences.getByTestId("store-preferences")).toBeVisible();
    // The language is chosen where the look is, beside the theme.
    await expect(formOf(page, "How the panel looks").getByRole("group", { name: "Language" })).toBeVisible();
    // Nothing is typed, nothing is saved: the form is looked at only.
    await expectHealthy(page, errors);
  });
});

test.describe("the finder", () => {
  test("Control+K opens it, a hostname prefix finds the host, Escape closes it", async ({ page }) => {
    const { errors } = watchErrors(page);
    const host = hosts[0];
    await page.goto("/hosts");
    await expect(head(page, "Hosts")).toBeVisible();

    const finder = page.getByTestId("finder");
    await expect(finder).toHaveCount(0);
    await page.keyboard.press("Control+k");
    await expect(finder).toBeVisible();
    const field = page.getByTestId("finder-field");
    await expect(field).toBeFocused();

    // A prefix of at least two characters is a query of the fleet.
    await field.fill(host.hostname.slice(0, Math.max(2, Math.min(4, host.hostname.length))));
    const row = finder.locator(".fl-finder-row").filter({ has: page.locator(".fl-finder-name", { hasText: exact(host.hostname) }) });
    await expect(row.first()).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(finder).toHaveCount(0);
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
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);

    // The overview is read in five tabs: the notes are on the summary, the
    // failure domain among the system's facts, and the quarantine door with
    // the lifecycle.
    const notes = card(page, "Notes");
    await expect(notes).toBeVisible();
    await expect(notes.locator(".fl-card-note")).toContainText("audit trail");


    await openTab(page, "System");
    // The failure domain is a fact of the system container: the domain,
    // or the badge that says the host is not placed.
    const domain = card(page, "System").locator(".fl-fact")
      .filter({ has: page.locator("dt", { hasText: /^Failure domain$/ }) }).locator("dd");
    await expect(domain).toBeVisible();
    if (detail.failure_domain) {
      await expect(domain).toContainText(detail.failure_domain);
    } else {
      await expect(domain.locator(".fl-pill", { hasText: "not placed" })).toBeVisible();
    }

    await openTab(page, "Lifecycle");
    // The quarantine button is looked at, never pressed: the door stands
    // for whoever may quarantine a live host, and is absent otherwise.
    const lifecycle = card(page, "Lifecycle");
    await expect(lifecycle).toBeVisible();
    const alive = detail.lifecycle_state !== "retired" && detail.lifecycle_state !== "retiring";
    const quarantine = lifecycle.getByTestId("quarantine-open");
    if (alive && detail.lifecycle_state !== "quarantined" && granted.has("host.quarantine")) {
      await expect(quarantine).toBeVisible();
      await expect(quarantine).toHaveClass(/fl-danger/);
    } else {
      await expect(quarantine).toHaveCount(0);
    }
    await expectHealthy(page, errors);
  });

  test("the packages tab shows the installed packages with a search box", async ({ page, request }) => {
    const { errors } = watchErrors(page);
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    const notice = await openModule(page, host, "packages", "Packages");
    test.skip(notice !== null, absent(notice ?? ""));
    const list = await request.get(`/api/v1/hosts/${host.id}/packages`);
    test.skip(list.status() === 403, absent("the token may not read the package list (packages.read)"));
    expect(list.ok(), `GET /api/v1/hosts/${host.id}/packages answered ${list.status()}`).toBeTruthy();
    const packages = (await list.json()) as { items: { name: string }[] };

    await expect(card(page, "Updates")).toBeVisible();
    await expect(card(page, "Sources")).toBeVisible();
    const installed = card(page, "Installed packages");
    await expect(installed).toBeVisible();
    test.skip(packages.items.length === 0, absent("the panel has not read the package list of this host yet"));

    // The tools stand in the bar of the container: the search, the filter,
    // the order.
    const search = installed.getByTestId("package-search");
    await expect(search).toBeVisible();
    const table = installed.locator("table").first();
    await expect(table.locator("th", { hasText: "Package" }).first()).toBeVisible();
    await expect(table.locator("tbody tr").first()).toBeVisible();

    // The search narrows in the browser; what it finds is on the screen.
    const first = packages.items[0].name;
    await search.fill(first);
    await expect(table.getByText(first, { exact: true }).first()).toBeVisible();
    await search.fill("no-such-package-" + Date.now());
    await expect(installed.locator(".fl-empty")).toBeVisible();
    await search.fill("");
    await expect(table.locator("tbody tr").first()).toBeVisible();
    await expectHealthy(page, errors);
  });
});
