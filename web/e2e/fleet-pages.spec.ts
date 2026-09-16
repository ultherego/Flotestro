import { expect, test, type APIRequestContext, type Locator, type Page } from "@playwright/test";
import {
  expectHealthy, fleetHosts, hostTags, onlineHostWith, onlineHosts, permissions, setHostTags, watchErrors, type Host,
} from "./fleet";

/**
 * The fleet pages added after the host workspace: groups, reads,
 * monitoring, relays, settings, access and the audit trail. Each page is
 * opened, its header band and widgets are compared with what the API
 * answers, and one read-only interaction is exercised.
 *
 * Two tests leave a mark and clean it up: the group test tags a host and
 * creates a dynamic group around the tag, both removed at the end; the
 * read test orders a journal read on two hosts, which is a record the API
 * keeps - a fan-out cannot be deleted, and it changes nothing on the
 * hosts. A page the token may not see is skipped with the permission it
 * would need, not failed.
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

/** A whole-text match: "Hosts" must not find "Hosts by state". */
function exact(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}

/** The card of a fleet page by its title. */
function card(page: Page, title: string) {
  return page.locator(".card").filter({ has: page.locator(".card-title", { hasText: exact(title) }) });
}

/** Every value of a status bar has settled on a number. */
async function expectCounted(bar: Locator, count: number) {
  const values = bar.getByTestId("status-bar-value");
  await expect(values).toHaveCount(count);
  for (const value of await values.all()) {
    await expect(value).toHaveText(/^\d+$/);
  }
}

test.describe("groups", () => {
  test("a tag set on a host finds the host in the list and resolves a dynamic group", async ({ page, request }) => {
    test.skip(!granted.has("host.tag.write"), "the token may not tag a host (host.tag.write)");
    test.skip(!granted.has("host.group.write"), "the token may not create a group (host.group.write)");
    test.slow();
    const { errors } = watchErrors(page);

    // A tag is a fact the panel records; the host is not asked, so any
    // host serves, online or not. The tag and the group carry a stamp so
    // a run that died half-way leaves something recognisable behind.
    const host = onlineHosts(hosts)[0] ?? hosts[0];
    const stamp = Date.now().toString(36);
    const tag = `e2e=t${stamp}`;
    const groupName = `e2e-${stamp}`;
    const original = await hostTags(request, host.id);
    let groupID = "";

    try {
      // The tag is typed in the host header, where the operator edits it.
      await page.goto(`/hosts/${host.id}/overview`);
      const facts = page.locator(".host-header-facts");
      await facts.getByRole("button", { name: "edit tags" }).click();
      const input = facts.getByPlaceholder("tags separated by spaces, e.g. role=db tier=gold");
      await input.fill([...original, tag].join(" "));
      await facts.getByRole("button", { name: "Save" }).click();
      await expect(facts.locator(".chip", { hasText: tag })).toBeVisible();
      expect(await hostTags(request, host.id)).toContain(tag);

      // The chip leads to the host list narrowed to the tag: the tagged
      // host, and no other.
      await page.goto(`/hosts?tag=${encodeURIComponent(tag)}`);
      const table = page.locator("table").first();
      await expect(table).toBeVisible();
      await expect(table.locator("tbody tr")).toHaveCount(1);
      await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();

      // A dynamic group around the tag.
      await page.goto("/groups");
      await expect(header(page, "Groups")).toBeVisible();
      await page.locator(".page-header").getByRole("button", { name: "New group" }).click();
      const form = card(page, "New group");
      await expect(form).toBeVisible();
      await form.getByPlaceholder("e.g. databases-gold").fill(groupName);
      // The select is found through its field: the wrapping label lends
      // the control the text of the chosen option.
      await form.locator("label.field").filter({ hasText: /^Kind/ }).locator("select").selectOption("dynamic");
      await form.getByPlaceholder("key or key=value").fill(tag);
      // The builder shows the expression exactly as it will be sent.
      await expect(form.locator(".actions .source")).toHaveText(`tag=${tag}`);
      await form.getByRole("button", { name: "Create group" }).click();

      await expect(page).toHaveURL(/\/groups\/[^/]+$/);
      groupID = page.url().split("/groups/")[1];
      await expect(page.locator(".page-header").getByRole("heading")).toContainText(groupName);
      await expect(page.locator(".page-header .badge", { hasText: "dynamic" })).toBeVisible();
      await expect(card(page, "Selector").locator("p.mono")).toHaveText(`tag=${tag}`);
      // Today's answer: the one tagged host.
      const members = page.locator("table").first();
      await expect(members.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
      await expect(members.locator("tbody tr")).toHaveCount(1);
      await expect(page.getByText("1 hosts")).toBeVisible();

      // The list counts it the same way.
      await page.goto("/groups");
      const row = page.getByRole("row").filter({ has: page.getByRole("link", { name: groupName, exact: true }) });
      await expect(row).toHaveCount(1);
      await expect(row.locator(".badge", { hasText: "dynamic" })).toBeVisible();
      await expect(row.getByRole("cell").nth(3)).toHaveText("1");
      await expectHealthy(page, errors);
    } finally {
      // The group first: a selector that names a tag nobody carries would
      // only resolve to nothing, but the host is left as it was found.
      if (groupID) await request.delete(`/api/v1/host-groups/${groupID}`);
      await setHostTags(request, host.id, original);
    }
    expect(await hostTags(request, host.id)).toEqual(original);
    if (groupID) await expectDeleted(request, `/api/v1/host-groups/${groupID}`);
  });

  test("the empty group form refuses to create without a name or a member", async ({ page }) => {
    test.skip(!granted.has("host.group.write"), "the token may not create a group (host.group.write)");
    await page.goto("/groups");
    await expect(header(page, "Groups")).toBeVisible();
    await page.locator(".page-header").getByRole("button", { name: "New group" }).click();
    const form = card(page, "New group");
    await expect(form.getByRole("button", { name: "Create group" })).toBeDisabled();
    await form.getByPlaceholder("e.g. databases-gold").fill("nobody");
    // A static group needs at least one member; the name alone is not one.
    await expect(form.getByRole("button", { name: "Create group" })).toBeDisabled();
    await form.getByRole("button", { name: "Cancel" }).click();
    await expect(form).toHaveCount(0);
  });
});

test.describe("reads", () => {
  test("a journal read fans out to two hosts and the lines come back merged", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), "the token may not order a read (job.create)");
    const capable = onlineHosts(hosts).filter((host) => host.capabilities?.some((item) => item.name === "journald" && item.available));
    test.skip(capable.length < 2, `only ${capable.length} online hosts with journald; a fan-out needs two`);
    test.slow();
    const { errors } = watchErrors(page);
    const targets = capable.slice(0, 2);

    await page.goto("/reads");
    await expect(header(page, "Reads")).toBeVisible();
    await expect(card(page, "Hosts by state").getByTestId("status-bar")).toBeVisible();
    await expect(card(page, "Your reads")).toBeVisible();
    await expect(card(page, "By operation")).toBeVisible();

    await page.locator(".page-header").getByRole("button", { name: "New read" }).click();
    const form = card(page, "New read");
    await expect(form).toBeVisible();
    const operation = form.locator("label.field").filter({ hasText: /^Operation/ }).locator("select");
    await expect(operation.locator("option").first()).toBeAttached();
    test.skip((await operation.locator("option[value='journal.read']").count()) === 0, "this installation opens no journal read to a fan-out");
    await operation.selectOption("journal.read");
    await expect(form.locator("textarea")).toHaveValue(/"journal"/);
    await form.getByPlaceholder("e.g. checking the leak on the web tier").fill("e2e journal read on two hosts");

    await form.locator("label.field").filter({ hasText: /^Named by/ }).locator("select").selectOption("hosts");
    const chooser = form.locator("table");
    await expect(chooser).toBeVisible();
    for (const host of targets) {
      await chooser.getByRole("row").filter({ has: page.getByRole("cell", { name: host.hostname, exact: true }) }).getByRole("checkbox").check();
    }
    await expect(form.getByText("2 chosen")).toBeVisible();
    await form.locator(".card-foot").getByRole("button", { name: "Read", exact: true }).click();

    // The order leads to the fan-out page, which follows the jobs until
    // every host has answered.
    await expect(page).toHaveURL(/\/reads\/[^/]+$/);
    const id = page.url().split("/reads/")[1];
    await expect(page.locator(".page-header").getByRole("heading")).toContainText("journal.read");
    await expect(page.locator(".page-header .page-description")).toContainText("every host answered", { timeout: 120_000 });

    const response = await request.get(`/api/v1/reads/${id}`);
    expect(response.ok(), `GET /api/v1/reads/${id} answered ${response.status()}`).toBeTruthy();
    const view = (await response.json()) as {
      counts: { queued: number; running: number; succeeded: number; failed: number };
      hosts: { hostname: string; state: string }[];
      timeline?: unknown[];
    };
    expect(view.counts.queued + view.counts.running).toBe(0);
    expect(view.hosts.map((host) => host.hostname).sort()).toEqual(targets.map((host) => host.hostname).sort());
    expect(view.counts.succeeded, `no host answered: ${JSON.stringify(view.hosts)}`).toBeGreaterThan(0);

    // The hosts table names both, and the states match the API.
    const table = card(page, "Hosts").locator("table");
    for (const host of view.hosts) {
      const row = table.getByRole("row").filter({ has: page.getByRole("link", { name: host.hostname, exact: true }) });
      await expect(row).toHaveCount(1);
      await expect(row.locator(".badge").first()).toHaveText(stateLabel(host.state));
    }

    // The merged timeline: every line carries the chip of its host, or
    // the page says that no line carried a timestamp to merge by.
    const timeline = card(page, "Timeline");
    await expect(timeline).toBeVisible();
    const merged = timeline.locator("pre.hm-log > div");
    const untimed = timeline.getByText("No line carries a timestamp");
    await expect(merged.first().or(untimed)).toBeVisible();
    if (await merged.count()) {
      const named = new Set<string>();
      for (const chip of await merged.locator(".chip").all()) named.add((await chip.textContent()) ?? "");
      for (const host of view.hosts.filter((entry) => entry.state === "succeeded")) {
        expect(named, `the merged timeline carries no line of ${host.hostname}`).toContain(host.hostname);
      }
    }
    // Grouped by host, every answered host has its own block of lines.
    await timeline.getByRole("button", { name: "group by host" }).click();
    for (const host of view.hosts.filter((entry) => entry.state === "succeeded")) {
      await expect(timeline.locator("h4.widget-subhead", { hasText: host.hostname })).toContainText(/\d+ lines/);
    }
    await expect(timeline.locator("pre.hm-log")).toHaveCount(view.counts.succeeded);

    // The list counts the new read among the others.
    await page.goto("/reads");
    await expect(card(page, "Your reads").getByRole("link", { name: "journal.read" }).first()).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("monitoring", () => {
  test("the fleet page counts the alerts and filters the history by state", async ({ page, request }) => {
    test.skip(!granted.has("monitoring.read"), "the token may not read monitoring (monitoring.read)");
    const { errors } = watchErrors(page);
    const overview = await request.get("/api/v1/monitoring");
    test.skip(overview.status() === 503, "this installation runs without the built-in monitoring");
    expect(overview.ok(), `GET /api/v1/monitoring answered ${overview.status()}`).toBeTruthy();
    const summary = (await overview.json()) as { hosts_reporting: number; hosts_silent: number; rules: number };
    // The overview counts the enabled rules; the table lists every rule.
    const catalogue = await request.get("/api/v1/monitoring/rules");
    const listed = catalogue.ok() ? ((await catalogue.json()) as { items: { enabled: boolean }[] }).items : undefined;
    if (listed) expect(listed.filter((rule) => rule.enabled)).toHaveLength(summary.rules);

    await page.goto("/monitoring");
    await expect(header(page, "Monitoring")).toBeVisible();
    // Three severities, then the alerts somebody took, the pending and
    // the silenced ones: six segments, each a number.
    const firing = card(page, "Firing now").getByTestId("status-bar");
    await expectCounted(firing, 6);
    await expect(firing.getByRole("listitem").filter({ hasText: "Acknowledged" })).toHaveCount(1);

    // The coverage tiles carry the numbers of the API answer.
    const coverage = card(page, "Coverage");
    await expect(coverage.locator(".stat").filter({ hasText: "Hosts reporting" }).locator(".stat-value")).toHaveText(String(summary.hosts_reporting));
    await expect(coverage.locator(".stat").filter({ hasText: "Hosts silent" }).locator(".stat-value")).toHaveText(String(summary.hosts_silent));
    await expect(coverage.locator(".stat").filter({ hasText: "Enabled rules" }).locator(".stat-value")).toHaveText(String(summary.rules));

    // The rules table lists as many rules as the tiles count, or says
    // that there are none.
    const rules = card(page, "Rules");
    await expect(rules.locator("tbody tr").first().or(rules.getByText(/No rules yet|You do not have permission/))).toBeVisible();
    if (listed && listed.length > 0) await expect(rules.locator("tbody tr")).toHaveCount(listed.length);

    // The history filter runs on the server.
    const history = card(page, "Recent alerts");
    await expect(history.locator("tbody tr").first().or(history.getByText("No alerts recorded in this state."))).toBeVisible();
    const filtered = page.waitForResponse((response) => response.url().includes("/api/v1/monitoring/alerts?") && response.url().includes("state=resolved"));
    await history.locator(".card-actions select").selectOption("resolved");
    expect((await filtered).ok()).toBeTruthy();
    await expect(history.locator("tbody tr").first().or(history.getByText("No alerts recorded in this state."))).toBeVisible();
    for (const badge of await history.locator("tbody tr td:nth-child(4) .badge").all()) {
      await expect(badge).toHaveText("resolved");
    }
    await expect(card(page, "Silences in force")).toBeVisible();
    await expectHealthy(page, errors);
  });

  test("the host page draws the samples of the window it is asked for", async ({ page, request }) => {
    test.skip(!granted.has("monitoring.read"), "the token may not read monitoring (monitoring.read)");
    const host = onlineHostWith(hosts, "monitoring");
    test.skip(!host, "no online host reports the monitoring adapter");
    const target = host as Host;
    const { errors } = watchErrors(page);

    const metrics = await request.get(`/api/v1/hosts/${target.id}/metrics?range=3h`);
    test.skip(metrics.status() === 503, "this installation runs without the built-in monitoring");
    expect(metrics.ok(), `GET /api/v1/hosts/${target.id}/metrics answered ${metrics.status()}`).toBeTruthy();
    const series = (await metrics.json()) as { points?: unknown[]; sampling_interval_seconds: number };

    await page.goto(`/hosts/${target.id}/monitoring`);
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Monitoring", exact: true })).toBeVisible();
    const freshness = page.locator(".hm-freshness");
    await expect(freshness).toContainText(`sampled every ${series.sampling_interval_seconds} s`);

    // The alert bar of the host settles on numbers once the report is in.
    const alerts = page.locator(".hm-section").filter({ has: page.locator("h3", { hasText: exact("Alerts") }) }).first();
    await expectCounted(alerts.getByTestId("status-bar"), 5);

    // A sample means a chart; none means the page says so instead of a
    // chart of zeros.
    const cpu = page.locator(".hm-section").filter({ has: page.locator("h3", { hasText: exact("CPU") }) });
    if ((series.points ?? []).length > 0) {
      await expect(cpu.locator("svg.chart")).toBeVisible();
    } else {
      await expect(cpu.locator(".empty")).toBeVisible();
    }

    // The window switch asks the server for another range.
    const wider = page.waitForResponse((response) => response.url().includes(`/api/v1/hosts/${target.id}/metrics?range=24h`));
    await page.getByRole("group", { name: "Window" }).getByRole("button", { name: "24 hours" }).click();
    expect((await wider).ok()).toBeTruthy();
    await expect(page.getByRole("group", { name: "Window" }).getByRole("button", { name: "24 hours" })).toHaveClass(/active/);

    for (const title of ["Load", "Memory", "Network", "Filesystems", "Facts", "Silence", "Silences in force"]) {
      await expect(page.locator(".hm-section h3", { hasText: exact(title) }).first()).toBeVisible();
    }
    // The silence button stays off without a reason: a silence is a
    // decision with a reason and an owner.
    await expect(page.getByRole("button", { name: /^Silence (every rule of this host|this rule)$/ })).toBeDisabled();
    await expectHealthy(page, errors);
  });
});

test.describe("relays", () => {
  test("the relay list agrees with the API and opens a relay", async ({ page, request }) => {
    test.skip(!granted.has("host.enroll.read"), "the token may not read the relays (host.enroll.read)");
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/relays");
    expect(response.ok(), `GET /api/v1/relays answered ${response.status()}`).toBeTruthy();
    const relays = ((await response.json()) as { items: { id: string; name: string; site: string; state: string }[] }).items;

    await page.goto("/relays");
    await expect(header(page, "Relays")).toBeVisible();
    const state = card(page, "State");
    await expect(state).toContainText(`${relays.length} relays`);
    await expectCounted(state.getByTestId("status-bar"), 4);
    await expect(card(page, "By site")).toBeVisible();

    const table = page.locator("table").first();
    if (relays.length === 0) {
      await expect(page.getByText("No relay is registered.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }
    await expect(table.locator("tbody tr")).toHaveCount(relays.length);
    for (const relay of relays) {
      const row = table.getByRole("row").filter({ has: page.getByRole("link", { name: relay.name, exact: true }) });
      await expect(row).toHaveCount(1);
      await expect(row.locator(".badge").first()).toHaveText(relay.state.replace(/_/g, " "));
    }

    // One relay: the details and the hosts that come through it.
    const first = relays[0];
    await table.getByRole("link", { name: first.name, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/relays/${first.id}$`));
    await expect(header(page, first.name)).toBeVisible();
    await expect(page.locator(".page-header .breadcrumb").getByRole("link", { name: "Relays" })).toBeVisible();
    await expect(card(page, "Details")).toContainText(first.site);
    await expect(card(page, "Last report")).toBeVisible();
    const attested = card(page, "Hosts attested");
    await expect(attested.locator("tbody tr").first().or(attested.getByText("No host has an open session through this relay."))).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("settings", () => {
  test("every area of the configuration is a card with its facts", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), "the token may not read the settings (settings.read)");
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/settings");
    expect(response.ok(), `GET /api/v1/settings answered ${response.status()}`).toBeTruthy();
    const settings = (await response.json()) as {
      source: string;
      areas: { key: string; title: string; facts: { key: string; value?: unknown; secret?: boolean; configured?: boolean }[] }[];
    };
    expect(settings.areas.length).toBeGreaterThan(0);

    await page.goto("/settings");
    await expect(header(page, "Settings")).toBeVisible();
    await expect(page.locator(".page-header .page-description")).toContainText(settings.source);
    const cards = page.locator(".widgets .card");
    await expect(cards).toHaveCount(settings.areas.length);
    for (const area of settings.areas) {
      const section = card(page, area.title);
      await expect(section).toHaveCount(1);
      await expect(section.locator("dt")).toHaveCount(area.facts.length);
      // A secret is never shown, only whether it is set.
      for (const fact of area.facts.filter((entry) => entry.secret)) {
        const value = section.locator("dd").nth(area.facts.indexOf(fact));
        await expect(value).toContainText(fact.configured ? "set" : "not set");
        // Not even the mask the API sends in place of the value.
        if (typeof fact.value === "string" && fact.value !== "") await expect(value).not.toContainText(fact.value);
      }
    }
    await expectHealthy(page, errors);
  });
});

test.describe("access", () => {
  test("the access review tab counts the identities and filters the flagged ones", async ({ page, request }) => {
    test.skip(!granted.has("principal.manage"), "the token may not manage access (principal.manage)");
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/access/review");
    expect(response.ok(), `GET /api/v1/access/review answered ${response.status()}`).toBeTruthy();
    const review = (await response.json()) as { count: number; flagged: number; items: { flags: string[] }[] };

    await page.goto("/access");
    await expect(header(page, "Access")).toBeVisible();
    const tabs = page.locator(".tabs").first();
    await expect(tabs.getByRole("button", { name: "Group mappings" })).toHaveClass(/active/);
    await tabs.getByRole("button", { name: "Access review" }).click();
    await expect(tabs.getByRole("button", { name: "Access review" })).toHaveClass(/active/);

    const stats = page.locator(".stats");
    await expect(stats.locator(".stat").filter({ hasText: "Identities" }).locator(".stat-value")).toHaveText(String(review.count));
    await expect(stats.locator(".stat").filter({ hasText: "Flagged" }).locator(".stat-value")).toHaveText(String(review.flagged));

    const table = card(page, "Access review");
    await expect(table.locator("tbody tr")).toHaveCount(review.items.length);
    await expect(table.getByRole("link", { name: "Export CSV" })).toHaveAttribute("href", "/api/v1/access/review?format=csv");

    // The filter is applied in the browser: the flagged rows stay.
    await table.locator(".card-actions select").selectOption("flagged");
    const flagged = review.items.filter((item) => item.flags.length > 0).length;
    if (flagged === 0) {
      await expect(table.getByText("No identity matches the filter.")).toBeVisible();
    } else {
      await expect(table.locator("tbody tr")).toHaveCount(flagged);
      for (const row of await table.locator("tbody tr").all()) {
        await expect(row.locator(".badge.warn").first()).toBeVisible();
      }
    }
    await expectHealthy(page, errors);
  });
});

test.describe("audit", () => {
  test("the trail is charted, counted and filtered by outcome on the server", async ({ page }) => {
    test.skip(!granted.has("audit.read"), "the token may not read the audit trail (audit.read)");
    const { errors } = watchErrors(page);
    await page.goto("/audit");
    await expect(header(page, "Audit")).toBeVisible();

    const chart = card(page, "Events per hour");
    await expect(chart.locator("svg").or(chart.getByText("No events."))).toBeVisible();
    const outcome = card(page, "Outcome");
    await expect(outcome.getByTestId("status-bar")).toHaveClass(/compact/);
    await expectCounted(outcome.getByTestId("status-bar"), 3);

    const count = page.locator(".toolbar").getByText(/^\d+ events$/);
    await expect(count).toBeVisible();
    const listed = Number((await count.textContent())?.split(" ")[0]);
    const rows = page.locator("table tbody tr:not(.detail-row)");
    if (listed > 0) await expect(rows).toHaveCount(listed);

    // Denials only: the server narrows the page and the badges agree.
    const denied = page.waitForResponse((response) => response.url().includes("/api/v1/audit?") && response.url().includes("outcome=denied"));
    await page.locator(".toolbar select").selectOption("denied");
    expect((await denied).ok()).toBeTruthy();
    await expect(rows.first().or(page.getByText("No events."))).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row.locator("td").nth(5).locator(".badge")).toHaveText("denied");
    }
    await expectHealthy(page, errors);
  });

  test("an event that rests on an approval shows its chain under the row", async ({ page, request }) => {
    test.skip(!granted.has("audit.read"), "the token may not read the audit trail (audit.read)");
    const response = await request.get("/api/v1/audit?limit=100");
    expect(response.ok(), `GET /api/v1/audit answered ${response.status()}`).toBeTruthy();
    const events = ((await response.json()) as { items: { action: string; approval_chain?: { created_by: string; approvers: string[] } }[] }).items;
    const approved = events.find((event) => event.approval_chain);
    test.skip(!approved, "no event of the last hundred carries an approval chain");
    const chain = approved?.approval_chain as { created_by: string; approvers: string[] };

    await page.goto(`/audit?action=${encodeURIComponent((approved as { action: string }).action)}`);
    await expect(header(page, "Audit")).toBeVisible();
    const shown = page.locator(".fp-audit-chain").first();
    await expect(shown).toBeVisible();
    await expect(shown).toContainText("Approval chain");
    await expect(shown).toContainText(`ordered by ${chain.created_by}`);
    await expect(shown).toContainText(chain.approvers.length > 0 ? chain.approvers[0] : "—");
  });
});

/** The badge text of a job state, as the panel names the ones a read ends in. */
function stateLabel(state: string): string {
  const names: Record<string, string> = { timed_out: "timed out", ineligible: "cannot run this", awaiting_approval: "awaiting approval" };
  return names[state] ?? state;
}

/** The resource answers 404 once it is gone. */
async function expectDeleted(request: APIRequestContext, path: string) {
  const response = await request.get(path);
  expect(response.status(), `${path} still answers ${response.status()}`).toBe(404);
}
