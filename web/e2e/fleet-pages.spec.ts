import { expect, test, type APIRequestContext, type Locator } from "@playwright/test";
import {
  absent, card, expectHealthy, fleetHosts, head, hostTags, onlineHostWith, onlineHosts, permissions,
  setHostTags, watchErrors, type Host,
} from "./fleet";

/**
 * The fleet pages added after the host workspace: groups, reads, monitoring,
 * relays, settings, access and the audit trail.
 */

let hosts: Host[] = [];
let granted = new Set<string>();

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
  granted = await permissions(request);
});

/** Every segment a band drew has settled on a number. */
async function expectCounted(band: Locator) {
  await expect(band).toBeVisible();
  for (const value of await band.locator(".fl-band-value").all()) {
    await expect(value).toHaveText(/^\d+$/);
  }
}

test.describe("groups", () => {
  test("a tag set on a host finds the host in the list and resolves a dynamic group", async ({ page, request }) => {
    test.skip(!granted.has("host.tag.write"), absent("the token may not tag a host (host.tag.write)"));
    test.skip(!granted.has("host.group.write"), absent("the token may not create a group (host.group.write)"));
    test.slow();
    const { errors } = watchErrors(page);

    // A tag is a fact the panel records; the host is not asked, so any host
    // serves, online or not.
    const host = onlineHosts(hosts)[0] ?? hosts[0];
    const stamp = Date.now().toString(36);
    const tag = `e2e=t${stamp}`;
    const groupName = `e2e-${stamp}`;
    const original = await hostTags(request, host.id);
    let groupID = "";

    try {
      // The tag is typed in the host's own head, where the operator edits it.
      await page.goto(`/hosts/${host.id}/overview`);
      const lead = page.locator(".fl-head-lead").first();
      await lead.getByTestId("edit-tags").click();
      await lead.locator("input").first().fill([...original, tag].join(" "));
      await lead.getByRole("button", { name: "Save" }).click();
      await expect(lead.locator(".fl-tag", { hasText: tag })).toBeVisible();
      expect(await hostTags(request, host.id)).toContain(tag);

      // The chip leads to the host list narrowed to the tag: the tagged
      // host, and no other.
      await page.goto(`/hosts?tag=${encodeURIComponent(tag)}`);
      const table = page.getByTestId("hosts");
      await expect(table).toBeVisible();
      await expect(table.locator("tbody tr")).toHaveCount(1);
      await expect(table.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();

      // A dynamic group around the tag.
      await page.goto("/groups");
      await expect(head(page, "Groups")).toBeVisible();
      await page.getByTestId("new-group").click();
      const form = card(page, "New group");
      await expect(form).toBeVisible();
      await form.getByTestId("group-name").fill(groupName);
      await form.getByTestId("group-kind").selectOption("dynamic");
      await form.getByTestId("rule-value-tag").fill(tag);
      // The builder shows the expression exactly as it will be sent.
      await expect(form.locator(".fl-note.fl-mono")).toHaveText(`tag=${tag}`);
      await form.getByTestId("create-group").click();

      /* Creating a group no longer leaves the list: the form closes and
         the group is on the list it was made from, which is where it is
         then read. The claim - a selector group that resolves to the one
         tagged host - is made on the row and on the group's own screen. */
      await expect(form).toHaveCount(0);
      const row = page.locator(`tr[data-testid="group-${groupName}"]`);
      await expect(row).toHaveCount(1);
      await expect(row.locator(".fl-pill", { hasText: "selector" })).toBeVisible();
      await expect(row.getByRole("cell").nth(3)).toHaveText("1");

      await row.getByRole("link", { name: groupName, exact: true }).click();
      await expect(page).toHaveURL(/\/groups\/[^/]+$/);
      groupID = page.url().split("/groups/")[1];
      /* One group is read on the groups screen rather than on a page of
         its own, so the heading stays the section's; the group names
         itself in its own container. */
      await expect(card(page, "Group")).toContainText(groupName);
      await expect(card(page, "Group")).toContainText("selector");
      await expect(page.getByTestId("group-selector")).toContainText(`tag=${tag}`);
      // Today's answer: the one tagged host.
      const members = page.getByTestId("group-members");
      await expect(members.getByRole("link", { name: host.hostname, exact: true })).toBeVisible();
      await expect(members.locator("tbody tr")).toHaveCount(1);
      await expect(page.getByTestId("kpi-group-hosts").locator(".fl-kpi-value")).toHaveText("1");
      await expectHealthy(page, errors);
    } finally {
      // The group first: a selector that names a tag nobody carries would
      // only resolve to nothing, but the host is left as it was found.
      if (!groupID) {
        const listed = await request.get("/api/v1/host-groups?limit=200");
        const found = listed.ok()
          ? ((await listed.json()) as { items: { id: string; name: string }[] }).items.find((one) => one.name === groupName)
          : undefined;
        groupID = found?.id ?? "";
      }
      if (groupID) await request.delete(`/api/v1/host-groups/${groupID}`);
      await setHostTags(request, host.id, original);
    }
    expect(await hostTags(request, host.id)).toEqual(original);
    if (groupID) await expectDeleted(request, `/api/v1/host-groups/${groupID}`);
  });

  test("the empty group form refuses to create without a name or a member", async ({ page }) => {
    test.skip(!granted.has("host.group.write"), absent("the token may not create a group (host.group.write)"));
    await page.goto("/groups");
    await expect(head(page, "Groups")).toBeVisible();
    await page.getByTestId("new-group").click();
    const form = card(page, "New group");
    await expect(form.getByTestId("create-group")).toBeDisabled();
    await form.getByTestId("group-name").fill("nobody");
    // A static group needs at least one member; the name alone is not one.
    await expect(form.getByTestId("create-group")).toBeDisabled();
    await form.getByRole("button", { name: "Cancel" }).click();
    await expect(form).toHaveCount(0);
  });
});

test.describe("reads", () => {
  test("a journal read fans out to two hosts and the lines come back merged", async ({ page, request }) => {
    test.skip(!granted.has("job.create"), absent("the token may not order a read (job.create)"));
    const capable = onlineHosts(hosts).filter((host) => host.capabilities?.some((item) => item.name === "journald" && item.available));
    test.skip(capable.length < 2, absent(`only ${capable.length} online hosts with journald; a fan-out needs two`));
    test.slow();
    const { errors } = watchErrors(page);
    const targets = capable.slice(0, 2);

    await page.goto("/reads");
    await expect(head(page, "Reads")).toBeVisible();
    await expect(card(page, "Hosts by state").getByTestId("read-states")).toBeVisible();
    await expect(card(page, "Your reads")).toBeVisible();
    await expect(card(page, "By operation")).toBeVisible();

    await page.getByTestId("new-read").click();
    const form = card(page, "New read");
    await expect(form).toBeVisible();
    const operation = form.getByTestId("read-action");
    await expect(operation.locator("option").first()).toBeAttached();
    test.skip((await operation.locator("option[value='journal.read']").count()) === 0, absent("this installation opens no journal read to a fan-out"));
    await operation.selectOption("journal.read");
    await expect(form.getByTestId("read-payload")).toHaveValue(/"journal"/);
    await form.getByPlaceholder("e.g. checking the leak on the web tier").fill("e2e journal read on two hosts");

    await form.getByRole("button", { name: "hosts by name" }).click();
    const chooser = form.getByTestId("read-hosts");
    await expect(chooser).toBeVisible();
    for (const host of targets) {
      await chooser.locator(`tr[data-testid="pick-${host.hostname}"]`).getByRole("checkbox").check();
    }
    await expect(form.getByText("2 chosen")).toBeVisible();
    await form.getByTestId("order-read").click();

    // The order leads to the fan-out page, which follows the jobs until
    // every host has answered.
    await expect(page).toHaveURL(/\/reads\/[^/]+$/);
    const id = page.url().split("/reads/")[1];
    await expect.poll(async () => {
      const answer = await request.get(`/api/v1/reads/${id}`);
      if (!answer.ok()) return 1;
      const view = (await answer.json()) as { counts: { queued: number; running: number } };
      return view.counts.queued + view.counts.running;
    }, { timeout: 120_000, message: "the fan-out never settled" }).toBe(0);

    const response = await request.get(`/api/v1/reads/${id}`);
    expect(response.ok(), `GET /api/v1/reads/${id} answered ${response.status()}`).toBeTruthy();
    const view = (await response.json()) as {
      counts: { queued: number; running: number; succeeded: number; failed: number };
      hosts: { hostname: string; state: string }[];
      timeline?: unknown[];
    };
    expect(view.hosts.map((host) => host.hostname).sort()).toEqual(targets.map((host) => host.hostname).sort());
    expect(view.counts.succeeded, `no host answered: ${JSON.stringify(view.hosts)}`).toBeGreaterThan(0);

    // The band over the fan-out counts the same states the API does.
    await expectCounted(page.getByTestId("read-host-states"));
    await expect(page.getByTestId("read-host-states")).toContainText(String(view.counts.succeeded));

    // The hosts table names both, and the states match the API.
    const table = page.getByTestId("fanout-hosts");
    for (const host of view.hosts) {
      const row = table.locator("tbody tr").filter({ has: page.getByRole("link", { name: host.hostname, exact: true }) });
      await expect(row).toHaveCount(1);
      await expect(row.locator(".fl-pill").first()).toHaveText(stateLabel(host.state));
    }

    // The merged timeline: every line carries the chip of its host, or
    // the page says that no line carried a timestamp to merge by.
    const timeline = card(page, "Timeline");
    await expect(timeline).toBeVisible();
    const merged = page.getByTestId("read-timeline").locator("div");
    const untimed = timeline.getByText("No line carries a timestamp");
    await expect(merged.first().or(untimed).first()).toBeVisible();
    if (await merged.count()) {
      const named = new Set<string>();
      for (const chip of await merged.locator(".fl-tag").all()) named.add((await chip.textContent()) ?? "");
      for (const host of view.hosts.filter((entry) => entry.state === "succeeded")) {
        expect(named, `the merged timeline carries no line of ${host.hostname}`).toContain(host.hostname);
      }
    }
    // Grouped by host, every answered host has its own block of lines.
    await timeline.getByRole("button", { name: "group by host" }).click();
    for (const host of view.hosts.filter((entry) => entry.state === "succeeded")) {
      await expect(timeline.locator("h3.fl-subhead", { hasText: host.hostname })).toContainText(/\d+ lines/);
    }

    // The list counts the new read among the others.
    await page.goto("/reads");
    await expect(card(page, "Your reads").getByRole("link", { name: "journal.read" }).first()).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("monitoring", () => {
  test("the fleet page counts the alerts and filters the history by state", async ({ page, request }) => {
    test.skip(!granted.has("monitoring.read"), absent("the token may not read monitoring (monitoring.read)"));
    const { errors } = watchErrors(page);
    const overview = await request.get("/api/v1/monitoring");
    test.skip(overview.status() === 503, absent("this installation runs without the built-in monitoring"));
    expect(overview.ok(), `GET /api/v1/monitoring answered ${overview.status()}`).toBeTruthy();
    const summary = (await overview.json()) as { hosts_reporting: number; hosts_silent: number; rules: number };
    // The overview counts the enabled rules; the table lists every rule.
    const catalogue = await request.get("/api/v1/monitoring/rules");
    const listed = catalogue.ok() ? ((await catalogue.json()) as { items: { enabled: boolean }[] }).items : undefined;
    if (listed) expect(listed.filter((rule) => rule.enabled)).toHaveLength(summary.rules);

    await page.goto("/monitoring");
    await expect(head(page, "Monitoring")).toBeVisible();

    /* The coverage of the sampling used to be a sentence across the top;
       it is three figures now, read straight off the same answer. */
    await expect(page.getByTestId("kpi-Hosts reporting").locator(".fl-kpi-value"))
      .toHaveText(String(summary.hosts_reporting));
    await expect(page.getByTestId("kpi-Gone quiet").locator(".fl-kpi-value"))
      .toHaveText(String(summary.hosts_silent));
    await expect(page.getByTestId("kpi-Rules enabled").locator(".fl-kpi-value"))
      .toHaveText(String(summary.rules));

    // Severity on its own, and what has been done about an alert beside
    // it as figures rather than mixed into the same band.
    const firing = card(page, "Firing now");
    await expectCounted(firing.getByTestId("severities"));
    await expect(firing.locator(".fl-figs")).toContainText("acknowledged");

    // The rules table lists as many rules as the catalogue holds, or says
    // that there are none.
    const rules = card(page, "Rules");
    await expect(
      page.getByTestId("rules").or(rules.getByText(/No rules yet|You do not have permission/)).first(),
    ).toBeVisible();
    if (listed && listed.length > 0) await expect(page.getByTestId("rules").locator("tbody tr")).toHaveCount(listed.length);

    // The history filter runs on the server.
    const history = card(page, "Alerts");
    await expect(
      page.getByTestId("alerts").or(history.getByText("No alert is recorded in this state.")).first(),
    ).toBeVisible();
    const filtered = page.waitForResponse((response) => response.url().includes("/api/v1/monitoring/alerts?") && response.url().includes("state=resolved"));
    await history.getByTestId("alert-state").selectOption("resolved");
    expect((await filtered).ok()).toBeTruthy();
    await expect(
      page.getByTestId("alerts").or(history.getByText("No alert is recorded in this state.")).first(),
    ).toBeVisible();
    // Every row the filter left carries the state it promised.
    for (const row of await page.getByTestId("alerts").locator("tbody tr").all()) {
      await expect(row.locator(".fl-pill", { hasText: "resolved" }).first()).toBeVisible();
    }
    await expect(card(page, "Silences in force")).toBeVisible();
    await expectHealthy(page, errors);
  });

  test("the host page draws the samples of the window it is asked for", async ({ page, request }) => {
    test.skip(!granted.has("monitoring.read"), absent("the token may not read monitoring (monitoring.read)"));
    const host = onlineHostWith(hosts, "monitoring");
    test.skip(!host, absent("no online host reports the monitoring adapter"));
    const target = host as Host;
    const { errors } = watchErrors(page);

    const metrics = await request.get(`/api/v1/hosts/${target.id}/metrics?range=3h`);
    test.skip(metrics.status() === 503, absent("this installation runs without the built-in monitoring"));
    expect(metrics.ok(), `GET /api/v1/hosts/${target.id}/metrics answered ${metrics.status()}`).toBeTruthy();
    const series = (await metrics.json()) as { points?: unknown[]; sampling_interval_seconds: number };

    await page.goto(`/hosts/${target.id}/monitoring`);
    await expect(page.locator(".fl-head-title").first()).toContainText(target.hostname);
    // How often the host samples is a fact of the sampling card now, in
    // the host's own words rather than a line under the heading.
    await expect(card(page, "Sampling")).toContainText(`every ${series.sampling_interval_seconds} s`);

    // The alert band of the host settles on numbers once the report is in.
    await expectCounted(page.getByTestId("alert-states"));

    // A sample means a chart; none means the page says so instead of a
    // chart of zeros.
    const cpu = card(page, "CPU");
    if ((series.points ?? []).length > 0) {
      await expect(page.getByTestId("cpu-chart")).toBeVisible();
    } else {
      await expect(cpu.locator(".fl-empty")).toBeVisible();
    }

    // The window switch asks the server for another range.
    const window = page.getByRole("group", { name: "Window" });
    const wider = page.waitForResponse((response) => response.url().includes(`/api/v1/hosts/${target.id}/metrics?range=24h`));
    await window.getByRole("button", { name: "24 hours" }).click();
    expect((await wider).ok()).toBeTruthy();
    await expect(window.getByRole("button", { name: "24 hours" })).toHaveAttribute("aria-pressed", "true");

    for (const title of ["Load", "Memory", "Network", "Filesystems", "Facts", "Silence", "Silences in force"]) {
      await expect(card(page, title).first()).toBeVisible();
    }
    // The silence button stays off without a reason: a silence is a
    // decision with a reason and an owner.
    await expect(page.getByTestId("silence")).toBeDisabled();
    await expectHealthy(page, errors);
  });
});

test.describe("relays", () => {
  test("the relay list agrees with the API and opens a relay", async ({ page, request }) => {
    test.skip(!granted.has("host.enroll.read"), absent("the token may not read the relays (host.enroll.read)"));
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/relays");
    expect(response.ok(), `GET /api/v1/relays answered ${response.status()}`).toBeTruthy();
    const relays = ((await response.json()) as { items: { id: string; name: string; site: string; state: string }[] }).items;

    await page.goto("/relays");
    await expect(head(page, "Relays")).toBeVisible();
    await expectCounted(card(page, "State").getByTestId("relay-states"));
    await expect(card(page, "By site")).toBeVisible();

    if (relays.length === 0) {
      await expect(page.getByText("No relay is registered.")).toBeVisible();
      await expectHealthy(page, errors);
      return;
    }
    const table = page.getByTestId("relays");
    await expect(table.locator("tbody tr")).toHaveCount(relays.length);
    for (const relay of relays) {
      const row = table.locator("tbody tr").filter({ has: page.getByTestId(`pick-${relay.name}`) });
      await expect(row).toHaveCount(1);
      await expect(row.locator(".fl-pill").first()).toHaveText(relay.state.replace(/_/g, " "));
    }

    /* One relay: its own container beside the list, not a page of its
       own. The reader picks it and reads it where the list is, which is
       the shape every list on this panel has. */
    const first = relays[0];
    await page.getByTestId(`pick-${first.name}`).click();
    await expect(card(page, first.name)).toContainText(first.site);
    await expect(card(page, "Hosts attested")).toBeVisible();
    await expect(card(page, "The spool over time")).toBeVisible();
    await expectHealthy(page, errors);
  });
});

test.describe("settings", () => {
  test("every area of the configuration is a container with its facts", async ({ page, request }) => {
    test.skip(!granted.has("settings.read") && !granted.has("principal.manage"), absent("the token may not read the settings (settings.read)"));
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/settings");
    expect(response.ok(), `GET /api/v1/settings answered ${response.status()}`).toBeTruthy();
    const settings = (await response.json()) as {
      source: string;
      areas: { key: string; title: string; facts: { key: string; value?: unknown; secret?: boolean; configured?: boolean }[] }[];
    };
    expect(settings.areas.length).toBeGreaterThan(0);

    await page.goto("/settings");
    await expect(head(page, "Settings")).toBeVisible();
    // Where the values come from is the long answer, and it waits behind the
    // mark beside the title rather than taking the top of every page view.
    await expect(page.getByTestId("screen-help")).toHaveCount(0);
    await page.getByTestId("screen-help-toggle").click();
    // In the screen's own words, not in the server's. The API sends a source
    // string, but putting it on the page would print an English constant to
    // a Polish reader - so what is checked is that the page states the rule
    // that string exists for: these values are read at start and a change
    // needs a restart.
    await expect(page.getByTestId("screen-help")).toContainText("needs a restart");
    await expect(card(page, "What the process was started with")).toContainText("Read at start");

    // One container per area the API reports.
    for (const area of settings.areas) {
      const tile = card(page, area.title);
      await expect(tile, `no container for ${area.title}`).toHaveCount(1);
      await expect(tile.locator("dt")).toHaveCount(area.facts.length);
      await expect(tile.locator(".fl-card-note")).toContainText(`${area.facts.length} value`);
      // A secret is never shown, only whether it is set.
      for (const fact of area.facts.filter((entry) => entry.secret)) {
        const value = tile.locator("dd").nth(area.facts.indexOf(fact));
        await expect(value).toContainText(fact.configured ? "set" : "not set");
        // Not even the mask the API sends in place of the value.
        if (typeof fact.value === "string" && fact.value !== "") await expect(value).not.toContainText(fact.value);
      }
    }

    // The search is how a configuration screen is actually read: a name in
    // mind, and only what carries it on the screen.
    const first = settings.areas[0];
    await page.getByTestId("settings-search").fill(first.title);
    await expect(card(page, first.title)).toHaveCount(1);
    for (const area of settings.areas.filter((one) => one.title !== first.title)) {
      await expect(card(page, area.title)).toHaveCount(0);
    }

    await expectHealthy(page, errors);
  });
});

test.describe("access", () => {
  test("the access review counts the identities and filters the flagged ones", async ({ page, request }) => {
    test.skip(!granted.has("principal.manage"), absent("the token may not manage access (principal.manage)"));
    const { errors } = watchErrors(page);
    const response = await request.get("/api/v1/access/review");
    expect(response.ok(), `GET /api/v1/access/review answered ${response.status()}`).toBeTruthy();
    const review = (await response.json()) as { count: number; flagged: number; items: { flags: string[] }[] };

    /* Access is a screen of its own again rather than a tab of the
       settings: /access is where the identities, the roles and the
       review are read. */
    await page.goto("/access");
    await expect(head(page, "Users and access")).toBeVisible();

    const table = card(page, "Access review");
    await expect(table).toBeVisible();
    const figures = table.locator(".fl-card-foot");
    await expect(figures.locator(".fl-fig").filter({ hasText: "Identities" })).toContainText(String(review.count));
    await expect(figures.locator(".fl-fig").filter({ hasText: "Flagged" })).toContainText(String(review.flagged));

    await expect(page.getByTestId("access-review").locator("tbody tr")).toHaveCount(review.items.length);
    await expect(table.getByRole("button", { name: "Export CSV" })).toBeVisible();

    // The filter is applied in the browser: the flagged rows stay.
    await table.getByTestId("review-only").selectOption("flagged");
    const flagged = review.items.filter((item) => item.flags.length > 0).length;
    if (flagged === 0) {
      await expect(table.getByText("No identity matches this.")).toBeVisible();
    } else {
      await expect(page.getByTestId("access-review").locator("tbody tr")).toHaveCount(flagged);
      for (const row of await page.getByTestId("access-review").locator("tbody tr").all()) {
        await expect(row.locator(".fl-pill.fl-warn").first()).toBeVisible();
      }
    }
    await expectHealthy(page, errors);
  });
});

test.describe("audit", () => {
  test("the trail is charted, counted and filtered by outcome on the server", async ({ page }) => {
    test.skip(!granted.has("audit.read"), absent("the token may not read the audit trail (audit.read)"));
    const { errors } = watchErrors(page);
    await page.goto("/audit");
    await expect(head(page, "Audit")).toBeVisible();

    const chart = card(page, "Events per hour");
    await expect(chart.locator("svg").or(chart.getByText("No event answers this.")).first()).toBeVisible();
    await expectCounted(card(page, "Outcome").getByTestId("outcomes"));

    const events = card(page, "Events");
    const rows = page.getByTestId("events").locator("tbody tr:not(.fl-row-detail):not(.fl-row-under)");
    await expect(rows.first().or(events.getByText("No event answers this.")).first()).toBeVisible();

    // Denials only: the server narrows the page and the badges agree.
    const denied = page.waitForResponse((response) => response.url().includes("/api/v1/audit?") && response.url().includes("outcome=denied"));
    await page.getByTestId("outcome").selectOption("denied");
    expect((await denied).ok()).toBeTruthy();
    // Scoped to the list: the chart above says "No event answers this." too.
    await expect(rows.first().or(events.locator(".fl-empty")).first()).toBeVisible();
    for (const row of await rows.all()) {
      await expect(row.locator("td").nth(5).locator(".fl-pill")).toHaveText("denied");
    }
    await expectHealthy(page, errors);
  });

  test("an event that rests on an approval shows its chain under the row", async ({ page, request }) => {
    test.skip(!granted.has("audit.read"), absent("the token may not read the audit trail (audit.read)"));
    const response = await request.get("/api/v1/audit?limit=100");
    expect(response.ok(), `GET /api/v1/audit answered ${response.status()}`).toBeTruthy();
    const events = ((await response.json()) as { items: { action: string; approval_chain?: { created_by: string; approvers: string[] } }[] }).items;
    const approved = events.find((event) => event.approval_chain);
    test.skip(!approved, absent("no event of the last hundred carries an approval chain"));
    const chain = approved?.approval_chain as { created_by: string; approvers: string[] };

    await page.goto(`/audit?action=${encodeURIComponent((approved as { action: string }).action)}`);
    await expect(head(page, "Audit")).toBeVisible();
    // The line a row carries without being clicked: who ordered it and
    // who approved it, under the row it belongs to.
    const shown = page.locator("tr.fl-row-under .fl-note").first();
    await expect(shown).toBeVisible();
    await expect(shown).toContainText(`Ordered by ${chain.created_by}`);
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
