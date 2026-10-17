import { expect, test, type Locator } from "@playwright/test";
import { absent, card, fleetHosts, hostWith, openHostList, type Host } from "./fleet";

/**
 * The acceptance criteria of the host management document (HOST-UI): unknown
 * is shown as unknown and never as zero, a change asks before it runs, and
 * every module says where its data came from and how fresh it is.
 */

let hosts: Host[] = [];

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
});

test.describe("HOST-UI: unknown is not zero", () => {
  test("a count the fleet has not determined shows as a dash in the list, never zero", async ({ page }) => {
    // Two counts on this row can be undetermined, and the claim is the same
    // for both: the update count, which a host has none of before its first
    // package read, and the security count, which the arch and rhel tooling
    // does not report at all. The test takes whichever the fleet has, so it
    // runs on a fleet where every host has already read its packages.
    const noUpdates = hosts.find((host) => host.pending_updates === null);
    const noSecurity = hosts.find((host) => host.pending_security_updates === null);
    const host = noUpdates ?? noSecurity;
    test.skip(!host, absent(
      "every host reports both an update count and a security count, so the list has no undetermined number to show"));
    const column = noUpdates ? "Updates" : "Security updates";

    const table = await openHostList(page);
    if (column === "Security updates") {
      // The security column starts folded away; the operator unfolds it
      // from the chooser, and so does the test.
      await page.getByTestId("hosts-columns").click();
      await page.locator(".fl-columns-list").getByRole("checkbox", { name: "Security updates" }).check();
      await page.getByTestId("hosts-columns").click();
    }
    const row = (name: string) => table.locator(`tr[data-testid="host-${name}"]`);
    const target = row((host as Host).hostname);
    await expect(target).toHaveCount(1);

    /* The panel being replaced wrote the word "unknown" into the cell; this
       one writes an em dash in the faint colour it uses for every value
       nobody has. The claim the document makes is the one kept here: an
       undetermined count is not a nought and is not drawn as a number. */
    const cell = await cellOf(table, target, column);
    await expect(cell).toBeVisible();
    await expect(cell).toHaveText("—");
    await expect(cell).not.toHaveText(/^\s*0\s*$/);

    // A determined count in the same column is the number, never the dash.
    const known = hosts.find((entry) =>
      typeof (column === "Updates" ? entry.pending_updates : entry.pending_security_updates) === "number");
    expect(known, `no host reports a ${column} count, so the two cannot be told apart`).toBeTruthy();
    const knownCell = await cellOf(table, row((known as Host).hostname), column);
    await expect(knownCell).not.toHaveText("—");
    await expect(knownCell).toContainText(
      String(column === "Updates" ? (known as Host).pending_updates : (known as Host).pending_security_updates));
  });

  test("the overview shows undetermined counts as dashes, not zeros", async ({ page }) => {
    const host = hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);

    // What needs attention on this host: a null count from the API is a
    // dash on the row and says it was not counted; a number is that number.
    const attention = card(page, "Needs attention");
    await expect(attention).toBeVisible();
    const updates = attention.locator(".fl-needs-row").filter({ hasText: "Updates waiting" });
    await expect(updates).toHaveCount(1);
    if (host.pending_updates === null) {
      await expect(updates.locator(".fl-needs-count")).toHaveText("—");
      await expect(updates).toContainText("not counted");
    } else {
      await expect(updates.locator(".fl-needs-count")).toHaveText(String(host.pending_updates));
    }
  });
});

test.describe("HOST-UI: a change asks before it runs", () => {
  test("the reboot button opens a confirmation naming the target, and cancel sends nothing", async ({ page }) => {
    const host = hostWith(hosts, "systemd") ?? hosts[0];
    const posted: string[] = [];
    page.on("request", (request) => {
      if (request.method() !== "GET" && request.url().includes("/api/v1/")) posted.push(`${request.method()} ${request.url()}`);
    });

    // The orders are on the Change tab; the first one is the state.
    await page.goto(`/hosts/${host.id}/power?tab=change`);
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);
    const reboot = page.getByTestId("reboot");
    const unreported = page.getByText("This host has not reported its boot state yet.");
    await expect(reboot.or(unreported).first()).toBeVisible();
    test.skip(await unreported.isVisible(), absent(
      `${host.hostname} has not reported its boot state, so the power module offers no action to confirm`));

    await expect(page.getByRole("dialog")).toHaveCount(0);
    await reboot.click();

    // The question is a dialog now rather than a card below the button,
    // and it carries the same three things: what it does, which machine,
    // and the two answers it will not go without.
    const confirmation = page.getByRole("dialog", { name: "Reboot host" });
    await expect(confirmation).toBeVisible();
    await expect(confirmation).toContainText(`Target: ${host.hostname}`);
    await expect(confirmation).toContainText(`${host.site} / ${host.environment}`);
    await expect(confirmation.getByText("Type the hostname to confirm:")).toBeVisible();
    await expect(confirmation.getByTestId("confirm-reason")).toBeVisible();
    await expect(confirmation.getByTestId("confirm-target")).toBeVisible();

    // The confirming button stays off until the reason and the hostname
    // are typed; nothing is typed here.
    await expect(confirmation.getByTestId("confirm-order")).toBeDisabled();
    await confirmation.getByTestId("confirm-cancel").click();
    await expect(confirmation).toHaveCount(0);

    expect(posted, "a request that would change the host was sent").toEqual([]);
  });

  test("a shutdown needs a reason before its button is even enabled", async ({ page }) => {
    const host = hostWith(hosts, "systemd") ?? hosts[0];
    // The orders are on the Change tab; the first one is the state.
    await page.goto(`/hosts/${host.id}/power?tab=change`);
    const shutdown = page.getByTestId("shutdown");
    const unreported = page.getByText("This host has not reported its boot state yet.");
    await expect(shutdown.or(unreported).first()).toBeVisible();
    test.skip(await unreported.isVisible(), absent(
      `${host.hostname} has not reported its boot state, so the shutdown button is not on the page`));

    await expect(shutdown).toBeDisabled();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    // The reason is asked for on the page, before the confirmation, and
    // the button answers to it.
    await page.getByTestId("shutdown-reason").fill("disk replacement, ticket 1234");
    await expect(shutdown).toBeEnabled();
  });
});

test.describe("HOST-UI: source and freshness", () => {
  test("the overview says where its data came from and when it was observed", async ({ page }) => {
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    // The System container is the second reading of the overview.
    await page.goto(`/hosts/${host.id}/overview?tab=system`);
    await expect(page.locator(".fl-head-title").first()).toContainText(host.hostname);

    /* The line used to stand under every module's own heading with a
       testid of its own. It is the foot of the container whose facts it
       vouches for now - which is where a reader looks for it - and it
       still names all three: the source, the revision and when the
       machine was observed. The absolute time on hover went with the
       move: the line is plain text. */
    const system = card(page, "System");
    await expect(system).toBeVisible();
    const foot = system.locator(".fl-card-foot");
    // The line arrives with the module read; a host that has never sent
    // one has nothing to vouch for its facts and the claim does not apply.
    const said = await foot.count() > 0
      || await foot.isVisible({ timeout: 15_000 }).catch(() => false);
    test.skip(!said, absent(`${host.hostname} has not reported its system module`));
    await expect(foot).toHaveText(/Source: .+, revision \S+, observed .+/);
  });

  test("the host header carries the state, the address with its origin and the last report", async ({ page }) => {
    const host = hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    const header = page.locator(".fl-head").first();
    await expect(header).toBeVisible();
    await expect(header.locator(".fl-head-title")).toContainText(host.hostname);
    const lead = header.locator(".fl-head-lead");
    await expect(lead.locator(".fl-pill").first()).toHaveText(host.connection_state);
    await expect(lead.locator(".fl-stripitem", { hasText: "Site" })).toContainText(`${host.site} / ${host.environment}`);
    await expect(lead.locator(".fl-stripitem", { hasText: "Seen" })).toContainText("ago");
    // The address chip names its origin (session, agent, manual) or says
    // the address is unknown; a bare address would hide how it was learnt.
    const source = lead.getByTestId("address-source");
    const unknown = lead.getByText("address unknown");
    await expect(source.or(unknown).first()).toBeVisible();
    if (await source.count() > 0) {
      expect(["session", "agent", "manual", "unknown"]).toContain(((await source.textContent()) ?? "").trim());
    }
  });
});

/**
 * The cell of a row under a named column.
 *
 * The kit's table draws no column name on its cells, so the column is
 * found once in the head - where a sortable heading carries its label
 * plus an arrow - and the cell is the one at that place in the row.
 */
async function cellOf(table: Locator, row: Locator, column: string): Promise<Locator> {
  const heads = await table.locator("thead th").allTextContents();
  const at = heads.findIndex((text) => text.replace(/[↑↓↕⇅▲▼]/g, "").trim() === column);
  expect(at, `the list has no "${column}" column; it drew ${JSON.stringify(heads)}`).toBeGreaterThanOrEqual(0);
  return row.locator("td").nth(at);
}
