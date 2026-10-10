import { expect, test } from "@playwright/test";
import { absent, fleetHosts, hostWith, openHostList, type Host } from "./fleet";

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
  test("a count the fleet has not determined shows unknown in the list, never zero", async ({ page }) => {
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
    const column = noUpdates ? "updates" : "security";

    const table = await openHostList(page);
    if (column === "security") {
      // The security column is not on the screen by default; the operator
      // turns it on, and so does the test.
      await page.getByTestId("column-chooser").click();
      await page.getByRole("group", { name: "Columns" }).getByLabel("Security updates").check();
      await page.keyboard.press("Escape");
    }
    const rowOf = (name: string) =>
      table.getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });
    const row = rowOf((host as Host).hostname);
    await expect(row).toHaveCount(1);
    const cell = row.locator(`td[data-column="${column}"]`);
    await expect(cell).toBeVisible();
    await expect(cell.locator(".badge.unknown")).toHaveText("unknown");
    await expect(cell).not.toHaveText(/^\s*0\s*$/);

    // A determined count in the same column is the number, never the badge
    // that says the count is unknown.
    const known = hosts.find((entry) =>
      typeof (column === "updates" ? entry.pending_updates : entry.pending_security_updates) === "number");
    expect(known, `no host reports a ${column} count, so the two cannot be told apart`).toBeTruthy();
    const knownCell = rowOf((known as Host).hostname).locator(`td[data-column="${column}"]`);
    await expect(knownCell.locator(".badge.unknown")).toHaveCount(0);
    await expect(knownCell).toContainText(
      String(column === "updates" ? (known as Host).pending_updates : (known as Host).pending_security_updates));
  });

  test("the overview shows undetermined counts as dashes and badges, not zeros", async ({ page }) => {
    const host = hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview" })).toBeVisible();

    // The attention bar of the host: a null count from the API is a dash
    // on the segment, a number is that number.
    const attention = page.getByTestId("status-bar").filter({ hasText: "Updates waiting" });
    const updates = attention.getByRole("listitem").filter({ hasText: "Updates waiting" }).getByTestId("status-bar-value");
    if (host.pending_updates === null) {
      await expect(updates).toHaveText("—");
    } else {
      await expect(updates).toHaveText(String(host.pending_updates));
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

    await page.goto(`/hosts/${host.id}/power`);
    const header = page.locator(".hm-header").getByRole("heading", { name: "Power", exact: true });
    const unreported = page.getByText("This host has not reported its boot state yet.");
    await expect(header.or(unreported).first()).toBeVisible();
    test.skip(await unreported.isVisible(), absent(
      `${host.hostname} has not reported its boot state, so the power module offers no action to confirm`));

    await expect(page.getByTestId("target-confirmation")).toHaveCount(0);
    await page.getByRole("button", { name: "Reboot", exact: true }).click();

    const confirmation = page.getByTestId("target-confirmation");
    await expect(confirmation).toBeVisible();
    await expect(confirmation.getByRole("heading", { name: "Reboot host" })).toBeVisible();
    await expect(confirmation).toContainText(`Target: ${host.hostname}`);
    await expect(confirmation).toContainText(`${host.site} / ${host.environment}`);
    await expect(confirmation.getByText("Type the hostname to confirm:")).toBeVisible();

    // The confirming button stays off until the reason and the hostname
    // are typed; nothing is typed here.
    await expect(confirmation.getByRole("button", { name: "Reboot host" })).toBeDisabled();
    await confirmation.getByRole("button", { name: "Cancel" }).click();
    await expect(confirmation).toHaveCount(0);

    expect(posted, "a request that would change the host was sent").toEqual([]);
  });

  test("a shutdown needs a reason before its button is even enabled", async ({ page }) => {
    const host = hostWith(hosts, "systemd") ?? hosts[0];
    await page.goto(`/hosts/${host.id}/power`);
    const header = page.locator(".hm-header").getByRole("heading", { name: "Power", exact: true });
    const unreported = page.getByText("This host has not reported its boot state yet.");
    await expect(header.or(unreported).first()).toBeVisible();
    test.skip(await unreported.isVisible(), absent(
      `${host.hostname} has not reported its boot state, so the shutdown button is not on the page`));

    await expect(page.getByRole("button", { name: "Shut down", exact: true })).toBeDisabled();
    await expect(page.getByTestId("target-confirmation")).toHaveCount(0);
  });
});

test.describe("HOST-UI: source and freshness", () => {
  test("a module page says where its data came from and when it was observed", async ({ page }) => {
    const host = hosts.find((entry) => entry.connection_state === "online") ?? hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview" })).toBeVisible();

    const freshness = page.getByTestId("module-freshness");
    await expect(freshness).toBeVisible();
    await expect(freshness).toHaveText(/Source: .+, revision \S+, observed/);
    // The time is relative on the line and absolute on hover.
    const time = freshness.locator("span[title]");
    await expect(time).toHaveCount(1);
    await expect(time).not.toBeEmpty();
    await expect(time).toHaveAttribute("title", /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    await expect(time).toHaveText(/ago$|in a moment/);
  });

  test("the host header carries the state, the address with its origin and the last report", async ({ page }) => {
    const host = hosts[0];
    await page.goto(`/hosts/${host.id}/overview`);
    const header = page.locator(".host-header");
    await expect(header).toBeVisible();
    await expect(header.locator(".badge").first()).toHaveText(host.connection_state);
    await expect(header.getByTitle("site / environment")).toHaveText(`${host.site} / ${host.environment}`);
    await expect(header.getByTitle("last seen")).toContainText("seen");
    // The address chip names its origin (session, agent, manual) or says
    // the address is unknown; a bare address would hide how it was learnt.
    const address = header.locator(".chip-tag").first().or(header.getByText("address unknown"));
    await expect(address.first()).toBeVisible();
  });
});
