import { expect, test } from "@playwright/test";
import { fleetHosts, hostWith, openHostList, type Host } from "./fleet";

/**
 * The acceptance criteria of the host management document (HOST-UI):
 * unknown is shown as unknown and never as zero, a change asks before it
 * runs, and every module says where its data came from and how fresh it
 * is. No confirmation is ever completed here, so the fleet is untouched.
 */

let hosts: Host[] = [];

test.beforeAll(async ({ request }) => {
  hosts = await fleetHosts(request);
  expect(hosts.length, "the token sees no host; enroll one before running the tests").toBeGreaterThan(0);
});

test.describe("HOST-UI: unknown is not zero", () => {
  test("a host whose update count is undetermined shows unknown in the list", async ({ page }) => {
    // The Arch host reports no security count and, before its first
    // package read, no update count at all; any host with a null count
    // serves the check.
    const undetermined = hosts.find((host) => host.pending_updates === null);
    test.skip(!undetermined, "every host reports an update count; nothing on the list is undetermined right now");
    const host = undetermined as Host;

    const table = await openHostList(page);
    const row = table.getByRole("row").filter({ has: page.getByRole("link", { name: host.hostname, exact: true }) });
    await expect(row).toHaveCount(1);
    const updates = row.getByTestId("host-updates");
    await expect(updates).toBeVisible();
    await expect(updates.locator(".badge.unknown")).toHaveText("unknown");
    await expect(updates).not.toHaveText(/^\s*0\s*$/);
    // A known count next to it is a meter, not a badge.
    const known = hosts.find((entry) => typeof entry.pending_updates === "number");
    if (known) {
      const knownRow = table.getByRole("row").filter({ has: page.getByRole("link", { name: known.hostname, exact: true }) });
      await expect(knownRow.getByTestId("host-updates").locator(".meter-value")).toHaveText(String(known.pending_updates));
    }
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
    test.skip(await unreported.isVisible(), `${host.hostname} has not reported its boot state; the power module has no actions yet`);

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
    test.skip(await unreported.isVisible(), `${host.hostname} has not reported its boot state`);

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
