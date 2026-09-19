import { expect, test } from "@playwright/test";
import { expectHealthy, openHostList, watchErrors } from "../fleet";

/**
 * The smoke test of the whole stack on a runner: signing in, the fleet, one
 * host, and one operation from the click to the host's typed answer. It
 * guards that the parts start and talk to each other; what every screen
 * shows is the Vitest suite's and the laboratory's to check.
 *
 * tests/e2e/smoke.sh starts the control plane and the fake agent and passes
 * the bootstrap token and the host that enrolled. The test refuses to run
 * without them rather than passing against an empty fleet.
 */

const token = process.env.FLOTESTRO_TOKEN ?? "";
const hostname = process.env.FLOTESTRO_E2E_HOSTNAME ?? "";
const hostID = process.env.FLOTESTRO_E2E_HOST_ID ?? "";

/** The header the API reads of the test carry; the browser signs itself in. */
const authorization = { Authorization: `Bearer ${token}` };

test.beforeAll(() => {
  for (const [name, value] of Object.entries({ FLOTESTRO_TOKEN: token, FLOTESTRO_E2E_HOSTNAME: hostname, FLOTESTRO_E2E_HOST_ID: hostID })) {
    expect(value, `${name} is empty; start the stack with tests/e2e/smoke.sh`).not.toBe("");
  }
});

test("the panel signs in, shows the host and follows one operation to its answer", async ({ page, request }) => {
  const { errors } = watchErrors(page);

  // The way in without an identity provider: the bootstrap token the first
  // start of the control plane wrote into the state directory.
  await page.goto("/");
  await page.getByText("Sign in with a bootstrap token").click();
  await page.locator('.login-screen input[type="password"]').fill(token);
  await page.getByRole("button", { name: "Continue to the first run" }).click();
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.locator(".page-header").getByRole("heading", { name: "First run" })).toBeVisible();

  // The fleet: the host the fake agent enrolled stands in the list, and its
  // name leads to its workspace.
  const table = await openHostList(page);
  const link = table.getByRole("link", { name: hostname, exact: true });
  await expect(link).toBeVisible();
  await link.click();
  await expect(page).toHaveURL(new RegExp(`/hosts/${hostID}/overview$`));
  await expect(page.locator(".hm-header").getByRole("heading", { name: "Overview" })).toBeVisible();

  // One operation through. The read of the unit list is the cheapest order
  // the panel offers: the panel sends it, the gateway delivers it, the agent
  // answers and the answer comes back to the screen. The fake agent performs
  // no tasks, so the answer is the typed refusal "unsupported" - a refusal is
  // an answer, and the round trip is what this test guards. A different code
  // means something on the way changed the task, not that the host said no.
  await page.goto(`/hosts/${hostID}/services`);
  await expect(page.locator(".hm-header").getByRole("heading", { name: "Services" })).toBeVisible();
  const button = page.locator(".hm-header").getByRole("button", { name: "Read from host" });
  await expect(button, "the panel refuses to order a read from this host").toBeEnabled();
  const ordered = page.waitForResponse((response) =>
    response.url().includes(`/api/v1/hosts/${hostID}/operations`) && response.request().method() === "POST");
  await button.click();
  const job = (await (await ordered).json()) as { id: string };
  expect(job.id, "the order carried no job identifier").toBeTruthy();
  await expect(page.getByText(`Job ${job.id.slice(0, 8)} has been queued.`)).toBeVisible();

  await expect
    .poll(async () => {
      const response = await request.get(`/api/v1/jobs/${job.id}`, { headers: authorization });
      expect(response.ok(), `GET /api/v1/jobs/${job.id} answered ${response.status()}`).toBeTruthy();
      const state = (await response.json()) as { state: string; result_error_code?: string };
      return `${state.state} ${state.result_error_code ?? ""}`.trim();
    }, { timeout: 120_000 })
    .toBe("failed unsupported");

  // The same answer on the screen: the host's job list names the operation,
  // its state and the code the host answered with.
  await page.goto(`/hosts/${hostID}/jobs`);
  const row = page.locator("tbody tr").filter({ hasText: "unit.status" }).first();
  await expect(row).toBeVisible();
  await expect(row.locator(".badge").first()).toHaveText("failed");
  await expect(row.locator("code")).toHaveText("unsupported");

  await expectHealthy(page, errors);
});
