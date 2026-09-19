/*
 * The smoke test of the whole stack, as a runner can run it: a real control
 * plane, a fake agent and this browser, all started by tests/e2e/smoke.sh.
 * The suite beside it (playwright.config.ts) drives the panel of the
 * laboratory and needs a fleet; this one needs nothing but the stack the
 * script brings up.
 *
 * The browser signs in on the login screen with the bootstrap token, so no
 * Authorization header is set here: a header would sign every request in and
 * the sign-in would prove nothing. The few API reads of the test carry the
 * header themselves.
 *
 * Nothing is uploaded anywhere. A trace and a screenshot of a failure stay in
 * test-results/ on the machine that ran it, which on a runner is thrown away
 * with the runner.
 */
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "e2e/ci",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  use: {
    baseURL: process.env.BASE_URL ?? "http://127.0.0.1:8080",
    viewport: { width: 1600, height: 1000 },
    // The assertions read English labels; the panel would follow a Polish
    // browser otherwise.
    locale: "en-US",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1600, height: 1000 } },
    },
  ],
});
