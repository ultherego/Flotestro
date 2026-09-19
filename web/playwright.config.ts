/*
 * End-to-end tests of the panel against a running control plane.
 *
 * The tests open the panel served by the control plane itself, so they need
 * a live installation with at least one enrolled host, and an API token
 * whose principal may read the fleet and campaigns:
 *
 *   BASE_URL=http://192.168.56.10:8080 FLOTESTRO_TOKEN=<api token> npm run test:e2e
 *
 * BASE_URL defaults to http://127.0.0.1:8080. The token goes into the
 * Authorization header of every request the browser and the API client
 * make; without it the panel shows the login screen and every test fails
 * on the first assertion.
 *
 * Optional environment:
 *   FLOTESTRO_SITE   the site the campaign scope is narrowed to (default:
 *                    the site of the first host the API lists)
 *   PLAYWRIGHT_BROWSERS_PATH  where the Chromium build lives, when it was
 *                    installed for another checkout (e.g. /tmp/shots)
 *
 * Nothing here changes the fleet: no campaign is created, no operation is
 * confirmed. A test that opens a confirmation card cancels it.
 *
 * The HTML report lands in playwright-report/; `npx playwright show-report`
 * opens it. A failed test keeps its trace and screenshot in test-results/.
 */
import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.BASE_URL ?? "http://127.0.0.1:8080";
const token = process.env.FLOTESTRO_TOKEN ?? "";

export default defineConfig({
  testDir: "e2e",
  // e2e/ci is the smoke test of the runner: it drives a stack that
  // tests/e2e/smoke.sh starts and has no business against a live fleet.
  testIgnore: "ci/**",
  // The tests share one installation and one fleet; running them one at a
  // time keeps their reads from tripping over each other's navigation.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL,
    extraHTTPHeaders: token ? { Authorization: `Bearer ${token}` } : {},
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
