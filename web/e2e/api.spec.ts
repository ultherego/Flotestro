import { expect, test } from "@playwright/test";

/**
 * The API the panel is built on, asked directly. The request context
 * carries the same Authorization header as the browser, so a failure here
 * separates a broken server from a broken screen.
 */

test.describe("API", () => {
  test("the OpenAPI document lists the host collection", async ({ request }) => {
    const response = await request.get("/api/v1/openapi.json");
    expect(response.ok(), `GET /api/v1/openapi.json answered ${response.status()}`).toBeTruthy();
    expect(response.headers()["content-type"]).toContain("json");
    const document = (await response.json()) as { openapi?: string; paths?: Record<string, unknown> };
    expect(document.openapi, "the document names its OpenAPI version").toMatch(/^3\./);
    const paths = Object.keys(document.paths ?? {});
    expect(paths).toContain("/api/v1/hosts");
    expect(paths).toContain("/api/v1/hosts/{id}");
    expect(paths).toContain("/api/v1/fleet/summary");
    expect(paths).toContain("/api/v1/errors");
  });

  test("the error guide has items an operator can act on", async ({ request }) => {
    const response = await request.get("/api/v1/errors");
    expect(response.ok(), `GET /api/v1/errors answered ${response.status()}`).toBeTruthy();
    const body = (await response.json()) as { items: { code: string; meaning: string; action: string; retry: string; counts_as_failure: boolean }[] };
    expect(body.items.length).toBeGreaterThan(0);
    for (const guide of body.items) {
      expect(guide.code, "every guide has a code").toMatch(/^\S+$/);
      expect(guide.meaning, `${guide.code} says what happened`).not.toBe("");
      expect(guide.action, `${guide.code} says what to do next`).not.toBe("");
      expect(["never", "automatic", "after_change", "after_replan", "read_state"], `${guide.code} has a retry policy`).toContain(guide.retry);
      expect(typeof guide.counts_as_failure).toBe("boolean");
    }
    // A code is an identifier: two guides for one code would leave the
    // screen to pick one at random.
    const codes = body.items.map((guide) => guide.code);
    expect(new Set(codes).size).toBe(codes.length);
  });

  test("the fleet summary counts hosts", async ({ request }) => {
    const response = await request.get("/api/v1/fleet/summary");
    expect(response.ok(), `GET /api/v1/fleet/summary answered ${response.status()}`).toBeTruthy();
    const summary = (await response.json()) as Record<string, unknown>;
    expect(typeof summary.hosts).toBe("number");
    expect(summary.hosts as number).toBeGreaterThan(0);
    for (const field of ["online", "offline", "reboot_required", "with_failed_units", "quarantined_hosts", "in_maintenance"]) {
      expect(typeof summary[field], `${field} is a count`).toBe("number");
      expect(summary[field] as number).toBeGreaterThanOrEqual(0);
    }
    expect((summary.online as number) + (summary.offline as number)).toBeLessThanOrEqual(summary.hosts as number);
  });

  test("the host list is paged and never larger than the summary", async ({ request }) => {
    const [hosts, summary] = await Promise.all([
      request.get("/api/v1/hosts?limit=2").then((response) => response.json() as Promise<{ items: unknown[]; count: number; total?: number; next_cursor?: string }>),
      request.get("/api/v1/fleet/summary").then((response) => response.json() as Promise<{ hosts: number }>),
    ]);
    expect(hosts.items.length).toBeLessThanOrEqual(2);
    expect(hosts.count).toBe(hosts.items.length);
    expect(typeof hosts.total, "the list counts across every page").toBe("number");
    // The summary counts every visible host, retired ones included; the
    // list may leave some out, never add any.
    expect(hosts.total as number).toBeLessThanOrEqual(summary.hosts);
    if ((hosts.total as number) > 2) expect(hosts.next_cursor, "a longer list hands back a cursor").toBeTruthy();
  });

  test("a request without a session is refused, not served", async ({ playwright, baseURL }) => {
    // A context of its own, without the Authorization header of the suite.
    const anonymous = await playwright.request.newContext({ baseURL, extraHTTPHeaders: {} });
    try {
      const response = await anonymous.get("/api/v1/whoami");
      expect([401, 403]).toContain(response.status());
    } finally {
      await anonymous.dispose();
    }
  });
});
