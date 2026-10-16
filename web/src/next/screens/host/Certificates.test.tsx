import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Certificates, byDeadline, commonName, deadlineTone, renewOrder } from "./Certificates";
import type { Host } from "../../../lib/types";

/**
 * A certificate module is read for one thing before anything else: what
 * expires next, and whether anything renews it. Everything here is about
 * what the module does with the host's answer - the order it places, the
 * refusal it shows, and the dash it draws where the host said nothing.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const deleted: string[] = [];
const answers: Record<string, unknown> = {};
let postResult: unknown = { id: "0123456789abcdef", requires_approval: false };

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest match wins: `/api/v1/hosts/h1/certificates` is a prefix of
  // `/api/v1/hosts/h1/certificates/deployments`, and answering the second
  // with the first hands the screen the wrong document.
  const reply = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const answer = answers[key];
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => { asked.push(path); return reply(path); },
      post: (path: string, body?: unknown) => { posted.push({ path, body }); return Promise.resolve(postResult); },
      put: () => Promise.resolve({}),
      del: (path: string) => { deleted.push(path); return Promise.resolve(undefined); },
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  enrolled_at: "2026-10-01T00:00:00Z",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, capabilities: [], identity: {},
} as unknown as Host;

/** The server's verdict on what this operator may order here. */
const actions = (over: Record<string, { allowed: boolean; reason?: string; missing?: string }> = {}) => ({
  version: 1,
  items: ["certificate.deploy", "certificate.renew", "certificate.scan", "certificate.plan"].map((action) => ({
    action,
    permission: action,
    mutating: true,
    risk: "normal",
    allowed: over[action]?.allowed ?? true,
    reason: over[action]?.reason,
    reason_code: over[action] && !over[action].allowed ? "permission_denied" : undefined,
    missing_permission: over[action]?.missing,
  })),
});

const certificate = (over: Record<string, unknown> = {}) => ({
  path: "/etc/pki/tls/certs/web.crt",
  subject: "CN=www.lab.internal",
  sans: ["www.lab.internal", "lab.internal"],
  not_after: "2026-12-01T00:00:00Z",
  source: "certmonger",
  renewal: "tracked",
  tracking: { request: "20260101000000", ca: "IPA", auto_renew: true, status: "MONITORING" },
  status: "warning",
  days_to_expiry: 21,
  watched: true,
  managed: false,
  ...over,
});

const report = (over: Record<string, unknown> = {}) => ({
  host_id: "h1",
  certificates: [certificate()],
  targets: [{ id: "t1", path: "/etc/pki/tls/certs/web.crt", key_path: "/etc/pki/tls/private/web.key", service: "httpd", updated_by: "ulther", updated_at: "2026-10-01T00:00:00Z" }],
  status: "ok",
  tracking_known: true,
  keys_known: true,
  stale: false,
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Certificates host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  deleted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  postResult = { id: "0123456789abcdef", requires_approval: false };
});

describe("what the module reads", () => {
  it("orders the list by deadline, the soonest first and the unknown last", () => {
    const list = byDeadline([
      { path: "/c", not_after: undefined },
      { path: "/a", not_after: "2027-01-01T00:00:00Z" },
      { path: "/b", not_after: "2026-11-01T00:00:00Z" },
    ] as never);
    expect(list.map((one) => one.path)).toEqual(["/b", "/a", "/c"]);
  });

  it("reads the common name out of a subject so the names beside it can be listed", () => {
    expect(commonName("O=Lab, CN=www.lab.internal")).toBe("www.lab.internal");
    expect(commonName(undefined)).toBe("");
  });

  it("calls a deadline nobody could judge unknown, never valid", () => {
    expect(deadlineTone("valid")).toBe("ok");
    expect(deadlineTone("critical")).toBe("error");
    expect(deadlineTone("warning")).toBe("warn");
    expect(deadlineTone("")).toBe("unknown");
  });

  it("composes a renewal through the registry, and refuses one with nothing to name", () => {
    const good = renewOrder("20260101000000", "/etc/pki/tls/certs/web.crt", "httpd.service", "");
    expect(good.problems).toEqual([]);
    // An empty field is left out of the payload, not sent as an empty one.
    expect(good.payload).toEqual({
      certificate: {
        request: "20260101000000",
        path: "/etc/pki/tls/certs/web.crt",
        reload_unit: "httpd.service",
      },
    });
    // Neither a request nor a path: the panel refuses before the host does.
    expect(renewOrder("", "", "", "").problems.length).toBeGreaterThan(0);
  });
});

describe("the certificates of a host", () => {
  it("draws a certificate with its deadline and what renews it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("certificate-/etc/pki/tls/certs/web.crt");
    expect(row).toHaveTextContent("21 d left");
    // certmonger renews it, and certmonger is also where it came from.
    expect(within(row).getAllByText("certmonger")).toHaveLength(2);
    // A SAN that only repeats the common name says nothing new.
    expect(row).toHaveTextContent("also lab.internal");
    expect(row).not.toHaveTextContent("also www.lab.internal, lab.internal");
  });

  it("says a key the host never reported is a dash, and never a clean mode", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({ certificates: [certificate({ key: undefined })] }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("certificate-/etc/pki/tls/certs/web.crt");
    expect(row).toHaveTextContent("—");
    expect(within(row).queryByText("0644")).toBeNull();
  });

  it("counts the deadlines and says the ones nobody counted are not nought", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({
        certificates: [certificate(), certificate({ path: "/b", status: "expired", days_to_expiry: -3 })],
      }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const band = await screen.findByTestId("deadline");
    expect(band).toHaveTextContent("under 30 days");
    expect(band).toHaveTextContent("expired");
    // The ones at nought go under the band as words, not as slivers.
    expect(band).toHaveTextContent("valid");
  });

  it("says nothing is watched yet, and offers the way to watch something", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({ certificates: [], targets: [] }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText(/No certificate is watched on this host yet. Add a path/)).toBeInTheDocument());
  });

  it("warns that the picture is old rather than letting it read as current", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({ stale: true }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/older than a day and a half/)).toBeInTheDocument());
  });

  it("says when it could not tell what renews these certificates, and why", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({ tracking_known: false, tracking_reason: "certmonger is not running" }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText(/could not tell what renews these certificates: certmonger is not running/))
        .toBeInTheDocument());
  });

  it("names the facts the host could not collect, as answers of \"not known\"", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report({ missing: { tracking: "certmonger absent" } }),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const table = await screen.findByTestId("not-established");
    expect(table).toHaveTextContent("tracking");
    expect(table).toHaveTextContent("certmonger absent");
  });
});

describe("what the module does", () => {
  it("renews through the registry, after a reason and the machine's own name", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("renew-/etc/pki/tls/certs/web.crt"));

    // Nothing is ordered until the reason and the hostname are both there.
    const confirm = screen.getByTestId("confirm-order");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "expires in three weeks" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(confirm);

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toEqual({
      action: "certificate.renew",
      reason: "expires in three weeks",
      payload: {
        certificate: {
          request: "20260101000000",
          path: "/etc/pki/tls/certs/web.crt",
        },
      },
    });
    // The job the order became is named where the sentence stands.
    await waitFor(() => expect(screen.getByRole("link", { name: "01234567" })).toHaveAttribute("href", "/next/jobs/0123456789abcdef"));
  });

  it("scans the host with the paths the panel watches", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("certificate-scan"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toEqual({
      action: "certificate.scan",
      payload: {
        certificate: {
          targets: [{ path: "/etc/pki/tls/certs/web.crt", key_path: "/etc/pki/tls/private/web.key", service: "httpd" }],
        },
      },
    });
  });

  it("watches a path without touching the host", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    postResult = { id: "t2", path: "/etc/pki/tls/certs/api.crt" };
    draw();
    fireEvent.click(await screen.findByTestId("watch-open"));
    fireEvent.change(await screen.findByTestId("watch-path"), { target: { value: "/etc/pki/tls/certs/api.crt" } });
    fireEvent.click(screen.getByTestId("watch-save"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/certificates/targets");
    expect(posted[0].body).toMatchObject({ path: "/etc/pki/tls/certs/api.crt" });
  });

  it("asks before it stops watching, and carries the reason with it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    fireEvent.click(await screen.findByTestId("unwatch-/etc/pki/tls/certs/web.crt"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "moved to another host" } });
    fireEvent.change(screen.getByTestId("confirm-host"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(deleted).toHaveLength(1));
    expect(deleted[0]).toContain("path=%2Fetc%2Fpki%2Ftls%2Fcerts%2Fweb.crt");
    expect(deleted[0]).toContain("reason=moved%20to%20another%20host");
  });

  it("reads the deployments of the file the operator opened, and of no other", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/certificates/deployments": { items: [
        { path: "/etc/pki/tls/certs/web.crt", fingerprint_sha256: "abcdef0123456789ff", deployed_by: "ulther", deployed_at: "2026-10-01T00:00:00Z" },
      ] },
      "/api/v1/hosts/h1/actions": actions(),
    });
    draw();
    const row = await screen.findByTestId("certificate-/etc/pki/tls/certs/web.crt");
    fireEvent.click(within(row).getByRole("button", { name: "/etc/pki/tls/certs/web.crt" }));
    const table = await screen.findByTestId("deployments");
    expect(table).toHaveTextContent("abcdef0123456789");
    expect(asked.some((one) =>
      one.startsWith("/api/v1/hosts/h1/certificates/deployments?path=%2Fetc%2Fpki%2Ftls%2Fcerts%2Fweb.crt"))).toBe(true);
  });
});

describe("what the server refuses", () => {
  it("does not draw a renewal the server would not take", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions({ "certificate.renew": { allowed: false, reason: "no", missing: "certificate.renew" } }),
    });
    draw();
    await screen.findByTestId("certificate-/etc/pki/tls/certs/web.crt");
    await waitFor(() => expect(screen.queryByTestId("renew-/etc/pki/tls/certs/web.crt")).toBeNull());
  });

  it("keeps a refused scan on the screen with the server's own reason on it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions({
        "certificate.scan": { allowed: false, reason: "the host is quarantined" },
      }),
    });
    draw();
    const scan = await screen.findByTestId("certificate-scan");
    expect(scan).toBeDisabled();
    expect(scan).toHaveAttribute("title", "the host is quarantined");
  });

  it("says once that the module can be read but not changed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/certificates": report(),
      "/api/v1/hosts/h1/actions": actions({
        "certificate.deploy": { allowed: false, missing: "certificate.deploy" },
        "certificate.renew": { allowed: false, missing: "certificate.renew" },
      }),
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText(/You can read this module; changing it needs the permission/)).toBeInTheDocument());
  });
});
