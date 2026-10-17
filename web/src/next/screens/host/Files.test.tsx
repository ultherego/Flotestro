import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Files, differenceText, hostRollbackPayload, hostVersionRefusal } from "./Files";

/**
 * A managed file is read for one question: does the host have what the
 * panel expects. Drift is an established divergence, never a default
 * one - a file the host could not read is neither matching nor drifted,
 * and content that came from a secret is not compared at all.
 */

const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/hosts/h1/files` must not
        // answer `/api/v1/hosts/h1/files/history?path=…`.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1234abcd", requires_approval: true });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
} as unknown as Parameters<typeof Files>[0]["host"];

const allowed = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "normal", allowed: true,
  })),
});

const file = (over: Record<string, unknown>) => ({
  path: "/etc/example.conf", updated_by: "tester", updated_at: "2026-10-15T08:00:00Z",
  exists: true, drift: false, mode: "0644", observed_mode: "0644",
  desired_sha256: "a".repeat(64), observed_sha256: "a".repeat(64),
  ...over,
});

function base(items: unknown[]) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/files": { items },
    "/api/v1/hosts/h1/actions": allowed("file.ensure", "file.remove", "file.rollback", "file.read"),
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Files host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the managed files of a host", () => {
  it("tells apart matching, drifted, missing and not compared", async () => {
    base([
      file({}),
      file({ path: "/etc/drifted.conf", drift: true }),
      file({ path: "/etc/gone.conf", exists: false }),
      file({ path: "/etc/secret.conf", drift_unknown_reason: "the content came from the secret store" }),
      file({ path: "/etc/unreadable.conf", unavailable_reason: "permission denied" }),
    ]);
    draw();
    await waitFor(() => expect(screen.getByTestId("file-/etc/example.conf")).toBeInTheDocument());
    expect(within(screen.getByTestId("file-/etc/example.conf")).getByText("matches")).toBeInTheDocument();
    expect(within(screen.getByTestId("file-/etc/drifted.conf")).getByText("changed outside the panel")).toBeInTheDocument();
    expect(within(screen.getByTestId("file-/etc/gone.conf")).getByText("missing on host")).toBeInTheDocument();
    // The panel holds no fingerprint of content from a secret, so it does
    // not pretend the file matches.
    expect(within(screen.getByTestId("file-/etc/secret.conf")).getByText("content not compared")).toBeInTheDocument();
    expect(within(screen.getByTestId("file-/etc/unreadable.conf")).getByText("permission denied")).toBeInTheDocument();
  });

  it("says so when the file list cannot be read, instead of drawing noughts", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    // A list nobody could read is not a host with no managed files, so
    // the tiles are not drawn at a nought beside the failure.
    expect(screen.queryByTestId("kpi-Managed files")).toBeNull();
  });

  it("counts a file the host could not read as unknown, not as matching", async () => {
    base([file({}), file({ path: "/etc/unreadable.conf", unavailable_reason: "permission denied" })]);
    draw();
    await waitFor(() => expect(screen.getByTestId("file-/etc/unreadable.conf")).toBeInTheDocument());
    const band = screen.getByTestId("file-states");
    expect(within(band).getByLabelText("unknown")).toHaveTextContent("1");
    expect(within(band).getByLabelText("as expected")).toHaveTextContent("1");
  });

  it("asks the host to read a file back without any confirmation", async () => {
    base([file({})]);
    draw();
    await waitFor(() => expect(screen.getByTestId("read-/etc/example.conf")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("read-/etc/example.conf"));
    await waitFor(() => expect(posted).toHaveLength(1));
    // Reading changes nothing on the host, so it asks nobody anything.
    expect(posted[0].body).toMatchObject({ action: "file.read", payload: { file: { path: "/etc/example.conf" } } });
    expect(screen.queryByTestId("confirm-order")).toBeNull();
  });

  it("removes a file with the fingerprint it was last seen with", async () => {
    base([file({ observed_sha256: "b".repeat(64) })]);
    draw();
    await waitFor(() => expect(screen.getByTestId("remove-/etc/example.conf")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("remove-/etc/example.conf"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "no longer managed here" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "file.remove",
      reason: "no longer managed here",
      payload: { file: { path: "/etc/example.conf", expected_sha256: "b".repeat(64) } },
    });
    // The answer says the order waits on somebody, and leads to it.
    await waitFor(() => expect(screen.getByTestId("job-notice")).toHaveTextContent("waiting for approval"));
  });

  it("opens the history of the file that was clicked, and nothing else", async () => {
    base([file({})]);
    Object.assign(answers, {
      "/api/v1/hosts/h1/files/history": {
        items: [
          { sha256: "a".repeat(64), size_bytes: 120, applied_by: "tester", applied_at: "2026-10-15T08:00:00Z" },
          { sha256: "c".repeat(64), size_bytes: 100, applied_by: "tester", applied_at: "2026-10-01T08:00:00Z" },
        ],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-/etc/example.conf")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-/etc/example.conf"));
    await waitFor(() => expect(screen.getByTestId("file-history")).toBeInTheDocument());
    const history = screen.getByTestId("file-history");
    expect(within(history).getByText("current")).toBeInTheDocument();
    // The version the host already has cannot be rolled back to while
    // nothing has drifted; an older one can.
    expect(screen.getByTestId(`rollback-${"a".repeat(64)}`)).toBeDisabled();
    expect(screen.getByTestId(`rollback-${"c".repeat(64)}`)).toBeEnabled();
  });

  it("will not order back a copy the host cannot name", async () => {
    base([file({
      host_versions: [
        { sha256: "d".repeat(64), size_bytes: 10, mode: "0600", kept_at: "2026-10-14T08:00:00Z", ordered_by: "tester" },
        { size_bytes: 10, kept_at: "2026-10-13T08:00:00Z", from_secret: true },
      ],
    })]);
    draw();
    await waitFor(() => expect(screen.getByTestId("open-/etc/example.conf")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-/etc/example.conf"));
    await waitFor(() => expect(screen.getByTestId("host-versions")).toBeInTheDocument());
    expect(screen.getByTestId("restore-2026-10-14T08:00:00Z")).toBeEnabled();
    expect(screen.getByTestId("restore-2026-10-13T08:00:00Z")).toBeDisabled();
  });

  it("writes a new file from the content typed, or from a secret, never both", async () => {
    base([file({})]);
    draw();
    await waitFor(() => expect(screen.getByTestId("manage-file")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("manage-file"));
    await waitFor(() => expect(screen.getByTestId("new-path")).toBeInTheDocument());
    expect(screen.getByTestId("new-write")).toBeDisabled();
    fireEvent.change(screen.getByTestId("new-path"), { target: { value: "/etc/new.conf" } });
    fireEvent.change(screen.getByTestId("new-secret"), { target: { value: "repo.token" } });
    // Content from the store takes the place of typed content entirely.
    expect(screen.queryByTestId("new-content")).toBeNull();
    fireEvent.click(screen.getByTestId("new-write"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "the repository token" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm-order"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toMatchObject({
      action: "file.ensure",
      payload: { file: { path: "/etc/new.conf", content_secret: { name: "repo.token" }, mode: "644" } },
    });
  });

  it("says a host with nothing managed has nothing managed, and offers the way in", async () => {
    base([]);
    draw();
    await waitFor(() => expect(screen.getByText(/does not manage any file/)).toBeInTheDocument());
    expect(screen.getByTestId("manage-file")).toBeInTheDocument();
  });
});

describe("what the files module works out on its own", () => {
  it("names why a copy the host kept cannot be ordered back", () => {
    expect(hostVersionRefusal({ size_bytes: 1, kept_at: "x", from_secret: true })).toBe("from_secret");
    expect(hostVersionRefusal({ size_bytes: 1, kept_at: "x" })).toBe("no_checksum");
    expect(hostVersionRefusal({ size_bytes: 1, kept_at: "x", sha256: "f".repeat(64) })).toBe("");
  });

  it("binds a return to the copy and to what the host has now", () => {
    const payload = hostRollbackPayload(
      {
        path: "/etc/example.conf", updated_by: "t", updated_at: "x",
        exists: true, drift: false, observed_sha256: "b".repeat(64),
      },
      { size_bytes: 1, kept_at: "x", sha256: "d".repeat(64), mode: "0600" },
    );
    expect(payload).toEqual({
      file: {
        path: "/etc/example.conf",
        version_sha256: "d".repeat(64),
        expected_sha256: "b".repeat(64),
        mode: "0600",
      },
    });
  });

  it("marks what a version added and what it took away", () => {
    expect(differenceText("one\ntwo", "one\nthree")).toBe("  one\n- two\n+ three");
  });
});

describe("the patch the difference kept from the panel being replaced", () => {
  it("colours what the version would put in and what it would take out", async () => {
    base([file({})]);
    Object.assign(answers, {
      "/api/v1/hosts/h1/files/history": {
        items: [
          { sha256: "a".repeat(64), size_bytes: 10, applied_at: "2026-10-15T08:00:00Z", applied_by: "tester" },
          { sha256: "c".repeat(64), size_bytes: 10, applied_at: "2026-10-14T08:00:00Z", applied_by: "tester" },
        ],
      },
      [`/api/v1/files/versions/${"a".repeat(64)}`]: { content: "one\nthree" },
      [`/api/v1/files/versions/${"c".repeat(64)}`]: { content: "one\ntwo" },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-/etc/example.conf")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-/etc/example.conf"));
    await waitFor(() => expect(screen.getByTestId(`compare-${"c".repeat(64)}`)).toBeEnabled());
    fireEvent.click(screen.getByTestId(`compare-${"c".repeat(64)}`));
    await waitFor(() => expect(screen.getByTestId("file-difference")).toBeInTheDocument());
    const patch = screen.getByTestId("file-difference");
    // The line that goes out and the line that comes in are told apart by
    // the product's own colours, which is what the old <pre class="ui-diff">
    // did and what a plain readout lost.
    expect(patch.querySelector(".fl-diff-out")?.textContent).toBe("- two");
    expect(patch.querySelector(".fl-diff-in")?.textContent).toBe("+ three");
  });
});
