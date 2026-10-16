import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Support, bundleSize, reasonGiven, shortDigest, watching } from "./Support";

/**
 * What the screen sends with a bundle, and what it refuses to show.
 *
 * The address the panel mints for a download is a bearer of the archive
 * for the length of its window. It goes from the answer that minted it
 * straight into the fetch, and this file is what keeps it from drifting
 * into a link, a title or the page's own history.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const fetched: string[] = [];
const answers: Record<string, unknown> = {};
const refusals: Record<string, { status: number; code: string; message: string }> = {};

const LINK = "https://panel/api/v1/support/bundles/b1/archive?t=bearer-never-on-screen";

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const longest = (path: string, from: Record<string, unknown>) =>
    Object.keys(from).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const key = longest(path, answers);
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        const refusal = refusals[longest(path, refusals) ?? ""];
        if (refusal) {
          return Promise.reject(new actual.ApiError(refusal.status, refusal.code, refusal.message));
        }
        const key = longest(path, answers);
        return Promise.resolve(key ? answers[key] : {});
      },
    },
    fetchWithCredentials: (address: string) => {
      fetched.push(address);
      return Promise.resolve({
        ok: true,
        statusText: "OK",
        blob: () => Promise.resolve(new Blob(["archive"])),
      } as unknown as Response);
    },
  };
});

const whoami = (permissions: string[]) => ({
  subject: "operator", kind: "user", roles: [], bindings: [], permissions,
});

const bundle = (over: Record<string, unknown> = {}) => ({
  id: "b1",
  state: "ready",
  reason: "ticket OPS-71",
  requested_by: "operator",
  requested_at: "2026-10-15T09:00:00Z",
  ready_at: "2026-10-15T09:01:00Z",
  size_bytes: 3 * 1024 * 1024,
  archive_sha256: "0123456789abcdef0123",
  files: 42,
  scanned: true,
  downloads: 0,
  downloadable: true,
  ...over,
});

const listing = (items: unknown[]) => ({
  items,
  count: items.length,
  retention: { bundles: "14 days", never_fetched: "48 hours" },
  token_ttl: "5 minutes",
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Support />, { wrapper });
}

/** The whole of what a reader can see, attributes included. */
function everythingOnScreen(): string {
  return document.body.innerHTML;
}

beforeEach(() => {
  // jsdom has neither of these, and the screen hands a blob to the browser.
  URL.createObjectURL = vi.fn(() => "blob:archive");
  URL.revokeObjectURL = vi.fn();
  HTMLAnchorElement.prototype.click = vi.fn();
  Object.assign(answers, {
    "/api/v1/whoami": whoami(["support.bundle.create", "support.bundle.read"]),
    "/api/v1/support/bundles": listing([bundle()]),
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  asked.length = 0;
  sent.length = 0;
  fetched.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
});

describe("the helpers the list is read by", () => {
  it("says a size in the unit it reads at a glance", () => {
    expect(bundleSize(900)).toBe("900 B");
    expect(bundleSize(4096)).toBe("4 KiB");
    expect(bundleSize(3 * 1024 * 1024)).toBe("3.0 MiB");
  });

  it("shortens a digest to what two people can compare by eye, and a missing one to a dash", () => {
    expect(shortDigest("0123456789abcdef")).toBe("0123456789ab");
    expect(shortDigest(undefined)).toBe("—");
  });

  it("watches only while something is still being assembled", () => {
    expect(watching([bundle() as never])).toBe(false);
    expect(watching([bundle({ state: "pending" }) as never])).toBe(true);
  });

  it("holds a reason to the length the server takes", () => {
    expect(reasonGiven("short")).toBe(false);
    expect(reasonGiven("  ticket OPS-71  ")).toBe(true);
  });
});

describe("asking for a bundle", () => {
  it("sends the reason the trail keeps, and not before it is long enough", async () => {
    Object.assign(answers, { "/api/v1/support/bundles": listing([]) });
    draw();
    await screen.findByTestId("ask");
    expect(screen.getByTestId("ask")).toBeDisabled();

    fireEvent.change(screen.getByTestId("reason"), { target: { value: "short" } });
    expect(screen.getByTestId("ask")).toBeDisabled();

    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    await waitFor(() => expect(screen.getByTestId("ask")).toBeEnabled());
    fireEvent.click(screen.getByTestId("ask"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ path: "/api/v1/support/bundles", body: { reason: "ticket OPS-71" } });
    await waitFor(() => expect(screen.getByText(/being assembled; it can be fetched/)).toBeInTheDocument());
  });

  it("will not ask for a second while one is being assembled", async () => {
    Object.assign(answers, { "/api/v1/support/bundles": listing([bundle({ state: "pending" })]) });
    draw();
    await screen.findByTestId("ask");
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    await waitFor(() => expect(screen.getByText(/wait for it before asking for another/)).toBeInTheDocument());
    expect(screen.getByTestId("ask")).toBeDisabled();
  });

  it("shows a refusal rather than a bundle that was never made", async () => {
    refusals["/api/v1/support/bundles"] = {
      status: 401, code: "reauthentication_required", message: "sign in again first",
    };
    draw();
    await screen.findByTestId("ask");
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    fireEvent.click(screen.getByTestId("ask"));
    await waitFor(() => expect(screen.getByText("sign in again first")).toBeInTheDocument());
  });

  it("says who may ask, where the reader may not", async () => {
    Object.assign(answers, { "/api/v1/whoami": whoami(["support.bundle.read"]) });
    draw();
    await waitFor(() => expect(screen.getByText(/support.bundle.create permission/)).toBeInTheDocument());
    expect(screen.queryByTestId("ask")).toBeNull();
  });
});

describe("the list of bundles", () => {
  it("draws a bundle as its size, its digest and what became of it", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("bundle-b1")).toBeInTheDocument());
    const row = screen.getByTestId("bundle-b1");
    expect(row).toHaveTextContent("3.0 MiB");
    expect(row).toHaveTextContent("42");
    expect(row).toHaveTextContent("0123456789ab");
    expect(within(row).getByText("ready")).toBeInTheDocument();
    expect(within(row).getByText("never")).toBeInTheDocument();
    // The whole digest is there to compare against, under the pointer.
    expect(within(row).getByTitle("0123456789abcdef0123")).toBeInTheDocument();
  });

  it("says a bundle still being assembled has no size yet, and never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/support/bundles": listing([bundle({ state: "pending", files: 0, size_bytes: 0, archive_sha256: undefined })]),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("bundle-b1")).toBeInTheDocument());
    const row = screen.getByTestId("bundle-b1");
    expect(within(row).getByText("being assembled")).toBeInTheDocument();
    expect(within(row).queryByText("0")).toBeNull();
    expect(within(row).queryByText("0 B")).toBeNull();
    expect(row).toHaveTextContent("—");
  });

  it("names the code a refused bundle came back with", async () => {
    Object.assign(answers, {
      "/api/v1/support/bundles": listing([bundle({ state: "failed", error_code: "redaction_failed" })]),
    });
    draw();
    await waitFor(() => expect(screen.getByText("redaction_failed")).toBeInTheDocument());
  });

  it("says how long a bundle and a link are kept", async () => {
    draw();
    await waitFor(() => expect(screen.getByText("14 days")).toBeInTheDocument());
    expect(screen.getByText("48 hours")).toBeInTheDocument();
    expect(screen.getByText("5 minutes")).toBeInTheDocument();
  });

  it("says the panel holds none rather than drawing an empty table", async () => {
    Object.assign(answers, { "/api/v1/support/bundles": listing([]) });
    draw();
    await waitFor(() => expect(screen.getByText(/holds no support bundle/)).toBeInTheDocument());
  });
});

describe("fetching a bundle", () => {
  it("mints a link with the reason, fetches it, and never puts it on the screen", async () => {
    Object.assign(answers, {
      "/api/v1/support/bundles/b1/download": { url: LINK, expires_at: "2026-10-15T09:10:00Z" },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("download-b1")).toBeInTheDocument());
    // Without a reason the download is held back: it is on the trail too.
    expect(screen.getByTestId("download-b1")).toBeDisabled();

    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    await waitFor(() => expect(screen.getByTestId("download-b1")).toBeEnabled());
    fireEvent.click(screen.getByTestId("download-b1"));

    await waitFor(() => expect(fetched).toEqual([LINK]));
    expect(sent[0]).toMatchObject({
      path: "/api/v1/support/bundles/b1/download", body: { reason: "ticket OPS-71" },
    });
    await waitFor(() => expect(screen.getByText(/the link it came through is spent/)).toBeInTheDocument());
    // The address is a bearer of the archive; it is used and not shown.
    expect(everythingOnScreen()).not.toContain("bearer-never-on-screen");
  });

  it("says what the fetch came back with rather than handing over nothing", async () => {
    Object.assign(answers, {
      "/api/v1/support/bundles/b1/download": { url: LINK, expires_at: "2026-10-15T09:10:00Z" },
    });
    refusals["/api/v1/support/bundles/b1/download"] = {
      status: 403, code: "forbidden", message: "the link was already spent",
    };
    draw();
    await waitFor(() => expect(screen.getByTestId("download-b1")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    fireEvent.click(screen.getByTestId("download-b1"));
    await waitFor(() => expect(screen.getByText("the link was already spent")).toBeInTheDocument());
    expect(fetched).toHaveLength(0);
  });

  it("offers no download to a reader who may not read one", async () => {
    Object.assign(answers, { "/api/v1/whoami": whoami(["support.bundle.create"]) });
    draw();
    await waitFor(() => expect(screen.getByTestId("bundle-b1")).toBeInTheDocument());
    expect(screen.queryByTestId("download-b1")).toBeNull();
  });

  it("offers no download for a bundle the server will not hand over", async () => {
    Object.assign(answers, { "/api/v1/support/bundles": listing([bundle({ downloadable: false })]) });
    draw();
    await waitFor(() => expect(screen.getByTestId("bundle-b1")).toBeInTheDocument());
    expect(screen.queryByTestId("download-b1")).toBeNull();
  });
});
