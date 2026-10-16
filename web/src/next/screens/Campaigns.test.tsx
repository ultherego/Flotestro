import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Campaigns, campaignTone } from "./Campaigns";
import { ToastProvider } from "../../components/Toast";

/**
 * The list narrows on the server, so the band above it and the rows below
 * it are one question asked once. The tone of a state is the other thing
 * worth holding: a campaign waiting for a person is not a campaign that
 * failed, and the colours must not say they are the same.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const campaign = (over: Record<string, unknown>) => ({
  id: "c1", name: "patch the lab", action_type: "packages.upgrade", state: "running",
  canary_size: 1, wave_size: 5, max_concurrent: 2, failure_threshold_percent: 10,
  failure_threshold_absolute: 2, reboot_policy: "never", requires_approval: true,
  offline_policy: "skip", manual_gate: false, connectivity_lost_absolute: 0,
  approval_fingerprint: "f", created_by: "tszymanski", created_at: "2026-10-16T08:00:00Z",
  progress: { total: 4, succeeded: 3, failed: 1, unknown: 0, skipped: 0, pending: 0 },
  ...over,
});

function draw(where = "/campaigns") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Campaigns />, { wrapper });
}

afterEach(() => { cleanup(); asked.length = 0; });

describe("the campaign list", () => {
  it("draws a campaign as its name, its state and how far it has got", async () => {
    Object.assign(answers, {
      "/api/v1/campaigns": { items: [campaign({})], count: 1, total: 1, limit: 50, offset: 0 },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("campaign-patch the lab")).toBeInTheDocument());
    const row = screen.getByTestId("campaign-patch the lab");
    expect(within(row).getByRole("link", { name: "patch the lab" })).toHaveAttribute("href", "/campaigns/c1");
    expect(within(row).getByText("running")).toBeInTheDocument();
    // Done, failed and pending, in that order and labelled as such: the
    // column says which number is which so nobody has to guess.
    expect(row).toHaveTextContent("3 / 1 / 0");
  });

  it("counts the states of what the server returned, not of everything", async () => {
    Object.assign(answers, {
      "/api/v1/campaigns": {
        items: [campaign({}), campaign({ id: "c2", name: "second", state: "awaiting_approval" })],
        count: 2, total: 9, limit: 50, offset: 0,
      },
    });
    draw();
    // The band draws before the answer arrives, so the wait is for a row:
    // waiting for the band alone measured an empty list.
    await waitFor(() => expect(screen.getByTestId("campaign-second")).toBeInTheDocument());
    const band = screen.getByTestId("campaign-states");
    expect(band).toHaveTextContent("Awaiting approval");
    expect(band).toHaveTextContent("In progress");
    // Nine in all, two on this page, and the card says so rather than
    // letting the band pretend it counted the fleet.
    const card = band.closest(".fl-card") as HTMLElement;
    expect(card.querySelector(".fl-card-note")).toHaveTextContent("2 of 9 shown");
  });

  it("narrows on the server", async () => {
    Object.assign(answers, { "/api/v1/campaigns": { items: [], count: 0, total: 0, limit: 50, offset: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("state")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("state"), { target: { value: "paused" } });
    await waitFor(() => expect(asked.some((one) => one.includes("state=paused"))).toBe(true));
  });

  it("narrows by the operation and by when a campaign started, as the old list did", async () => {
    Object.assign(answers, { "/api/v1/campaigns": { items: [], count: 0, total: 0, limit: 50, offset: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("action")).toBeInTheDocument());
    asked.length = 0;
    // Typed filters settle before they are sent: a letter at a time is a
    // request at a time, and the list under the hand flickers.
    fireEvent.change(screen.getByTestId("action"), { target: { value: "packages.upgrade" } });
    await waitFor(() => expect(
      asked.some((one) => decodeURIComponent(one).includes("action=packages.upgrade")),
    ).toBe(true));
    asked.length = 0;
    fireEvent.change(screen.getByTestId("since"), { target: { value: "2026-10-01T00:00" } });
    await waitFor(() => expect(asked.some((one) => one.includes("since="))).toBe(true));
  });

  it("takes the whole filter from the address and puts it back", async () => {
    Object.assign(answers, { "/api/v1/campaigns": { items: [], count: 0, total: 0, limit: 50, offset: 0 } });
    draw("/campaigns?action=packages.upgrade&requester=tszymanski");
    // What the reader narrowed the list to is what the link they copy
    // carries, so a link in and a link out are the same link.
    await waitFor(() => expect(
      asked.some((one) => decodeURIComponent(one).includes("action=packages.upgrade")),
    ).toBe(true));
    expect(asked.some((one) => one.includes("requester=tszymanski"))).toBe(true);
    expect((screen.getByTestId("action") as HTMLInputElement).value).toBe("packages.upgrade");
  });

  it("says an empty list is empty rather than drawing a head over nothing", async () => {
    draw();
    await waitFor(() => expect(screen.getByText("No campaign matches this.")).toBeInTheDocument());
  });
});

describe("the tone of a campaign's state", () => {
  it("keeps what waits for a person apart from what failed", () => {
    expect(campaignTone("awaiting_approval")).toBe("warn");
    expect(campaignTone("manual_gate")).toBe("warn");
    expect(campaignTone("failed")).toBe("error");
    expect(campaignTone("plan_failed")).toBe("error");
    // A campaign somebody stopped is not a campaign that broke.
    expect(campaignTone("canceled")).toBe("unknown");
    expect(campaignTone("completed")).toBe("ok");
    // "Completed with issues" is not a success: it is a thing to read.
    expect(campaignTone("completed_with_issues")).toBe("warn");
  });
});
