import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Readiness, verdictTone } from "./Readiness";
import { readinessVerdict } from "../../pages/Readiness";
import { ToastProvider } from "../../components/Toast";

/**
 * The screen exists because "unknown is not nought" was enforced in every
 * module and shown to the operator nowhere. The one way to fail at it here
 * is to draw a green nought over a fleet whose hosts have said nothing, so
 * that is what these hold - once over the verdict itself, and once over
 * the screen that draws it.
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
        // The longest key that the path begins with answers it: a key of
        // "/api/v1/settings/layout" would otherwise answer the readiness
        // call and hand the screen the wrong document.
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

const NO_LAYOUT = { widgets: [], present: false, revision: 0 };

/** A fleet reading, with the counts that matter named by the caller. */
const fleet = (over: Record<string, unknown>) => ({
  hosts: 4, silent: 0, operations: 30, unorderable: 0, gaps: [], ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Readiness />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the verdict at the head of the readiness screen", () => {
  it("is ok only when every host answered and nothing is missing", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 0, gaps: [] })).toBe("ok");
  });

  it("is unknown when a host has reported no adapter, even with no gap found", () => {
    // The gaps are empty because the silent host contributes none: it is
    // not known to be missing anything, which is a different thing from
    // being known to be complete.
    expect(readinessVerdict({ silent: 1, unorderable: 0, gaps: [] })).toBe("unknown");
  });

  it("asks for attention when an operation can be ordered nowhere", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 3, gaps: [{ nowhere: true }] })).toBe("attention");
  });

  it("asks for attention over a gap on some hosts", () => {
    expect(readinessVerdict({ silent: 0, unorderable: 0, gaps: [{ nowhere: false }] })).toBe("attention");
  });

  it("puts attention above unknown: a known gap is not softened by a silent host", () => {
    expect(readinessVerdict({ silent: 2, unorderable: 5, gaps: [{ nowhere: true }] })).toBe("attention");
  });

  it("never gives a silent fleet the colour of a passing one", () => {
    expect(verdictTone("ok")).toBe("ok");
    expect(verdictTone("unknown")).toBe("unknown");
    expect(verdictTone("attention")).toBe("warn");
  });
});

describe("the readiness screen", () => {
  it("says a fleet with nothing missing can be asked for everything", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({}),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText("Every operation can be ordered on every host of this fleet.")).toBeInTheDocument());
  });

  it("will not call a silent fleet ready, and colours the count unknown rather than drawing a nought", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({ silent: 2 }),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    // The banner is on screen before the answer is, so the wait is for
    // the sentence: waiting for the banner alone read the loading line.
    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent("reported no adapter at all"));
    expect(screen.queryByText("Every operation can be ordered on every host of this fleet.")).not.toBeInTheDocument();
    // Two hosts said nothing: the tile wears the unknown state, not the
    // green of a fleet that answered.
    expect(screen.getByTestId("kpi-Silent about their adapters")).toHaveAttribute("data-state", "unknown");
  });

  it("asks for attention over a gap found on some hosts, and says the reason once", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({
        gaps: [{
          requirement: "docker.compose",
          operations: ["compose.up", "compose.down"],
          satisfied: 2,
          nowhere: false,
          hosts: [
            { id: "h1", hostname: "web-1", reason: "this host has no Docker Compose plugin" },
            { id: "h2", hostname: "web-2", reason: "this host has no Docker Compose plugin" },
          ],
        }],
      }),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("gaps-somewhere")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("1 requirements are not met everywhere");
    const row = screen.getByTestId("gap-docker.compose");
    expect(within(row).getByText("docker.compose")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/h1");
    // Both hosts gave the same sentence, so it is a cause and is written
    // once rather than once per machine.
    expect(within(row).getAllByText("this host has no Docker Compose plugin")).toHaveLength(1);
    expect(within(row).getByText("2 hosts offer it")).toBeInTheDocument();
  });

  it("says a host reported no adapter rather than inventing a reason for it", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({
        silent: 1,
        unorderable: 2,
        gaps: [{
          requirement: "podman.socket",
          operations: ["container.list"],
          satisfied: 0,
          nowhere: true,
          hosts: [{ id: "h9", hostname: "db-1", silent: true }],
        }],
      }),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("gaps-nowhere")).toBeInTheDocument());
    const row = screen.getByTestId("gap-podman.socket");
    expect(within(row).getByText("has reported no adapter at all")).toBeInTheDocument();
    // One operation, not "1 operations".
    expect(within(row).getByRole("button", { name: "1 operation" })).toBeInTheDocument();
    // A known gap is not softened by the silent host, but the silent host
    // is still said on the screen written to say it.
    expect(screen.getByRole("status")).toHaveTextContent("1 hosts have reported no adapter at all");
  });

  it("opens the work a requirement blocks in a card of its own", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({
        gaps: [{
          requirement: "docker.socket",
          operations: ["container.list", "container.restart"],
          satisfied: 0,
          nowhere: false,
          hosts: [{ id: "h1", hostname: "web-1", reason: "no docker socket" }],
        }],
      }),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("gap-docker.socket")).toBeInTheDocument());
    expect(screen.queryByText("container.restart")).not.toBeInTheDocument();
    fireEvent.click(within(screen.getByTestId("gap-docker.socket")).getByRole("button", { name: "2 operations" }));
    await waitFor(() => expect(screen.getByText("container.restart")).toBeInTheDocument());
    expect(screen.getByText("container.list")).toBeInTheDocument();
  });

  it("reads the fleet from the server rather than counting a loaded page", async () => {
    Object.assign(answers, {
      "/api/v1/fleet/readiness": fleet({}),
      "/api/v1/settings/layout": NO_LAYOUT,
    });
    draw();
    await waitFor(() => expect(asked.some((one) => one === "/api/v1/fleet/readiness")).toBe(true));
  });
});
