import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Status, blockSummary, blockTone, STATUS_REFRESH_INTERVAL } from "./Status";
import { duration as formatSeconds, goDuration as humanDuration } from "../lib/format";

/* The helpers judge the tone and shape the numbers; the page only draws
   what they say, so they are tested on their own, without a screen. */

describe("blockTone", () => {
  it("draws a block the server could not judge as unknown, never as fine", () => {
    expect(blockTone({ ok: null })).toBe("unknown");
    expect(blockTone({ ok: null, attention: "a note" })).toBe("unknown");
  });

  it("draws a failed block red whatever else it says", () => {
    expect(blockTone({ ok: false })).toBe("error");
    expect(blockTone({ ok: false, attention: "a note" })).toBe("error");
  });

  it("draws a fine block amber when it carries a note and green otherwise", () => {
    expect(blockTone({ ok: true, attention: "a consumer fails its deliveries" })).toBe("warn");
    expect(blockTone({ ok: true })).toBe("ok");
    expect(blockTone({ ok: true, attention: "" })).toBe("ok");
  });
});

describe("formatSeconds", () => {
  it("keeps a fraction below ten seconds and drops it above", () => {
    expect(formatSeconds(0.42)).toBe("0.4s");
    expect(formatSeconds(4)).toBe("4.0s");
    expect(formatSeconds(42.6)).toBe("43s");
  });

  it("breaks minutes, hours and days down to the next unit", () => {
    expect(formatSeconds(90)).toBe("1m 30s");
    expect(formatSeconds(3600 + 15 * 60)).toBe("1h 15m");
    expect(formatSeconds(2 * 86400 + 3 * 3600)).toBe("2d 3h");
  });

  it("shows a negative or unreadable value as a dash rather than a number", () => {
    expect(formatSeconds(-1)).toBe("—");
    expect(formatSeconds(Number.NaN)).toBe("—");
  });
});

describe("STATUS_REFRESH_INTERVAL", () => {
  it("refreshes every fifteen seconds", () => {
    expect(STATUS_REFRESH_INTERVAL).toBe(15_000);
  });
});

describe("humanDuration", () => {
  it("reads a Go duration in days, hours, minutes and seconds, the zero parts left out", () => {
    expect(humanDuration("720h0m0s")).toBe("30 d");
    expect(humanDuration("6h0m0s")).toBe("6 h");
    expect(humanDuration("4m30s")).toBe("4 min 30 s");
    expect(humanDuration("29m53s")).toBe("29 min 53 s");
    expect(humanDuration("26h0m0s")).toBe("1 d 2 h");
  });

  it("shows a value in another shape as it came", () => {
    expect(humanDuration("soon")).toBe("soon");
    expect(humanDuration("")).toBe("");
  });
});

/* ---------------------------------------------------------------------- */
/* The screen itself. Three of its blocks send a structure, and a structure */
/* is what this page used to print as a line of JSON through the side of a  */
/* card.                                                                   */
/* ---------------------------------------------------------------------- */

const view = {
  generated_at: "2026-10-13T08:00:00Z",
  ok: false,
  unknown: 1,
  links: { openapi: "/api/v1/openapi.json", metrics: "/metrics" },
  blocks: {
    database: { ok: true, facts: { reachable: true, latency_ms: 1.37, size_bytes: 94_000_000 } },
    replicas: {
      ok: true,
      facts: {
        gateway_id: "panel-7f3a9c2e1b",
        replicas_seen: 2,
        connections_per_replica: 10,
        replicas: [
          { gateway_id: "panel-7f3a9c2e1b", instance_id: "i-1", hostname: "panel-a", pool_max_conns: 10, started_at: "2026-10-13T06:00:00Z", heartbeat_seconds_ago: 2.1, this: true },
          { gateway_id: "panel-02bd44aa71", instance_id: "i-2", hostname: "panel-b", pool_max_conns: 10, started_at: "2026-10-13T06:04:00Z", heartbeat_seconds_ago: 3.4 },
        ],
      },
    },
    crypto: {
      ok: false,
      reason: "this replica is behind the installation record",
      facts: {
        installation_id: "7f3a9c2e1b4d5e6f8a9b0c1d2e3f4a5b",
        provider: "file",
        active_key_id: "k-7f3a",
        issuer_fingerprint: "9f2c1a4b8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211aabbccdd",
        keys: ["k-7f3a", "k-02bd"],
        versions_by_key: { "k-7f3a": 3, "k-02bd": 1 },
        pending_rewrap: 0,
      },
    },
    monitoring: { ok: null, reason: "the monitoring could not be judged", facts: { enabled: true } },
  },
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return { ...actual, api: { ...actual.api, get: () => Promise.resolve(view) } };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/status"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("the status screen", () => {
  it("opens with the verdict of the whole and what could not be judged", async () => {
    draw(<Status />);
    await waitFor(() => expect(screen.getByTestId("verdict")).toBeInTheDocument());
    expect(screen.getByTestId("verdict")).toHaveTextContent("A part of this panel is not fine");
    expect(screen.getByTestId("verdict")).toHaveTextContent("1 of 4 parts could not be judged");
  });

  it("names the parts that need a look above the detail", async () => {
    draw(<Status />);
    await waitFor(() => expect(screen.getByTestId("needs-attention")).toBeInTheDocument());
    const zone = screen.getByTestId("needs-attention");
    expect(zone).toHaveTextContent("Cryptographic state");
    expect(zone).toHaveTextContent("Monitoring");
    // The two that are fine are not in this zone; they are below, closed.
    expect(zone).not.toHaveTextContent("Database");
  });

  it("puts every part on the screen at once and marks the ones that are not fine", async () => {
    draw(<Status />);
    await waitFor(() => expect(document.querySelectorAll(".part").length).toBeGreaterThan(0));
    const parts = Array.from(document.querySelectorAll(".part"));
    const of = (name: string) => parts.find((one) => one.querySelector(".part-title")?.textContent?.includes(name));
    // The four parts the server judged, all drawn, none behind a click.
    expect(parts).toHaveLength(4);
    expect(of("Database")?.className).toContain("ok");
    expect(of("Cryptographic state")?.className).toContain("error");
    // Unknown is not fine, and it is marked as its own thing rather than green.
    expect(of("Monitoring")?.className).toContain("unknown");
  });

  it("says the one fact worth reading first on every part", async () => {
    draw(<Status />);
    await waitFor(() => expect(document.querySelectorAll(".part-summary").length).toBeGreaterThan(0));
    const parts = Array.from(document.querySelectorAll(".part"));
    const summary = (name: string) =>
      parts.find((one) => one.querySelector(".part-title")?.textContent?.includes(name))
        ?.querySelector(".part-summary")?.textContent;
    expect(summary("Replicas")).toContain("2 alive");
    expect(summary("Database")).toContain("1.4 ms round trip");
  });

  /* The defect: the replicas of the control plane and the keys of the
     installation are structures, and every one of them was drawn with
     String() - one unbreakable line that left the card through its right
     edge. */
  it("draws each replica as its own list of named fields, never as JSON", async () => {
    draw(<Status />);
    await waitFor(() => expect(screen.getAllByText("Pool max conns").length).toBe(2));
    const part = screen.getAllByText("Pool max conns")[0].closest(".part") as HTMLElement;
    // Seven fields per replica: a table of seven columns inside a tile is a
    // row with its end cut off, so each record is a list of its own.
    expect(within(part).queryByRole("table")).toBeNull();
    expect(part.querySelectorAll(".records > dl")).toHaveLength(2);
    expect(part.textContent).not.toContain('"gateway_id"');
    expect(part.textContent).not.toContain("[object Object]");
  });

  it("draws the keys of the installation and their versions without JSON", async () => {
    draw(<Status />);
    await waitFor(() => expect(screen.getByText("Versions per key")).toBeInTheDocument());
    const part = screen.getByText("Versions per key").closest(".part") as HTMLElement;
    expect(part.textContent).not.toContain("{");
    expect(part.textContent).toContain("k-7f3a");
  });

  it("shortens the identifiers instead of letting them out of the card", async () => {
    draw(<Status />);
    await waitFor(() => expect(screen.getByText("Issuer fingerprint")).toBeInTheDocument());
    const whole = view.blocks.crypto.facts.issuer_fingerprint as string;
    const row = screen.getByText("Issuer fingerprint").nextElementSibling as HTMLElement;
    expect(within(row).getByRole("button")).toHaveAttribute("title", whole);
    expect(row.textContent).not.toBe(whole);
  });
});

describe("blockSummary", () => {
  const t = (text: string, values?: Record<string, string | number>) =>
    text.replace(/\{(\w+)\}/g, (_, key) => String(values?.[key] ?? ""));

  it("gives every part one fact worth reading while it is closed", () => {
    expect(blockSummary("replicas", { replicas_seen: 3 }, t)).toBe("3 alive");
    expect(blockSummary("outbox", { pending: 4 }, t)).toBe("4 events waiting");
    expect(blockSummary("scheduler", { running: 2, queued: 9 }, t)).toBe("2 running, 9 queued");
    expect(blockSummary("crypto", { provider: "file", keys: ["a", "b"] }, t)).toBe("file, 2 keys");
    expect(blockSummary("directory", { configured: false }, t)).toBe("not configured");
    expect(blockSummary("housekeeping", {}, t)).toBe("never swept");
  });

  it("says nothing rather than zero when the fact never arrived", () => {
    // A latency of nothing is not a latency of zero; the summary stays empty
    // and the section's own rows say what is missing.
    expect(blockSummary("database", {}, t)).toBe("");
    expect(blockSummary("certificates", {}, t)).toBe("");
  });
});
