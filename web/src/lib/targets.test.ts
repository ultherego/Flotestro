import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement, type ReactNode } from "react";
import type { CampaignTarget } from "./types";
import { loadedTargets, TARGET_PAGE, TARGET_STATES, useTargets, type TargetPage } from "./targets";

/* The pages come from the API; the client is replaced by a function each
   test programs. The mock is hoisted with the module, because the factory
   runs while the hook module is being imported. */
const get = vi.hoisted(() => vi.fn());

vi.mock("./api", () => ({
  api: { get },
}));

afterEach(() => {
  cleanup();
  get.mockReset();
});

/** A target row with only the fields a test reads; the API returns more. */
function target(id: string, state = "pending"): CampaignTarget {
  return { host_id: id, hostname: id, state } as unknown as CampaignTarget;
}

function page(items: CampaignTarget[], next?: string): TargetPage {
  return { items, count: items.length, total: 5, ...(next ? { next_cursor: next } : {}) };
}

/** The hook queries the API, so it runs inside a query client with retries off. */
function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return createElement(QueryClientProvider, { client }, children);
}

describe("loadedTargets", () => {
  it("flattens the loaded pages into one list in their order", () => {
    const data = { pages: [page([target("a"), target("b")], "c2"), page([target("c")])] };
    expect(loadedTargets(data).map((row) => row.host_id)).toEqual(["a", "b", "c"]);
  });

  it("is an empty list before the first page, not an undefined one", () => {
    expect(loadedTargets(undefined)).toEqual([]);
    expect(loadedTargets({ pages: [] })).toEqual([]);
  });
});

describe("TARGET_STATES", () => {
  it("lists every state a target can be in, each once, the open ones before the closed", () => {
    expect(new Set(TARGET_STATES).size).toBe(TARGET_STATES.length);
    for (const state of ["pending", "running", "succeeded", "failed", "skipped", "ineligible", "excluded", "canceled"]) {
      expect(TARGET_STATES).toContain(state);
    }
    expect(TARGET_STATES.indexOf("pending")).toBeLessThan(TARGET_STATES.indexOf("succeeded"));
    expect(TARGET_STATES.indexOf("running")).toBeLessThan(TARGET_STATES.indexOf("failed"));
  });
});

describe("useTargets", () => {
  it("asks for the first page of the campaign with the page size and no filter", async () => {
    get.mockResolvedValue(page([target("a")]));
    const { result } = renderHook(() => useTargets("c1", {}), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith(`/api/v1/campaigns/c1/targets?limit=${TARGET_PAGE}`);
    expect(loadedTargets(result.current.data).map((row) => row.host_id)).toEqual(["a"]);
    expect(result.current.hasNextPage).toBe(false);
  });

  it("puts the state, the wave and the search into the query for the server to filter", async () => {
    get.mockResolvedValue(page([]));
    const { result } = renderHook(() => useTargets("c1", { state: "failed", wave: 2, search: "db 01" }), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = new URL(get.mock.calls[0][0] as string, "http://panel");
    expect(url.pathname).toBe("/api/v1/campaigns/c1/targets");
    expect(url.searchParams.get("limit")).toBe(String(TARGET_PAGE));
    expect(url.searchParams.get("state")).toBe("failed");
    expect(url.searchParams.get("wave")).toBe("2");
    expect(url.searchParams.get("q")).toBe("db 01");
    expect(url.searchParams.has("cursor")).toBe(false);
  });

  it("leaves out a negative wave and an empty search, which mean no filter", async () => {
    get.mockResolvedValue(page([]));
    const { result } = renderHook(() => useTargets("c1", { wave: -1, search: "", state: "" }), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    const url = new URL(get.mock.calls[0][0] as string, "http://panel");
    expect([...url.searchParams.keys()]).toEqual(["limit"]);
  });

  it("follows the cursor to the next page and stops when the server hands none back", async () => {
    get.mockResolvedValueOnce(page([target("a")], "cursor-2")).mockResolvedValueOnce(page([target("b")]));
    const { result } = renderHook(() => useTargets("c1", {}), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.hasNextPage).toBe(true);

    await result.current.fetchNextPage();
    await waitFor(() => expect(loadedTargets(result.current.data)).toHaveLength(2));
    const second = new URL(get.mock.calls[1][0] as string, "http://panel");
    expect(second.searchParams.get("cursor")).toBe("cursor-2");
    expect(result.current.hasNextPage).toBe(false);
  });

  it("does not ask for the targets of no campaign", async () => {
    const { result } = renderHook(() => useTargets("", {}), { wrapper });
    // Nothing to wait for: a disabled query never runs its function.
    await new Promise((done) => setTimeout(done, 20));
    expect(get).not.toHaveBeenCalled();
    expect(result.current.isFetching).toBe(false);
    expect(loadedTargets(result.current.data)).toEqual([]);
  });
});
