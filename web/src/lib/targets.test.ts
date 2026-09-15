import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement, type ReactNode } from "react";
import type { CampaignTarget } from "./types";
import {
  expressionSuggestions, expressionText, loadedTargets, parseExpression, SELECTOR_KEYS, SELECTOR_OPERATORS,
  TARGET_PAGE, TARGET_STATES, useTargets, type TargetPage,
} from "./targets";

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

describe("parseExpression", () => {
  /** The selector the text means, as the server would receive it. */
  function selector(text: string) {
    const check = parseExpression(text);
    if (!check.ok) throw new Error(`${text}: ${check.error}`);
    return check.expression;
  }
  /** The error of a text that does not parse. */
  function refusal(text: string): string {
    const check = parseExpression(text);
    if (check.ok) throw new Error(`${text} parsed as ${JSON.stringify(check.expression)}`);
    return check.error;
  }

  it("reads one condition, with or without spaces around the operator", () => {
    expect(selector("site = warsaw")).toEqual({ site: "warsaw" });
    expect(selector("site=warsaw")).toEqual({ site: "warsaw" });
    expect(selector("os == debian")).toEqual({ os_family: "debian" });
  });

  it("keeps the equals sign of a tag inside its value", () => {
    expect(selector("tag=role=db")).toEqual({ tag: "role=db" });
    expect(selector("tag = role=db")).toEqual({ tag: "role=db" });
  });

  it("takes every key of the live selector under its name or alias", () => {
    expect(selector("security_updates = true and reboot_required = false and failed_units = true")).toEqual({
      all: [{ security_updates: "true" }, { reboot_required: "false" }, { failed_units: "true" }],
    });
    expect(selector("env = prod and connection = online and lifecycle = active and release_channel = beta")).toEqual({
      all: [{ environment: "prod" }, { connection_state: "online" }, { lifecycle_state: "active" }, { channel: "beta" }],
    });
    expect(selector("os_version = 12 and relay = edge-1 and failure_domain = rack-7 and owner = platform")).toEqual({
      all: [{ os_version: "12" }, { relay: "edge-1" }, { failure_domain: "rack-7" }, { owner: "platform" }],
    });
    expect(selector("group = databases and capability = packages.apt")).toEqual({
      all: [{ group: "databases" }, { capability: "packages.apt" }],
    });
  });

  it("compares the agent version with every operator and nothing else", () => {
    expect(selector("agent_version < 0.49.0")).toEqual({ agent_version: "< 0.49.0" });
    expect(selector("agent_version<=0.49.0")).toEqual({ agent_version: "<= 0.49.0" });
    expect(selector("agent_version >= v0.49.0")).toEqual({ agent_version: ">= v0.49.0" });
    expect(selector("agent_version > 0.48.2")).toEqual({ agent_version: "> 0.48.2" });
    expect(selector("agent_version = 0.49.0")).toEqual({ agent_version: "0.49.0" });
    expect(selector("agent_version != 0.49.0")).toEqual({ not: { agent_version: "0.49.0" } });
    expect(refusal("site < warsaw")).toContain("applies to agent_version");
    expect(refusal("agent_version < latest")).toContain("not a version");
    expect(refusal("agent_version >= 0.49.0-rc1")).toContain("not a version");
  });

  it("binds and tighter than or, not to one condition, and parentheses over both", () => {
    expect(selector("site = a or site = b and tag = x")).toEqual({
      any: [{ site: "a" }, { all: [{ site: "b" }, { tag: "x" }] }],
    });
    expect(selector("(site = a or site = b) and tag = x")).toEqual({
      all: [{ any: [{ site: "a" }, { site: "b" }] }, { tag: "x" }],
    });
    expect(selector("not site = a and tag = x")).toEqual({ all: [{ not: { site: "a" } }, { tag: "x" }] });
    expect(selector("not (site = a or site = b)")).toEqual({ not: { any: [{ site: "a" }, { site: "b" }] } });
    expect(selector("environment != prod")).toEqual({ not: { environment: "prod" } });
    expect(selector("SITE = warsaw AND Tag = role")).toEqual({ all: [{ site: "warsaw" }, { tag: "role" }] });
  });

  it("takes a value with spaces in double quotes", () => {
    expect(selector('owner = "platform team"')).toEqual({ owner: "platform team" });
    expect(selector('owner = "the \\"core\\" team"')).toEqual({ owner: 'the "core" team' });
  });

  it("refuses what the server refuses, naming the place", () => {
    expect(refusal("")).toBe("the expression is empty");
    expect(refusal("colour = blue")).toContain('"colour" at 0 is not a key');
    expect(refusal("site warsaw")).toContain("an operator such as = is expected");
    expect(refusal("site =")).toContain("a value is expected");
    expect(refusal("site = a and")).toContain("a condition is missing");
    expect(refusal("site = a site = b")).toContain('unexpected "site" at 9');
    expect(refusal("(site = a")).toContain("never closed");
    expect(refusal("site = a)")).toContain('unexpected ")"');
    expect(refusal('owner = "platform')).toContain("quote opened at 8 is never closed");
    expect(refusal("site => a")).toContain("is not an operator");
    expect(refusal("security_updates = yes")).toContain("not one of true, false");
    expect(refusal("connection = sleeping")).toContain("not one of online, offline, stale, unknown");
    expect(refusal("tag = Role=db")).toContain("is not a tag");
    expect(refusal("site = " + "x".repeat(129))).toContain("longer than 128");
    expect(parseExpression("site = warsaw and colour = blue")).toMatchObject({ ok: false, at: 18 });
  });

  it("reads back what expressionText writes", () => {
    const expression = selector("(site=warsaw and not tag=role=db) or agent_version < 0.49.0");
    const text = expressionText(expression);
    expect(text).toBe("((site=warsaw and not tag=role=db) or agent_version < 0.49.0)");
    expect(selector(text)).toEqual(expression);
    expect(expressionText({ agent_version: "0.49.0" })).toBe("agent_version = 0.49.0");
    expect(expressionText(undefined)).toBe("");
  });
});

describe("expressionSuggestions", () => {
  it("offers the keys where a condition starts, narrowed by what is typed", () => {
    expect(expressionSuggestions("")).toEqual([...SELECTOR_KEYS.map((key) => key.name), "not"]);
    expect(expressionSuggestions("sec")).toEqual(["security_updates"]);
    expect(expressionSuggestions("site = a and ")).toContain("tag");
    expect(expressionSuggestions("not (")).toContain("site");
    expect(expressionSuggestions("site = a and re")).toEqual(["reboot_required", "relay"]);
  });

  it("offers the operators after a key: every one for the version, equality for the rest", () => {
    expect(expressionSuggestions("site ")).toEqual(["=", "!="]);
    expect(expressionSuggestions("site")).toEqual(["=", "!="]);
    expect(expressionSuggestions("agent_version ")).toEqual(SELECTOR_OPERATORS);
    expect(expressionSuggestions("agent_version <")).toEqual(SELECTOR_OPERATORS);
  });

  it("offers the values of a key that takes a fixed set, and nothing for free text", () => {
    expect(expressionSuggestions("connection = ")).toEqual(["online", "offline", "stale", "unknown"]);
    expect(expressionSuggestions("connection = on")).toEqual(["online"]);
    expect(expressionSuggestions("reboot_required = ")).toEqual(["true", "false"]);
    expect(expressionSuggestions("site = ")).toEqual([]);
  });

  it("offers the keywords after a complete condition", () => {
    expect(expressionSuggestions("site = a ")).toEqual(["and", "or"]);
    expect(expressionSuggestions("site = a an")).toEqual(["and"]);
    expect(expressionSuggestions("(site = a) ")).toEqual(["and", "or"]);
    expect(expressionSuggestions("owner = site ")).toEqual(["and", "or"]);
  });

  it("offers nothing while a quote is open", () => {
    expect(expressionSuggestions('owner = "plat')).toEqual([]);
  });
});
