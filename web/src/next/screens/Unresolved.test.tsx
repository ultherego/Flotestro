import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  anythingOpen, describeKind, kindTone, readingKind, Unresolved, verifierReading,
} from "./Unresolved";
import { ToastProvider } from "../../components/Toast";

/**
 * Three things this screen must never get wrong, and they are the three
 * it is tested for.
 *
 * The two uncertainties are different work and are never read as one
 * thing - not in their numbers, not in their words, not in their colour.
 * A narrowed page with no rows on it is not a fleet with nothing open,
 * and the sentence under the empty table is read from the counts the
 * server sent. And a ruling carries the reason it was made on, because a
 * ruling without one is a screen being cleared.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // Longest prefix wins: "/api/v1/unresolved" would otherwise answer for
  // "/api/v1/unresolved/x/ruling" too, and the screen would be handed the
  // wrong document while the test read green.
  const find = (path: string) =>
    Object.keys(answers).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const key = find(path);
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        const key = find(path);
        return Promise.resolve(key ? answers[key] : {});
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const item = (over: Record<string, unknown> = {}) => ({
  attempt_id: "a1", job_id: "j1", host_id: "h1", hostname: "agent-debian",
  action: "sysctl.ensure", kind: "applied_unverified" as const, reading: "did_not_hold" as const,
  verification: { expected: "vm.swappiness=10", observed: "vm.swappiness=60" },
  first_seen: "2026-10-14T10:00:00Z",
  ...over,
});

const counts = (over: Record<string, number> = {}) => ({
  outcome_unknown_operations: 4, outcome_unknown_hosts: 2,
  applied_unverified_operations: 7, applied_unverified_hosts: 3,
  did_not_hold_operations: 5, did_not_hold_hosts: 2,
  could_not_read_operations: 2, could_not_read_hosts: 1,
  ...over,
});

const page = (over: Record<string, unknown> = {}) =>
  ({ counts: counts(), items: [item()], total: 1, ...over });

function draw() {
  const client = new QueryClient({
    // The panel's own default: the page on screen stays while the next one
    // is fetched. A bare client would not be testing what the panel does.
    defaultOptions: { queries: { retry: false, placeholderData: (previous: unknown) => previous } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Unresolved />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the screen of unconfirmed operations", () => {
  it("draws a row as its host, its task and what the row actually says", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("unresolved-a1")).toBeInTheDocument());
    const row = screen.getByTestId("unresolved-a1");
    expect(within(row).getByRole("link", { name: "agent-debian" })).toHaveAttribute("href", "/hosts/h1");
    expect(within(row).getByRole("link", { name: "sysctl.ensure" })).toHaveAttribute("href", "/jobs/j1");
    // The conclusion in the operator's language, and the two values it was
    // drawn from underneath it.
    expect(within(row).getByTestId("reading-a1")).toHaveTextContent("The change did not hold.");
    expect(within(row).getByTestId("reading-a1")).toHaveTextContent("vm.swappiness=60");
  });

  it("says nobody has looked again rather than calling it never", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("unresolved-a1")).toBeInTheDocument());
    expect(within(screen.getByTestId("unresolved-a1")).getByText("not since")).toBeInTheDocument();
  });
});

describe("the two uncertainties", () => {
  it("are counted apart and never added together", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("count-outcome_unknown")).toHaveTextContent("4"));
    const happened = screen.getByTestId("count-outcome_unknown");
    const held = screen.getByTestId("count-applied_unverified");
    expect(happened).toHaveTextContent("Did it happen?");
    expect(held).toHaveTextContent("Did it hold?");
    expect(held).toHaveTextContent("7");
    // Eleven would be the sum, and the sum is the number this screen must
    // never show: the two ask for different work.
    expect(happened.textContent).not.toContain("11");
    expect(held.textContent).not.toContain("11");
  });

  it("counts the hosts apart from the operations", async () => {
    // One host with seven uncertain operations is not seven hosts with one
    // each, so both numbers are on the tile.
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("count-applied_unverified")).toHaveTextContent("7"));
    expect(screen.getByTestId("count-applied_unverified")).toHaveTextContent("on 3 hosts");
    expect(screen.getByTestId("count-outcome_unknown")).toHaveTextContent("on 2 hosts");
  });

  it("are never coloured the same", () => {
    // An outcome nobody knows is not a fault; a change that was applied and
    // never verified is something somebody has to go and look at.
    expect(kindTone("outcome_unknown")).toBe("unknown");
    expect(kindTone("applied_unverified")).toBe("warn");
    expect(kindTone("outcome_unknown")).not.toBe(kindTone("applied_unverified"));
  });

  it("shows a count the server did not send as unknown and not as a nought", async () => {
    // A panel mid-upgrade serves the two kind counts and not the two
    // readings inside them. Nought would say the fleet has none of either.
    Object.assign(answers, {
      "/api/v1/unresolved": {
        counts: {
          outcome_unknown_operations: 4, outcome_unknown_hosts: 2,
          applied_unverified_operations: 7, applied_unverified_hosts: 3,
        },
        items: [item()], total: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("count-applied_unverified")).toHaveTextContent("7"));
    const unreadable = screen.getByTestId("count-could_not_read");
    expect(unreadable).toHaveAttribute("data-state", "unknown");
    expect(unreadable).toHaveTextContent("—");
    expect(unreadable).not.toHaveTextContent("0");
    expect(unreadable).toHaveTextContent("Could not be read: unknown");
  });
});

describe("what an empty table says", () => {
  it("does not read as a settled fleet when the filter emptied the page", async () => {
    // The operator narrowed to one kind and sees no rows. The fleet still
    // has the other kind open, and the sentence has to say which of the two
    // situations this is - read from the counts, never from the rows.
    Object.assign(answers, {
      "/api/v1/unresolved": { counts: counts({ outcome_unknown_operations: 0, outcome_unknown_hosts: 0 }), items: [], total: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText("Nothing of this kind is open.")).toBeInTheDocument());
    expect(screen.queryByText("Every operation this fleet reported has an outcome somebody could confirm.")).toBeNull();
  });

  it("says the fleet is settled only when the counts say so", async () => {
    Object.assign(answers, {
      "/api/v1/unresolved": {
        counts: {
          outcome_unknown_operations: 0, outcome_unknown_hosts: 0,
          applied_unverified_operations: 0, applied_unverified_hosts: 0,
        },
        items: [], total: 0,
      },
    });
    draw();
    await waitFor(() => expect(
      screen.getByText("Every operation this fleet reported has an outcome somebody could confirm."),
    ).toBeInTheDocument());
  });
});

describe("narrowing", () => {
  it("asks the server rather than sieving the page", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("unresolved-a1")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.click(screen.getByRole("tab", { name: "Did it happen?" }));
    await waitFor(() => expect(asked.some((one) => one.includes("kind=outcome_unknown"))).toBe(true));
  });

  it("is one question at a time, so no combination can hold nothing by construction", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("unresolved-a1")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: "Did it happen?" }));
    await waitFor(() => expect(asked.some((one) => one.includes("kind=outcome_unknown"))).toBe(true));
    asked.length = 0;
    fireEvent.click(screen.getByRole("tab", { name: "Could not be read" }));
    await waitFor(() => expect(asked.some((one) => one.includes("reading=could_not_read"))).toBe(true));
    expect(asked.every((one) => !one.includes("kind="))).toBe(true);
  });

  it("walks the list on the server, by offset", async () => {
    Object.assign(answers, { "/api/v1/unresolved": { counts: counts(), items: [item()], total: 140 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("page-2")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.click(screen.getByTestId("page-2"));
    await waitFor(() => expect(asked.some((one) => one.includes("offset=50"))).toBe(true));
    // And it stays there: the clamp that puts a reader back on the last page
    // when the list shrinks must not fire while this page is being fetched.
    await waitFor(() => expect(screen.getByTestId("page-2")).toHaveAttribute("aria-current", "page"));
  });
});

describe("a ruling", () => {
  it("cannot be recorded without the reason it was made on", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-a1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rule-a1"));
    expect(screen.getByTestId("ruling-save")).toBeDisabled();
    // Whitespace is not a basis.
    fireEvent.change(screen.getByTestId("ruling-basis"), { target: { value: "   " } });
    expect(screen.getByTestId("ruling-save")).toBeDisabled();
  });

  it("carries its reason, its verdict and the uncertainty it answers", async () => {
    Object.assign(answers, { "/api/v1/unresolved": page() });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-a1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rule-a1"));
    fireEvent.change(screen.getByTestId("ruling-verdict"), { target: { value: "confirmed_not_applied" } });
    fireEvent.change(screen.getByTestId("ruling-basis"), { target: { value: "read /etc/sysctl.d on the host" } });
    fireEvent.click(screen.getByTestId("ruling-save"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/unresolved/a1/ruling");
    expect(posted[0].body).toEqual({
      kind: "applied_unverified",
      ruling: "confirmed_not_applied",
      basis: "read /etc/sysctl.d on the host",
    });
  });

  it("names every attempt of a batch rather than letting the server re-read the filter", async () => {
    // Re-reading the filter would also rule on whatever arrived between the
    // list being fetched and the button being pressed.
    Object.assign(answers, {
      "/api/v1/unresolved": { counts: counts(), items: [item(), item({ attempt_id: "a2" })], total: 2 },
      "/api/v1/unresolved/rulings": { ruled: 2, attempts: 2 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-on-all")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rule-on-all"));
    fireEvent.change(screen.getByTestId("batch-basis"), { target: { value: "the host was rebuilt" } });
    fireEvent.click(screen.getByTestId("batch-save"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/unresolved/rulings");
    expect(posted[0].body).toMatchObject({
      ruling: "confirmed_not_applied",
      basis: "the host was rebuilt",
      attempt_ids: ["a1", "a2"],
    });
  });

  it("keeps what it could not rule on in front of the operator", async () => {
    Object.assign(answers, {
      "/api/v1/unresolved": page({ items: [item()], total: 1 }),
      "/api/v1/unresolved/rulings": {
        ruled: 0, attempts: 1,
        refused: [{ attempt_id: "a1", code: "already_ruled", message: "somebody ruled on it first" }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rule-on-all")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rule-on-all"));
    fireEvent.change(screen.getByTestId("batch-basis"), { target: { value: "the host was rebuilt" } });
    fireEvent.click(screen.getByTestId("batch-save"));
    await waitFor(() => expect(screen.getByTestId("batch-ruled")).toHaveTextContent("0 of 1"));
    expect(screen.getByText(/somebody ruled on it first/)).toBeInTheDocument();
  });
});

/* The decisions the screen rests on are pure, so they are also checked
   without a browser - the browser cannot say what the rule is, only that
   this one page obeyed it. */

describe("describeKind", () => {
  it("asks a different question of each uncertainty", () => {
    const unknown = describeKind("outcome_unknown");
    const unverified = describeKind("applied_unverified");
    expect(unknown.question).toBe("Did it happen?");
    expect(unverified.question).toBe("Did it hold?");
    expect(unknown.question).not.toBe(unverified.question);
    expect(unknown.title).not.toBe(unverified.title);
  });
});

describe("anythingOpen", () => {
  const none = {
    outcome_unknown_operations: 0, outcome_unknown_hosts: 0,
    applied_unverified_operations: 0, applied_unverified_hosts: 0,
  };

  it("is false only when both kinds are empty", () => {
    expect(anythingOpen(none)).toBe(false);
    expect(anythingOpen({ ...none, outcome_unknown_operations: 1, outcome_unknown_hosts: 1 })).toBe(true);
    expect(anythingOpen({ ...none, applied_unverified_operations: 1, applied_unverified_hosts: 1 })).toBe(true);
  });

  it("reads the counts and not the list, so a filtered page cannot look settled", () => {
    expect(anythingOpen({ ...none, applied_unverified_operations: 3, applied_unverified_hosts: 2 })).toBe(true);
  });
});

describe("the verifier's reading", () => {
  const encode = (value: unknown) =>
    btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))));

  it("comes back out of the base64 the server writes it as", () => {
    const raw = encode({ expected: "vm.nr_hugepages=1048576", observed: "vm.nr_hugepages=1205", verified: false });
    expect(verifierReading(raw)).toMatchObject({
      expected: "vm.nr_hugepages=1048576", observed: "vm.nr_hugepages=1205",
    });
  });

  it("keeps a path that is not ASCII intact", () => {
    // atob alone gives one byte per character, so this is the case that
    // decides whether the one line an operator reads to find the file is
    // readable at all.
    const raw = encode({ expected: "sha256:aa", observed: "sha256:bb", reason: "the file /srv/ważne/plik.conf differs" });
    expect(verifierReading(raw)?.reason).toContain("/srv/ważne/plik.conf");
  });

  it("is nothing rather than a crash when the host sent something odd", () => {
    for (const raw of ["", "not base64 at all!!", btoa("{"), btoa('"a string"'), null, undefined, 7]) {
      expect(verifierReading(raw)).toBeNull();
    }
  });

  it("takes an object as it is, for the day the server stops encoding it", () => {
    expect(verifierReading({ expected: "a", observed: "b" })).toEqual({ expected: "a", observed: "b" });
  });
});

describe("the reading the server decided", () => {
  it("is taken from the row rather than worked out again", () => {
    // The list is paged and counted on the server, so a screen that
    // classified on its own would put numbers above a list that disagrees
    // with them. Here the two deliberately differ, and the row wins.
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" }, "could_not_read")).toBe("could_not_read");
    expect(readingKind("outcome_unknown", null, "did_not_hold")).toBe("did_not_hold");
  });

  it("falls back to the old derivation for a row that carries none", () => {
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" })).toBe("did_not_hold");
    expect(readingKind("applied_unverified", { expected: "on", observed: "unknown" })).toBe("could_not_read");
    expect(readingKind("applied_unverified", null)).toBe("could_not_read");
    expect(readingKind("outcome_unknown", null)).toBe("outcome_unknown");
  });

  it("ignores a value it does not know rather than trusting it", () => {
    expect(readingKind("applied_unverified", { expected: "on", observed: "off" }, "something-else")).toBe("did_not_hold");
  });

  it("never claims a change did not hold when the question is whether it happened", () => {
    expect(readingKind("outcome_unknown", { expected: "on", observed: "off" })).toBe("outcome_unknown");
  });
});
