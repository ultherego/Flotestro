import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Shell } from "./Shell";

/**
 * The shell is the one part of the panel every screen is seen through,
 * so what is held here is what a reader must be able to do from any of
 * them: find their way anywhere, see who they are signed in as, and be
 * told what is waiting for them.
 *
 * The finder is the part worth guarding. A rail reaches the places of
 * the panel and cannot reach the thousandth host; before this was
 * written the box in the bar was a field that did nothing, which is
 * worse than no box at all.
 *
 * The bell is the other. A count nobody could take is not a count of
 * none: a bell that draws a nought over a refused read tells the
 * operator everything is clear when nobody has looked.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};
/** Answers held open by the test, so a late one can be let go on purpose. */
const held: Record<string, { promise: Promise<unknown>; let_go: (value: unknown) => void }> = {};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      // Longest prefix wins: a short key answering a longer path is how a
      // screen gets handed the wrong document and nobody notices.
      get: (path: string) => {
        asked.push(path);
        for (const [mark, one] of Object.entries(held)) {
          if (path.includes(mark)) return one.promise;
        }
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        return key ? Promise.resolve(answers[key]) : Promise.reject(new actual.ApiError(404, "no", "no"));
      },
    },
  };
});

vi.mock("../lib/capabilities", () => ({ useCapabilities: () => ({}) }));
vi.mock("../lib/preferences", () => ({ usePreferences: () => ({ save: () => Promise.resolve() }) }));
vi.mock("./look", () => ({
  useLook: () => ({ theme: "mocha-peach", setTheme: () => {}, scale: "normal", setScale: () => {} }),
}));

/** One hit of the fleet-wide search, in the shape the server serves. */
const hit = (over: Record<string, unknown>) => ({
  kind: "host", id: "h9", title: "agent-arch", subtitle: "lab / test", path: "/hosts/h9/overview",
  ...over,
});

/** Every path the shell reads, so no short key answers a longer one. */
function serve(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/whoami": { subject: "ulther", display_name: "Ulther", roles: ["owner"], permissions: ["host.read"] },
    "/api/v1/search": { items: [hit({})], truncated: [] },
    "/api/v1/tags": { items: [], count: 0 },
    ...over,
  });
}

/** A promise the test lets go when it chooses, for a path carrying `mark`. */
function hold(mark: string) {
  let let_go: (value: unknown) => void = () => {};
  const promise = new Promise<unknown>((resolve) => { let_go = resolve; });
  held[mark] = { promise, let_go };
  return (value: unknown) => { delete held[mark]; let_go(value); };
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(held)) delete held[key];
});

const draw = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/next"]}>
        <Routes>
          <Route path="/next" element={<Shell trail={{ section: "Fleet" }}>board</Shell>} />
          <Route path="/next/hosts/:id" element={<p>one host</p>} />
          <Route path="/next/jobs/:id" element={<p>one job</p>} />
          <Route path="/next/campaigns/:id" element={<p>one campaign</p>} />
          <Route path="/next/groups" element={<p>the groups</p>} />
          <Route path="/next/tags" element={<p>the tags</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

/** Open the finder and type, as a reader does. */
async function look(text: string) {
  fireEvent.click(screen.getByTestId("open-finder"));
  fireEvent.change(screen.getByTestId("finder-field"), { target: { value: text } });
}

describe("the shell", () => {
  it("stands the person at the foot of the rail, not in the bar", async () => {
    serve();
    draw();
    await waitFor(() => expect(screen.getByTestId("user")).toHaveTextContent("Ulther"));
    const rail = document.querySelector(".fl-rail");
    expect(rail).not.toBeNull();
    expect(within(rail as HTMLElement).getByTestId("user")).toBeInTheDocument();
  });

  it("opens the finder on the one key everybody already knows", async () => {
    serve();
    draw();
    expect(screen.queryByTestId("finder")).toBeNull();
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    await waitFor(() => expect(screen.getByTestId("finder")).toBeInTheDocument());
  });

  it("reaches a host by name, which the rail cannot", async () => {
    serve();
    draw();
    await look("agent");
    await waitFor(() => expect(screen.getByText("agent-arch")).toBeInTheDocument());
    // The arrow keys walk it and Enter opens it: the one interaction
    // every other panel has already taught the reader.
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("one host")).toBeInTheDocument());
  });

  it("says so rather than showing nothing when nothing answers", async () => {
    serve({ "/api/v1/search": { items: [], truncated: [] } });
    draw();
    await look("zzzz");
    await waitFor(() => expect(screen.getByTestId("finder")).toHaveTextContent("Nothing here answers to that."));
  });

  it("closes on Escape and walks on the arrows", async () => {
    serve({
      "/api/v1/search": {
        items: [hit({}), hit({ id: "h8", title: "agent-debian", subtitle: "lab / test" })],
        truncated: [],
      },
    });
    draw();
    await look("agent");
    await waitFor(() => expect(screen.getByText("agent-debian")).toBeInTheDocument());
    const field = screen.getByTestId("finder-field");
    fireEvent.keyDown(field, { key: "ArrowDown" });
    // The second row is the one Enter would take, not the first.
    await waitFor(() => expect(screen.getByTestId("finder-host:h8")).toHaveAttribute("aria-selected", "true"));
    fireEvent.keyDown(field, { key: "ArrowUp" });
    await waitFor(() => expect(screen.getByTestId("finder-host:h9")).toHaveAttribute("aria-selected", "true"));
    fireEvent.keyDown(field, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("finder")).toBeNull());
  });
});

describe("what the finder reaches", () => {
  it("opens a job by the identifier somebody pasted out of a report", async () => {
    serve({
      "/api/v1/search": {
        items: [hit({
          kind: "job", id: "9f2c1a44-0000-4000-8000-000000000001",
          title: "package.update on db-01", subtitle: "9f2c1a44 · succeeded", path: "/jobs/9f2c1a44",
        })],
        truncated: [],
      },
    });
    draw();
    await look("9f2c1a44");
    const row = await screen.findByTestId("finder-job:9f2c1a44-0000-4000-8000-000000000001");
    expect(row).toHaveAttribute("href", "/next/jobs/9f2c1a44-0000-4000-8000-000000000001");
    expect(within(row).getByText("job")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("one job")).toBeInTheDocument());
  });

  it("opens a campaign by its name", async () => {
    serve({
      "/api/v1/search": {
        items: [hit({ kind: "campaign", id: "c7", title: "October patching", subtitle: "package.update · running" })],
        truncated: [],
      },
    });
    draw();
    await look("octo");
    const row = await screen.findByTestId("finder-campaign:c7");
    expect(row).toHaveAttribute("href", "/next/campaigns/c7");
    expect(within(row).getByText("campaign")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("one campaign")).toBeInTheDocument());
  });

  it("opens a group by its name", async () => {
    serve({
      "/api/v1/search": {
        items: [hit({ kind: "group", id: "g3", title: "database servers", subtitle: "selector · 12 hosts" })],
        truncated: [],
      },
    });
    draw();
    await look("data");
    const row = await screen.findByTestId("finder-group:g3");
    expect(within(row).getByText("group")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("the groups")).toBeInTheDocument());
  });

  it("reaches a tag, which the fleet-wide search does not know about", async () => {
    serve({
      "/api/v1/search": { items: [], truncated: [] },
      "/api/v1/tags": { items: [{ tag: "role=database", hosts: 12 }, { tag: "site=lab", hosts: 4 }], count: 2 },
    });
    draw();
    await look("role");
    const row = await screen.findByTestId("finder-tag:role=database");
    expect(within(row).getByText("tag")).toBeInTheDocument();
    expect(row).toHaveTextContent("12 hosts");
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("the tags")).toBeInTheDocument());
  });

  it("says of every answer which kind of thing it is", async () => {
    serve({
      "/api/v1/search": {
        items: [
          hit({}),
          hit({ kind: "job", id: "j1", title: "service.restart on web-02", subtitle: "j1 · failed" }),
          hit({ kind: "campaign", id: "c7", title: "October patching", subtitle: "running" }),
        ],
        truncated: [],
      },
      "/api/v1/tags": { items: [{ tag: "octal", hosts: 1 }], count: 1 },
    });
    draw();
    await look("oct");
    await screen.findByTestId("finder-tag:octal");
    for (const kind of ["host", "job", "campaign", "tag"]) {
      expect(screen.getByTestId("finder")).toHaveTextContent(kind);
    }
  });

  it("leaves out a kind the new panel has no screen for", async () => {
    serve({
      "/api/v1/search": {
        items: [hit({}), hit({ kind: "secret", id: "smtp-password", title: "smtp-password", subtitle: "vault" })],
        truncated: [],
      },
    });
    draw();
    await look("agent");
    await screen.findByTestId("finder-host:h9");
    // A row that led to "this screen is not written yet" is worse than no
    // row: it promises a place that is not there.
    expect(screen.queryByText("smtp-password")).toBeNull();
  });

  it("asks the fleet nothing until there is something to look for", async () => {
    serve();
    draw();
    await look("a");
    await waitFor(() => expect(screen.getByTestId("finder")).toBeInTheDocument());
    // One character names nearly everything; the server is not troubled
    // with it, and neither is the tag catalogue.
    await act(async () => { await new Promise((settle) => setTimeout(settle, 350)); });
    expect(asked.filter((one) => one.startsWith("/api/v1/search"))).toHaveLength(0);
    expect(asked.filter((one) => one.startsWith("/api/v1/tags"))).toHaveLength(0);
  });

  it("never lets an older answer overwrite a newer one", async () => {
    serve({ "/api/v1/search": { items: [hit({ id: "h1", title: "db-01", subtitle: "lab / prod" })], truncated: [] } });
    const letGo = hold("q=agent");
    draw();
    await look("agent");
    // The slow question is out and unanswered.
    await waitFor(() => expect(asked.some((one) => one.includes("q=agent"))).toBe(true));
    fireEvent.change(screen.getByTestId("finder-field"), { target: { value: "db" } });
    await waitFor(() => expect(screen.getByText("db-01")).toBeInTheDocument());
    // Now the older one answers. It belongs to a question nobody is
    // asking any more, so it must not land on the screen.
    letGo({ items: [hit({ id: "h9", title: "agent-arch", subtitle: "lab / test" })], truncated: [] });
    await act(async () => { await new Promise((settle) => setTimeout(settle, 50)); });
    expect(screen.queryByText("agent-arch")).toBeNull();
    expect(screen.getByText("db-01")).toBeInTheDocument();
  });
});

describe("the bell", () => {
  it("says how many are waiting behind it", async () => {
    serve({ "/api/v1/notifications/deliveries": { items: [], count: 0, dead_letters: 3 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("bell")).toHaveAttribute("aria-label", "Notifications: 3 waiting"));
    const bar = document.querySelector(".fl-bar") as HTMLElement;
    expect(within(bar).getByText("3")).toBeInTheDocument();
  });

  it("reads the figure off the same answer the screen reads", async () => {
    serve({ "/api/v1/notifications/deliveries": { items: [], count: 0, dead_letters: 1 } });
    draw();
    await waitFor(() => expect(asked.some((one) => one.startsWith("/api/v1/notifications/deliveries"))).toBe(true));
  });

  it("draws no number at all when nothing is waiting", async () => {
    serve({ "/api/v1/notifications/deliveries": { items: [], count: 0, dead_letters: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("bell"))
      .toHaveAttribute("aria-label", "Notifications: nothing waiting"));
    const bar = document.querySelector(".fl-bar") as HTMLElement;
    expect(within(bar).queryByText("0")).toBeNull();
  });

  it("shows no number when the count was refused, rather than a nought", async () => {
    // Nothing answers the deliveries path: the read is refused.
    serve();
    draw();
    await waitFor(() => expect(asked.some((one) => one.startsWith("/api/v1/notifications/deliveries"))).toBe(true));
    const bar = document.querySelector(".fl-bar") as HTMLElement;
    await waitFor(() => expect(screen.getByTestId("bell")).toHaveAttribute("aria-label", "Notifications"));
    // A count nobody could take is not a count of none.
    expect(within(bar).queryByText("0")).toBeNull();
    expect(screen.getByTestId("bell")).not.toHaveTextContent("0");
  });
});
