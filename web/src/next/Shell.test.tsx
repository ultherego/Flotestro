import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Shell } from "./Shell";

/**
 * The shell is the one part of the panel every screen is seen through,
 * so what is held here is what a reader must be able to do from any of
 * them: find their way anywhere, and see who they are signed in as.
 *
 * The finder is the part worth guarding. A rail reaches the places of
 * the panel and cannot reach the thousandth host; before this was
 * written the box in the bar was a field that did nothing, which is
 * worse than no box at all.
 */

const answers: Record<string, unknown> = {
  "/api/v1/whoami": { subject: "ulther", display_name: "Ulther", roles: ["owner"], permissions: ["host.read"] },
  "/api/v1/hosts": { items: [{ id: "h9", hostname: "agent-arch", site: "lab", environment: "test" }], count: 1 },
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      // Longest prefix wins: a short key answering a longer path is how a
      // screen gets handed the wrong document and nobody notices.
      get: (path: string) => {
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

afterEach(cleanup);

const draw = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/next"]}>
        <Routes>
          <Route path="/next" element={<Shell trail={{ section: "Fleet" }}>board</Shell>} />
          <Route path="/next/hosts/:id" element={<p>one host</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("the shell", () => {
  it("stands the person at the foot of the rail, not in the bar", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("user")).toHaveTextContent("Ulther"));
    const rail = document.querySelector(".fl-rail");
    expect(rail).not.toBeNull();
    expect(within(rail as HTMLElement).getByTestId("user")).toBeInTheDocument();
  });

  it("opens the finder on the one key everybody already knows", async () => {
    draw();
    expect(screen.queryByTestId("finder")).toBeNull();
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    await waitFor(() => expect(screen.getByTestId("finder")).toBeInTheDocument());
  });

  it("reaches a host by name, which the rail cannot", async () => {
    draw();
    fireEvent.click(screen.getByTestId("open-finder"));
    fireEvent.change(screen.getByTestId("finder-field"), { target: { value: "agent" } });
    await waitFor(() => expect(screen.getByText("agent-arch")).toBeInTheDocument());
    // The arrow keys walk it and Enter opens it: the one interaction
    // every other panel has already taught the reader.
    fireEvent.keyDown(screen.getByTestId("finder-field"), { key: "Enter" });
    await waitFor(() => expect(screen.getByText("one host")).toBeInTheDocument());
  });

  it("says so rather than showing nothing when nothing answers", async () => {
    draw();
    fireEvent.click(screen.getByTestId("open-finder"));
    fireEvent.change(screen.getByTestId("finder-field"), { target: { value: "zzzz" } });
    await waitFor(() => expect(screen.getByTestId("finder")).toHaveTextContent("Nothing here answers to that."));
  });
});
