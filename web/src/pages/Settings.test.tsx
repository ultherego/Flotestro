import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Settings } from "./Settings";

/**
 * A configuration screen is read with one name in mind. It used to answer
 * that by putting every value of every area on the screen at once; now the
 * areas are closed, they say how many values they hold, and the search opens
 * the ones that match.
 */

const settings = {
  source: "the environment of the control plane process",
  note: "",
  areas: [
    {
      key: "server",
      title: "Server",
      facts: [
        { key: "gateway_addr", value: "0.0.0.0:8443" },
        { key: "pool_max_conn_lifetime", value: "12h0m0s" },
      ],
    },
    {
      key: "database",
      title: "Database",
      facts: [
        { key: "dsn", value: "postgres://flotestro@db.flotestro.test:5432/flotestro?sslmode=verify-full" },
        { key: "pool_min_conns", value: null, secret: true, configured: true },
      ],
    },
  ],
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The panel of this test has no monitoring, so that card draws nothing.
        if (path.startsWith("/api/v1/settings/monitoring")) return Promise.reject(new Error("no monitoring"));
        return Promise.resolve(settings);
      },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/settings"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("the settings screen", () => {
  it("puts every area on the screen as a tile, with how many values it holds", async () => {
    draw(<Settings />);
    await waitFor(() => expect(document.querySelectorAll(".part").length).toBe(2));
    for (const tile of Array.from(document.querySelectorAll(".part"))) {
      expect(tile.querySelector(".part-summary")?.textContent).toContain("2 values");
    }
    // The values themselves are there, not behind anything.
    expect(screen.getByText("Agent gateway")).toBeInTheDocument();
  });

  it("finds a setting by name and leaves only what carries it", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-search")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "lifetime" } });
    await waitFor(() => expect(document.querySelectorAll(".part").length).toBe(1));
    const tile = document.querySelector(".part") as HTMLElement;
    expect(tile.textContent).toContain("Server");
    expect(tile.querySelector(".part-summary")?.textContent).toContain("1 value");
    expect(screen.queryByText("Agent gateway")).toBeNull();
  });

  it("says so when nothing carries that name", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-search")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "kerberos" } });
    await waitFor(() => expect(screen.getByText("No setting of that name.")).toBeInTheDocument());
  });

  it("keeps a secret as the answer whether it is set, never as a value", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByText("set")).toBeInTheDocument());
    expect(screen.queryByText(/postgres:\/\/flotestro@/)).not.toBeNull();
  });
});
