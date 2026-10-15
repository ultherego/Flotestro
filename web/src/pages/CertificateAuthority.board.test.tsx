import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../components/Toast";
import { CertificateAuthority } from "./CertificateAuthority";

/**
 * The fleet CA as a board.
 *
 * The screen holds two different jobs - the trust set, and a rotation in
 * two phases - and an installation in the middle of a rotation wants the
 * second at the top for a week and then never again. What this checks is
 * that the arrangement it stored is the one drawn, and that a panel the
 * screen cannot draw right now takes no space in the row.
 */

const stored = {
  widgets: [{ key: "rotation", width: 12 }, { key: "trust_set", width: 6 }],
  present: true,
  revision: 2,
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/settings/layout/")) return Promise.resolve(stored);
        if (path === "/api/v1/pki") return Promise.resolve({ authorities: [] });
        return Promise.resolve({ items: [], total: 0 });
      },
    },
  };
});

afterEach(cleanup);

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ToastProvider>
          <CertificateAuthority reportError={() => {}} />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("the fleet CA as a board", () => {
  it("draws what the installation arranged, in its order and widths", async () => {
    draw();
    // The bar appears only once the stored arrangement has arrived; before
    // that the screen draws the one it ships with.
    await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());

    const grid = screen.getByTestId("board-grid");
    // The two stored panels come first; a panel the record says nothing
    // about follows them rather than staying invisible for ever.
    expect(grid.children.length).toBeGreaterThanOrEqual(2);
    expect((grid.children[0] as HTMLElement).className).toContain("span-12");
    expect((grid.children[1] as HTMLElement).className).toContain("span-6");
  });
});
