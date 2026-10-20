import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { NextPanel } from "./Panel";

/**
 * A screen is fetched when it is first opened, not with the shell: the whole
 * interface in one file was 2.5 MB. What is held here is that the way of
 * fetching still ends on the screen - an address that is a lazy screen must
 * come out as that screen, with a bone where it was being fetched, and an
 * address that is nothing must still say so without fetching anything.
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => (path.startsWith("/api/v1/whoami")
        ? Promise.resolve({ subject: "ulther", display_name: "Ulther", roles: [], permissions: [] })
        : Promise.reject(new actual.ApiError(404, "no", "no"))),
    },
  };
});
vi.mock("../lib/capabilities", () => ({ useCapabilities: () => ({}) }));
vi.mock("../lib/preferences", () => ({
  usePreferences: () => ({ preferences: {}, settled: true, save: () => Promise.resolve() }),
}));
vi.mock("./look", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./look")>()),
  useLook: () => ({ theme: "mocha-peach", setTheme: () => {}, scale: "normal", setScale: () => {} }),
}));

afterEach(cleanup);

const draw = (at: string) => render(
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={[at]}>
      <NextPanel look={{ theme: "mocha-peach", scale: "normal" } as never} />
    </MemoryRouter>
  </QueryClientProvider>,
);

describe("the screens that are fetched when they are opened", () => {
  it("draws a bone while the screen is fetched, and then the screen", async () => {
    const { container } = draw("/support");
    expect(container.querySelector(".fl-bone")).not.toBeNull();
    expect(await screen.findByText("Support bundle")).toBeInTheDocument();
  });

  it("says plainly that an address leads nowhere, without fetching a screen for it", () => {
    draw("/nowhere-at-all");
    expect(screen.getByText("Page not found.")).toBeInTheDocument();
  });
});
