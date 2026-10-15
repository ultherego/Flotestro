import { afterEach, describe, expect, it } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { LoginScreen } from "./App";

/**
 * The doors of the login screen, and the rule that each one can be named.
 *
 * Since 16.10 the screen carries two password boxes: the password of a local
 * account and the bootstrap token. On the day the second one arrived the
 * smoke test of the whole stack broke - it asked for "the password box on
 * the login screen" and Playwright found two and refused to guess. The stack
 * was healthy; nobody could get through the door.
 *
 * So what is checked here is not that the boxes exist but that each is
 * reachable by a name of its own. A third door tomorrow is then free.
 */

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(cleanup);

describe("the login screen", () => {
  it("names every password box it shows", () => {
    const { container } = draw(<LoginScreen provider={false} />);

    const boxes = Array.from(container.querySelectorAll('input[type="password"]'));
    expect(boxes.length, "a password box was added or removed; the name below has to follow").toBe(2);
    // The point of the test: addressing a box by its type is ambiguous, and
    // addressing it by name is not.
    expect(boxes.map((box) => box.getAttribute("data-testid")).sort())
      .toEqual(["bootstrap-token", "signin-password"]);
  });

  it("offers the password form where there is no identity provider", () => {
    draw(<LoginScreen provider={false} />);

    expect(screen.getByTestId("signin-subject")).toBeInTheDocument();
    expect(screen.getByTestId("signin-submit")).toBeInTheDocument();
    // The only other way in is the bootstrap token, and it is not a person's
    // account: the screen must not pretend a provider is there.
    expect(screen.queryByText("Sign in with identity provider")).not.toBeInTheDocument();
  });

  it("keeps the password form next to the provider where both exist", () => {
    draw(<LoginScreen provider={true} />);

    expect(screen.getByTestId("signin-subject")).toBeInTheDocument();
    expect(screen.getByText("Sign in with identity provider")).toBeInTheDocument();
  });
});
