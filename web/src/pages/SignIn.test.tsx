import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { PasswordSignIn } from "./SignIn";

/**
 * Signing in where there is no identity provider.
 *
 * The panel had no door for a person without one: /auth/login answers 501
 * and the bootstrap token is for the first group mapping. What this checks
 * is the part that is easy to get wrong in a hurry - that a refusal is shown
 * rather than swallowed, and that a password that has to be replaced sends
 * its owner to the form rather than into the panel.
 */

const answers: { signIn: unknown; fail?: Error } = { signIn: {} };
const sent: { path: string; body: unknown }[] = [];
const went: string[] = [];

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      post: (path: string, body: unknown) => {
        sent.push({ path, body });
        if (answers.fail) return Promise.reject(answers.fail);
        return Promise.resolve(answers.signIn);
      },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  went.length = 0;
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { set href(value: string) { went.push(value); }, get href() { return went.at(-1) ?? ""; } },
  });
});

afterEach(() => { cleanup(); sent.length = 0; answers.fail = undefined; answers.signIn = {}; });

describe("signing in with a password", () => {
  it("asks the panel and lands on the dashboard", async () => {
    draw(<PasswordSignIn />);
    fireEvent.change(screen.getByTestId("signin-subject"), { target: { value: "ada" } });
    fireEvent.change(screen.getByTestId("signin-password"), { target: { value: "a long enough one" } });
    fireEvent.click(screen.getByTestId("signin-submit"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/auth/password");
    expect(sent[0].body).toEqual({ subject: "ada", password: "a long enough one" });
    await waitFor(() => expect(went.at(-1)).toBe("/dashboard"));
  });

  it("sends somebody whose password was chosen for them to change it first", async () => {
    answers.signIn = { must_change_password: true };
    draw(<PasswordSignIn />);
    fireEvent.change(screen.getByTestId("signin-subject"), { target: { value: "ada" } });
    fireEvent.change(screen.getByTestId("signin-password"), { target: { value: "the one they were given" } });
    fireEvent.click(screen.getByTestId("signin-submit"));
    await waitFor(() => expect(went.at(-1)).toBe("/profile?change_password=1"));
  });

  it("shows the refusal rather than swallowing it", async () => {
    answers.fail = new Error("the identity or the password is wrong");
    draw(<PasswordSignIn />);
    fireEvent.change(screen.getByTestId("signin-subject"), { target: { value: "ada" } });
    fireEvent.change(screen.getByTestId("signin-password"), { target: { value: "not the one" } });
    fireEvent.click(screen.getByTestId("signin-submit"));
    await waitFor(() =>
      expect(screen.getByTestId("signin-refusal")).toHaveTextContent("the identity or the password is wrong"));
    // And the form is usable again: a refusal that leaves the button
    // disabled is a refusal nobody can answer.
    expect(screen.getByTestId("signin-submit")).toBeEnabled();
    expect(went).toHaveLength(0);
  });

  it("asks for both halves before it offers to try", () => {
    draw(<PasswordSignIn />);
    expect(screen.getByTestId("signin-submit")).toBeDisabled();
    fireEvent.change(screen.getByTestId("signin-subject"), { target: { value: "ada" } });
    expect(screen.getByTestId("signin-submit")).toBeDisabled();
    fireEvent.change(screen.getByTestId("signin-password"), { target: { value: "x" } });
    expect(screen.getByTestId("signin-submit")).toBeEnabled();
  });
});
