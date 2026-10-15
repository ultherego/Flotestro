import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "./Toast";
import { Board } from "./board";
import { ApiError } from "../lib/api";
import type { BoardEntry } from "./board";

/**
 * What a write of an arrangement carries, and what happens when two people
 * arrange the same screen.
 *
 * One administrator rearranging a screen rearranges it for every operator in
 * the installation. That makes three things part of the act rather than
 * decoration: it is written with a reason the trail keeps, it is written
 * against the revision it was read at, and the person who loses a race is
 * told so instead of watching their work disappear.
 */

const stored = {
  widgets: [{ key: "first", width: 4 }, { key: "second", width: 6 }],
  present: true,
  revision: 7,
};
const sent: { path: string; body: unknown }[] = [];
const answers: { put?: unknown; del?: unknown } = {};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: () => Promise.resolve(stored),
      put: (path: string, body: unknown) => {
        sent.push({ path, body });
        return answers.put instanceof Error ? Promise.reject(answers.put) : Promise.resolve(stored);
      },
      del: (path: string) => {
        sent.push({ path, body: undefined });
        return answers.del instanceof Error ? Promise.reject(answers.del) : Promise.resolve(undefined);
      },
    },
  };
});

const catalogue: BoardEntry[] = [
  { key: "first", title: "First", width: 4 },
  { key: "second", title: "Second", width: 6 },
];

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ToastProvider>
          <Board
            screen="fleet"
            catalogue={catalogue}
            drawn={{ first: <div>one</div>, second: <div>two</div> }}
          />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

async function arrange() {
  draw();
  await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Arrange this screen"));
}

beforeEach(() => { sent.length = 0; answers.put = undefined; answers.del = undefined; });
afterEach(cleanup);

describe("storing an arrangement", () => {
  it("will not store one without a reason for the trail", async () => {
    await arrange();
    expect(screen.getByTestId("board-save")).toBeDisabled();

    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("board-save")).toBeDisabled();

    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the night shift reads the alerts first" } });
    await waitFor(() => expect(screen.getByTestId("board-save")).toBeEnabled());
  });

  it("carries the revision it was read at, so the second editor does not win by being last", async () => {
    await arrange();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the night shift reads the alerts first" } });
    fireEvent.click(screen.getByTestId("board-save"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/settings/layout/fleet");
    expect(sent[0].body).toMatchObject({
      revision: 7,
      reason: "the night shift reads the alerts first",
    });
  });

  it("says plainly when somebody else arranged the screen meanwhile", async () => {
    answers.put = new ApiError(409, "layout_changed", "somebody else arranged this screen");
    await arrange();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the night shift reads the alerts first" } });
    fireEvent.click(screen.getByTestId("board-save"));

    // The refusal is not shown as a raw code: the editor is told what
    // happened to their work and what to do about it.
    await waitFor(() => expect(screen.getByText(/Somebody else arranged this screen/)).toBeInTheDocument());
    // And the editor is closed, because what is on screen is now theirs.
    await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());
  });

  it("offers the way back to the arrangement the panel ships with", async () => {
    await arrange();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "this arrangement did not work out" } });
    fireEvent.click(screen.getByTestId("board-reset"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toContain("/api/v1/settings/layout/fleet?reason=");
    expect(decodeURIComponent(sent[0].path)).toContain("this arrangement did not work out");
  });
});
