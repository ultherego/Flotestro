import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Tags, hostsWithTag, splitTag, validTagName } from "./Tags";
import { ToastProvider } from "../../components/Toast";

/**
 * What the catalogue says about one tag, and what a rename sends.
 *
 * A rename reaches every host carrying the tag at once, so the two things
 * held hardest here are that it asks before it goes and that the reason
 * the trail keeps travels with it.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    return Promise.resolve(answers[key]);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        const asked = body as { from: string; to: string };
        return Promise.resolve({ from: asked.from, to: asked.to, hosts: 4, host_ids: [] });
      },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve(undefined); },
    },
  };
});

const writer = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.tag.write"] };
const reader = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.read"] };

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Tags />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the catalogue", () => {
  it("draws a tag as its key, its value and the hosts carrying it, with the name leading to them", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "role=db", hosts: 4 }], count: 1 },
      "/api/v1/whoami": reader,
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("tag-role=db")).toBeInTheDocument());
    const row = screen.getByTestId("tag-role=db");
    expect(within(row).getByRole("link", { name: "role=db" })).toHaveAttribute("href", "/hosts?tag=role%3Ddb");
    expect(within(row).getByText("role")).toBeInTheDocument();
    expect(within(row).getByText("db")).toBeInTheDocument();
    expect(row).toHaveTextContent("4");
  });

  it("says a plain tag has no value with a dash rather than an empty cell", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "canary", hosts: 2 }], count: 1 },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("tag-canary")).toBeInTheDocument());
    const row = screen.getByTestId("tag-canary");
    expect(within(row).getByTitle("a plain tag, written without a value")).toHaveTextContent("—");
  });

  it("says how many of how many it is drawing when the search narrows it", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "role=db", hosts: 4 }, { tag: "canary", hosts: 2 }], count: 2 },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("tag-canary")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("tag-search"), { target: { value: "role" } });
    await waitFor(() => expect(screen.queryByTestId("tag-canary")).not.toBeInTheDocument());
    const card = screen.getByTestId("tag-role=db").closest(".fl-card") as HTMLElement;
    expect(card.querySelector(".fl-card-note")).toHaveTextContent("1 of 2 tags");
  });

  it("says a fleet nobody has tagged is untagged, and where a tag is written", async () => {
    Object.assign(answers, { "/api/v1/tags": { items: [], count: 0 }, "/api/v1/whoami": reader });
    draw();
    await waitFor(() => expect(screen.getByText(/No host you may read carries a tag/)).toBeInTheDocument());
  });
});

describe("renaming a tag", () => {
  it("asks first, says what it will and will not reach, and sends the reason with it", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "role=db", hosts: 4 }, { tag: "canary", hosts: 2 }], count: 2 },
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rename-a-tag")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rename-a-tag"));
    // Open, and nothing sent: the dialog is the question, not the act.
    expect(sent).toHaveLength(0);
    expect(screen.getByTestId("tag-rename")).toBeDisabled();

    fireEvent.change(screen.getByTestId("tag-from"), { target: { value: "role=db" } });
    fireEvent.change(screen.getByTestId("tag-to"), { target: { value: "role=database" } });
    // Still shut: the trail has not been told why.
    expect(screen.getByTestId("tag-rename")).toBeDisabled();
    expect(screen.getByText(/go on naming it and match nothing/)).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("tag-reason"), { target: { value: "unifying the spelling, FLO-412" } });
    expect(screen.getByTestId("tag-rename")).toBeEnabled();
    fireEvent.click(screen.getByTestId("tag-rename"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({
      method: "POST",
      path: "/api/v1/tags/rename",
      body: { from: "role=db", to: "role=database", reason: "unifying the spelling, FLO-412" },
    });
  });

  it("refuses a name the server would refuse, before the request leaves", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "role=db", hosts: 4 }], count: 1 },
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rename-a-tag")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rename-a-tag"));
    fireEvent.change(screen.getByTestId("tag-from"), { target: { value: "role=db" } });
    fireEvent.change(screen.getByTestId("tag-to"), { target: { value: "Role DB" } });
    fireEvent.change(screen.getByTestId("tag-reason"), { target: { value: "unifying the spelling" } });
    expect(screen.getByTestId("tag-rename")).toBeDisabled();
    expect(screen.getByText("Not a tag: key or key=value, lower-case key.")).toBeInTheDocument();
    expect(sent).toHaveLength(0);
  });

  it("is not offered to whoever may not write tags", async () => {
    Object.assign(answers, {
      "/api/v1/tags": { items: [{ tag: "role=db", hosts: 4 }], count: 1 },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("tag-role=db")).toBeInTheDocument());
    expect(screen.queryByTestId("rename-a-tag")).not.toBeInTheDocument();
  });
});

describe("a tag taken apart", () => {
  it("keeps a plain tag's value absent rather than empty", () => {
    expect(splitTag("canary")).toEqual({ key: "canary" });
    expect(splitTag("role=db")).toEqual({ key: "role", value: "db" });
    // Only the first `=` divides: a value may carry one.
    expect(splitTag("url=https://a=b")).toEqual({ key: "url", value: "https://a=b" });
  });

  it("escapes the tag in the address it hands on", () => {
    expect(hostsWithTag("role=db")).toBe("/hosts?tag=role%3Ddb");
  });

  it("takes the names the server takes and no others", () => {
    expect(validTagName("canary")).toBe(true);
    expect(validTagName("role=db")).toBe(true);
    expect(validTagName("Role")).toBe(false);
    expect(validTagName("role db")).toBe(false);
    expect(validTagName(`a=${"b".repeat(200)}`)).toBe(false);
  });
});
