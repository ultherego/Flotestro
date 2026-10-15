import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { AccessHolders, holdersToShow, shortScope } from "./AccessHolders";

/**
 * Who may sign in, which is not the same question as who has signed in.
 *
 * The owner holds a role through a directory group and had never been shown
 * on the identities list, because the panel makes a record at the first
 * sign-in. A screen about access that only lists the records answers a
 * question nobody asked.
 */

const answer = {
  items: [
    {
      subject: "xdupa", display_name: "X Dupa", kind: "user", signed_in: false,
      groups: ["flotestro-operators"],
      roles: [{ role: "operator", scope: "site=lab env=* team=* owner=* tag=*", from: "group", group: "flotestro-operators" }],
    },
    {
      subject: "bootstrap-admin", kind: "user", signed_in: true,
      principal_id: "00000000-0000-4000-8000-000000000001",
      roles: [{ role: "platform_admin", scope: "site=* env=* team=* owner=* tag=*", from: "binding" }],
    },
  ],
  count: 2,
  directory: { configured: true, read: true, users: 12 },
};

let directory = answer.directory as Record<string, unknown>;

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path === "/api/v1/access/holders") {
          return Promise.resolve({ ...answer, directory });
        }
        return Promise.resolve({ items: [], count: 0 });
      },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/settings?tab=users"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => { cleanup(); directory = answer.directory as Record<string, unknown>; });

describe("shortScope", () => {
  it("drops the categories that narrow nothing", () => {
    expect(shortScope("site=lab env=* team=* owner=* tag=*")).toBe("site=lab");
    expect(shortScope("site=* env=* team=* owner=* tag=*")).toBe("");
    expect(shortScope("site=lab env=prod team=* owner=team-a tag=*")).toBe("site=lab env=prod owner=team-a");
  });
});

describe("holdersToShow", () => {
  const people = [
    { subject: "zzz-from-group", roles: [{ role: "viewer", scope: "", from: "group", group: "g" }], signed_in: false, kind: "user" },
    { subject: "aaa-bound", roles: [{ role: "operator", scope: "", from: "binding" }], signed_in: true, kind: "user" },
  ];

  it("puts the directory's people first whatever the filter", () => {
    // The laboratory's panel holds 1785 identities a suite left behind and
    // five people. Sorted by name, the people are nowhere.
    expect(holdersToShow(people, "everyone", "").map((one) => one.subject))
      .toEqual(["zzz-from-group", "aaa-bound"]);
  });

  it("separates where the access comes from", () => {
    expect(holdersToShow(people, "directory", "").map((one) => one.subject)).toEqual(["zzz-from-group"]);
    expect(holdersToShow(people, "bound", "").map((one) => one.subject)).toEqual(["aaa-bound"]);
  });

  it("searches the name, the role and the group", () => {
    expect(holdersToShow(people, "everyone", "operator").map((one) => one.subject)).toEqual(["aaa-bound"]);
    expect(holdersToShow(people, "everyone", "g").map((one) => one.subject)).toEqual(["zzz-from-group"]);
  });
});

describe("who may sign in", () => {
  it("lists somebody the directory lets in before they have ever signed in", async () => {
    draw(<AccessHolders />);
    await waitFor(() => expect(screen.getByTestId("holder-xdupa")).toBeInTheDocument());
    const row = within(screen.getByTestId("holder-xdupa"));
    expect(row.getByText("operator")).toBeInTheDocument();
    // Where it comes from, named: the group, not "somehow".
    expect(row.getByText(/flotestro-operators/)).toBeInTheDocument();
    // And that the panel has no record of them yet - which is not the same
    // as them having no access.
    expect(row.getByText("not yet")).toBeInTheDocument();
    // The scope the group grants, with the wildcards left out.
    expect(row.getByText("site=lab")).toBeInTheDocument();
  });

  it("tells a role bound by hand from one a group grants", async () => {
    draw(<AccessHolders />);
    // The screen opens on the directory's people; the bound identities are
    // behind their own button.
    await waitFor(() => expect(screen.getByTestId("holders-bound")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("holders-bound"));
    await waitFor(() => expect(screen.getByTestId("holder-bootstrap-admin")).toBeInTheDocument());
    const row = within(screen.getByTestId("holder-bootstrap-admin"));
    expect(row.getByText("bound to this identity")).toBeInTheDocument();
    expect(row.getByText("yes")).toBeInTheDocument();
    // A binding over the whole fleet narrows nothing, and the row says so in
    // a word rather than with five wildcards.
    expect(row.getByText("everywhere")).toBeInTheDocument();
  });

  it("says when the directory did not answer rather than showing its half as empty", async () => {
    directory = { configured: true, read: false, reason: "dial tcp 192.168.56.50:443: connect: no route to host" };
    draw(<AccessHolders />);
    await waitFor(() => expect(screen.getByTestId("directory-unread")).toBeInTheDocument());
    expect(screen.getByTestId("directory-unread").textContent).toContain("no route to host");
  });

  it("says when there is no directory at all, which is a different thing", async () => {
    directory = { configured: false, read: false };
    draw(<AccessHolders />);
    await waitFor(() => expect(screen.getByTestId("directory-absent")).toBeInTheDocument());
    expect(screen.queryByTestId("directory-unread")).toBeNull();
  });
});
