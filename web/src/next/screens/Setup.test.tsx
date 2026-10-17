import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Setup, stepLink } from "./Setup";
import { ToastProvider } from "../../components/Toast";

/**
 * The first run: the second screen anybody ever sees.
 *
 * What it has to get right is the order of the work, what the panel
 * actually found, and the fact that nothing which signs anybody in is
 * ever drawn. The bootstrap token is named as live and never shown, and
 * a step nobody has the right to act on offers no button at all.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What a write answers with; an Error here is rejected rather than returned. */
const writes: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: "/api/v1/setup"
  // left to answer "/api/v1/setup/test-oidc" would hand a test button the
  // whole checklist, and the assertion after that measures the harness.
  const longest = (table: Record<string, unknown>, path: string) =>
    Object.keys(table).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];

  const read = (path: string) => {
    asked.push(path);
    const key = longest(answers, path);
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    const value = answers[key];
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value);
  };
  const write = (method: string) => (path: string, body?: unknown) => {
    sent.push({ method, path, body });
    const key = longest(writes, path);
    const value = key ? writes[key] : undefined;
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value ?? {});
  };
  return {
    ...actual,
    api: { ...actual.api, get: read, post: write("POST"), put: write("PUT"), del: write("DELETE") },
  };
});

const step = (over: Record<string, unknown> = {}) => ({
  key: "identity_provider", state: "done", detail: "Keycloak answered.", path: "/settings", ...over,
});

const checklist = (over: Record<string, unknown> = {}) => ({
  steps: [
    step({ key: "identity_provider", state: "done", detail: "Issuer https://id.example.org.", path: "/settings" }),
    step({ key: "group_mapping", state: "undone", detail: "No mapping.", path: "/access?tab=mappings" }),
    step({ key: "advertised_address", state: "undone", detail: "Not confirmed.", path: "/setup" }),
    step({ key: "hosts", state: "undone", detail: "No host has enrolled.", path: "/hosts/new" }),
    step({ key: "directory", state: "optional", detail: "No connector.", path: "/directory" }),
  ],
  done: 1,
  total: 4,
  complete: false,
  bootstrap_live: true,
  ...over,
});

const capabilities = { identity_provider: true, directory: true, directory_write: true, local_users: false, campaign_v2: true };

const admin = {
  subject: "tszymanski", kind: "user", roles: [], bindings: [],
  permissions: ["settings.read", "settings.advertise.write", "principal.manage", "identity.read"],
};
const reader = { subject: "nobody", kind: "user", roles: [], bindings: [], permissions: ["host.read"] };

const advertised = {
  in_force: ["127.0.0.1"],
  source: "default",
  loopback_only: true,
  environment_in_force: false,
  candidates: [
    { name: "192.168.56.10", kind: "address", interface: "eth1", loopback: false },
    { name: "panel", kind: "hostname", loopback: false },
  ],
  note: "The agents are told this at enrolment.",
};

const base = (over: Record<string, unknown> = {}) => ({
  "/api/v1/setup": checklist(),
  "/api/v1/whoami": admin,
  "/api/v1/capabilities": capabilities,
  "/api/v1/settings/advertised": advertised,
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/setup"]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Setup />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(writes)) delete writes[key];
});

describe("where a step leads", () => {
  it("sends the reader into the new panel, never back into the one it replaces", () => {
    expect(stepLink("/hosts/new")).toBe("/hosts/new");
    expect(stepLink("/access?tab=mappings")).toBe("/access?tab=mappings");
  });
});

describe("the first run", () => {
  it("draws nothing it has not read yet, and never the word Loading", () => {
    Object.assign(answers, base());
    const { container } = draw();
    expect(container.querySelectorAll(".fl-bone").length).toBeGreaterThan(0);
    expect(screen.queryByText("Loading…")).toBeNull();
  });

  it("works down the server's list, numbered, each with what the panel found", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("found-group_mapping")).toBeInTheDocument());
    expect(screen.getByText("1. Identity provider")).toBeInTheDocument();
    expect(screen.getByText("2. First group mapping")).toBeInTheDocument();
    expect(screen.getByTestId("found-identity_provider"))
      .toHaveTextContent("Issuer https://id.example.org.");
    expect(screen.getByText("1 of 4 required steps done")).toBeInTheDocument();
    // The first undone step is the one to do now, said in a word. A step
    // is a row of the list since 17.10, not a card of its own.
    const mapping = screen.getByTestId("step-group_mapping");
    expect(within(mapping).getByText("do this next")).toBeInTheDocument();
    const provider = screen.getByTestId("step-identity_provider");
    expect(within(provider).queryByText("do this next")).toBeNull();
  });

  it("names the bootstrap token as live and never shows anything that signs anybody in", async () => {
    Object.assign(answers, base());
    const { container } = draw();
    await waitFor(() => expect(screen.getByTestId("found-group_mapping")).toBeInTheDocument());
    expect(screen.getByText(/The bootstrap token still works\. It is for the first mapping only/))
      .toBeInTheDocument();
    // Nothing on the screen is a credential, and nothing put one in an address.
    expect(container.textContent).not.toMatch(/token=|Bearer /);
    // Nor does any field hold one: the value exists in a file on the
    // control plane and reaches no input, no readout and no address.
    for (const field of container.querySelectorAll("input,textarea,pre")) {
      expect(field.textContent ?? "").not.toMatch(/[A-Za-z0-9_-]{32,}/);
    }
    for (const link of container.querySelectorAll("a")) {
      expect(link.getAttribute("href") ?? "").not.toMatch(/token/i);
    }
  });

  it("says so differently when API tokens are all this installation has", async () => {
    Object.assign(answers, base({
      "/api/v1/setup": checklist({
        steps: [step({ key: "identity_provider", state: "optional", detail: "No provider." })],
        done: 0, total: 1,
      }),
    }));
    draw();
    await waitFor(() => expect(screen.getByTestId("found-identity_provider")).toBeInTheDocument());
    expect(screen.getByText(/nothing else administers this installation/)).toBeInTheDocument();
  });

  it("leads out of every step into the new panel", async () => {
    Object.assign(answers, base());
    draw();
    await waitFor(() => expect(screen.getByTestId("go-hosts")).toBeInTheDocument());
    expect(screen.getByTestId("go-hosts")).toHaveAttribute("href", "/hosts/new");
    expect(screen.getByTestId("go-group_mapping")).toHaveAttribute("href", "/access?tab=mappings");
    // The step whose work is done here leads nowhere else.
    expect(screen.queryByTestId("go-advertised_address")).toBeNull();
  });

  it("tests the identity provider where the reader may, and says what answered", async () => {
    Object.assign(answers, base());
    Object.assign(writes, {
      "/api/v1/setup/test-oidc": {
        ok: true, elapsed_ms: 42,
        provider: { issuer: "https://id.example.org", jwks_url: "https://id.example.org/jwks", keys: 2, at: "" },
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("test-oidc")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("test-oidc"));
    await waitFor(() => expect(screen.getByTestId("test-oidc-verdict")).toHaveTextContent("Answered in 42 ms"));
    expect(sent[0]).toMatchObject({ method: "POST", path: "/api/v1/setup/test-oidc" });
    expect(screen.getByText("Issuer https://id.example.org, 2 signing keys at https://id.example.org/jwks."))
      .toBeInTheDocument();
  });

  it("offers no test and no form to somebody who may not act", async () => {
    Object.assign(answers, base({ "/api/v1/whoami": reader }));
    draw();
    await waitFor(() => expect(screen.getByTestId("found-group_mapping")).toBeInTheDocument());
    expect(screen.queryByTestId("test-oidc")).toBeNull();
    expect(screen.queryByTestId("test-directory")).toBeNull();
    expect(screen.queryByTestId("mapping-add")).toBeNull();
    expect(screen.getByText("Only whoever manages access can add a mapping; ask an administrator."))
      .toBeInTheDocument();
    // Nor does it offer to confirm the address the whole fleet dials.
    await waitFor(() => expect(screen.getByTestId("advertised-address")).toBeInTheDocument());
    expect(screen.queryByTestId("advertised-confirm")).toBeNull();
  });

  it("adds the first mapping in place, and not before the reason is long enough", async () => {
    Object.assign(answers, base());
    Object.assign(writes, {
      "/api/v1/group-mappings": { group_name: "flotestro-admins", role: "platform_admin" },
    });
    draw();
    // An undone mapping step opens its form without being asked.
    await waitFor(() => expect(screen.getByTestId("mapping-add")).toBeInTheDocument());
    expect(screen.getByTestId("mapping-add")).toBeDisabled();

    fireEvent.change(screen.getByTestId("mapping-group"), { target: { value: "flotestro-admins" } });
    fireEvent.change(screen.getByTestId("mapping-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("mapping-add")).toBeDisabled();

    fireEvent.change(screen.getByTestId("mapping-reason"), { target: { value: "first run: the platform team" } });
    fireEvent.change(screen.getByTestId("mapping-site"), { target: { value: "lab" } });
    expect(screen.getByTestId("mapping-add")).toBeEnabled();
    fireEvent.click(screen.getByTestId("mapping-add"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/group-mappings",
      body: {
        group_name: "flotestro-admins",
        role: "platform_admin",
        site: "lab",
        environment: "",
        reason: "first run: the platform team",
      },
    });
  });

  it("offers to sign in again rather than losing the change, when the server asks for it", async () => {
    Object.assign(answers, base());
    const { ApiError } = await import("../../lib/api");
    Object.assign(writes, {
      "/api/v1/group-mappings": new ApiError(401, "reauthentication_required", "Sign in again to change access."),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("mapping-add")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("mapping-group"), { target: { value: "flotestro-admins" } });
    fireEvent.change(screen.getByTestId("mapping-reason"), { target: { value: "first run: the platform team" } });
    fireEvent.click(screen.getByTestId("mapping-add"));
    await waitFor(() => expect(screen.getByTestId("step-up")).toBeInTheDocument());
    expect(screen.getByText("Re-authentication required.")).toBeInTheDocument();
  });

  it("confirms the address the agents dial, and confirms nothing by itself", async () => {
    Object.assign(answers, base());
    Object.assign(writes, {
      "/api/v1/settings/advertised": { ...advertised, in_force: ["192.168.56.10"], source: "confirmed", loopback_only: false },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("advertised-address")).toBeInTheDocument());
    // A proposal is not a setting: nothing is picked and nothing can be sent.
    expect(screen.getByTestId("advertised-confirm")).toBeDisabled();
    fireEvent.click(screen.getByTestId("advertised-192.168.56.10"));
    fireEvent.change(screen.getByTestId("advertised-reason"), { target: { value: "the lab network" } });
    expect(screen.getByTestId("advertised-confirm")).toBeEnabled();
    fireEvent.click(screen.getByTestId("advertised-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "PUT",
      path: "/api/v1/settings/advertised",
      body: { names: ["192.168.56.10"], reason: "the lab network" },
    });
  });

  it("says which step is done and which is only advice", async () => {
    Object.assign(answers, base({
      "/api/v1/setup": checklist({ done: 4, total: 4, complete: true, bootstrap_live: false }),
    }));
    draw();
    await waitFor(() => expect(screen.getByText("Every required step is done")).toBeInTheDocument());
    expect(screen.getByText("The warnings and the optional steps below are advice, not blockers."))
      .toBeInTheDocument();
    const directory = screen.getByTestId("step-directory");
    expect(within(directory).getByText("Optional")).toBeInTheDocument();
    // With no bootstrap token live there is nothing to take account of first.
    expect(screen.queryByText(/bootstrap token/)).toBeNull();
  });

  it("says what went wrong when the checklist itself cannot be read", async () => {
    Object.assign(answers, { "/api/v1/whoami": admin, "/api/v1/capabilities": capabilities });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.getByRole("alert")).toHaveTextContent("no such thing");
    // The screen still says what it is, so nobody is left on a blank page.
    expect(screen.getByText("First run")).toBeInTheDocument();
  });
});
