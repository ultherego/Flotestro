import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import {
  Secrets, filterSecrets, reasonGiven, secretAddress, secretReference, storeCounts, destroyable,
  REASON_MIN_LENGTH, SECRETS_SCREEN,
} from "./Secrets";
import { ToastProvider } from "../../components/Toast";

/**
 * The store as an operator uses it, and the one rule the whole screen
 * exists to keep: a value goes in and never comes out again. The tests
 * below read the request bodies, because that is the only place a value is
 * allowed to be, and read the document, because that is the place it is
 * not.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What a write answers with; an Error here is rejected rather than returned. */
const writes: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. A short key
  // left to answer a longer path - "/api/v1/secrets" for
  // "/api/v1/secrets/repo.token/rotate" - hands the screen the wrong
  // document, and every assertion after that is measuring the harness.
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

const secret = (over: Record<string, unknown>) => ({
  id: "s1",
  name: "repo.token",
  description: "package repository token",
  current_version: 2,
  created_by: "tszymanski",
  created_at: "2026-09-01T08:00:00Z",
  updated_at: "2026-10-01T08:00:00Z",
  ...over,
});

const writer = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["secret.write", "secret.destroy"] };
const reader = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["secret.read"] };

/** A value no test may ever find on the screen. */
const VALUE = "ghp-never-printed-0123456789";

/** Where the panel stands now, so a click can be read as an address. */
function Where() {
  const where = useLocation();
  return <span data-testid="where">{where.pathname}</span>;
}

/**
 * The screen under the two addresses it answers on: the store, and one
 * secret. The name is the identifier in both, because the value is the
 * identifier of nothing and may never stand in an address.
 */
function draw(at = "/secrets") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <ToastProvider>
          <Routes>
            <Route path="/secrets" element={<Secrets />} />
            <Route path="/secrets/:name" element={<Secrets />} />
          </Routes>
          <Where />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(writes)) delete writes[key];
});

describe("what the store says about itself", () => {
  it("counts what the server listed, not the page", () => {
    const rows = [
      { current_version: 2, retired_at: undefined },
      { current_version: 1, retired_at: undefined },
      { current_version: 3, retired_at: "2026-10-01T00:00:00Z" },
    ];
    expect(storeCounts(rows)).toEqual({ issuable: 2, retired: 1, neverRotated: 1 });
  });

  it("writes a reference a job payload can take, and never a value", () => {
    expect(secretReference("repo.token", 2)).toBe('{"name":"repo.token","version":2}');
    expect(secretReference("repo.token")).toBe('{"name":"repo.token"}');
  });

  it("keeps the reason rule in one place", () => {
    expect(reasonGiven("short")).toBe(false);
    expect(reasonGiven("x".repeat(REASON_MIN_LENGTH))).toBe(true);
  });

  it("narrows on the name and on what it is for", () => {
    const rows = [{ name: "repo.token", description: "packages" }, { name: "smtp", description: "mail relay" }];
    expect(filterSecrets(rows, "mail").map((one) => one.name)).toEqual(["smtp"]);
    expect(filterSecrets(rows, "REPO").map((one) => one.name)).toEqual(["repo.token"]);
  });

  it("will not destroy the version a host could still be issued", () => {
    const one = { current_version: 2, retired_at: undefined };
    expect(destroyable(one, { version: 2, destroyed_at: undefined })).toBe(false);
    expect(destroyable(one, { version: 1, destroyed_at: undefined })).toBe(true);
    expect(destroyable(one, { version: 1, destroyed_at: "2026-10-01T00:00:00Z" })).toBe(false);
  });

  it("leads to the record inside the new panel", () => {
    expect(secretAddress("repo.token")).toBe("/secrets/repo.token");
  });
});

describe("the secret store", () => {
  it("draws a secret as its name, its version and whether it may still be issued", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("secret-repo.token")).toBeInTheDocument());
    const row = screen.getByTestId("secret-repo.token");
    expect(within(row).getByRole("link", { name: "repo.token" })).toHaveAttribute("href", "/secrets/repo.token");
    expect(row).toHaveTextContent("package repository token");
    expect(row).toHaveTextContent("2");
    expect(within(row).getByText("issuable")).toBeInTheDocument();
  });

  it("says a retired secret is retired and offers nothing that would be refused", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({ name: "old.token", retired_at: "2026-10-01T00:00:00Z" })] },
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("secret-old.token")).toBeInTheDocument());
    const row = screen.getByTestId("secret-old.token");
    expect(within(row).getByText("retired")).toBeInTheDocument();
    // A reference to a retired secret is a job that fails at the lease, so
    // none of the three buttons is drawn for one.
    expect(within(row).queryByTestId("copy-old.token")).toBeNull();
    expect(within(row).queryByTestId("rotate-old.token")).toBeNull();
    expect(within(row).queryByTestId("retire-old.token")).toBeNull();
  });

  it("shows the shape of what has not arrived, never the word loading", () => {
    Object.assign(answers, { "/api/v1/whoami": reader });
    const { container } = draw();
    expect(container.querySelectorAll(".fl-bone").length).toBeGreaterThan(0);
    expect(screen.queryByText("Loading…")).toBeNull();
  });

  it("offers no write to a sign-in that may only read", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("secret-repo.token")).toBeInTheDocument());
    expect(screen.getByTestId("new-secret")).toBeDisabled();
    const row = screen.getByTestId("secret-repo.token");
    expect(within(row).queryByTestId("rotate-repo.token")).toBeNull();
    expect(within(row).queryByTestId("retire-repo.token")).toBeNull();
    // The reference carries no value, so copying it is everybody's.
    expect(within(row).getByTestId("copy-repo.token")).toBeInTheDocument();
  });

  it("says so rather than drawing an empty store when the read is refused", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, {
      "/api/v1/secrets": new ApiError(403, "forbidden", "not for you"),
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() =>
      expect(screen.getByText("You do not have permission to read the secret store.")).toBeInTheDocument());
  });
});

describe("one secret from the address", () => {
  const version = (over: Record<string, unknown> = {}) => ({
    version: 2, size_bytes: 40, created_by: "tszymanski", created_at: "2026-10-01T08:00:00Z",
    ...over,
  });
  const history = (over: Record<string, unknown> = {}) => secret({
    versions: [version(), version({ version: 1, created_at: "2026-09-01T08:00:00Z" })],
    ...over,
  });

  it("opens the secret the address names: its metadata, its versions, and no value anywhere", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      // The server does not send a value; if it ever did, nothing here
      // may draw it.
      "/api/v1/secrets/repo.token": { ...history(), value: VALUE },
      "/api/v1/whoami": writer,
    });
    draw("/secrets/repo.token");
    await waitFor(() => expect(screen.getByTestId("version-2")).toBeInTheDocument());
    expect(screen.getByTestId("version-1")).toBeInTheDocument();
    expect(within(screen.getByTestId("version-2")).getByText("current")).toBeInTheDocument();
    expect(screen.getByTestId("kpi-secret-version")).toHaveTextContent("2");
    // The reference is what a reader takes away, by name and pinned.
    expect(screen.getByTestId("reference-current")).toHaveTextContent('{"name":"repo.token"}');
    expect(screen.getByTestId("reference-pinned")).toHaveTextContent('{"name":"repo.token","version":2}');
    // The one rule of the whole screen: no value, on the page or in the
    // address.
    expect(document.body.textContent).not.toContain(VALUE);
    expect(screen.getByTestId("where")).toHaveTextContent("/secrets/repo.token");
    expect(screen.getByTestId("where").textContent).not.toContain(VALUE);
    // The store's own list is not drawn underneath it.
    expect(screen.queryByTestId("secrets-table")).not.toBeInTheDocument();
  });

  it("says a name that is in no store is in no store, and offers the store", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/secrets/ghost.token": new ApiError(404, "not_found", "no such secret"),
      "/api/v1/whoami": writer,
    });
    draw("/secrets/ghost.token");
    await waitFor(() => expect(screen.getByText(/No secret named ghost.token/)).toBeInTheDocument());
    expect(screen.queryByTestId("secret-versions")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All secrets" })).toHaveAttribute("href", "/secrets");
  });

  it("puts the secret picked from a row in the address", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/secrets/repo.token": history(),
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("secret-repo.token")).toBeInTheDocument());
    expect(screen.getByTestId("where")).toHaveTextContent("/secrets");
    fireEvent.click(within(screen.getByTestId("secret-repo.token")).getByRole("link", { name: "repo.token" }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/secrets/repo.token"));
    await waitFor(() => expect(screen.getByTestId("secret-versions")).toBeInTheDocument());
  });

  it("destroys a version's content only with a reason and an acknowledgement, and sends the reason", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/secrets/repo.token": history(),
      "/api/v1/whoami": writer,
    });
    Object.assign(writes, { "/api/v1/secrets/repo.token/versions/1": history() });
    draw("/secrets/repo.token");
    await waitFor(() => expect(screen.getByTestId("destroy-1")).toBeInTheDocument());
    // The current version is not offered while the secret is still issuable.
    expect(screen.queryByTestId("destroy-2")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("destroy-1"));
    const confirm = screen.getByTestId("destroy-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("destroy-reason"), { target: { value: "rotated away months ago" } });
    expect(confirm).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({
      method: "DELETE",
      path: "/api/v1/secrets/repo.token/versions/1",
      body: { reason: "rotated away months ago" },
    });
  });

  it("offers no destruction to a sign-in that may only write", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/secrets/repo.token": history(),
      "/api/v1/whoami": reader,
    });
    draw("/secrets/repo.token");
    await waitFor(() => expect(screen.getByTestId("version-1")).toBeInTheDocument());
    expect(screen.queryByTestId("destroy-1")).not.toBeInTheDocument();
  });
});

describe("putting a value in", () => {
  async function openTheForm() {
    Object.assign(answers, { "/api/v1/secrets": { items: [secret({})] }, "/api/v1/whoami": writer });
    Object.assign(writes, { "/api/v1/secrets": secret({ name: "smtp.password", current_version: 1 }) });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-secret")).toBeEnabled());
    fireEvent.click(screen.getByTestId("new-secret"));
    await waitFor(() => expect(screen.getByTestId("secret-name")).toBeInTheDocument());
  }

  it("keeps the button shut until the server would accept the request", async () => {
    await openTheForm();
    expect(screen.getByTestId("secret-create")).toBeDisabled();
    fireEvent.change(screen.getByTestId("secret-name"), { target: { value: "smtp.password" } });
    fireEvent.change(screen.getByTestId("secret-value"), { target: { value: VALUE } });
    expect(screen.getByTestId("secret-create")).toBeDisabled();
    // A reason one character short is still a refusal, so the button holds.
    fireEvent.change(screen.getByTestId("secret-reason"), { target: { value: "x".repeat(REASON_MIN_LENGTH - 1) } });
    expect(screen.getByTestId("secret-create")).toBeDisabled();
    fireEvent.change(screen.getByTestId("secret-reason"), { target: { value: "the mail relay was re-keyed" } });
    expect(screen.getByTestId("secret-create")).toBeEnabled();
  });

  it("sends the value in the body and nowhere else", async () => {
    await openTheForm();
    fireEvent.change(screen.getByTestId("secret-name"), { target: { value: "smtp.password" } });
    fireEvent.change(screen.getByTestId("secret-description"), { target: { value: "the mail relay" } });
    fireEvent.change(screen.getByTestId("secret-value"), { target: { value: VALUE } });
    fireEvent.change(screen.getByTestId("secret-reason"), { target: { value: "the mail relay was re-keyed" } });
    fireEvent.click(screen.getByTestId("secret-create"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/secrets",
      body: {
        name: "smtp.password",
        description: "the mail relay",
        value: VALUE,
        reason: "the mail relay was re-keyed",
      },
    });
    // No address ever carries it, which is what a proxy log would keep.
    expect(sent.every((one) => !one.path.includes(VALUE))).toBe(true);
    expect(asked.every((one) => !one.includes(VALUE))).toBe(true);
  });

  it("hides the value while it is typed, and prints it nowhere after", async () => {
    await openTheForm();
    const field = screen.getByTestId("secret-value");
    expect(field).toHaveAttribute("type", "password");
    fireEvent.change(field, { target: { value: VALUE } });
    fireEvent.change(screen.getByTestId("secret-name"), { target: { value: "smtp.password" } });
    fireEvent.change(screen.getByTestId("secret-reason"), { target: { value: "the mail relay was re-keyed" } });
    fireEvent.click(screen.getByTestId("secret-create"));

    await waitFor(() => expect(screen.getByTestId("secrets-notice")).toBeInTheDocument());
    // The acknowledgement names the secret and its version; a screen that
    // echoed what was stored would have put the value on every operator's
    // display and in every screenshot of it.
    expect(screen.getByTestId("secrets-notice")).toHaveTextContent("smtp.password");
    expect(document.body.textContent ?? "").not.toContain(VALUE);
  });

  it("shows a refusal where the request was made", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, { "/api/v1/secrets": { items: [secret({})] }, "/api/v1/whoami": writer });
    Object.assign(writes, { "/api/v1/secrets": new ApiError(409, "secret_exists", "A secret of that name is already stored.") });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-secret")).toBeEnabled());
    fireEvent.click(screen.getByTestId("new-secret"));
    fireEvent.change(screen.getByTestId("secret-name"), { target: { value: "repo.token" } });
    fireEvent.change(screen.getByTestId("secret-value"), { target: { value: VALUE } });
    fireEvent.change(screen.getByTestId("secret-reason"), { target: { value: "the token was re-issued" } });
    fireEvent.click(screen.getByTestId("secret-create"));

    await waitFor(() =>
      expect(screen.getByText("A secret of that name is already stored.")).toBeInTheDocument());
    expect(document.body.textContent ?? "").not.toContain(VALUE);
  });
});

describe("rotating and retiring", () => {
  it("rotates to the next version with a value and a reason", async () => {
    Object.assign(answers, { "/api/v1/secrets": { items: [secret({})] }, "/api/v1/whoami": writer });
    Object.assign(writes, { "/api/v1/secrets/repo.token/rotate": secret({ current_version: 3 }) });
    draw();
    await waitFor(() => expect(screen.getByTestId("rotate-repo.token")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rotate-repo.token"));

    // The form names the version the rotation produces, not the one in force.
    await waitFor(() => expect(screen.getByText(/becomes version 3/)).toBeInTheDocument());
    expect(screen.getByTestId("secret-rotate")).toBeDisabled();
    fireEvent.change(screen.getByTestId("rotate-value"), { target: { value: VALUE } });
    fireEvent.change(screen.getByTestId("rotate-reason"), { target: { value: "the forge rotated the token" } });
    fireEvent.click(screen.getByTestId("secret-rotate"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/secrets/repo.token/rotate",
      body: { value: VALUE, reason: "the forge rotated the token" },
    });
    await waitFor(() => expect(screen.getByTestId("secrets-notice")).toHaveTextContent("version 3"));
    expect(document.body.textContent ?? "").not.toContain(VALUE);
  });

  /**
   * The rotation belongs under the secret it rotates. The panel being
   * replaced opened it in a second row there, and a card elsewhere on
   * the page leaves the reader checking which secret the form in front
   * of them is about - on a store of forty, that is the whole question.
   */
  it("opens the rotation under the row of the secret it rotates", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({}), secret({ id: "s2", name: "ca.key" })] },
      "/api/v1/whoami": writer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("rotate-repo.token")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rotate-repo.token"));

    const field = await screen.findByTestId("rotate-value");
    const opened = field.closest("tr.fl-row-detail");
    expect(opened).not.toBeNull();
    expect(opened?.closest("table")).toBe(screen.getByTestId("secrets-table"));
    expect(opened?.previousElementSibling).toBe(screen.getByTestId("secret-repo.token"));
    // The other secret is still a row, and still offers its own rotation.
    expect(screen.getByTestId("secret-ca.key")).toBeInTheDocument();

    // The button that opened the row closes it again.
    expect(screen.getByTestId("rotate-repo.token")).toHaveTextContent("Close");
    fireEvent.click(screen.getByTestId("rotate-repo.token"));
    await waitFor(() => expect(screen.queryByTestId("rotate-value")).toBeNull());
  });

  it("will not retire until it is acknowledged and a reason is given", async () => {
    Object.assign(answers, { "/api/v1/secrets": { items: [secret({})] }, "/api/v1/whoami": writer });
    Object.assign(writes, { "/api/v1/secrets/repo.token/retire": secret({ retired_at: "2026-10-16T00:00:00Z" }) });
    draw();
    await waitFor(() => expect(screen.getByTestId("retire-repo.token")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("retire-repo.token"));

    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
    const dialog = screen.getByRole("dialog");
    expect(screen.getByTestId("secret-retire")).toBeDisabled();
    fireEvent.change(screen.getByTestId("retire-reason"), { target: { value: "the forge was decommissioned" } });
    // The reason alone is not enough: a retirement cannot be undone.
    expect(screen.getByTestId("secret-retire")).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox"));
    expect(screen.getByTestId("secret-retire")).toBeEnabled();

    fireEvent.click(screen.getByTestId("secret-retire"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/secrets/repo.token/retire",
      body: { reason: "the forge was decommissioned" },
    });
  });

  it("shows a refusal of a retirement without closing the decision", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, { "/api/v1/secrets": { items: [secret({})] }, "/api/v1/whoami": writer });
    Object.assign(writes, {
      "/api/v1/secrets/repo.token/retire": new ApiError(401, "reauthentication_required", "Sign in again to retire a secret."),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("retire-repo.token")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("retire-repo.token"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(screen.getByTestId("retire-reason"), { target: { value: "the forge was decommissioned" } });
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(screen.getByTestId("secret-retire"));

    await waitFor(() =>
      expect(screen.getByText("Sign in again to retire a secret.")).toBeInTheDocument());
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });
});

/**
 * The store is arranged by whoever runs the installation, like every
 * other board of the panel. It was drawn on a plain screen in the
 * rewrite, and nothing said so: the control was simply not there and the
 * arrangement already stored for it could not be reached.
 */
describe("arranging the store", () => {
  it("offers the arrange bar and draws its containers on the board", async () => {
    Object.assign(answers, {
      "/api/v1/secrets": { items: [secret({})] },
      "/api/v1/whoami": writer,
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 1 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("board")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    expect(screen.getByTestId("arrange")).toHaveTextContent("Arrange this screen");
    // Under the name the server accepts, and the same one every time.
    expect(SECRETS_SCREEN).toMatch(/^[a-z0-9_]+$/);
    expect(asked).toContain(`/api/v1/settings/layout/${SECRETS_SCREEN}`);
  });
});
