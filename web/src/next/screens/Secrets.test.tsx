import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  Secrets, filterSecrets, reasonGiven, secretAddress, secretReference, storeCounts, destroyable,
  REASON_MIN_LENGTH,
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

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Secrets />, { wrapper });
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
    expect(secretAddress("repo.token")).toBe("/next/secrets/repo.token");
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
    expect(within(row).getByRole("link", { name: "repo.token" })).toHaveAttribute("href", "/next/secrets/repo.token");
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
