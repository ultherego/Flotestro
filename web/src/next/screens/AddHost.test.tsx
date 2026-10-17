import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { AddHost, hostReady, statusTone, stepTone, timeLeft } from "./AddHost";

/**
 * What the screen sends, what it refuses to send, and what it refuses to
 * draw.
 *
 * The one thing held hardest is the last of those: the enrollment token
 * exists for the single moment the order is answered, and it must not
 * reach the screen, the address bar or a title attribute. A test that only
 * checked the copy button would pass over a token printed beside it.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
const refusals: Record<string, { status: number; code: string; message: string }> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const longest = (path: string, from: Record<string, unknown>) =>
    Object.keys(from).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        const key = longest(path, answers);
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        const refusal = refusals[longest(path, refusals) ?? ""];
        if (refusal) {
          return Promise.reject(new actual.ApiError(refusal.status, refusal.code, refusal.message));
        }
        const key = longest(path, answers);
        return Promise.resolve(key ? answers[key] : {});
      },
    },
  };
});

// The stream is the screen's live source; under test the poll stands in for
// it, so the screen is drawn without a fetch nobody answers.
vi.mock("../../lib/stream", () => ({
  useEnrollmentStream: () => ({ connected: false, lastTurn: null }),
}));

const TOKEN = "enroll-9f3c-never-on-screen";

const whoami = (permissions: string[]) => ({
  subject: "operator", kind: "user", roles: [], bindings: [], permissions,
});

const profile = (over: Record<string, unknown> = {}) => ({
  kind: "agent",
  site: "lab",
  environment: "test",
  architecture: "amd64",
  channel: "stable",
  reason_required: false,
  connection: { enrollment_url: "https://panel/enroll", gateway_urls: ["https://panel:8443"] },
  config: { path: "/etc/flotestro/agent.yaml", content: "site: lab\nenvironment: test\n" },
  ca: {
    path: "/etc/flotestro/ca.pem", pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
    fingerprint_sha256: "AB:CD:EF", subject: "CN=Flotestro", not_after: "2030-01-01T00:00:00Z",
  },
  repository: { configured: true, url: "https://repo", key_url: "https://repo/key", package: "flotestro-agent" },
  image: { known: true, reference: "ghcr.io/flotestro/relay@sha256:dead" },
  architectures: ["amd64", "arm64"],
  families: [
    { key: "debian", label: "Debian", package_manager: "apt", steps: [
      { key: "repository", command: "sudo apt-get update" },
      { key: "enroll", command: "sudo -u flotestro-agent flotestro-agentctl enroll" },
    ] },
    { key: "arch", label: "Arch Linux", package_manager: "pacman", steps: [
      { key: "package", command: "sudo pacman -S --noconfirm flotestro-agent" },
    ] },
  ],
  ...over,
});

const order = (over: Record<string, unknown> = {}) => ({
  id: "ord-1",
  description: "web-042",
  site: "lab",
  environment: "test",
  kind: "agent",
  purpose: "new",
  max_uses: 1,
  uses: 0,
  status: "pending",
  expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
  created_by: "operator",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  config_url: "/api/v1/enrollment-requests/ord-1/config",
  steps: [],
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<AddHost />, { wrapper });
}

/**
 * The order is one guided form since 17.10 - five numbered steps as tabs,
 * the wizard of `/bulk` as the pattern - so a test opens the step whose
 * fields it is about instead of reading five cards at once.
 */
async function atStep(number: number) {
  fireEvent.click(await screen.findByRole("tab", { name: new RegExp(`^${number}\\.`) }));
}

/** The whole of what a reader can see, attributes included. */
function everythingOnScreen(): string {
  return document.body.innerHTML;
}

beforeEach(() => {
  Object.assign(answers, {
    "/api/v1/whoami": whoami(["host.enroll.create"]),
    "/api/v1/enrollment-requests?limit=100&status=pending": { items: [] },
    "/api/v1/fleet/activity": { by_site: [{ key: "lab", count: 3 }], by_environment: [{ key: "test", count: 3 }] },
    "/api/v1/relays": { items: [] },
    "/api/v1/installation-profiles": profile(),
  });
});

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
});

describe("the helpers the screen judges an order by", () => {
  it("calls a host ready only when it has a host and every stage is done", () => {
    expect(hostReady(undefined)).toBe(false);
    expect(hostReady(order() as never)).toBe(false);
    expect(hostReady(order({ enrolled_host_id: "h1", steps: [{ key: "token", state: "done" }] }) as never)).toBe(true);
    expect(hostReady(order({
      enrolled_host_id: "h1",
      steps: [{ key: "token", state: "done" }, { key: "connected", state: "waiting" }],
    }) as never)).toBe(false);
  });

  it("reads a waiting step as unknown and a stopped one that says why as a warning", () => {
    expect(stepTone({ key: "token", state: "waiting" })).toBe("unknown");
    expect(stepTone({ key: "token", state: "waiting", error_code: "token_expired" })).toBe("warn");
    expect(stepTone({ key: "token", state: "failed" })).toBe("error");
    expect(stepTone({ key: "token", state: "done" })).toBe("ok");
    expect(statusTone("pending")).toBe("ok");
    expect(statusTone("revoked")).toBe("unknown");
  });

  it("counts a token down to nought and no further", () => {
    const at = new Date("2026-10-16T12:00:00Z").getTime();
    expect(timeLeft("2026-10-16T12:02:05Z", at)).toBe("2:05");
    expect(timeLeft("2026-10-16T11:59:00Z", at)).toBe("0:00");
  });
});

describe("placing the order", () => {
  it("sends the placement, the owner and the tags as the server reads them", async () => {
    Object.assign(answers, { "/api/v1/enrollment-requests": { ...order(), token: TOKEN } });
    draw();
    await atStep(2);

    fireEvent.change(screen.getByTestId("description"), { target: { value: "web-042" } });
    fireEvent.change(screen.getByTestId("site"), { target: { value: "lab" } });
    fireEvent.change(screen.getByTestId("environment"), { target: { value: "test" } });
    fireEvent.change(screen.getByTestId("owner"), { target: { value: "  platform team  " } });
    // Spaces are the separator and an extra one is not an empty tag.
    fireEvent.change(screen.getByTestId("tags"), { target: { value: "role=web  tier=gold" } });
    fireEvent.change(screen.getByTestId("minutes"), { target: { value: "30" } });
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/enrollment-requests")).toBe(true));
    const placed = sent.find((one) => one.path === "/api/v1/enrollment-requests")?.body as Record<string, unknown>;
    expect(placed).toMatchObject({
      description: "web-042",
      site: "lab",
      environment: "test",
      kind: "agent",
      purpose: "new",
      relay_id: "",
      owner: "platform team",
      tags: ["role=web", "tier=gold"],
      max_uses: 1,
      ttl_minutes: 30,
    });
  });

  it("will not place an order with no placement, and says what is missing", async () => {
    draw();
    await atStep(2);
    fireEvent.change(screen.getByTestId("site"), { target: { value: "" } });
    await atStep(5);
    await waitFor(() => expect(screen.getByTestId("place-order")).toBeDisabled());
    expect(screen.getByText(/site and environment first/)).toBeInTheDocument();
    expect(sent).toHaveLength(0);
  });

  it("holds the order back until a reason is given where the server requires one", async () => {
    Object.assign(answers, { "/api/v1/installation-profiles": profile({ reason_required: true }) });
    draw();
    await atStep(2);
    await waitFor(() => expect(screen.getByTestId("reason")).toBeInTheDocument());
    await atStep(5);
    expect(screen.getByTestId("place-order")).toBeDisabled();
    expect(screen.getByText(/a reason first/)).toBeInTheDocument();

    await atStep(2);
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "ticket OPS-71" } });
    await atStep(5);
    await waitFor(() => expect(screen.getByTestId("place-order")).toBeEnabled());
  });

  it("shows a refusal in the reader's words and offers the field it asks for", async () => {
    refusals["/api/v1/enrollment-requests"] = {
      status: 422, code: "reason_required", message: "reason is required",
    };
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(screen.getByText(/The order needs a reason/)).toBeInTheDocument());
    expect(screen.getAllByTestId("reason").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByTestId("close-refusal"));
    await waitFor(() => expect(screen.queryByText(/The order needs a reason/)).toBeNull());
  });

  it("offers a stale sign-in as a sign-in, and puts nothing but the way back in the address", async () => {
    refusals["/api/v1/enrollment-requests"] = {
      status: 401, code: "reauthentication_required", message: "sign in again",
    };
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));
    await waitFor(() => expect(screen.getByTestId("sign-in-again")).toBeInTheDocument());
    expect(screen.getByText(/Re-authentication required/)).toBeInTheDocument();
  });
});

describe("the token", () => {
  it("is never drawn, never titled and never put in an address", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests": { ...order(), token: TOKEN },
      "/api/v1/enrollment-requests/ord-1": order(),
    });
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(screen.getByTestId("copy-token")).toBeInTheDocument());
    // The one place it may go is the clipboard, which the button reaches.
    expect(everythingOnScreen()).not.toContain(TOKEN);
    expect(screen.getByText(/do not put it in a shell command/)).toBeInTheDocument();
  });

  it("names the order's placement, its uses and how long is left", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests": { ...order(), token: TOKEN },
      "/api/v1/enrollment-requests/ord-1": order(),
    });
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(screen.getByTestId("copy-token")).toBeInTheDocument());
    expect(screen.getByText("0 / 1")).toBeInTheDocument();
    expect(screen.getAllByText("lab").length).toBeGreaterThan(0);
  });

  it("hands over the commands of the chosen family, and the files beside them", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests": { ...order(), token: TOKEN },
      "/api/v1/enrollment-requests/ord-1": order(),
    });
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(screen.getByTestId("command-repository")).toBeInTheDocument());
    expect(screen.getByTestId("command-repository")).toHaveValue("sudo apt-get update");
    expect(screen.getByTestId("command-enroll")).toHaveValue("sudo -u flotestro-agent flotestro-agentctl enroll");
    expect(screen.getByTestId("config-file")).toHaveValue("site: lab\nenvironment: test\n");
    expect(screen.getByTestId("fingerprint")).toHaveValue("AB:CD:EF");
  });
});

describe("the route to the panel", () => {
  it("offers no relay where the site has none, and says so", async () => {
    draw();
    await atStep(3);
    await waitFor(() => expect(screen.getByText(/has no relay/)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /Through a relay/ })).toBeNull();
  });

  it("binds the order to the relay that was chosen", async () => {
    Object.assign(answers, {
      "/api/v1/relays": { items: [{ id: "r1", name: "warsaw-relay", site: "lab", enrolled_at: "2026-01-01T00:00:00Z" }] },
      "/api/v1/enrollment-requests": { ...order(), token: TOKEN, relay_id: "r1" },
    });
    draw();
    await atStep(3);
    await waitFor(() => expect(screen.getByRole("button", { name: /Through a relay/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Through a relay/ }));
    fireEvent.change(await screen.findByTestId("relay"), { target: { value: "r1" } });
    await atStep(5);
    await waitFor(() => expect(screen.getByTestId("place-order")).toBeEnabled());
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(sent.length).toBeGreaterThan(0));
    expect((sent[0].body as { relay_id: string }).relay_id).toBe("r1");
  });
});

describe("what the permissions decide", () => {
  it("offers a relay only to somebody who may enroll one", async () => {
    draw();
    await screen.findByText(/relay.enroll.create permission/);
    expect(screen.queryByRole("button", { name: "Relay" })).toBeNull();
    // One host per token, because this operator may not ask for a batch.
    await atStep(2);
    expect(screen.getByTestId("uses")).toBeDisabled();
    expect(screen.getByText(/host.enroll.batch permission/)).toBeInTheDocument();
  });

  it("opens the pool of uses to somebody who may ask for a batch", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": whoami(["host.enroll.create", "host.enroll.batch", "relay.enroll.create"]),
    });
    draw();
    await waitFor(() => expect(screen.getByRole("button", { name: "Relay" })).toBeInTheDocument());
    await atStep(2);
    await waitFor(() => expect(screen.getByTestId("uses")).toBeEnabled());
    // More than one machine on one token is a reason the trail keeps.
    fireEvent.change(screen.getByTestId("uses"), { target: { value: "4" } });
    await atStep(5);
    await waitFor(() => expect(screen.getByTestId("place-order")).toBeDisabled());
    expect(screen.getByText(/a reason first/)).toBeInTheDocument();
  });
});

describe("what the host has done so far", () => {
  it("says why a step stopped in the operator's words, not in the code's", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests": { ...order(), token: TOKEN },
      "/api/v1/enrollment-requests/ord-1": order({
        status: "failed",
        steps: [
          { key: "token", state: "done" },
          { key: "certificate", state: "failed", error_code: "duplicate_machine_id", detail: "raw" },
        ],
      }),
    });
    draw();
    await atStep(5);
    fireEvent.click(screen.getByTestId("place-order"));

    await waitFor(() => expect(screen.getByTestId("step-certificate")).toBeInTheDocument());
    const row = screen.getByTestId("step-certificate");
    expect(row).toHaveTextContent(/already in the fleet under another host/);
    expect(row).not.toHaveTextContent("raw");
    expect(within(screen.getByTestId("step-token")).getByText("done")).toBeInTheDocument();
  });
});

describe("the history of orders", () => {
  it("revokes an open order and copies a closed one", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests?limit=100&status=pending": {
        items: [order({ id: "old-1", description: "waiting" })],
      },
      // The replacement answers with the order it placed, token and all; it
      // is the only moment that token exists.
      "/api/v1/enrollment-requests/old-1/replace": { ...order({ id: "new-1" }), token: TOKEN },
      "/api/v1/enrollment-requests/new-1": order({ id: "new-1" }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("order-old-1")).toBeInTheDocument());

    fireEvent.click(screen.getByTestId("revoke-old-1"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/enrollment-requests/old-1/revoke")).toBe(true));

    fireEvent.click(screen.getByTestId("replace-old-1"));
    await waitFor(() => expect(sent.some((one) => one.path === "/api/v1/enrollment-requests/old-1/replace")).toBe(true));
  });

  it("will not replace an identity recovery order from here", async () => {
    Object.assign(answers, {
      "/api/v1/enrollment-requests?limit=100&status=pending": {
        items: [order({ id: "rec-1", purpose: "replace_identity" })],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("replace-rec-1")).toBeInTheDocument());
    expect(screen.getByTestId("replace-rec-1")).toBeDisabled();
  });

  it("asks the server again when the status it is read by changes", async () => {
    Object.assign(answers, { "/api/v1/enrollment-requests?limit=100": { items: [] } });
    draw();
    await screen.findByTestId("history-status");
    asked.length = 0;
    fireEvent.change(screen.getByTestId("history-status"), { target: { value: "revoked" } });
    await waitFor(() => expect(asked.some((one) => one.includes("status=revoked"))).toBe(true));
  });
});
