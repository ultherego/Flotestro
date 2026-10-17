import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Packages, jobTone, originWords } from "./Packages";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";

/**
 * The software of one host, and the three things this screen is careful
 * about: a count nobody took is never a nought, a source the panel did
 * not write is never changed from here, and nothing destructive goes out
 * without a reason and the hostname typed out.
 */

const answers: Record<string, unknown> = {};
const sent: { method: string; path: string; body: unknown }[] = [];

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it. Here it
  // matters twice over: `/api/v1/hosts/h1/packages` is the panel's copy of
  // the list and `/api/v1/hosts/h1/inventory/packages` is the module, and
  // a short key answering both hands the screen the wrong document.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (key === undefined) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const found = answers[key];
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        return Promise.resolve({ id: "job-01234567", requires_approval: false });
      },
      put: (path: string, body?: unknown) => {
        sent.push({ method: "PUT", path, body });
        return Promise.resolve({ release_channel: (body as { channel: string }).channel });
      },
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Partial<Host> = {}): Host => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_family: "debian", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 18, pending_security_updates: 3,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as Host);

const allow = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.operate", mutating: true, risk: "normal", allowed: true,
  })),
});

const EVERY = [
  "packages.plan", "packages.list", "packages.install", "packages.remove", "packages.upgrade",
  "packages.hold.set", "packages.repair", "packages.repository.set", "agent.upgrade",
];

const fragment = (payload: Record<string, unknown>) => ({
  host_id: "h1", module: "packages", revision: "abcdef1234567890", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

const quiet = {
  "/api/v1/jobs": { items: [] },
  "/api/v1/hosts/h1/packages": { items: [], count: 0, state: { package_count: 0 } },
};

/**
 * The screen is three sub-tabs since 17.10 - what is installed, what is
 * being changed and what was done - and the address names which one is
 * open, so a test that works a form asks for `?tab=change` the way a
 * reader following a link would.
 */
function draw(one: Host = host(), tab?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/hosts/${one.id}/packages?tab=${tab}` : `/hosts/${one.id}/packages`;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Packages host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  // The folded columns are this browser's; one test must not fold them
  // for the next.
  window.localStorage.clear();
});

describe("the software of one host", () => {
  it("holds the packages that were named, and nothing else", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt", installed: 1200 }),
    });
    draw(host(), "change");
    await waitFor(() => expect(screen.getByTestId("hold")).toBeInTheDocument());
    expect(screen.getByTestId("hold")).toBeDisabled();
    fireEvent.change(screen.getByTestId("package-names"), { target: { value: "nginx, htop" } });
    fireEvent.click(screen.getByTestId("hold"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(sent[0].body).toEqual({
      action: "packages.hold.set",
      payload: { package_change: { packages: ["nginx", "htop"], hold: true } },
    });
  });

  it("says a count nobody took is unknown, and never a nought", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    draw(host({ pending_updates: null, pending_security_updates: null }));
    await waitFor(() => expect(screen.getByTestId("updates")).toBeInTheDocument());
    const updates = screen.getByTestId("updates");
    // A nought here would read as "nothing to do" on a host nobody has
    // asked. Every one of the four says it was not counted.
    expect(updates).toHaveTextContent("upgradable: not counted");
    expect(updates).toHaveTextContent("security: not counted");
    expect(updates).toHaveTextContent("held: not counted");
    expect(within(updates).queryByText("0")).toBeNull();
    expect(screen.getByText(/has not counted its updates yet/)).toBeInTheDocument();
  });

  it("records the release channel on the host, without running anything on it", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    draw(host(), "change");
    await waitFor(() => expect(screen.getByTestId("release-channel")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("release-channel"), { target: { value: "beta" } });
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "PUT", path: "/api/v1/hosts/h1/channel", body: { channel: "beta" } });
    await waitFor(() => expect(screen.getByText(/now follows the beta channel/)).toBeInTheDocument());
  });

  it("will not replace the agent with the version it already runs", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    draw(host(), "change");
    await waitFor(() => expect(screen.getByTestId("agent-version")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("agent-version"), { target: { value: "0.63.2" } });
    expect(screen.getByTestId("replace-agent")).toBeDisabled();
    fireEvent.change(screen.getByTestId("agent-version"), { target: { value: "0.64.0" } });
    await waitFor(() => expect(screen.getByTestId("replace-agent")).toBeEnabled());
    fireEvent.click(screen.getByTestId("replace-agent"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toMatchObject({ action: "agent.upgrade" });
  });

  it("asks before it repairs the package database, and carries the reason", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    draw(host({ package_database_broken: true }));
    await waitFor(() => expect(screen.getByTestId("repair")).toBeInTheDocument());
    expect(screen.getByText("needs repair")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("repair"));
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "dpkg was interrupted by a reboot" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-hostname"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "packages.repair",
      reason: "dpkg was interrupted by a reboot",
      payload: { package_repair: {} },
    });
  });

  it("changes only the sources the panel itself wrote", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({
        manager: "apt",
        repositories: {
          repositories_known: true,
          repositories: [
            { id: "debian", url: "https://deb.debian.org/debian", enabled: true, signed: true, managed: false, path: "/etc/apt/sources.list" },
            { id: "internal", url: "https://packages.example.com/debian", enabled: true, signed: false, managed: true, path: "/etc/apt/sources.list.d/internal.sources" },
          ],
        },
      }),
    });
    draw(host(), "change");
    await waitFor(() => expect(screen.getByTestId("source-debian")).toBeInTheDocument());
    // The distribution's own source is read here and changed on the host.
    expect(within(screen.getByTestId("source-debian")).getByRole("button", { name: "Remove" })).toBeDisabled();
    // A source without signature checking is drawn as a fault, not a setting.
    expect(within(screen.getByTestId("source-internal")).getByText("not checked")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("remove-source-internal"));
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "retiring the internal mirror" } });
    fireEvent.change(screen.getByTestId("confirm-hostname"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "packages.repository.set",
      reason: "retiring the internal mirror",
      payload: { repository: { id: "internal", remove: true } },
    });
  });

  it("says the panel has not read the package list, rather than showing a host with no software", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/has not read the package list/)).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("read-package-list"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({ action: "packages.list", payload: {} });
  });

  it("marks a hold nobody could read as unknown, not as a package that is free to move", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [] },
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({
        manager: "apt", installed: 2, holds_known: false, holds_unavailable_reason: "apt-mark is not installed",
      }),
      "/api/v1/hosts/h1/packages": {
        count: 1,
        state: { package_count: 1, collected_at: "2026-10-16T07:00:00Z" },
        items: [{ name: "nginx", version: "1.26.0", architecture: "amd64", repository_id: "debian" }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("package-nginx")).toBeInTheDocument());
    expect(screen.getByText(/apt-mark is not installed/)).toBeInTheDocument();
    expect(within(screen.getByTestId("package-nginx")).getByTitle("The holds were not read.")).toBeInTheDocument();
  });

  it("says the panel's copy is older than the host's own list", async () => {
    Object.assign(answers, {
      "/api/v1/jobs": { items: [] },
      "/api/v1/hosts/h1/actions": allow(...EVERY),
      "/api/v1/hosts/h1/inventory/packages": fragment({
        manager: "apt", installed: 1, installed_digest: "bbbb", holds_known: true, holds: [],
      }),
      "/api/v1/hosts/h1/packages": {
        count: 1,
        state: { package_count: 1, digest: "aaaa", collected_at: "2026-10-16T07:00:00Z" },
        items: [{ name: "nginx", version: "1.26.0" }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/changed since the panel read it/)).toBeInTheDocument());
  });

  it("draws no button for an order this operator may not place", async () => {
    Object.assign(answers, {
      ...quiet,
      "/api/v1/hosts/h1/actions": allow("packages.list"),
      "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt" }),
    });
    const reading = draw();
    // Reading the list is still offered: it changes nothing on the host,
    // and its arrival is how we know the verdicts have been read.
    await waitFor(() => expect(screen.getByTestId("read-package-list")).toBeInTheDocument());
    reading.unmount();

    // And on the tab the changes live on, not one of them is drawn - the
    // tab has to be the one asked for, or this would pass on an empty page.
    draw(host(), "change");
    // The form itself is drawn whatever the verdicts say - only the
    // buttons that place an order are gated - so the field is the proof
    // that the tab came up and the absences below mean something.
    await waitFor(() => expect(screen.getByTestId("package-names")).toBeInTheDocument());
    expect(screen.queryByTestId("plan-updates")).toBeNull();
    expect(screen.queryByTestId("hold")).toBeNull();
    expect(screen.queryByTestId("plan-removal")).toBeNull();
    expect(screen.queryByTestId("replace-agent")).toBeNull();
  });
});

describe("reading what a package says about itself", () => {
  it("names the origin class in the operator's words, and an em dash where the host named none", () => {
    const t = (text: string) => text;
    expect(originWords(t, "vendor_distribution")).toBe("distribution");
    expect(originWords(t, "third_party_repository")).toBe("third-party repository");
    expect(originWords(t, undefined)).toBe("—");
  });

  it("tells a transaction that worked from one that was never run", () => {
    expect(jobTone("succeeded")).toBe("ok");
    expect(jobTone("failed")).toBe("error");
    expect(jobTone("ineligible")).toBe("unknown");
    expect(jobTone("queued")).toBe("warn");
  });
});

describe("what the package table kept from the panel being replaced", () => {
  const listed = () => Object.assign(answers, {
    ...quiet,
    "/api/v1/hosts/h1/actions": allow(...EVERY),
    "/api/v1/hosts/h1/inventory/packages": fragment({ manager: "apt", installed: 2 }),
    "/api/v1/hosts/h1/packages": {
      items: [
        { name: "nginx", version: "1.24.0-1", architecture: "amd64", origin: "debian" },
        { name: "htop", version: "3.2.2-2", architecture: "amd64", origin: "debian" },
      ],
      count: 2,
      state: { package_count: 2 },
    },
  });

  it("folds a column away and keeps the choice in this browser", async () => {
    listed();
    draw();
    await waitFor(() => expect(screen.getByTestId("packages")).toBeInTheDocument());
    expect(within(screen.getByTestId("packages")).getByText("Version")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("packages-columns"));
    fireEvent.click(screen.getByRole("checkbox", { name: "Version" }));
    expect(within(screen.getByTestId("packages")).queryByText("Version")).not.toBeInTheDocument();
    expect(window.localStorage.getItem("fl.columns.host-packages")).toContain("version");
  });

  it("marks the row the card beside the table is about", async () => {
    listed();
    draw();
    await waitFor(() => expect(screen.getByTestId("package-nginx")).toBeInTheDocument());
    expect(screen.getByTestId("package-nginx")).not.toHaveClass("fl-row-marked");
    fireEvent.click(within(screen.getByTestId("package-nginx")).getByRole("button", { name: "nginx" }));
    await waitFor(() => expect(screen.getByTestId("package-nginx")).toHaveClass("fl-row-marked"));
    expect(screen.getByTestId("package-htop")).not.toHaveClass("fl-row-marked");
  });
});
