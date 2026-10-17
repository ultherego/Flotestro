import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../../lib/api";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import {
  Containers, DECLARATION_GROUPS, blocks, engineSuggestions, planVerdict, safePayload,
} from "./Containers";

/**
 * The summary is cheap and arrives with every inventory cycle; the lists,
 * the logs and the events cost the engine a walk over everything it holds
 * and are read on request. What is held here is that difference, that a
 * removal asks first and carries both a reason and the hostname, and that
 * a size the host could not measure is unknown rather than nought bytes.
 */

const sent: { path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  // The longest key that is a prefix of the path answers it: `…/containers`
  // is a prefix of `…/containers.full`, and answering the second with the
  // first hands the screen the summary where its lists go.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const found = answers[key];
    return found instanceof Error ? Promise.reject(found) : Promise.resolve(found);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => {
        sent.push({ path, body });
        return Promise.resolve({ id: "job-1234abcd", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = {
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
} as unknown as Host;

const may = (actions: string[], refused: Record<string, string> = {}) => ({
  version: 1,
  items: [
    ...actions.map((action) => ({
      action, permission: "host.docker.write", mutating: true, risk: "high", allowed: true,
    })),
    ...Object.entries(refused).map(([action, reason]) => ({
      action, permission: "host.docker.write", mutating: true, risk: "high",
      allowed: false, reason, reason_code: "permission_denied", missing_permission: "host.docker.write",
    })),
  ],
});

const EVERY = [
  "docker.read", "docker.plan", "docker.events", "docker.container.logs",
  "docker.container.start", "docker.container.stop", "docker.container.restart", "docker.container.remove",
  "docker.image.pull", "docker.prune",
  "docker.container.ensure", "docker.network.ensure", "docker.network.remove",
  "docker.volume.ensure", "docker.volume.remove",
];

const fragment = (module: string, payload: unknown) => ({
  host_id: "h1", module, revision: "abcdef0123456789", source: "agent",
  payload, observed_at: "2026-10-16T09:00:00Z",
});

const summary = {
  engine_version: "27.1.1", api_version: "1.46",
  containers: 3, running: 2, paused: 0, stopped: 1, unhealthy: 0, restart_looping: 0,
  images: 5, volumes: 2, networks: 3, volumes_unused: 1, networks_unused: 1,
};

const web = {
  id: "c1", name: "web", image: "nginx:1.27", state: "running", status: "Up 3 hours",
  health: "healthy", restart_count: 0,
  ports: [{ host_port: 8080, container_port: 80, protocol: "tcp" }],
  networks: [{ name: "bridge", ipv4: "172.17.0.2" }],
};

const worker = {
  id: "c2", name: "worker", image: "team/worker:2.1", state: "exited", status: "Exited (0)",
  restart_count: 3,
};

/**
 * The module is three sub-tabs since 17.10, and the address names which
 * one is open - so a test that reads the object tables or the
 * declaration asks for that tab, the way a reader following a link
 * would. The measurements and the notices stand above the tabs and are
 * there whichever one is open.
 */
function draw(tab?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/hosts/h1/containers?tab=${tab}` : "/hosts/h1/containers";
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[where]}>
        <ToastProvider>{children}</ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Containers host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the containers module says", () => {
  it("draws a container with its state, its health and its ports", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web, worker] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByTestId("container-web")).toBeInTheDocument());
    const row = screen.getByTestId("container-web");
    expect(row).toHaveTextContent("nginx:1.27");
    expect(row).toHaveTextContent("8080→80/tcp");
    expect(within(row).getByText("healthy")).toBeInTheDocument();
  });

  it("tells a container with no health check from an unhealthy one", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [worker] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByTestId("container-worker")).toBeInTheDocument());
    const row = screen.getByTestId("container-worker");
    expect(within(row).getByText("no check")).toBeInTheDocument();
    expect(within(row).queryByText("healthy")).toBeNull();
  });

  /**
   * Which compose project a thing belongs to is on its row, for all
   * three kinds of object. A container the operator stops by hand is put
   * back by the project that declares it, so "who owns this" is the
   * question a row has to answer before anybody touches it.
   */
  it("names the compose project on a container, a network and a volume", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", {
        containers: [{ ...web, compose: { project: "shop", service: "front" } }, worker],
        networks: [{ id: "n1", name: "shop_default", driver: "bridge", compose: "shop" }],
        volumes: [{ name: "shop_db", driver: "local", in_use: false, compose: "shop" }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByTestId("container-web")).toBeInTheDocument());
    expect(screen.getByTestId("container-web")).toHaveTextContent("shop/front");
    // A container no project declares says nothing rather than borrowing
    // the project of the row above it.
    expect(screen.getByTestId("container-worker")).not.toHaveTextContent("shop");

    fireEvent.click(screen.getByRole("tab", { name: /Networks/ }));
    expect(screen.getByTestId("network-shop_default")).toHaveTextContent("shop");

    fireEvent.click(screen.getByRole("tab", { name: /Volumes/ }));
    expect(screen.getByTestId("volume-shop_db")).toHaveTextContent("shop");
  });

  it("offers Start on a stopped container and Stop on a running one", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web, worker] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByTestId("stop-web")).toBeInTheDocument());
    expect(screen.queryByTestId("start-web")).toBeNull();
    expect(screen.getByTestId("start-worker")).toBeInTheDocument();
    expect(screen.queryByTestId("stop-worker")).toBeNull();

    fireEvent.click(screen.getByTestId("start-worker"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "docker.container.start",
      payload: { docker_container: { container_id: "c2", name: "worker", timeout_seconds: 10 } },
    });
  });

  it("asks for a reason and the hostname before it removes a container", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByTestId("remove-web")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("remove-web"));
    expect(screen.getByText(/Data outside volumes is lost/)).toBeInTheDocument();
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "decommissioning the old web" } });
    expect(screen.getByTestId("confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "docker.container.remove",
      reason: "decommissioning the old web",
      target_confirmation: "agent-arch",
      payload: { docker_container: { container_id: "c1", name: "web" } },
    });
  });

  it("keeps a volume size the host could not measure unknown, not nought", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", {
        volumes: [
          { name: "data", driver: "local", in_use: false, size_reason: "the engine does not report sizes here" },
          { name: "cache", driver: "local", in_use: true, size_bytes: 1048576, used_by: [{ container_id: "c1", container_name: "web", destination: "/var/cache", read_only: false }] },
        ],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByRole("tab", { name: /Volumes/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: /Volumes/ }));
    const row = screen.getByTestId("volume-data");
    expect(within(row).getByText("unknown")).toBeInTheDocument();
    expect(within(row).queryByText("0 B")).toBeNull();
    // A volume in use has no button: removing it loses the data of the
    // service that is using it right now.
    expect(screen.queryByTestId("remove-volume-cache")).toBeNull();
    expect(screen.getByTestId("remove-volume-data")).toBeInTheDocument();
  });

  it("removes exactly the volume the operator saw, by name", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", {
        volumes: [{ name: "data", driver: "local", in_use: false }],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByRole("tab", { name: /Volumes/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: /Volumes/ }));
    fireEvent.click(screen.getByTestId("remove-volume-data"));
    expect(screen.getByText(/This cannot be undone/)).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "the service is gone" } });
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(screen.getByTestId("confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "docker.prune",
      reason: "the service is gone",
      target_confirmation: "agent-arch",
      payload: { docker_prune: { volume_names: ["data"] } },
    });
  });

  it("gives an image in use no way to be removed", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", {
        images: [
          { id: "sha256:aaaa", tags: ["nginx:1.27"], size_bytes: 1000, in_use: true },
          { id: "sha256:bbbb", tags: [], size_bytes: 2000, in_use: false },
        ],
      }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByRole("tab", { name: /Images/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: /Images/ }));
    expect(screen.queryByTestId("remove-image-sha256:aaaa")).toBeNull();
    expect(screen.getByTestId("remove-image-sha256:bbbb")).toBeInTheDocument();
    // An image with no tag says so rather than showing an empty cell.
    expect(within(screen.getByTestId("image-sha256:bbbb")).getByText("untagged")).toBeInTheDocument();
  });

  it("pulls only a reference the API would take", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { images: [] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    // Pulling an image is a decision, so it lives with the declaration
    // rather than under the table of images it will join.
    draw("declaration");
    await waitFor(() => expect(screen.getByTestId("pull-reference")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("pull-reference"), { target: { value: "not a reference" } });
    expect(screen.getByTestId("pull-image")).toBeDisabled();
    fireEvent.change(screen.getByTestId("pull-reference"), { target: { value: "registry.example.test/team/app:1.4" } });
    fireEvent.click(screen.getByTestId("pull-image"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "docker.image.pull",
      payload: { docker_image: { reference: "registry.example.test/team/app:1.4" } },
    });
  });

  it("says nobody has read this host rather than that it holds nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", {
        engine_version: "27.1.1", running: 2, containers: 3,
      }),
      // Nobody has read the host, so the full state is simply not there.
      "/api/v1/hosts/h1/inventory/containers.full": new ApiError(404, "not_found", "no"),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("objects");
    await waitFor(() => expect(screen.getByText(/This host has not been read yet/)).toBeInTheDocument());
    // The engine's objects are not nought either; they are unknown until
    // somebody asks the host. That count is read on the state tab, which
    // is one click away.
    fireEvent.click(screen.getByRole("tab", { name: "State" }));
    expect(screen.getByText("Known after a read from the host.")).toBeInTheDocument();
  });

  it("orders a read from the host and does not wait on the inventory cycle", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("read-from-host")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("read-from-host"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({ action: "docker.read", payload: { docker_read: {} } });
  });

  it("keeps a count the inventory never carried unknown", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", { engine_version: "27.1.1" }),
      "/api/v1/hosts/h1/inventory/containers.full": new ApiError(404, "not_found", "no"),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Running")).toBeInTheDocument());
    // A host nobody has counted and a host with nothing running are
    // different answers.
    expect(screen.getByTestId("kpi-Running")).toHaveTextContent("—");
    expect(screen.getByTestId("kpi-Running")).toHaveAttribute("data-state", "unknown");
    expect(screen.getByTestId("kpi-Unhealthy")).toHaveAttribute("data-state", "unknown");
  });

  it("says once that the module is readable and not changeable", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web] }),
      "/api/v1/hosts/h1/actions": may(["docker.read"], Object.fromEntries(
        EVERY.filter((one) => one !== "docker.read").map((one) => [one, "no"]),
      )),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/needs the permission host.docker.write/)).toBeInTheDocument());
    expect(screen.queryByTestId("stop-web")).toBeNull();
    expect(screen.queryByTestId("remove-web")).toBeNull();
    // The read is still offered: it is a read, and it stands behind its own
    // permission rather than the module's changes.
    expect(screen.getByTestId("read-from-host")).toBeInTheDocument();
  });

  it("reads the engine's events over a closed window", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
      "/api/v1/jobs/job-1234abcd/attempts": { items: [] },
    });
    draw("objects");
    await waitFor(() => expect(screen.getByRole("tab", { name: /Events/ })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("tab", { name: /Events/ }));
    expect(screen.getByText(/Events are read on request/)).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("events-kind-container"));
    fireEvent.click(screen.getByTestId("read-events"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].body).toEqual({
      action: "docker.events",
      payload: {
        docker_events: { since_seconds: 3600, follow_seconds: 0, types: ["container"], max_events: 200 },
      },
    });
  });
});

describe("the declaration of what this host is to carry", () => {
  /**
   * The worst single container in the panel, counted: twenty-seven
   * fields in one cell of a board. They are the same twenty-seven, in
   * the same order the registry gives them, under headings that say
   * where one subject ends and the next begins.
   */
  it("asks for the twenty-seven fields under the subjects they belong to", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/inventory/containers": fragment("containers", summary),
      "/api/v1/hosts/h1/inventory/containers.full": fragment("containers.full", { containers: [web] }),
      "/api/v1/hosts/h1/actions": may(EVERY),
    });
    draw("declaration");
    await waitFor(() => expect(screen.getByTestId("field-name")).toBeInTheDocument());
    for (const heading of ["The container", "The image and what it runs", "What it is wired to",
      "Environment and labels", "Runtime limits", "The health check", "Secrets"]) {
      expect(screen.getByText(heading)).toBeInTheDocument();
    }
    // Every field the groups name is on the screen, and nothing the
    // operator could fill in before has gone missing with the headings.
    const named = DECLARATION_GROUPS["docker.container.ensure"].flatMap((group) => group.names);
    expect(named).toHaveLength(29);
    for (const field of named) {
      if (field === "force" || field === "health_disable" || field === "read_only_root_filesystem"
        || field === "stopped") continue;
      expect(screen.getByTestId(`field-${field}`)).toBeInTheDocument();
    }
    // And the declaration says itself what it is about, rather than
    // taking it from whichever table was open behind it.
    expect(screen.getByTestId("declare-action")).toBeInTheDocument();
  });

  it("keeps a form the groups were not written for in one block", () => {
    const fields = [
      { name: "name", label: "Volume", kind: "text" as const },
      { name: "driver", label: "Driver", kind: "text" as const },
    ];
    expect(blocks(fields)).toEqual([{ fields }]);
    expect(blocks(fields, [{ title: "Nothing of this form", names: ["elsewhere"] }]))
      .toEqual([{ fields }]);
    // A field no group names keeps its place, before the first heading.
    expect(blocks(fields, [{ title: "The volume", names: ["name"] }])).toEqual([
      { fields: [fields[1]] },
      { title: "The volume", fields: [fields[0]] },
    ]);
  });
});

describe("what the module reads out of the engine", () => {
  it("says what a plan would do, in a sentence", () => {
    expect(planVerdict("no_change")).toContain("nothing would change");
    expect(planVerdict("absent")).toContain("has nothing to do");
    expect(planVerdict(undefined)).toBe("What the plan would do");
    expect(planVerdict("something-new")).toBe("What the plan would do");
  });

  it("takes a hand-written payload only when it is an object", () => {
    expect(safePayload('{"docker_ensure":{"name":"web"}}')).toEqual({ docker_ensure: { name: "web" } });
    expect(safePayload("[1,2]")).toBeNull();
    expect(safePayload("not json")).toBeNull();
  });

  it("offers the names this host really carries, and nothing invented", () => {
    const suggestions = engineSuggestions({
      containers: [{ id: "c1", name: "web", image: "nginx", state: "running", status: "", restart_count: 0 }],
      networks: [{ id: "n1", name: "bridge", driver: "bridge", internal: false, attachable: false, ipv6: false, predefined: true, in_use: true }],
      volumes: [{ name: "data", driver: "local", in_use: false }],
      images: [{ id: "i1", tags: ["nginx:1.27"], size_bytes: 1, in_use: true }],
    });
    expect(suggestions.name).toEqual(["bridge", "data", "web"]);
    expect(suggestions.image).toEqual(["nginx:1.27"]);
    expect(suggestions.network).toEqual(["bridge"]);
    expect(engineSuggestions(undefined)).toEqual({});
  });
});
