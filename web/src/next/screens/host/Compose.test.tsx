import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../../../components/Toast";
import type { Host } from "../../../lib/types";
import { Compose, changeTone, digestSourceWords, planImageDigests } from "./Compose";

/**
 * A deployment is the one thing on this module that changes a machine, so
 * what is held here is what makes it safe: it carries the digest of the
 * plan and of every image in it, it is refused without a reason the trail
 * can keep, and it is not offered at all where the operator may not order
 * it. The counts above it are dashes until a project names them.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest key the path begins with wins: "/api/v1/jobs" also
        // begins "/api/v1/jobs/x/attempts", and a short key answering a
        // longer path hands the screen somebody else's document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-1", requires_approval: false });
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
  os_family: "arch", os_distribution: "arch", architecture: "amd64", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [{ name: "containers", version: 1, available: true, read_only: false }],
  identity: {},
} as unknown as Host;

const layout = { widgets: [], present: false, revision: 0 };

const allowed = (over: Record<string, boolean> = {}) => ({
  version: 1,
  items: [
    { action: "docker.compose.plan", permission: "job.create", mutating: false, risk: "low", allowed: over.plan !== false },
    {
      action: "docker.compose.deploy", permission: "job.create", mutating: true, risk: "high",
      allowed: over.deploy !== false,
      ...(over.deploy === false
        ? { reason_code: "permission_denied", missing_permission: "docker.write", reason: "you may not deploy here" }
        : {}),
    },
  ],
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Compose host={host} />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the compose module of a host", () => {
  it("plans the manifest it was given, as a plan and not as a change", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": allowed(),
    });
    draw();
    await screen.findByTestId("plan");
    fireEvent.change(screen.getByTestId("project"), { target: { value: "shop" } });
    fireEvent.change(screen.getByTestId("manifest"), { target: { value: "services:\n  web:\n    image: nginx" } });
    await waitFor(() => expect(screen.getByTestId("plan")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("plan"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "docker.compose.plan",
      payload: { compose: { project: "shop", manifest: "services:\n  web:\n    image: nginx" } },
    });
  });

  it("counts a project's deployments, and says nothing is counted before one is named", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/hosts/h1/compose/shop/versions": {
        count: 2,
        items: [
          {
            job_id: "v1", state: "succeeded", plan_digest: "sha256:aaaabbbbcccc", manifest: "services: {}",
            created_by: "tszymanski", created_at: "2026-10-15T09:00:00Z", applied: true,
          },
          {
            job_id: "v2", state: "failed", manifest: "services: {}",
            created_by: "tszymanski", created_at: "2026-10-14T09:00:00Z", applied: false,
          },
        ],
      },
    });
    draw();
    // Nobody has named a project, so nothing has been counted: the band
    // says so with dashes rather than claiming there were no deployments.
    const band = await screen.findByTestId("deployments");
    expect(band).toHaveTextContent("—");
    expect(band.querySelector(".fl-band")).toBeNull();

    fireEvent.change(screen.getByTestId("project"), { target: { value: "shop" } });
    await waitFor(() => expect(screen.getByTestId("version-v1")).toBeInTheDocument());
    expect(screen.getByTestId("deployments").querySelector(".fl-band")).not.toBeNull();
    // A version loads back into the editor rather than being redeployed on
    // the spot: the host's state may have moved since it was written.
    fireEvent.click(screen.getByTestId("load-v1"));
    expect(screen.getByTestId("manifest")).toHaveValue("services: {}");
  });

  it("binds the deployment to the plan digest and to every image digest", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/jobs/job-1/attempts": {
        items: [{
          status: "succeeded",
          detail: {
            payload: {
              project: "shop",
              digest: "sha256:planplanplanplan",
              services: [{ name: "web", image: "nginx:1", image_digest: "sha256:imageimage", digest_source: "registry" }],
              changes: [{ kind: "service", name: "web", action: "create" }],
            },
          },
        }],
      },
    });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    draw();
    fireEvent.change(screen.getByTestId("project"), { target: { value: "shop" } });
    fireEvent.change(screen.getByTestId("manifest"), { target: { value: "services: {}" } });
    await waitFor(() => expect(screen.getByTestId("plan")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("plan"));
    await vi.advanceTimersByTimeAsync(2500);
    vi.useRealTimers();

    await waitFor(() => expect(screen.getByTestId("plan-digest")).toHaveTextContent("sha256:planplanplanplan"));
    const services = screen.getByTestId("plan-services");
    expect(services).toHaveTextContent("from registry");

    const deploy = screen.getByTestId("deploy");
    // A reason the trail cannot use is no reason: the button stays shut.
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "short" } });
    expect(deploy).toBeDisabled();
    fireEvent.change(screen.getByTestId("reason"), { target: { value: "rollout of the new build" } });
    await waitFor(() => expect(deploy).not.toBeDisabled());
    fireEvent.click(deploy);
    await waitFor(() => expect(posted).toHaveLength(2));
    expect(posted[1].body).toMatchObject({
      action: "docker.compose.deploy",
      reason: "rollout of the new build",
      payload: {
        compose: {
          project: "shop",
          plan_digest: "sha256:planplanplanplan",
          image_digests: { web: "sha256:imageimage" },
        },
      },
    });
  });

  it("shows the refusal rather than a button that leads to one", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": allowed({ deploy: false }),
    });
    draw();
    // Every change this module offers is refused, so it says once what
    // changing it would take instead of quietly dropping its buttons.
    await waitFor(() => expect(screen.getByText(/docker\.write/)).toBeInTheDocument());
  });

  it("names what a plan would change, counted by kind", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/hosts/h1/actions": allowed(),
      "/api/v1/jobs/job-1/attempts": {
        items: [{
          status: "succeeded",
          detail: {
            payload: {
              project: "shop",
              digest: "sha256:dddd",
              warnings: ["the image is not pinned"],
              changes: [
                { kind: "service", name: "web", action: "create" },
                { kind: "service", name: "old", action: "remove" },
                { kind: "service", name: "api", action: "create" },
              ],
            },
          },
        }],
      },
    });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    draw();
    fireEvent.change(screen.getByTestId("project"), { target: { value: "shop" } });
    fireEvent.change(screen.getByTestId("manifest"), { target: { value: "services: {}" } });
    await waitFor(() => expect(screen.getByTestId("plan")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("plan"));
    await vi.advanceTimersByTimeAsync(2500);
    vi.useRealTimers();

    await waitFor(() => expect(screen.getByTestId("plan-changes")).toBeInTheDocument());
    const changes = screen.getByTestId("plan-changes");
    expect(within(changes).getByText("old")).toBeInTheDocument();
    // The warning the host sent stands above the plan, not inside it.
    expect(screen.getByText("the image is not pinned")).toBeInTheDocument();
  });
});

describe("what the compose module knows on its own", () => {
  it("binds only the services whose digest the plan resolved", () => {
    expect(planImageDigests({
      project: "shop", digest: "d",
      services: [
        { name: "web", image: "nginx", image_digest: "sha256:a" },
        { name: "bare", image: "redis" },
      ],
    })).toEqual({ web: "sha256:a" });
  });

  it("says where a digest came from in the operator's words, and leaves an unknown source alone", () => {
    expect(digestSourceWords("reference")).toBe("pinned in manifest");
    expect(digestSourceWords("registry")).toBe("from registry");
    expect(digestSourceWords("local")).toBe("from host image");
    expect(digestSourceWords("something-new")).toBe("something-new");
  });

  it("colours what goes away apart from what arrives", () => {
    expect(changeTone("remove")).toBe("error");
    expect(changeTone("create")).toBe("ok");
    expect(changeTone("update")).toBe("warn");
  });
});
