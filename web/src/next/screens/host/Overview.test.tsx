import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Overview, adapterSegment, diskPressure, timelineLink } from "./Overview";

/**
 * The overview is the screen a machine is decided about on: it is read for
 * what the host is, and it is used to correct what the panel records, to
 * cut the host off, to give it a new identity and to end it.
 *
 * So the tests here are about the writes: that each one leaves in the shape
 * the server reads, that none of them leaves without a reason and the
 * machine's own name typed out, that a refusal comes back in the operator's
 * words, and that a reader without the permission is offered nothing at all.
 */

const posted: { path: string; body: unknown }[] = [];
const written: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the server refuses, by the address it is asked at. */
const refusals: Record<string, Error> = {};

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  const answer = (path: string) => {
    // The longest match wins: `/api/v1/hosts/h1` is a prefix of
    // `/api/v1/hosts/h1/inventory/system`, and answering the second with
    // the first hands the screen the wrong document.
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
      get: (path: string) => answer(path),
      getWithMeta: async (path: string) => ({ data: await answer(path), etag: "W/\"7\"" }),
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        const refusal = refusals[path];
        if (refusal) return Promise.reject(refusal);
        return Promise.resolve(answers[`POST ${path}`] ?? { id: "job-1234abcd", requires_approval: false });
      },
      put: (path: string, body: unknown) => {
        written.push({ path, body });
        const refusal = refusals[path];
        if (refusal) return Promise.reject(refusal);
        return Promise.resolve({});
      },
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Record<string, unknown> = {}) => ({
  id: "h1", hostname: "agent-arch", machine_id: "m-1", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  management_address_source: "session",
  os_distribution: "arch", os_family: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: {},
  ...over,
}) as unknown as Parameters<typeof Overview>[0]["host"];

/** What the host's own preview allows; everything named here is allowed. */
const allowed = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "normal", allowed: true,
  })),
});

/** The same preview with every action refused, and the reason on each. */
const refused = (...actions: string[]) => ({
  version: 1,
  items: actions.map((action) => ({
    action, permission: "host.write", mutating: true, risk: "normal", allowed: false,
    reason_code: "permission_denied", reason: "missing permission host.write",
    missing_permission: "host.write",
  })),
});

/** What the signed-in reader may do; absent, they may only read. */
const whoami = (...permissions: string[]) => ({
  subject: "operator", kind: "user", roles: [], bindings: [], permissions,
});

const fragment = (payload: unknown) => ({
  host_id: "h1", module: "system", revision: "abcdef123456", source: "agent",
  observed_at: "2026-10-16T08:00:00Z", payload,
});

const EVERY_CHANGE = [
  "system.hostname.set", "host.quarantine", "host.quarantine.release", "host.decommission",
];

function base(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/hosts/h1/inventory/system": fragment({ hostname: "agent-arch", hardware: { cpu_cores: 4 } }),
    "/api/v1/hosts/h1/actions": allowed(...EVERY_CHANGE),
    "/api/v1/hosts/h1/timeline": { items: [], count: 0, sources: ["job", "audit", "session", "lifecycle", "alert", "campaign"] },
    "/api/v1/jobs": { items: [], count: 0 },
    "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    "/api/v1/hosts/h1": host(),
    "/api/v1/whoami": whoami(),
    ...over,
  });
}

function draw(one = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Overview host={one} />, { wrapper });
}

/** The dialog every decision on this screen goes through. */
function confirmWith(reason: string, typed: string) {
  fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: reason } });
  const target = screen.queryByTestId("confirm-target");
  if (target) fireEvent.change(target, { target: { value: typed } });
  fireEvent.click(screen.getByTestId("confirm-order"));
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  written.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
});

describe("what the overview records about a host", () => {
  it("writes a note with the body the server expects, after a reason and the hostname", async () => {
    base({ "/api/v1/whoami": whoami("host.tag.write") });
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-notes")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-notes"));
    fireEvent.change(screen.getByTestId("input-notes"), { target: { value: "the fan is noisy" } });
    fireEvent.click(screen.getByTestId("save-notes"));

    const order = screen.getByTestId("confirm-order");
    // Nothing goes out until the reason and the machine's own name are
    // both there: that is the whole point of the dialog.
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "ticket" } });
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "handover note, ticket 1234" } });
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-fedora" } });
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(order);

    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0].path).toBe("/api/v1/hosts/h1/notes");
    expect(written[0].body).toEqual({ notes: "the fan is noisy", reason: "handover note, ticket 1234" });
  });

  it("corrects the owner and the address the panel records", async () => {
    base({ "/api/v1/whoami": whoami("host.tag.write") });
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-owner")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-owner"));
    fireEvent.change(screen.getByTestId("input-owner"), { target: { value: "platform team" } });
    fireEvent.click(screen.getByTestId("save-owner"));
    confirmWith("the web tier changed hands", "agent-arch");
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0]).toEqual({
      path: "/api/v1/hosts/h1/owner",
      body: { owner: "platform team", reason: "the web tier changed hands" },
    });

    fireEvent.click(screen.getByTestId("edit-management-address"));
    fireEvent.change(screen.getByTestId("input-management-address"), { target: { value: "10.0.0.5" } });
    fireEvent.click(screen.getByTestId("save-management-address"));
    confirmWith("the relay route moved", "agent-arch");
    await waitFor(() => expect(written).toHaveLength(2));
    expect(written[1]).toEqual({
      path: "/api/v1/hosts/h1/management-address",
      body: { address: "10.0.0.5", reason: "the relay route moved" },
    });
  });

  it("moves the host to another site, and says what the move does not undo", async () => {
    base({ "/api/v1/whoami": whoami("host.tag.write") });
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-placement")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-placement"));
    // The site it already stands in is not a move, so nothing can be sent.
    expect(screen.getByTestId("save-placement")).toBeDisabled();
    fireEvent.change(screen.getByTestId("input-site"), { target: { value: "dc-2" } });
    fireEvent.click(screen.getByTestId("save-placement"));
    expect(screen.getByText(/nothing already planned is re-evaluated/)).toBeInTheDocument();
    confirmWith("moved to the new rack", "agent-arch");
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0].body).toEqual({ site: "dc-2", environment: "test", reason: "moved to the new rack" });
  });

  it("hands the host to another team only with the permission for it", async () => {
    base({
      "/api/v1/whoami": whoami("host.tag.write"),
      "/api/v1/teams": { items: [{ id: "t1", name: "payments" }], count: 1 },
    });
    draw();
    // Writing tags is not handing the machine to other people.
    await waitFor(() => expect(screen.getByTestId("fact-team")).toBeInTheDocument());
    expect(screen.queryByTestId("edit-team")).toBeNull();

    cleanup();
    answers["/api/v1/whoami"] = whoami("host.scope.write");
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-team")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-team"));
    await waitFor(() => expect(screen.getByRole("option", { name: "payments" })).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("input-team"), { target: { value: "t1" } });
    fireEvent.click(screen.getByTestId("save-team"));
    confirmWith("the payments group took it over", "agent-arch");
    await waitFor(() => expect(written).toHaveLength(1));
    expect(written[0]).toEqual({
      path: "/api/v1/hosts/h1/team",
      body: { team: "t1", reason: "the payments group took it over" },
    });
  });

  it("says a refusal of a write in the operator's words, and keeps the editor open", async () => {
    base({ "/api/v1/whoami": whoami("host.tag.write") });
    const { ApiError } = await import("../../../lib/api");
    refusals["/api/v1/hosts/h1/notes"] = new ApiError(412, "precondition_failed", "etag mismatch");
    draw();
    await waitFor(() => expect(screen.getByTestId("edit-notes")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("edit-notes"));
    fireEvent.change(screen.getByTestId("input-notes"), { target: { value: "the fan is noisy" } });
    fireEvent.click(screen.getByTestId("save-notes"));
    confirmWith("handover note, ticket 1234", "agent-arch");

    await waitFor(() => expect(screen.getByText(/Somebody changed this host/)).toBeInTheDocument());
    // The dialog is gone, the text is not: the operator has it to try again.
    expect(screen.queryByTestId("confirm-order")).toBeNull();
    expect(screen.getByTestId("input-notes")).toHaveValue("the fan is noisy");
  });

  it("offers a reader who may only read nothing to change", async () => {
    base({
      "/api/v1/whoami": whoami(),
      "/api/v1/hosts/h1/actions": refused(...EVERY_CHANGE),
    });
    draw();
    // The verdicts arrive with the preview, so the line that says what
    // changing would take is what the screen settles on.
    await waitFor(() => expect(screen.getByText(/You can read this module/)).toBeInTheDocument());
    for (const control of [
      "edit-notes", "edit-owner", "edit-management-address", "edit-failure-domain",
      "edit-placement", "edit-team", "quarantine-open", "decommission-open", "rename-open",
    ]) {
      expect(screen.queryByTestId(control)).toBeNull();
    }
    // And the facts are still there to read.
    expect(screen.getByTestId("fact-notes")).toBeInTheDocument();
  });
});

describe("the lifecycle of a host", () => {
  it("quarantines the host with its certificates, after the hostname is typed", async () => {
    base({
      "/api/v1/whoami": whoami("host.quarantine"),
      "POST /api/v1/hosts/h1/quarantine": { lifecycle_state: "quarantined", jobs_canceled: 2, certificates_revoked: 1 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("quarantine-open")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("quarantine-open"));
    fireEvent.click(screen.getByLabelText(/Revoke the certificates as well/));
    fireEvent.click(screen.getByTestId("quarantine"));

    const order = screen.getByTestId("confirm-order");
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-reason"), { target: { value: "key theft suspected" } });
    // The wrong machine's name is refused: the operator approves this one.
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-debian" } });
    expect(order).toBeDisabled();
    fireEvent.change(screen.getByTestId("confirm-target"), { target: { value: "agent-arch" } });
    fireEvent.click(order);

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/quarantine");
    expect(posted[0].body).toEqual({
      reason: "key theft suspected",
      revoke_certificates: true,
      typed_confirmation: "agent-arch",
    });
    await waitFor(() => expect(screen.getByText(/2 job\(s\) cancelled/)).toBeInTheDocument());
  });

  it("releases a quarantined host, and offers the release to nobody else", async () => {
    base({
      "/api/v1/whoami": whoami("host.quarantine.release"),
      "POST /api/v1/hosts/h1/quarantine/release": { lifecycle_state: "active" },
    });
    draw(host({ lifecycle_state: "quarantined", lifecycle_reason: "key theft suspected" }));
    await waitFor(() => expect(screen.getByTestId("release")).toBeInTheDocument());
    // A quarantined host is not quarantined again from here.
    expect(screen.queryByTestId("quarantine-open")).toBeNull();
    fireEvent.click(screen.getByTestId("release"));
    confirmWith("the incident is assessed", "agent-arch");

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/quarantine/release");
    expect(posted[0].body).toEqual({ reason: "the incident is assessed", typed_confirmation: "agent-arch" });
    await waitFor(() => expect(screen.getByText(/the agent reconnects on its own/)).toBeInTheDocument());
  });

  it("orders an identity recovery and shows the token once, with the command to run", async () => {
    base({
      "POST /api/v1/hosts/h1/identity-recovery": {
        id: "order-9a8b7c6d", token: "FLO-ONE-TIME", expires_at: "2026-10-17T08:00:00Z",
        site: "lab", environment: "test", kind: "agent", purpose: "replace_identity",
        max_uses: 1, uses: 0, status: "pending",
      },
    });
    draw(host({
      connection_state: "offline",
      last_connection_refusal: { code: "certificate_expired", at: "2026-10-16T07:00:00Z" },
    }));
    await waitFor(() => expect(screen.getByTestId("recovery-open")).toBeInTheDocument());
    // The gateway's own refusal is on the screen, with what to do about it.
    expect(screen.getByTestId("connection-refusal")).toHaveTextContent("certificate expired");
    fireEvent.click(screen.getByTestId("recovery-open"));
    fireEvent.click(screen.getByTestId("recovery"));
    confirmWith("the certificate expired", "agent-arch");

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/identity-recovery");
    expect(posted[0].body).toEqual({
      reason: "the certificate expired",
      description: "the certificate expired",
      revoke_old_immediately: false,
    });
    await waitFor(() => expect(screen.getByTestId("recovery-order")).toBeInTheDocument());
    expect(screen.getByTestId("recovery-token")).toHaveTextContent("FLO-ONE-TIME");
    expect(screen.getByTestId("recovery-command"))
      .toHaveTextContent("flotestro-agentctl identity reset --confirm agent-arch");
  });

  it("decommissions the host, and says when nothing confirmed the wipe", async () => {
    base({
      "POST /api/v1/hosts/h1/decommission": {
        host_id: "h1", lifecycle_state: "retired", reason: "sold", phase: "no_session",
        remote_cleanup_unconfirmed: true, running_tasks: [], leases_dropped: false,
        jobs_canceled: 3, certificates_revoked: 1, session_closed: false,
      },
    });
    draw(host({ connection_state: "offline" }));
    await waitFor(() => expect(screen.getByTestId("decommission-open")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("decommission-open"));
    expect(screen.getByText(/retired without its cooperation/)).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("decommission"));
    confirmWith("the machine is sold", "agent-arch");

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/decommission");
    expect(posted[0].body).toEqual({
      reason: "the machine is sold",
      typed_confirmation: "agent-arch",
      local_identity_wipe: true,
      revoke_immediately_if_offline: true,
    });
    await waitFor(() => expect(screen.getByTestId("decommission-result")).toBeInTheDocument());
    expect(screen.getByText(/wipe it out of band/)).toBeInTheDocument();
    expect(within(screen.getByTestId("decommission-result")).getByText("3")).toBeInTheDocument();
  });

  it("does not offer to end a host that has already ended", async () => {
    base();
    draw(host({ lifecycle_state: "retired", lifecycle_changed_at: "2026-10-10T00:00:00Z", lifecycle_changed_by: "ulther" }));
    await waitFor(() => expect(screen.getByText(/The trust in this host has ended/)).toBeInTheDocument());
    expect(screen.queryByTestId("decommission-open")).toBeNull();
    expect(screen.queryByTestId("recovery-open")).toBeNull();
  });
});

describe("the operations the overview places", () => {
  it("renames the host as an order on the operation registry", async () => {
    base();
    draw();
    await waitFor(() => expect(screen.getByTestId("rename-open")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("rename-open"));
    // The name it already carries is this screen's own refusal.
    fireEvent.change(screen.getByTestId("rename-hostname"), { target: { value: "agent-arch" } });
    expect(screen.getByTestId("rename")).toBeDisabled();
    fireEvent.change(screen.getByTestId("rename-hostname"), { target: { value: "web02.example.internal" } });
    fireEvent.click(screen.getByTestId("rename"));
    confirmWith("the machine took the web role", "agent-arch");

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({
      action: "system.hostname.set",
      reason: "the machine took the web role",
      target_confirmation: "agent-arch",
      payload: { hostname: { hostname: "web02.example.internal" } },
    });
    await waitFor(() => expect(screen.getByTestId("job-notice")).toHaveTextContent("job-1234"));
  });

  it("will not offer a rename of a host nothing can reach", async () => {
    base();
    draw(host({ connection_state: "offline" }));
    await waitFor(() => expect(screen.getByTestId("rename-open")).toBeInTheDocument());
    expect(screen.getByTestId("rename-open")).toBeDisabled();
  });
});

describe("what the overview reads", () => {
  it("counts a disk nobody reported as unknown, never as empty", () => {
    expect(diskPressure(undefined, undefined)).toEqual({});
    expect(diskPressure(100, 5).tone).toBe("error");
    expect(diskPressure(100, 15).tone).toBe("warn");
    expect(diskPressure(100, 50).tone).toBe("ok");
  });

  it("leads from an adapter to the module that drives it, inside the new panel", () => {
    expect(adapterSegment("systemd")).toBe("services");
    expect(adapterSegment("packages.apt")).toBe("packages");
    expect(adapterSegment("nothing")).toBeUndefined();
    expect(timelineLink(host(), { kind: "job", ref: { type: "job", id: "j1" } } as never))
      .toBe("/jobs/j1");
    expect(timelineLink(host(), { kind: "alert", ref: { type: "alert", id: "a1" } } as never))
      .toBe("/hosts/h1/monitoring");
  });

  it("lists the adapters with the reason each one is not there", async () => {
    base();
    draw(host({
      capabilities: [
        { name: "systemd", version: 1, available: true, read_only: false },
        { name: "docker", version: 1, available: false, read_only: false, reason: "no docker daemon" },
      ],
    }));
    await waitFor(() => expect(screen.getByTestId("adapter-registry")).toBeInTheDocument());
    const table = screen.getByTestId("adapter-registry");
    expect(within(table).getByRole("link", { name: "systemd" })).toHaveAttribute("href", "/hosts/h1/services");
    expect(within(table).getByText("no docker daemon")).toBeInTheDocument();
  });

  it("lines the history of the host up by time and says what it may not show", async () => {
    base({
      "/api/v1/hosts/h1/timeline": {
        count: 1,
        sources: ["job", "session", "lifecycle", "alert", "campaign"],
        items: [{
          at: "2026-10-16T07:00:00Z", kind: "lifecycle", id: "l1", title: "quarantined",
          state: "quarantined", actor: "ulther", ref: { type: "host", id: "h1" },
        }],
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-timeline")).toBeInTheDocument());
    const table = screen.getByTestId("host-timeline");
    expect(within(table).getByRole("link", { name: "quarantined" })).toHaveAttribute("href", "/hosts/h1/audit");
    expect(screen.getByText(/Not shown, no permission: audit/)).toBeInTheDocument();
  });
});
