import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { allowanceOf, moduleAccessOf, type HostActions } from "../lib/actions";
import { ActionGuard, ReadOnlyModuleNotice } from "./ActionGuard";

/* The guard draws a control only where the server said the order would be
   taken. The server is replaced by a fixed preview: a viewer who may read
   a unit's status and not restart it, on a host without Docker. */

const preview: HostActions = {
  version: 1,
  items: [
    { action: "unit.status", permission: "unit.status", mutating: false, risk: "low", allowed: true },
    {
      action: "unit.restart", permission: "unit.restart", mutating: true, risk: "high", allowed: false,
      reason_code: "permission_denied", missing_permission: "unit.restart",
      reason: "ordering unit.restart needs the permission unit.restart in scope site=lab env=test",
    },
    {
      action: "unit.stop", permission: "unit.stop", mutating: true, risk: "high", allowed: false,
      reason_code: "permission_denied", missing_permission: "unit.stop",
      reason: "ordering unit.stop needs the permission unit.stop in scope site=lab env=test",
    },
    {
      action: "docker.image.pull", permission: "docker.image.pull", mutating: true, risk: "medium", allowed: false,
      reason_code: "capability_missing", reason: "the host lacks capability docker",
    },
    {
      action: "system.shutdown", permission: "system.shutdown", mutating: true, risk: "critical", allowed: true,
      note: "asks for fresh authentication and a reason; asks for the target name typed in",
    },
  ],
};

const answers: Record<string, unknown> = { "/api/v1/hosts/h1/actions": preview };

vi.mock("../lib/api", () => ({
  api: {
    get: (path: string) => {
      if (path in answers) return Promise.resolve(answers[path]);
      return Promise.reject(new Error(`no answer for ${path}`));
    },
  },
}));

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

afterEach(cleanup);

describe("ActionGuard", () => {
  it("draws the control of an allowed action once the server answered", async () => {
    draw(<ActionGuard action="unit.status" host="h1"><button>Read</button></ActionGuard>);
    expect(screen.queryByRole("button", { name: "Read" })).toBeNull();
    await waitFor(() => expect(screen.getByRole("button", { name: "Read" })).toBeInTheDocument());
  });

  it("draws nothing for a refused action", async () => {
    draw(
      <>
        <ActionGuard action="unit.status" host="h1"><button>Read</button></ActionGuard>
        <ActionGuard action="unit.restart" host="h1"><button>Restart</button></ActionGuard>
      </>,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Read" })).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Restart" })).toBeNull();
  });

  it("keeps a refused control on the screen, disabled and explained, when asked to", async () => {
    draw(<ActionGuard action="docker.image.pull" host="h1" explain><button>Pull</button></ActionGuard>);
    const button = await screen.findByRole("button", { name: "Pull" });
    expect(button).toBeDisabled();
    const guard = button.closest(".action-guard");
    expect(guard).toHaveAttribute("title", "the host lacks capability docker");
    expect(guard).toHaveAttribute("data-reason-code", "capability_missing");
    expect(screen.getByText("the host lacks capability docker")).toBeInTheDocument();
  });

  it("draws the control as before when the preview itself cannot be read", async () => {
    draw(<ActionGuard action="unit.restart" host="h2"><button>Restart</button></ActionGuard>);
    await waitFor(() => expect(screen.getByRole("button", { name: "Restart" })).toBeInTheDocument());
  });
});

describe("ReadOnlyModuleNotice", () => {
  it("names the permissions when every change of the module is refused for one", async () => {
    draw(<ReadOnlyModuleNotice host="h1" actions={["unit.restart", "unit.stop"]} />);
    const notice = await screen.findByTestId("module-read-only");
    expect(notice).toHaveTextContent("You can read this module; changing it needs the permission unit.restart, unit.stop.");
  });

  it("repeats the host's reason when the refusal is not about a permission", async () => {
    draw(<ReadOnlyModuleNotice host="h1" actions={["docker.image.pull"]} />);
    const notice = await screen.findByTestId("module-read-only");
    expect(notice).toHaveTextContent("changing it is not possible here: the host lacks capability docker");
  });

  it("says nothing while one change is still allowed", async () => {
    draw(
      <>
        <ReadOnlyModuleNotice host="h1" actions={["unit.restart", "system.shutdown"]} />
        <ActionGuard action="unit.status" host="h1"><button>Read</button></ActionGuard>
      </>,
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Read" })).toBeInTheDocument());
    expect(screen.queryByTestId("module-read-only")).toBeNull();
  });
});

/* The verdict a screen reads is folded from the answer by pure functions;
   the three states of the answer - on its way, failed, arrived - are told
   apart here. */

describe("allowanceOf", () => {
  it("holds a control back while the answer is on its way", () => {
    const verdict = allowanceOf(undefined, { isPending: true, isError: false }, "unit.restart");
    expect(verdict).toMatchObject({ allowed: false, pending: true, known: false });
  });

  it("lets a control through when the preview failed, as the order's refusal is the backstop", () => {
    const verdict = allowanceOf(undefined, { isPending: false, isError: true }, "unit.restart");
    expect(verdict).toMatchObject({ allowed: true, known: false, pending: false });
  });

  it("reads the refusal with its code, its permission and its sentence", () => {
    const verdict = allowanceOf(preview, { isPending: false, isError: false }, "unit.restart");
    expect(verdict).toMatchObject({
      allowed: false, known: true, reason_code: "permission_denied",
      permission: "unit.restart", missing_permission: "unit.restart",
    });
    expect(allowanceOf(preview, { isPending: false, isError: false }, "system.shutdown")).toMatchObject({
      allowed: true, note: "asks for fresh authentication and a reason; asks for the target name typed in",
    });
  });

  it("refuses an action the catalogue does not know", () => {
    const verdict = allowanceOf(preview, { isPending: false, isError: false }, "unit.explode");
    expect(verdict).toMatchObject({ allowed: false, known: true, reason_code: "unknown_action" });
  });
});

describe("moduleAccessOf", () => {
  it("collects the missing permissions without repeats and apart from the host's reasons", () => {
    const access = moduleAccessOf(preview, { isPending: false, isError: false }, ["unit.restart", "unit.stop", "unit.restart", "docker.image.pull"]);
    expect(access.anyAllowed).toBe(false);
    expect(access.known).toBe(true);
    expect(access.permissions).toEqual(["unit.restart", "unit.stop"]);
    expect(access.reasons).toEqual(["the host lacks capability docker"]);
  });

  it("is not known before the answer and allows everything when the preview failed", () => {
    expect(moduleAccessOf(undefined, { isPending: true, isError: false }, ["unit.restart"])).toMatchObject({ known: false, pending: true });
    expect(moduleAccessOf(undefined, { isPending: false, isError: true }, ["unit.restart"])).toMatchObject({ known: false, anyAllowed: true });
  });
});
