import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { changesSummary, isHostPlan, JobPlan, PlanSummary, type HostPlan } from "./plan";

/* The attempts of a job come from the API; the client is replaced by a
   function each test programs. The mock is hoisted with the module,
   because the factory runs while the component is being imported. */
const get = vi.hoisted(() => vi.fn());

vi.mock("../lib/api", () => ({
  api: { get },
}));

afterEach(() => {
  cleanup();
  get.mockReset();
});

/** The plan reader queries the API, so it renders inside a query client with retries off. */
function drawWithQueries(element: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
}

describe("isHostPlan", () => {
  it("knows every plan kind the modules produce", () => {
    for (const kind of [
      "file_plan", "firewall_plan", "mount_plan", "network_plan", "dns_plan", "ssh_plan", "kernel_module_plan",
      "time_plan", "device_plan", "certificate_plan", "backup_plan", "trust_plan", "renewal_plan",
    ]) {
      expect(isHostPlan(kind), kind).toBe(true);
    }
  });

  it("does not take a read result for a plan", () => {
    // The unit detail and the schedule preview are typed results of reads:
    // the operator consents to nothing there, so they are not plans.
    for (const kind of ["unit_detail", "schedule_preview", "unit_status", "process_list", "", undefined]) {
      expect(isHostPlan(kind), String(kind)).toBe(false);
    }
  });
});

describe("PlanSummary", () => {
  it("names the action in words and lists the changes", () => {
    const { container } = render(<PlanSummary plan={{ action: "update", changes: ["content", "mode"] }} />);
    expect(container).toHaveTextContent("will change · content, mode");
    expect(container.querySelector("pre")).toBeNull();
  });

  it("reads every action the modules answer with", () => {
    const words: Record<string, string> = {
      create: "will be created",
      update: "will change",
      no_change: "already in desired state",
      remove: "will be removed",
      remove_absent: "already absent",
    };
    for (const [action, text] of Object.entries(words)) {
      const { container, unmount } = render(<PlanSummary plan={{ action }} />);
      expect(container, action).toHaveTextContent(text);
      unmount();
    }
  });

  it("shows an action it does not know as it is, and a plan without one as a plan", () => {
    const { container: odd } = render(<PlanSummary plan={{ action: "rotate" }} />);
    expect(odd).toHaveTextContent("rotate");
    const { container: bare } = render(<PlanSummary plan={{}} />);
    expect(bare).toHaveTextContent("plan");
  });

  it("puts a refusal in a red badge and nothing else", () => {
    const { container } = render(<PlanSummary plan={{ action: "update", changes: ["x"], refusal: "the path is a symlink" }} />);
    const badge = container.querySelector(".badge.error");
    expect(badge).toHaveTextContent("refused: the path is a symlink");
    expect(container).not.toHaveTextContent("will change");
  });

  it("reports a failed validator with the start of its output", () => {
    const output = "x".repeat(300);
    const { container } = render(<PlanSummary plan={{ action: "update", validator_failed: true, validator_output: output }} />);
    const badge = container.querySelector(".badge.error") as HTMLElement;
    expect(badge).toHaveTextContent(/^validator failed: x+$/);
    expect(badge.textContent?.length).toBe("validator failed: ".length + 200);
    const { container: quiet } = render(<PlanSummary plan={{ validator_failed: true }} />);
    expect(quiet.querySelector(".badge.error")).toHaveTextContent(/^validator failed$/);
  });

  it("shows the source resolved to a UUID next to the path of the order", () => {
    const plan: HostPlan = { action: "create", requested_source: "/dev/sdb1", resolved_source: "UUID=abcd-1234" };
    const { container } = render(<PlanSummary plan={plan} />);
    expect(container).toHaveTextContent("will be created · /dev/sdb1 → UUID=abcd-1234");
    // The same source on both sides is not worth a line.
    const { container: same } = render(<PlanSummary plan={{ action: "create", requested_source: "UUID=1", resolved_source: "UUID=1" }} />);
    expect(same).not.toHaveTextContent("→");
  });

  it("prints the document verbatim, because that is what lands on the host", () => {
    const document = "network:\n  version: 2\n";
    const { container } = render(<PlanSummary plan={{ action: "update", document }} />);
    expect(container.querySelector(".source")).toHaveTextContent("Document");
    expect(container.querySelector("pre.hm-log")?.textContent).toBe(document);
  });

  it("prints the commands one per line, and prefers the document when both exist", () => {
    const commands = ["ufw allow 22/tcp", "ufw reload"];
    const { container } = render(<PlanSummary plan={{ action: "update", commands }} />);
    expect(container.querySelector(".source")).toHaveTextContent("Commands");
    expect(container.querySelector("pre.hm-log")?.textContent).toBe("ufw allow 22/tcp\nufw reload");
    const { container: both } = render(<PlanSummary plan={{ action: "update", commands, document: "doc" }} />);
    expect(both.querySelector(".source")).toHaveTextContent("Document");
    expect(both.querySelector("pre.hm-log")?.textContent).toBe("doc");
    // An empty command list is no verbatim block at all.
    const { container: none } = render(<PlanSummary plan={{ action: "update", commands: [] }} />);
    expect(none.querySelector("pre")).toBeNull();
  });
});

describe("JobPlan", () => {
  it("reads the plan of the last planning attempt of the job", async () => {
    get.mockResolvedValue({
      items: [
        { detail: { kind: "file_plan", plan: { action: "create" } } },
        { detail: { kind: "unit_detail", units: [] } },
        { detail: { kind: "file_plan", plan: { action: "no_change" } } },
      ],
    });
    const { container } = drawWithQueries(<JobPlan jobId="job-1" />);
    await waitFor(() => expect(container).toHaveTextContent("already in desired state"));
    expect(get).toHaveBeenCalledWith("/api/v1/jobs/job-1/attempts");
    expect(container).not.toHaveTextContent("will be created");
  });

  it("shows a dash while no attempt carries a plan, and a bare plan when the detail has none", async () => {
    get.mockResolvedValue({ items: [{ detail: { kind: "unit_detail" } }] });
    const { container } = drawWithQueries(<JobPlan jobId="job-2" />);
    await waitFor(() => expect(get).toHaveBeenCalled());
    await waitFor(() => expect(container.querySelector(".source")).toHaveTextContent("—"));

    get.mockResolvedValue({ items: [{ detail: { kind: "ssh_plan" } }] });
    const { container: bare } = drawWithQueries(<JobPlan jobId="job-3" />);
    await waitFor(() => expect(bare).toHaveTextContent("plan"));
    expect(bare.querySelector(".badge")).toBeNull();
  });

  it("says that the plan is unavailable when the attempts cannot be read", async () => {
    get.mockRejectedValue(new Error("forbidden"));
    const { container } = drawWithQueries(<JobPlan jobId="job-4" />);
    await waitFor(() => expect(container.querySelector(".source")).toHaveTextContent("plan unavailable"));
  });
});

describe("changesSummary", () => {
  it("spells a package out with its versions and counts the rest", () => {
    const changes = [
      { name: "openssl", current_version: "3.0.1", candidate_version: "3.0.2", security: true },
      "a sentence of a file plan",
      ...Array.from({ length: 6 }, (_, i) => ({ name: `pkg${i}`, candidate_version: "1.0" })),
    ];
    const summary = changesSummary(changes);
    expect(summary.startsWith("openssl 3.0.1 → 3.0.2 (security), a sentence of a file plan, pkg0 1.0")).toBe(true);
    expect(summary.endsWith(" +2")).toBe(true);
    expect(summary).not.toContain("[object Object]");
  });
});
