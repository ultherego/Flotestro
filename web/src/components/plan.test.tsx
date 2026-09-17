import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import {
  changeAction, changesSummary, isHostPlan, JobPlan, PlanChanges, PlanFacts, PlanGroupView, PlanSummary, planStatus,
  STALE_PLAN_CODES, unknownPlanHosts, type HostPlan, type PlanGroup,
} from "./plan";

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

describe("PlanChanges", () => {
  const packages = [
    { name: "openssl", current_version: "3.0.1", candidate_version: "3.0.2", security: true, origin: "bookworm-security" },
    { name: "base-files", current_version: "13.1", candidate_version: "13.2" },
    { name: "zsh", candidate_version: "5.9" },
    { name: "libc6", current_version: "2.41-12", candidate_version: "2.41-13", security: true },
  ];

  it("lays a package plan out as a table sorted by name, with the versions in columns", () => {
    const { container } = render(<PlanChanges changes={packages} />);
    const rows = [...container.querySelectorAll("tbody tr")];
    expect(rows.map((row) => row.querySelector("td")?.textContent)).toEqual(["base-files", "libc6", "openssl", "zsh"]);
    const cells = (row: Element) => [...row.querySelectorAll("td")].map((cell) => cell.textContent);
    // A host that named no direction gets a dash, not an upgrade by default.
    expect(cells(rows[2])).toEqual(["openssl", "—", "3.0.1", "3.0.2", "securitybookworm-security"]);
    // A package new on the host has no version now; a dash says so, and
    // the direction follows from it.
    expect(cells(rows[3])).toEqual(["zsh", "install", "—", "5.9", ""]);
    expect(container.querySelectorAll(".badge.warn")).toHaveLength(2);
    expect(container.querySelector(".plan-changes-foot")).toHaveTextContent("4 packages · 2 security");
    expect(container.querySelector("button")).toBeNull();
    expect(container.querySelector("ul")).toBeNull();
  });

  it("folds a long plan to the first rows and opens the rest on request", () => {
    const many = Array.from({ length: 20 }, (_, i) => ({ name: `pkg${String(i).padStart(2, "0")}`, candidate_version: "1" }));
    const { container } = render(<PlanChanges changes={many} />);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(8);
    const button = container.querySelector("button") as HTMLButtonElement;
    expect(button).toHaveTextContent("Show all 20");
    fireEvent.click(button);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(20);
    expect(button).toHaveTextContent("Show fewer");
    fireEvent.click(button);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(8);
    expect(container.querySelector(".plan-changes-foot .source")).toHaveTextContent(/^20 packages$/);
  });

  it("names the direction, the origin and the architecture of every element the host filled", () => {
    const { container } = render(<PlanChanges changes={[
      { name: "openssl", current_version: "3.0.15-1", candidate_version: "3.0.16-1", action: "upgrade", origin: "Debian-Security:12/stable-security", architecture: "amd64", installed_delta_bytes: 2048, installed_delta_known: true },
      { name: "curl", current_version: "8.11.0-1", candidate_version: "8.10.0-1", action: "downgrade", origin: "fedora", architecture: "x86_64" },
      { name: "old-tool", current_version: "1.0", action: "remove", reason: "dependency", protected: true },
    ]} />);
    const rows = [...container.querySelectorAll("tbody tr")];
    const cells = (row: Element) => [...row.querySelectorAll("td")].map((cell) => cell.textContent);
    expect(cells(rows[0])).toEqual(["curl", "downgrade", "8.11.0-1", "8.10.0-1", "fedorax86_64"]);
    expect(cells(rows[1])).toEqual(["old-tool", "remove", "1.0", "—", "protecteddependency"]);
    expect(cells(rows[2])).toEqual(["openssl", "upgrade", "3.0.15-1", "3.0.16-1", "Debian-Security:12/stable-securityamd64+2.0 KiB"]);
    // A removal and a downgrade are what the operator must not miss.
    expect(container.querySelectorAll("tr.plan-change-attention")).toHaveLength(2);
    expect(container.querySelector(".plan-changes-foot")).toHaveTextContent("3 packages · 1 removed · 1 downgraded");
  });

  it("lists the changes of a file plan as sentences, and nothing for an empty plan", () => {
    const { container } = render(<PlanChanges changes={["content", "mode 0644 → 0600"]} />);
    expect(container.querySelector("table")).toBeNull();
    expect([...container.querySelectorAll("li")].map((item) => item.textContent)).toEqual(["content", "mode 0644 → 0600"]);
    const { container: none } = render(<PlanChanges changes={[]} />);
    expect(none.innerHTML).toBe("");
  });
});

describe("PlanFacts", () => {
  it("names the reboot, the download and a file system short of room", () => {
    const { container } = render(<PlanFacts plan={{
      reboot_predicted: true, download_bytes: 3 * 1048576,
      space: [
        { path: "/var", purpose: "download", basis: "measured", needed_bytes: 100, available_bytes: 1024 },
        { path: "/boot", purpose: "boot", basis: "boot_files", needed_bytes: 2048, available_bytes: 1024 },
      ],
    }} />);
    expect(container).toHaveTextContent("reboot predicted");
    expect(container).toHaveTextContent("download 3.0 MiB");
    expect(container).toHaveTextContent("/var (download cache): needs 100 B, 1.0 KiB free");
    // The short file system is a warning, the roomy one a plain fact.
    expect(container.querySelectorAll(".badge.warn")).toHaveLength(2);
    const { container: none } = render(<PlanFacts plan={{}} />);
    expect(none.innerHTML).toBe("");
  });
});

describe("changeAction", () => {
  it("takes the direction the host named, settles the two cases the versions decide, and guesses nothing else", () => {
    expect(changeAction({ name: "a", action: "downgrade", current_version: "1", candidate_version: "2" })).toBe("downgrade");
    expect(changeAction({ name: "a", candidate_version: "2" })).toBe("install");
    expect(changeAction({ name: "a", current_version: "1" })).toBe("remove");
    expect(changeAction({ name: "a", current_version: "1", candidate_version: "2" })).toBe("");
  });
});

describe("planStatus", () => {
  const future = new Date(Date.now() + 3600_000).toISOString();
  it("knows an envelope, a shaped plan of an older agent, and nothing else", () => {
    const envelope: PlanGroup = { plan_hash: "a", count: 1, hosts: ["h1"], expires_at: future, envelope: true, planner_version: "packages/1", plan: { kind: "package_plan", changes: [] } };
    expect(planStatus(envelope)).toBe("known");
    const older: PlanGroup = { plan_hash: "b", count: 1, hosts: ["h2"], expires_at: future, plan: { kind: "package_plan", manager: "apt", changes: [{ name: "x" }] } };
    expect(planStatus(older)).toBe("known");
    const file: PlanGroup = { plan_hash: "c", count: 1, hosts: ["h3"], expires_at: future, plan: { kind: "file_plan", plan: { action: "update" } } };
    expect(planStatus(file)).toBe("known");
    const empty: PlanGroup = { plan_hash: "d", count: 2, hosts: ["h4", "h5"], expires_at: future, plan: {} };
    expect(planStatus(empty)).toBe("unknown");
    const past: PlanGroup = { ...envelope, expires_at: "2020-01-01T00:00:00Z" };
    expect(planStatus(past)).toBe("expired");
    expect(unknownPlanHosts([envelope, older, empty])).toEqual(["h4", "h5"]);
  });

  it("names every code a host refuses a moved plan with", () => {
    for (const code of ["stale_plan", "replan_required", "plan_expired"]) expect(STALE_PLAN_CODES.has(code), code).toBe(true);
    expect(STALE_PLAN_CODES.has("transaction_failed")).toBe(false);
  });
});

describe("PlanGroupView", () => {
  it("shows the planner, marks an unknown plan and the hosts that refused the plan as stale", () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const group: PlanGroup = {
      plan_hash: "abcdef0123456789", count: 2, hosts: ["web-1", "web-2"], expires_at: future,
      envelope: true, planner_version: "packages/1",
      plan: { kind: "package_plan", mode: "upgrade", manager: "apt", planner_version: "packages/1", changes: [{ name: "libc6", candidate_version: "2.41-13", action: "install" }] },
    };
    const { container } = render(<PlanGroupView group={group} stale={["web-2", "db-9"]} />);
    expect(container.querySelector(".plan-group-head")).toHaveTextContent("Planner packages/1");
    expect(container.querySelector(".plan-group-head .badge.error")).toHaveTextContent("stale on 1 hosts");
    expect(container.querySelector("[data-testid=plan-group]")?.getAttribute("data-status")).toBe("known");

    const { container: unknown } = render(<PlanGroupView group={{ plan_hash: "0000", count: 1, hosts: ["old-1"], expires_at: future, plan: {} }} />);
    expect(unknown.querySelector("[data-testid=plan-group]")?.getAttribute("data-status")).toBe("unknown");
    expect(unknown.querySelector(".plan-group-head")).toHaveTextContent("unknown plan");
    expect(unknown.querySelector("table")).toBeNull();
    expect(unknown.querySelector(".warning")).toHaveTextContent("exclude the hosts with a reason");
  });

  it("keeps two plans of different fingerprints apart even over the same packages", () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const changes = [{ name: "libc6", current_version: "2.41-12", candidate_version: "2.41-13", action: "upgrade" }];
    const groups: PlanGroup[] = [
      { plan_hash: "aaaa", count: 1, hosts: ["web-1"], expires_at: future, envelope: true, plan: { kind: "package_plan", manager: "apt", changes: changes.map((c) => ({ ...c, origin: "Debian:12/stable" })) } },
      { plan_hash: "bbbb", count: 1, hosts: ["web-2"], expires_at: future, envelope: true, plan: { kind: "package_plan", manager: "apt", changes: changes.map((c) => ({ ...c, origin: "Debian-Security:12/stable-security" })) } },
    ];
    const { container } = render(<>{groups.map((group) => <PlanGroupView key={group.plan_hash} group={group} />)}</>);
    const sections = [...container.querySelectorAll("[data-testid=plan-group]")];
    expect(sections).toHaveLength(2);
    expect(sections[0]).toHaveTextContent("Debian:12/stable");
    expect(sections[1]).toHaveTextContent("Debian-Security:12/stable-security");
  });

  it("puts the hosts, the fingerprint and the expiry in a header and the packages in a table", () => {
    const group = {
      plan_hash: "abcdef0123456789abcdef0123456789",
      count: 2,
      hosts: ["web-1", "web-2"],
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      plan: {
        kind: "package_plan", mode: "upgrade", manager: "apt", reboot_predicted: true,
        changes: [{ name: "libc6", current_version: "2.41-12", candidate_version: "2.41-13", security: true }],
      },
    };
    const { container } = render(<PlanGroupView group={group} action="packages.upgrade" />);
    const head = container.querySelector(".plan-group-head");
    expect(head).toHaveTextContent("2 hosts web-1, web-2");
    expect(head).toHaveTextContent("abcdef0123456789");
    expect(head).toHaveTextContent("Valid until");
    expect(container.querySelector(".plan-group-words")).toHaveTextContent("packages.upgrade · packages will be upgraded (apt)");
    expect(container).toHaveTextContent("reboot predicted");
    expect(container.querySelector("tbody tr")).toHaveTextContent("libc6");
  });

  it("shows a host plan with its words and a refusal as the badge alone", () => {
    const base = { plan_hash: "0123456789abcdef", count: 1, hosts: ["db-1"], expires_at: "2099-01-01T00:00:00Z" };
    const { container } = render(<PlanGroupView group={{ ...base, plan: { kind: "file_plan", plan: { action: "update", changes: ["content"], document: "x=1" } } }} />);
    expect(container.querySelector(".plan-group-words")).toHaveTextContent("will change");
    expect(container.querySelector("li")).toHaveTextContent("content");
    expect(container.querySelector("pre.hm-log")?.textContent).toBe("x=1");
    const { container: refused } = render(<PlanGroupView group={{ ...base, plan: { kind: "file_plan", plan: { action: "update", refusal: "symlink" } } }} />);
    expect(refused.querySelector(".badge.error")).toHaveTextContent("refused: symlink");
    expect(refused.querySelector(".plan-group-words")).toBeNull();
  });
});
