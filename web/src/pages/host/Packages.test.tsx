import { describe, expect, it } from "vitest";
import { changePayload, operationBody, filterRows, heldCount, packageRows, packageVersion, planBinding, planExpired, planMode, type InstalledPackage, type PlanChange } from "./Packages";

/* The table joins three answers of the host - the installed list, the
   holds and the last upgrade plan - and the join decides what a row says
   about a package. It is a pure function, so every branch is checked here
   without a screen. */

const installed: InstalledPackage[] = [
  { name: "openssl", version: "3.0.15", release: "1~deb12u1", architecture: "amd64", source_name: "openssl", repository_id: "bookworm-security" },
  { name: "nano", version: "7.2", release: "1", architecture: "amd64", source_name: "nano" },
  { name: "libc6", version: "2.36", release: "9+deb12u9", architecture: "i386", source_name: "glibc", origin_class: "vendor_distribution" },
  { name: "zsh", version: "5.9", architecture: "amd64", epoch: "0" },
];

const plan: PlanChange[] = [
  { name: "openssl", current_version: "3.0.15-1~deb12u1", candidate_version: "3.0.16-1~deb12u1", security: true },
  { name: "libc6:i386", candidate_version: "2.36-9+deb12u10", security: false },
];

describe("packageVersion", () => {
  it("prints the version the way the manager does, with the epoch in front and the release behind", () => {
    expect(packageVersion({ name: "a", version: "1.2", release: "3", epoch: "2" })).toBe("2:1.2-3");
    expect(packageVersion({ name: "a", version: "1.2" })).toBe("1.2");
    // A zero epoch is no epoch to the eye.
    expect(packageVersion({ name: "a", version: "1.2", epoch: "0", release: "1" })).toBe("1.2-1");
  });
});

describe("packageRows", () => {
  it("marks the held packages when the holds were read, and leaves the state unknown when they were not", () => {
    const known = packageRows(installed, ["nano"], undefined);
    expect(known.find((row) => row.name === "nano")?.held).toBe(true);
    expect(known.find((row) => row.name === "zsh")?.held).toBe(false);

    const unread = packageRows(installed, undefined, undefined);
    for (const row of unread) expect(row.held).toBeUndefined();
  });

  it("takes the candidate version and the security flag from the plan, by the name or by name:arch", () => {
    const rows = packageRows(installed, [], plan);
    expect(rows.find((row) => row.name === "openssl")).toMatchObject({ candidate: "3.0.16-1~deb12u1", security: true });
    expect(rows.find((row) => row.name === "libc6")).toMatchObject({ candidate: "2.36-9+deb12u10", security: false });
    expect(rows.find((row) => row.name === "nano")).toMatchObject({ candidate: undefined, security: false });
  });

  it("shows a change the plan did not price as an unknown version rather than as nothing waiting", () => {
    const rows = packageRows(installed, [], [{ name: "zsh" }]);
    expect(rows.find((row) => row.name === "zsh")?.candidate).toBe("?");
  });

  it("carries the direction and the origin the plan named, and nothing for a plan that named none", () => {
    const rows = packageRows(installed, [], [
      { name: "openssl", candidate_version: "3.0.14-1~deb12u1", action: "downgrade", origin: "Debian:12/stable" },
      { name: "nano", candidate_version: "7.3-1" },
    ]);
    expect(rows.find((row) => row.name === "openssl")).toMatchObject({ action: "downgrade", candidateOrigin: "Debian:12/stable" });
    const nano = rows.find((row) => row.name === "nano");
    expect(nano?.action).toBeUndefined();
    expect(nano?.candidateOrigin).toBeUndefined();
  });
});

describe("planExpired", () => {
  it("is past the expiry the plan carries, and never for a plan without one", () => {
    const now = Date.parse("2026-09-17T12:00:00Z");
    expect(planExpired({ expires_at: "2026-09-17T11:59:59Z" }, now)).toBe(true);
    expect(planExpired({ expires_at: "2026-09-18T12:00:00Z" }, now)).toBe(false);
    expect(planExpired({}, now)).toBe(false);
    expect(planExpired(undefined, now)).toBe(false);
    expect(planExpired({ expires_at: "not a time" }, now)).toBe(false);
  });
});

describe("filterRows", () => {
  const rows = packageRows(installed, ["nano"], plan);

  it("sorts by name and reverses on request", () => {
    expect(filterRows(rows, "", "all").map((row) => row.name)).toEqual(["libc6", "nano", "openssl", "zsh"]);
    expect(filterRows(rows, "", "all", "desc").map((row) => row.name)).toEqual(["zsh", "openssl", "nano", "libc6"]);
  });

  it("searches the name and the source package, case-insensitively", () => {
    expect(filterRows(rows, "SSL", "all").map((row) => row.name)).toEqual(["openssl"]);
    expect(filterRows(rows, "glibc", "all").map((row) => row.name)).toEqual(["libc6"]);
    expect(filterRows(rows, "  ", "all")).toHaveLength(4);
  });

  it("keeps the upgradable, the security and the held packages on request", () => {
    expect(filterRows(rows, "", "upgradable").map((row) => row.name)).toEqual(["libc6", "openssl"]);
    expect(filterRows(rows, "", "security").map((row) => row.name)).toEqual(["openssl"]);
    expect(filterRows(rows, "", "held").map((row) => row.name)).toEqual(["nano"]);
  });

  it("keeps nothing under the held filter when the holds were not read", () => {
    expect(filterRows(packageRows(installed, undefined, plan), "", "held")).toEqual([]);
  });
});

describe("heldCount", () => {
  it("counts the holds only when the host read them", () => {
    expect(heldCount({ holds_known: true, holds: ["nano", "zsh"] })).toBe(2);
    expect(heldCount({ holds_known: true })).toBe(0);
    expect(heldCount({ holds_known: false, holds_unavailable_reason: "apt-mark showhold: code 1" })).toBeUndefined();
    expect(heldCount({})).toBeUndefined();
    expect(heldCount(undefined)).toBeUndefined();
  });
});

/* Plan, then apply: the screen reads the plan out of the plan job and
   binds the change to it. A change with no plan behind it has no payload
   at all - that is how the button stops existing. */
describe("planBinding", () => {
  it("reads the digest, the header and the approved elements", () => {
    const bound = planBinding({
      kind: "package_plan", plan_hash: "abc123", planner_version: "0.54.0", schema_version: 2,
      inventory_revision: "rev-9", resource_revision: "res-3", expires_at: "2026-09-18T12:00:00Z",
      changes: [{ name: "curl", current_version: "8.5", candidate_version: "8.6" }],
    });
    expect(bound?.plan_hash).toBe("abc123");
    expect(bound?.planner_version).toBe("0.54.0");
    expect(bound?.changes?.[0].candidate_version).toBe("8.6");
  });

  it("gives nothing for a result that is not a package plan or carries no digest", () => {
    expect(planBinding(undefined)).toBeNull();
    expect(planBinding({ kind: "package_apply", plan_hash: "abc" })).toBeNull();
    expect(planBinding({ kind: "package_plan" })).toBeNull();
    expect(planBinding({ kind: "package_plan", plan_hash: "" })).toBeNull();
  });
});

describe("operationBody", () => {
  it("names the operation beside its payload", () => {
    const body = operationBody("packages.install", { package_change: { packages: ["curl"] } });
    expect(body.action).toBe("packages.install");
    expect(body.payload).toEqual({ package_change: { packages: ["curl"] } });
  });

  // The payload was posted on its own, so the endpoint read an empty action
  // and refused every install and upgrade the screen offered.
  it("does not post the payload as the whole body", () => {
    const body = operationBody("packages.upgrade", { package_upgrade: { packages: ["curl"] } });
    expect(body).not.toHaveProperty("package_upgrade");
    expect(Object.keys(body).sort()).toEqual(["action", "payload"]);
  });
});

describe("changePayload", () => {
  const plan = {
    plan_hash: "abc123", planner_version: "0.54.0", schema_version: 2,
    inventory_revision: "rev-9", resource_revision: "res-3", expires_at: "2026-09-18T12:00:00Z",
    changes: [{ name: "curl", candidate_version: "8.6" }],
  };

  it("binds an install to its plan, under the field the API takes", () => {
    const payload = changePayload("packages.install", ["curl"], plan) as {
      package_change: { packages: string[]; plan_hash: string; plan: { planner_version: string } };
    };
    expect(payload.package_change.packages).toEqual(["curl"]);
    expect(payload.package_change.plan_hash).toBe("abc123");
    expect(payload.package_change.plan.planner_version).toBe("0.54.0");
  });

  it("binds an upgrade under its own field", () => {
    const payload = changePayload("packages.upgrade", ["curl"], plan) as {
      package_upgrade: { plan_hash: string };
    };
    expect(payload.package_upgrade.plan_hash).toBe("abc123");
  });

  it("sends the digest alone for a host whose planner builds no envelope", () => {
    const payload = changePayload("packages.install", ["curl"], { plan_hash: "abc123" }) as {
      package_change: { plan_hash: string; plan?: unknown };
    };
    expect(payload.package_change.plan_hash).toBe("abc123");
    expect(payload.package_change.plan).toBeUndefined();
  });

  it("has no payload without a plan, without packages or for another operation", () => {
    expect(changePayload("packages.install", ["curl"], null)).toBeNull();
    expect(changePayload("packages.install", [], plan)).toBeNull();
    expect(changePayload("packages.remove", ["curl"], plan)).toBeNull();
  });
});

describe("planMode", () => {
  it("asks for the plan of the change that is being prepared", () => {
    expect(planMode("packages.install")).toBe("install");
    expect(planMode("packages.upgrade")).toBe("upgrade");
  });
});
