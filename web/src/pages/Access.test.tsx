import { describe, expect, it } from "vitest";
import { expiresSoon, grantRequest, matchesIdentity, permissionMatrix, scopeKind, tabFromParam } from "./Access";
import { exportFileName, targetLink, toLocalInput } from "./Audit";

/* The access screen decides a few things without the server: which tab
   the address opens, which token is about to end, which identity a search
   names and how the role catalogue is laid out as a matrix. The audit
   screen decides where a target links and what the export is called. All
   of it is pure and is checked here without a screen. */

describe("tabFromParam", () => {
  it("opens the tab the address names and the first tab for anything else", () => {
    expect(tabFromParam("identities")).toBe("identities");
    expect(tabFromParam("roles")).toBe("roles");
    expect(tabFromParam("nonsense")).toBe("mappings");
    expect(tabFromParam(null)).toBe("mappings");
  });
});

describe("expiresSoon", () => {
  const now = Date.parse("2026-09-15T12:00:00Z");
  it("flags a token ending within the week and not one ending later", () => {
    expect(expiresSoon({ expires_at: "2026-09-18T12:00:00Z" }, now)).toBe(true);
    expect(expiresSoon({ expires_at: "2026-10-15T12:00:00Z" }, now)).toBe(false);
  });

  it("does not flag a token without an end, one already ended or one with an unreadable end", () => {
    expect(expiresSoon({}, now)).toBe(false);
    expect(expiresSoon({ expires_at: "2026-09-14T12:00:00Z" }, now)).toBe(false);
    expect(expiresSoon({ expires_at: "soon" }, now)).toBe(false);
  });
});

describe("matchesIdentity", () => {
  const alice = { id: "5f1c9e6a-0000-4000-8000-000000000001", subject: "alice", display_name: "Alice Example" };
  it("matches by subject, by name and by identifier, case aside", () => {
    expect(matchesIdentity(alice, "ALI")).toBe(true);
    expect(matchesIdentity(alice, "example")).toBe(true);
    expect(matchesIdentity(alice, "5f1c9e6a")).toBe(true);
    expect(matchesIdentity(alice, "bob")).toBe(false);
  });

  it("matches everything on an empty search and survives a missing name", () => {
    expect(matchesIdentity(alice, "  ")).toBe(true);
    expect(matchesIdentity({ id: "x", subject: "svc" }, "svc")).toBe(true);
  });
});

describe("permissionMatrix", () => {
  const matrix = permissionMatrix([
    { role: "viewer", permissions: ["host.read", "job.read"] },
    { role: "operator", permissions: ["job.create", "host.read"] },
  ]);
  it("lists every permission once, sorted, and the roles in the order given", () => {
    expect(matrix.permissions).toEqual(["host.read", "job.create", "job.read"]);
    expect(matrix.roles).toEqual(["viewer", "operator"]);
  });

  it("answers who may do what", () => {
    expect(matrix.has("viewer", "host.read")).toBe(true);
    expect(matrix.has("viewer", "job.create")).toBe(false);
    expect(matrix.has("operator", "job.create")).toBe(true);
    expect(matrix.has("nobody", "host.read")).toBe(false);
  });
});

describe("the audit page", () => {
  it("links a target to its page and nothing to a target without one", () => {
    expect(targetLink("host", "h1")).toBe("/hosts/h1/overview");
    expect(targetLink("campaign", "c1")).toBe("/campaigns/c1");
    expect(targetLink("job", "j1")).toBe("/jobs/j1");
    expect(targetLink("principal", "p1")).toBe("/access?tab=identities&q=p1");
    expect(targetLink("group_mapping", "g1")).toBeNull();
    expect(targetLink("host", "")).toBeNull();
    expect(targetLink(undefined, "h1")).toBeNull();
  });

  it("names the export after the server's header and plainly without one", () => {
    expect(exportFileName('attachment; filename="audit-from-20260901T000000Z.jsonl"')).toBe("audit-from-20260901T000000Z.jsonl");
    expect(exportFileName(null)).toBe("audit.jsonl");
  });

  it("turns an instant into the value of a datetime-local input and back", () => {
    const local = toLocalInput("2026-09-15T12:34:56Z");
    expect(local).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    expect(new Date(local).toISOString()).toBe("2026-09-15T12:34:00.000Z");
    expect(toLocalInput("")).toBe("");
    expect(toLocalInput("yesterday")).toBe("");
  });
});

/*
 * A role binding names a team, or a site and an environment, never both.
 * The server refuses a request that names both with scope_conflict; the
 * panel must never be able to send one, so the form is a choice of
 * vocabulary and the request is built from that choice alone. The two
 * functions below are what the form and the tables read, so both are
 * checked here without a screen.
 */

const principal = "5f1c9e6a-0000-4000-8000-000000000001";
const team = "8f2b1d3e-0000-4000-8000-000000000001";

describe("grantRequest", () => {
  const filled = {
    role: "operator", site: "lab", environment: "test", team,
    validUntil: "", reason: "  on-call rotation for the quarter  ",
  };

  it("sends a site binding to the role route, with no team in the body", () => {
    const request = grantRequest(principal, "site", filled);
    expect(request.path).toBe(`/api/v1/principals/${principal}/roles`);
    expect(request.body).toEqual({
      role: "operator", site: "lab", environment: "test",
      valid_until: "", reason: "on-call rotation for the quarter",
    });
    expect(request.body).not.toHaveProperty("team");
  });

  it("sends a team binding to the team-roles route, with no site or environment in the body", () => {
    const request = grantRequest(principal, "team", filled);
    expect(request.path).toBe(`/api/v1/principals/${principal}/team-roles`);
    expect(request.body).toEqual({
      role: "operator", team,
      valid_until: "", reason: "on-call rotation for the quarter",
    });
    // The fields of the other vocabulary are not sent empty; they are not
    // sent at all, which is what makes scope_conflict unreachable from
    // the panel even when the operator typed a site first.
    expect(request.body).not.toHaveProperty("site");
    expect(request.body).not.toHaveProperty("environment");
  });

  it("never names both vocabularies, whatever the fields hold", () => {
    for (const scope of ["site", "team"] as const) {
      const body = grantRequest(principal, scope, filled).body;
      const namesTeam = "team" in body;
      const namesSite = "site" in body || "environment" in body;
      expect(namesTeam && namesSite).toBe(false);
    }
  });
});

describe("scopeKind", () => {
  it("reads a binding with a team as a team binding", () => {
    expect(scopeKind({ site: "*", environment: "*", team })).toBe("team");
  });

  it("reads a binding without one as a site binding, so a team is never shown as the whole fleet", () => {
    expect(scopeKind({ site: "*", environment: "*" })).toBe("site");
    expect(scopeKind({ site: "lab", environment: "prod" })).toBe("site");
    expect(scopeKind(undefined)).toBe("site");
  });
});
