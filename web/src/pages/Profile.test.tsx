import { describe, expect, it } from "vitest";
import { groupPermissions } from "./Profile";

/* The helper folds the permission names by area; the page only draws
   the rows it returns, so it is tested on its own. */

describe("groupPermissions", () => {
  it("folds area.action names into one row per area, sorted, with the actions in order", () => {
    const groups = groupPermissions(["job.read", "audit.read", "job.create", "job.approve"]);
    expect(groups).toEqual([
      { area: "audit", actions: ["read"] },
      { area: "job", actions: ["approve", "create", "read"] },
    ]);
  });

  it("keeps the part after the first dot whole and a name without a dot as its own area", () => {
    expect(groupPermissions(["certificate.trust.plan", "everything"])).toEqual([
      { area: "certificate", actions: ["trust.plan"] },
      { area: "everything", actions: ["*"] },
    ]);
  });

  it("returns nothing for no permission", () => {
    expect(groupPermissions([])).toEqual([]);
  });
});
