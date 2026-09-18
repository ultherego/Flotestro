import { describe, expect, it } from "vitest";
import { DECLARATION_ACTIONS, planVerdict, safePayload } from "./Containers";
import { operationForm } from "../../lib/operations";

/* The declarative panel is the one place an operator changes the host by
   describing it rather than by naming steps. These tests guard what that
   asks of the panel: that the plan is said in words somebody can act on,
   that every operation the panel offers has a form behind it, and that a
   payload typed by hand is either a payload or nothing. */

describe("planVerdict", () => {
  it("says what would happen instead of naming the verb", () => {
    expect(planVerdict("replace")).toContain("removed and created again");
    expect(planVerdict("no_change")).toContain("already matches");
    expect(planVerdict("absent")).toContain("nothing to do");
  });

  it("does not guess at a verdict it does not know", () => {
    expect(planVerdict("something_new")).toBe("What the plan would do");
    expect(planVerdict(undefined)).toBe("What the plan would do");
  });
});

describe("the operations the panel offers", () => {
  it("has a form for every one of them", () => {
    for (const actions of Object.values(DECLARATION_ACTIONS)) {
      expect(actions.length).toBeGreaterThan(0);
      for (const action of actions) {
        expect(operationForm(action), action).toBeDefined();
      }
    }
  });

  // Nothing here is ordered without a plan, so every entry has to say so:
  // the sentence is what the operator reads before the first click.
  it("says that a plan comes first", () => {
    for (const actions of Object.values(DECLARATION_ACTIONS)) {
      for (const action of actions) {
        expect(operationForm(action)?.plan, action).toBeTruthy();
      }
    }
  });

  it("offers a declaration and a removal where removing the object is a decision of its own", () => {
    expect(DECLARATION_ACTIONS.network).toContain("docker.network.remove");
    expect(DECLARATION_ACTIONS.volume).toContain("docker.volume.remove");
    // A container is never removed from here: a declaration is about a
    // name, and taking a container away names one object by identifier.
    expect(DECLARATION_ACTIONS.container).toEqual(["docker.container.ensure"]);
  });
});

describe("safePayload", () => {
  it("takes an object and nothing else", () => {
    expect(safePayload('{"docker_ensure":{"name":"internal"}}'))
      .toEqual({ docker_ensure: { name: "internal" } });
    expect(safePayload("not json")).toBeNull();
    expect(safePayload("[1, 2]")).toBeNull();
    expect(safePayload("null")).toBeNull();
  });
});
