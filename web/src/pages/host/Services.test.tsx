import { describe, expect, it } from "vitest";
import { unitColumns } from "./Services";

/* The unit name identifies a row of the unit list; a preference that
   hides every other column still leaves it on the screen. */

describe("unitColumns", () => {
  it("fixes the unit name and names the rest for the chooser", () => {
    const columns = unitColumns((text) => text);
    expect(columns.filter((column) => column.fixed).map((column) => column.key)).toEqual(["unit"]);
    expect(columns.map((column) => column.key)).toEqual(["unit", "active", "sub_state", "on_boot", "actions"]);
  });
});
