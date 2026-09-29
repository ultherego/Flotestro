import { describe, expect, it } from "vitest";
import { unitColumns, unitOrder, unitToggleOrder } from "./Services";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* The unit name identifies a row of the unit list; a preference that
   hides every other column still leaves it on the screen. */

describe("unitColumns", () => {
  it("fixes the unit name and names the rest for the chooser", () => {
    const columns = unitColumns((text) => text);
    expect(columns.filter((column) => column.fixed).map((column) => column.key)).toEqual(["unit"]);
    expect(columns.map((column) => column.key)).toEqual(["unit", "active", "sub_state", "on_boot", "actions"]);
  });
});

/* Every unit operation goes through the registry, so the row buttons on
   this page and the Bulk workspace send one payload and refuse one set of
   names. The names in the table always fit; one typed into the address bar
   does not have to. */

function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

describe("unitOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    for (const action of ["unit.start", "unit.stop", "unit.restart", "unit.reset_failed"]) {
      expect(unitOrder(action, "nginx.service").payload).toEqual(bulk(action, { unit: "nginx.service" }));
      expect(unitOrder(action, "nginx.service").payload).toEqual({ unit: { unit: "nginx.service" } });
      expect(unitOrder(action, "nginx.service").problems).toEqual([]);
    }
  });

  it("refuses a name systemd would not take, as the Bulk workspace does", () => {
    const entry = operationForm("unit.restart");
    for (const unit of ["", "nginx", "nginx.device", "../etc/passwd"]) {
      expect(unitOrder("unit.restart", unit).problems, unit).not.toEqual([]);
      expect(unitOrder("unit.restart", unit).problems).toEqual(entry?.validate({ unit }));
    }
  });
});

describe("unitToggleOrder", () => {
  it("sends what the Bulk workspace sends, both ways round", () => {
    expect(unitToggleOrder("unit.enable.set", "nginx.service", true).payload)
      .toEqual(bulk("unit.enable.set", { unit: "nginx.service", enabled: true }));
    expect(unitToggleOrder("unit.enable.set", "nginx.service", true).payload)
      .toEqual({ unit_toggle: { unit: "nginx.service", enabled: true } });
    // Turning it off carries no flag: the registry leaves out what is
    // false, and the host reads an absent flag as off.
    expect(unitToggleOrder("unit.mask.set", "nginx.service", false).payload)
      .toEqual(bulk("unit.mask.set", { unit: "nginx.service", enabled: false }));
    expect(unitToggleOrder("unit.mask.set", "nginx.service", false).payload)
      .toEqual({ unit_toggle: { unit: "nginx.service" } });
  });

  it("refuses a name systemd would not take", () => {
    expect(unitToggleOrder("unit.mask.set", "nginx", true).problems).not.toEqual([]);
  });
});
