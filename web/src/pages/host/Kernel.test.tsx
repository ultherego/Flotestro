import { describe, expect, it } from "vitest";
import { moduleBlockOrder, moduleLoadOrder, sysctlOrder } from "./Kernel";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* The host page and the Bulk workspace order the same three operations, so
   they have to order them the same way: one payload for one input, and one
   set of refusals. Every test here puts the page's order beside the
   registry entry the Bulk wizard fills in. */

/** The payload the Bulk workspace sends for a form filled in like this. */
function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

describe("sysctlOrder", () => {
  const settings = "vm.swappiness = 10\nnet.ipv4.ip_forward = 1";

  it("sends what the Bulk workspace sends", () => {
    expect(sysctlOrder({ settings }).payload).toEqual(bulk("sysctl.ensure", { settings }));
    expect(sysctlOrder({ settings }).payload).toEqual({
      kernel: { settings: { "vm.swappiness": "10", "net.ipv4.ip_forward": "1" } },
    });
    expect(sysctlOrder({ settings }).problems).toEqual([]);
  });

  // The refusal this page had no idea about until it went through the
  // registry: the panel writes in its own branches and nowhere else.
  it("refuses a key outside the branch the module owns", () => {
    const outside = { settings: "dev.raid.speed_limit_max = 200000" };
    expect(sysctlOrder(outside).problems).toEqual(
      operationForm("sysctl.ensure")?.validate({ ...emptyForm(operationForm("sysctl.ensure")!), ...outside }),
    );
    expect(sysctlOrder(outside).problems[0].message).toContain("vm. net. fs. kernel. user.");
  });

  it("refuses a name that is not a setting, a value the file would not keep, and an empty order", () => {
    expect(sysctlOrder({ settings: "Vm.Swappiness = 10" }).problems[0].message).toContain("is not a setting name");
    expect(sysctlOrder({ settings: 'vm.swappiness = "10' }).problems[0].message).toContain("would not keep");
    expect(sysctlOrder({ settings: "" }).problems[0].message).toContain("at least one setting");
  });
});

describe("moduleBlockOrder", () => {
  it("sends what the Bulk workspace sends, both ways round", () => {
    expect(moduleBlockOrder("nouveau", false).payload)
      .toEqual(bulk("kernel.module.blacklist", { module: "nouveau", blacklist: true }));
    expect(moduleBlockOrder("nouveau", false).payload)
      .toEqual({ kernel: { module: "nouveau", blacklist: true } });
    // Unblocking carries no flag: the registry leaves out what is false,
    // and the host reads an absent flag as "not blocked".
    expect(moduleBlockOrder("nouveau", true).payload)
      .toEqual(bulk("kernel.module.blacklist", { module: "nouveau", blacklist: false }));
    expect(moduleBlockOrder("nouveau", true).payload).toEqual({ kernel: { module: "nouveau" } });
  });

  it("refuses on the host page the modules it refuses in Bulk", () => {
    for (const module of ["ext4", "xfs", "dm_mod", "virtio_net", "e1000", "nf_tables"]) {
      const order = moduleBlockOrder(module, false);
      expect(order.problems, module).not.toEqual([]);
      expect(order.problems).toEqual(
        operationForm("kernel.module.blacklist")?.validate({ module, blacklist: true }),
      );
    }
  });
});

describe("moduleLoadOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    expect(moduleLoadOrder("br_netfilter").payload)
      .toEqual(bulk("kernel.module.load", { module: "br_netfilter" }));
    expect(moduleLoadOrder("br_netfilter").payload).toEqual({ kernel: { module: "br_netfilter" } });
    expect(moduleLoadOrder("br_netfilter").problems).toEqual([]);
  });

  it("refuses a name the kernel would not know", () => {
    expect(moduleLoadOrder("BR Netfilter").problems).not.toEqual([]);
    expect(moduleLoadOrder("").problems[0].message).toContain("Name the module");
  });
});
