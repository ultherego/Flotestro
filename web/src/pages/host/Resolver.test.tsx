import { describe, expect, it } from "vitest";
import { resolverOrder } from "./Resolver";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* The resolver form on the host page and the one in the Bulk workspace are
   the same form: the same fields, the same payload and the same refusals.
   A host that cannot resolve names loses the directory and with it the way
   in, so the values are checked before the order goes out, not after. */

function bulk(form: FormValue): Record<string, unknown> {
  const entry = operationForm("dns.host.apply");
  if (!entry) throw new Error("the registry has no form for dns.host.apply");
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

const filled: FormValue = {
  interface: "enp0s3",
  servers: "192.0.2.53\n192.0.2.54",
  search_domains: "corp.example.com",
  ignore_auto_dns: true,
  rollback_seconds: 120,
};

describe("resolverOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    expect(resolverOrder(filled).payload).toEqual(bulk(filled));
    expect(resolverOrder(filled).payload).toEqual({
      dns: {
        interface: "enp0s3",
        servers: ["192.0.2.53", "192.0.2.54"],
        search_domains: ["corp.example.com"],
        ignore_auto_dns: true,
        rollback_seconds: 120,
      },
    });
    expect(resolverOrder(filled).problems).toEqual([]);
  });

  // The refusal the page did not make before: a name server is an address,
  // and a resolver pointed at a name has nothing to resolve it with.
  it("refuses a name server that is not an address", () => {
    const order = resolverOrder({ ...filled, servers: "dns.corp.example.com" });
    expect(order.problems).not.toEqual([]);
    expect(order.problems[0].message).toContain("not an IP address");
  });

  it("refuses what the Bulk workspace refuses, field for field", () => {
    const entry = operationForm("dns.host.apply");
    const cases: FormValue[] = [
      { servers: "" },
      { servers: "999.1.1.1" },
      { interface: "" },
      { interface: "an interface with spaces" },
      { rollback_seconds: 7200 },
      { search_domains: "~corp" },
    ];
    for (const change of cases) {
      const form = { ...filled, ...change };
      expect(resolverOrder(form).problems, JSON.stringify(change)).not.toEqual([]);
      expect(resolverOrder(form).problems).toEqual(entry?.validate({ ...emptyForm(entry), ...form }));
    }
  });
});
