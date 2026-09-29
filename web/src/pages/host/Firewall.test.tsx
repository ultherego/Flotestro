import { describe, expect, it } from "vitest";
import { ruleOrder, ruleRemoveOrder, zonePortOrder, zoneServiceOrder } from "./Firewall";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* The four changes on this page go through the operation registry, so the
   host page and the Bulk workspace send one payload and refuse one set of
   values. Two bindings travel on top of the composed payload and are this
   screen's own: the fingerprint of the ruleset the operator read, and the
   watchdog a zone change needs. */

function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

function refusals(action: string, form: FormValue) {
  const entry = operationForm(action);
  return entry?.validate({ ...emptyForm(entry), ...form });
}

const rule = {
  rule_id: "allow-monitoring",
  chain: "input",
  action: "accept",
  protocol: "tcp",
  ports: ["9100", "9200-9300"],
  sources: ["192.0.2.0/24"],
  comment: "the metrics scraper",
  break_glass: false,
};

const ruleForm: FormValue = {
  ...rule,
  ports: rule.ports.join("\n"),
  sources: rule.sources.join("\n"),
  rollback_seconds: 120,
};

describe("ruleOrder", () => {
  it("sends what the Bulk workspace sends, with the ruleset it was composed on", () => {
    const order = ruleOrder(rule, "abc123");
    const section = bulk("firewall.rule.ensure", ruleForm).firewall as Record<string, unknown>;
    expect(order.payload).toEqual({ firewall: { ...section, expected_hash: "abc123" } });
    expect(order.payload).toEqual({
      firewall: {
        rule_id: "allow-monitoring",
        chain: "input",
        action: "accept",
        protocol: "tcp",
        ports: ["9100", "9200-9300"],
        sources: ["192.0.2.0/24"],
        comment: "the metrics scraper",
        rollback_seconds: 120,
        expected_hash: "abc123",
      },
    });
    expect(order.problems).toEqual([]);
  });

  // The refusals the page did not make before it went through the registry.
  it("refuses on the host page what the Bulk workspace refuses", () => {
    const cases: [Partial<typeof rule>, string][] = [
      [{ rule_id: "Allow Monitoring!" }, "A rule name is lower-case"],
      [{ rule_id: "" }, "Give the rule a name"],
      [{ protocol: "icmp" }, "Ports belong to TCP and UDP"],
      [{ ports: ["http"] }, "neither a port nor a range"],
      [{ ports: ["9300-9100"] }, "neither a port nor a range"],
      [{ sources: ["192.0.2.1"] }, "not an address with a mask"],
      [{ comment: 'the "metrics" scraper' }, "no quote, backslash or newline"],
      // A rule with no protocol, no port, no source and no interface is a
      // rule about everything.
      [{ protocol: "", ports: [], sources: [] }, "covers all traffic"],
    ];
    for (const [change, sentence] of cases) {
      const order = ruleOrder({ ...rule, ...change }, "abc123");
      expect(order.problems, JSON.stringify(change)).not.toEqual([]);
      expect(order.problems[0].message).toContain(sentence);
      expect(order.problems).toEqual(refusals("firewall.rule.ensure", {
        ...ruleForm, ...change,
        ports: (change.ports ?? rule.ports).join("\n"),
        sources: (change.sources ?? rule.sources).join("\n"),
      }));
    }
  });
});

describe("ruleRemoveOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    expect(ruleRemoveOrder("allow-monitoring").payload)
      .toEqual(bulk("firewall.rule.remove", { rule_id: "allow-monitoring", rollback_seconds: 120 }));
    expect(ruleRemoveOrder("allow-monitoring").payload)
      .toEqual({ firewall: { rule_id: "allow-monitoring", rollback_seconds: 120 } });
    expect(ruleRemoveOrder("allow-monitoring").problems).toEqual([]);
  });

  // A managed rule whose comment carries no marker has no name, and a
  // removal with no name used to go out all the same.
  it("refuses a rule the panel cannot name", () => {
    expect(ruleRemoveOrder("").problems).not.toEqual([]);
  });
});

describe("zonePortOrder", () => {
  it("sends what the Bulk workspace sends, plus the watchdog of a reload", () => {
    const order = zonePortOrder("public", "8443", "tcp", true);
    const section = bulk("firewall.zone.port", {
      zone: "public", ports: "8443", protocol: "tcp", enable: true,
    }).firewall as Record<string, unknown>;
    expect(order.payload).toEqual({ firewall: { ...section, rollback_seconds: 120 } });
    expect(order.payload).toEqual({
      firewall: { zone: "public", ports: ["8443"], protocol: "tcp", enable: true, rollback_seconds: 120 },
    });
    expect(order.problems).toEqual([]);
    // Closing carries no flag: the registry leaves out what is false.
    expect(zonePortOrder("public", "8443", "tcp", false).payload)
      .toEqual({ firewall: { zone: "public", ports: ["8443"], protocol: "tcp", rollback_seconds: 120 } });
  });

  it("refuses a port or a protocol the zone would not take", () => {
    for (const [port, protocol] of [["http", "tcp"], ["0", "tcp"], ["99999", "tcp"], ["8443", "sctp"]]) {
      const order = zonePortOrder("public", port, protocol, true);
      expect(order.problems, `${port}/${protocol}`).not.toEqual([]);
      expect(order.problems).toEqual(refusals("firewall.zone.port", {
        zone: "public", ports: port, protocol, enable: true,
      }));
    }
  });
});

describe("zoneServiceOrder", () => {
  it("sends what the Bulk workspace sends, plus the watchdog of a reload", () => {
    const order = zoneServiceOrder("public", "https", true);
    const section = bulk("firewall.zone.service", {
      zone: "public", service: "https", enable: true,
    }).firewall as Record<string, unknown>;
    expect(order.payload).toEqual({ firewall: { ...section, rollback_seconds: 120 } });
    expect(order.payload).toEqual({
      firewall: { zone: "public", service: "https", enable: true, rollback_seconds: 120 },
    });
    expect(order.problems).toEqual([]);
  });

  it("refuses a name firewalld would not know", () => {
    expect(zoneServiceOrder("public", "", true).problems).not.toEqual([]);
    expect(zoneServiceOrder("public", "HTTPS", true).problems).not.toEqual([]);
  });
});
