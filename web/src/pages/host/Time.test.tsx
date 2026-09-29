import { describe, expect, it } from "vitest";
import { timeSourcesOrder, timeZoneOrder } from "./Time";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* The clock is what everything else assumes, so the two changes this page
   offers go out exactly as the Bulk workspace would send them, and are
   refused here for the reasons they are refused there. */

function bulk(action: string, form: FormValue): Record<string, unknown> {
  const entry = operationForm(action);
  if (!entry) throw new Error(`the registry has no form for ${action}`);
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

function refusals(action: string, form: FormValue) {
  const entry = operationForm(action);
  return entry?.validate({ ...emptyForm(entry), ...form });
}

describe("timeSourcesOrder", () => {
  const servers = ["ntp1.example.com", "192.0.2.10"];

  it("sends what the Bulk workspace sends", () => {
    const order = timeSourcesOrder(servers, true, false);
    expect(order.payload).toEqual(bulk("time.config.apply", {
      servers: servers.join("\n"), allow_step: true, enable_dropin: false,
    }));
    expect(order.payload).toEqual({ time: { servers, allow_step: true } });
    expect(order.problems).toEqual([]);
  });

  it("carries the consent to write the daemon's own file when it is given", () => {
    expect(timeSourcesOrder(servers, false, true).payload)
      .toEqual({ time: { servers, enable_dropin: true } });
  });

  // Three refusals the page did not make before it went through the
  // registry: too many sources, a source that is not a name or an address,
  // and one source named twice.
  it("refuses what the Bulk workspace refuses", () => {
    const cases: [string[], string][] = [
      [[], "at least one time server"],
      [Array.from({ length: 9 }, (_, i) => `ntp${i}.example.com`), "at most eight"],
      [["-not-a-host-"], "neither an address nor a host name"],
      [["ntp1.example.com", "ntp1.example.com"], "on the list twice"],
    ];
    for (const [list, sentence] of cases) {
      const order = timeSourcesOrder(list, false, false);
      expect(order.problems, sentence).not.toEqual([]);
      expect(order.problems[0].message).toContain(sentence);
      expect(order.problems).toEqual(refusals("time.config.apply", {
        servers: list.join("\n"), allow_step: false, enable_dropin: false,
      }));
    }
  });
});

describe("timeZoneOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    expect(timeZoneOrder("Europe/Warsaw").payload)
      .toEqual(bulk("time.timezone.set", { timezone: "Europe/Warsaw" }));
    expect(timeZoneOrder("Europe/Warsaw").payload).toEqual({ time: { timezone: "Europe/Warsaw" } });
    expect(timeZoneOrder("Europe/Warsaw").problems).toEqual([]);
  });

  it("refuses a zone that is a path, a sentence or nothing", () => {
    for (const zone of ["../../etc/passwd", "europe warsaw", ""]) {
      expect(timeZoneOrder(zone).problems, zone).not.toEqual([]);
      expect(timeZoneOrder(zone).problems).toEqual(refusals("time.timezone.set", { timezone: zone }));
    }
  });
});
