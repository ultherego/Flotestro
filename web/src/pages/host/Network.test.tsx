import { describe, expect, it } from "vitest";
import {
  acceptRAWords, layerKind, layerMembers, layerSummary, privacyWords, routeProtocolWords,
  type Interface,
} from "./Network";

/* The layering is the one thing on this page that answers "what is this
   interface made of" rather than "what does it carry". A member that has
   given its addressing to a bond looks, on every other column, like a card
   nobody configured - so the page has to say who owns it. */

function link(fields: Partial<Interface>): Interface {
  return { name: "enp0s8", index: 3, mtu: 1500, oper_state: "up", management: false, ...fields };
}

describe("layerKind", () => {
  it("names the layer from what the host reported about it", () => {
    expect(layerKind(link({ bond: { miimon_ms: 100 } }))).toBe("bond");
    expect(layerKind(link({ bridge: { stp: true, vlan_filtering: false } }))).toBe("bridge");
    expect(layerKind(link({ vlan: { id: 100, parent: "bond0" } }))).toBe("vlan");
  });

  it("leaves a plain link without a kind, even when a layer owns it", () => {
    expect(layerKind(link({}))).toBe("");
    expect(layerKind(link({ master: "bond0" }))).toBe("");
  });
});

describe("layerMembers", () => {
  it("reads the members of whichever layer has them", () => {
    expect(layerMembers(link({ bond: { miimon_ms: 100, members: ["a", "b"] } }))).toEqual(["a", "b"]);
    expect(layerMembers(link({ bridge: { stp: false, vlan_filtering: false, members: ["c"] } }))).toEqual(["c"]);
  });

  it("gives a VLAN no members: it has a parent instead", () => {
    expect(layerMembers(link({ vlan: { id: 100, parent: "bond0" } }))).toEqual([]);
  });
});

describe("layerSummary", () => {
  it("says what a layer is made of", () => {
    expect(layerSummary(link({ bond: { miimon_ms: 100, mode: "active-backup", members: ["a", "b"] } })))
      .toBe("bond (active-backup) of a, b");
    expect(layerSummary(link({ vlan: { id: 100, parent: "bond0" } }))).toBe("vlan 100 on bond0");
  });

  it("says a bridge with no member yet is a bridge with no member yet", () => {
    // An empty bridge is a legitimate thing to build: the virtual machines
    // are attached to it afterwards, and an empty list must not read as a
    // mistake.
    expect(layerSummary(link({ bridge: { stp: false, vlan_filtering: false } })))
      .toBe("bridge of nothing yet");
  });

  it("says who owns a member, because its own addressing went there", () => {
    expect(layerSummary(link({ master: "bond0" }))).toBe("member of bond0");
    expect(layerSummary(link({}))).toBe("");
  });
});

/* The second family's switches are the kernel's numbers. Unknown stays
   unknown: a setting that could not be read is not the same as one that is
   off, and the panel must not turn the first into the second. */

describe("the IPv6 switches in words", () => {
  it("keeps an unread setting unknown", () => {
    expect(acceptRAWords(undefined)).toBe("unknown");
    expect(privacyWords(undefined)).toBe("unknown");
  });

  it("reads the kernel's numbers", () => {
    expect(acceptRAWords(0)).toBe("ignored");
    expect(acceptRAWords(1)).toBe("accepted");
    expect(acceptRAWords(2)).toBe("accepted, even while forwarding");
    expect(privacyWords(0)).toBe("off");
    expect(privacyWords(1)).toBe("public preferred");
    expect(privacyWords(2)).toBe("temporary preferred");
  });
});

describe("routeProtocolWords", () => {
  it("says who put the route there", () => {
    expect(routeProtocolWords("ra")).toBe("router advertisement");
    expect(routeProtocolWords("kernel")).toBe("kernel (from an address)");
    expect(routeProtocolWords(undefined)).toBe("—");
  });
});
