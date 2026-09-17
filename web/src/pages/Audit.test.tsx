import { describe, expect, it } from "vitest";
import { actorKey, actorView, exportFileName, targetLink, toLocalInput } from "./Audit";

/* The actor of an event is shown from the snapshot the trail kept: the
   name it had, the immutable identifier on hover, and a link only to a
   host, a relay or a campaign the snapshot names. */

const t = (text: string) => text;
const hostID = "377802f9-a0e9-4afa-ad68-293a0873bcf3";
const withActor = (actor: Record<string, string>, actor_type = "user", actor_id = "x") =>
  ({ actor_type, actor_id, actor });

describe("actorView", () => {
  it("shows the historical display name and keeps the immutable identifier", () => {
    const who = actorView(withActor({
      principal_id: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", subject: "alice", display_name: "Alice Kowalska", kind: "user",
    }, "user", "alice"), t);
    expect(who).toEqual({ text: "Alice Kowalska", id: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", kind: "user" });
  });

  it("links a host, a relay and a campaign the snapshot names, and nothing else", () => {
    expect(actorView(withActor({
      subject: hostID, kind: "agent", resource_type: "host", resource_id: hostID, resource_name: "agent-arch",
    }, "agent", hostID), t)).toEqual({ text: "agent agent-arch", id: hostID, kind: "agent", to: `/hosts/${hostID}/overview` });
    expect(actorView(withActor({
      subject: "relay-warsaw", kind: "relay", resource_type: "relay", resource_id: "9b6c1a2e-1f3d-4c5b-8a7e-2d4f6a8c0e1b", resource_name: "relay-warsaw",
    }, "agent", "relay-warsaw"), t).to).toBe("/relays/9b6c1a2e-1f3d-4c5b-8a7e-2d4f6a8c0e1b");
    expect(actorView(withActor({
      subject: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6", kind: "system", resource_type: "campaign",
      resource_id: "b9aa09ed-534f-48d5-89fb-12750d0560b6", resource_name: "kernel rollout",
    }, "system", "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6"), t)).toEqual({
      text: "kernel rollout", id: "b9aa09ed-534f-48d5-89fb-12750d0560b6", kind: "system",
      to: "/campaigns/b9aa09ed-534f-48d5-89fb-12750d0560b6",
    });
    // A policy has a resource but no page as an actor; a machine
    // identifier is a row of nothing and never a host.
    expect(actorView(withActor({
      subject: "policy:0b1c2d3e-4f50-4617-8283-94a5b6c7d8e9", kind: "system", resource_type: "policy",
      resource_id: "0b1c2d3e-4f50-4617-8283-94a5b6c7d8e9",
    }, "system", "policy:0b1c2d3e-4f50-4617-8283-94a5b6c7d8e9"), t).to).toBeUndefined();
    const machine = actorView(withActor({
      subject: "2cd1131243654fe6b49ee4d704ea2c5a", kind: "machine", resource_type: "machine",
      resource_name: "2cd1131243654fe6b49ee4d704ea2c5a",
    }, "agent", "2cd1131243654fe6b49ee4d704ea2c5a"), t);
    expect(machine.to).toBeUndefined();
    expect(machine.text).toBe("2cd1131243654fe6b49ee4d704ea2c5a");
  });

  it("never links an agent by the text of actor_id, and shows an event without a snapshot as it was written", () => {
    // A host identifier as actor_id with a snapshot that names no host:
    // the host is gone, and the identifier is not turned into a page.
    const gone = actorView(withActor({ subject: hostID, kind: "agent" }, "agent", hostID), t);
    expect(gone).toEqual({ text: hostID, id: hostID, kind: "agent" });
    expect(actorView({ actor_type: "agent", actor_id: hostID }, t)).toEqual({ text: hostID, id: hostID, kind: "agent" });
  });
});

describe("actorKey", () => {
  it("groups by the kind and the immutable identifier, so a rename stays one actor", () => {
    const before = withActor({ principal_id: "p1", subject: "alice", display_name: "Alice", kind: "user" }, "user", "alice");
    const after = withActor({ principal_id: "p1", subject: "alice", display_name: "Alicja", kind: "user" }, "user", "alice");
    expect(actorKey(before)).toBe(actorKey(after));
    expect(actorKey(before)).toBe("user:p1");
    // A machine and a host with the same digits are two actors.
    expect(actorKey(withActor({ subject: "2cd1131243654fe6b49ee4d704ea2c5a", kind: "machine" }, "agent", "2cd1131243654fe6b49ee4d704ea2c5a")))
      .not.toBe(actorKey(withActor({ subject: hostID, kind: "agent", resource_id: hostID }, "agent", hostID)));
    expect(actorKey({ actor_type: "system", actor_id: "panel" })).toBe("system:panel");
  });
});

describe("the small helpers of the trail", () => {
  it("links a target where the panel has a page and reads the export's file name", () => {
    expect(targetLink("host", hostID)).toBe(`/hosts/${hostID}/overview`);
    expect(targetLink("nothing", "x")).toBeNull();
    expect(exportFileName('attachment; filename="audit-from-20260901T000000Z.jsonl"')).toBe("audit-from-20260901T000000Z.jsonl");
    expect(exportFileName(null)).toBe("audit.jsonl");
    expect(toLocalInput("not a date")).toBe("");
  });
});
