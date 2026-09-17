import { describe, expect, it } from "vitest";
import { actorLabel, digest } from "./Audit";

/* The actor of an event is named for the operator by pure functions:
   the campaign by a link, the agent by its host, a person by name. */

const t = (text: string, params?: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (match, name: string) => (params && name in params ? String(params[name]) : match));
const host = { id: "377802f9-a0e9-4afa-ad68-293a0873bcf3", hostname: "agent-arch" };

describe("actorLabel", () => {
  it("links a campaign actor to the campaign and keeps the identifier on hover", () => {
    const who = actorLabel({ actor_type: "system", actor_id: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6" }, host, t);
    expect(who).toEqual({
      text: "campaign b9aa09ed",
      to: "/campaigns/b9aa09ed-534f-48d5-89fb-12750d0560b6",
      title: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6",
    });
  });

  it("names the agent by its host, whether the type or the identifier says so", () => {
    expect(actorLabel({ actor_type: "agent", actor_id: "377802f9-a0e9-4afa-ad68-293a0873bcf3" }, host, t)).toEqual({
      text: "agent of agent-arch", title: "377802f9-a0e9-4afa-ad68-293a0873bcf3",
    });
    expect(actorLabel({ actor_type: "", actor_id: host.id }, host, t).text).toBe("agent of agent-arch");
  });

  it("leaves a person and the panel as they are", () => {
    expect(actorLabel({ actor_type: "user", actor_id: "bootstrap-admin" }, host, t)).toEqual({ text: "bootstrap-admin" });
    expect(actorLabel({ actor_type: "system", actor_id: "panel" }, host, t)).toEqual({ text: "panel" });
  });

  it("reads the snapshot: the name as it was, the identifier on hover, a link only to a resource with a page", () => {
    const person = { actor_type: "user", actor_id: "alice", actor: {
      principal_id: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b", subject: "alice", display_name: "Alice Kowalska", kind: "user",
    } };
    expect(actorLabel(person, host, t)).toEqual({ text: "Alice Kowalska", to: undefined, title: "6f1d2c3b-4a5e-4f60-8b71-9c8d7e6f5a4b" });

    // The agent of this host is named as such and not linked to itself.
    const own = { actor_type: "agent", actor_id: host.id, actor: {
      subject: host.id, kind: "agent", resource_type: "host", resource_id: host.id, resource_name: "old-name",
    } };
    expect(actorLabel(own, host, t)).toEqual({ text: "agent of agent-arch", title: host.id });

    // A machine identifier that parses as a host identifier is not a host.
    const machine = { actor_type: "agent", actor_id: "2cd1131243654fe6b49ee4d704ea2c5a", actor: {
      subject: "2cd1131243654fe6b49ee4d704ea2c5a", kind: "machine", resource_type: "machine", resource_name: "2cd1131243654fe6b49ee4d704ea2c5a",
    } };
    expect(actorLabel(machine, host, t).to).toBeUndefined();

    const campaign = { actor_type: "system", actor_id: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6", actor: {
      subject: "campaign:b9aa09ed-534f-48d5-89fb-12750d0560b6", kind: "system", resource_type: "campaign",
      resource_id: "b9aa09ed-534f-48d5-89fb-12750d0560b6", resource_name: "kernel rollout",
    } };
    expect(actorLabel(campaign, host, t)).toEqual({
      text: "campaign kernel rollout", to: "/campaigns/b9aa09ed-534f-48d5-89fb-12750d0560b6", title: "b9aa09ed-534f-48d5-89fb-12750d0560b6",
    });
  });
});

describe("digest", () => {
  it("reads the interesting keys of the detail in order and skips the empty ones", () => {
    expect(digest({ reason: "handover", state: "queued", hostname: "web01", permission: "" })).toBe("reason=handover · state=queued");
    expect(digest({ error_code: "unit_not_found" })).toBe("error_code=unit_not_found");
  });

  it("is empty for no detail", () => {
    expect(digest(undefined)).toBe("");
    expect(digest({})).toBe("");
  });
});
