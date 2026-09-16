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
