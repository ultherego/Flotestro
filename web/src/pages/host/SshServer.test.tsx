import { describe, expect, it } from "vitest";
import { effectiveConfigurationMissing } from "./SshServer";

/* A snapshot without a reason and without a single setting from "sshd -T"
   is an unread configuration, not a server that listens nowhere. */

describe("effectiveConfigurationMissing", () => {
  it("says the configuration is missing when nothing of sshd -T is there", () => {
    expect(effectiveConfigurationMissing({})).toBe(true);
    expect(effectiveConfigurationMissing({ ports: [] })).toBe(true);
  });

  it("says nothing when the server named a port or a policy", () => {
    expect(effectiveConfigurationMissing({ ports: ["22"] })).toBe(false);
    expect(effectiveConfigurationMissing({ permit_root_login: "prohibit-password" })).toBe(false);
    expect(effectiveConfigurationMissing({ password_authentication: "no" })).toBe(false);
  });
});
