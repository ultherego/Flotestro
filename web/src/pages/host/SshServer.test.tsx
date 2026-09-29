import { describe, expect, it } from "vitest";
import { effectiveConfigurationMissing, sshConfigOrder, sshConfigSettings } from "./SshServer";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

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

/* The change form on this page is the registry's own, so it sends what the
   Bulk workspace sends and refuses what it refuses. */

function bulk(form: FormValue): Record<string, unknown> {
  const entry = operationForm("ssh.config.apply");
  if (!entry) throw new Error("the registry has no form for ssh.config.apply");
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

describe("sshConfigOrder", () => {
  const filled: FormValue = {
    permit_root_login: "no",
    password_authentication: "no",
    max_auth_tries: "4",
    allow_groups: "admins\noperators",
    allow_lockout: true,
  };

  it("sends what the Bulk workspace sends", () => {
    expect(sshConfigOrder(filled).payload).toEqual(bulk(filled));
    expect(sshConfigOrder(filled).payload).toEqual({
      ssh: {
        permit_root_login: "no",
        password_authentication: "no",
        max_auth_tries: "4",
        allow_groups: ["admins", "operators"],
        allow_lockout: true,
      },
    });
    expect(sshConfigOrder(filled).problems).toEqual([]);
  });

  // The two refusals the page did not make before: an attempt count the
  // server would not take, and an account pattern it would not either.
  it("refuses what the Bulk workspace refuses", () => {
    const entry = operationForm("ssh.config.apply");
    const cases: FormValue[] = [
      { max_auth_tries: "0" },
      { max_auth_tries: "200" },
      { max_auth_tries: "four" },
      { allow_groups: "a group with spaces" },
    ];
    for (const change of cases) {
      const form = { ...filled, ...change };
      expect(sshConfigOrder(form).problems, JSON.stringify(change)).not.toEqual([]);
      expect(sshConfigOrder(form).problems).toEqual(entry?.validate({ ...emptyForm(entry), ...form }));
    }
  });

  // The registry has no way of saying this: "leave it alone" is a legal
  // value for every field, so an order that changes nothing is legal there.
  it("counts the settings so the page can refuse an order that changes nothing", () => {
    expect(sshConfigSettings(sshConfigOrder({}))).toEqual([]);
    expect(sshConfigSettings(sshConfigOrder({ allow_lockout: true }))).toEqual([]);
    expect(sshConfigSettings(sshConfigOrder(filled)).sort())
      .toEqual(["allow_groups", "max_auth_tries", "password_authentication", "permit_root_login"]);
  });
});
