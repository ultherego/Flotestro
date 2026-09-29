import { describe, expect, it } from "vitest";
import { enrollOrder } from "./Identity";
import { emptyForm, operationForm, type FormValue } from "../../lib/operations";

/* Joining a domain goes through the operation registry, so this page and
   the Bulk workspace send one payload and refuse one set of names. The
   realm is put in capitals on the way in, because that is what a realm is. */

function bulk(form: FormValue): Record<string, unknown> {
  const entry = operationForm("identity.host.enroll");
  if (!entry) throw new Error("the registry has no form for identity.host.enroll");
  return entry.toPayload({ ...emptyForm(entry), ...form });
}

describe("enrollOrder", () => {
  it("sends what the Bulk workspace sends", () => {
    const order = enrollOrder("example.internal", "example.internal", "ipa.example.internal", "web02.example.internal");
    expect(order.payload).toEqual(bulk({
      domain: "example.internal",
      realm: "EXAMPLE.INTERNAL",
      server: "ipa.example.internal",
      hostname: "web02.example.internal",
    }));
    expect(order.payload).toEqual({
      domain_enroll: {
        domain: "example.internal",
        realm: "EXAMPLE.INTERNAL",
        server: "ipa.example.internal",
        hostname: "web02.example.internal",
      },
    });
    expect(order.problems).toEqual([]);
  });

  it("leaves out a server nobody named", () => {
    expect(enrollOrder("example.internal", "EXAMPLE.INTERNAL", "", "web02.example.internal").payload)
      .toEqual({
        domain_enroll: {
          domain: "example.internal", realm: "EXAMPLE.INTERNAL", hostname: "web02.example.internal",
        },
      });
  });

  // The refusal the page did not make before: a name in capitals reaches
  // the directory as a different name from the one the host answers to.
  it("refuses what the Bulk workspace refuses", () => {
    const entry = operationForm("identity.host.enroll");
    const cases: [string, string, string][] = [
      ["", "EXAMPLE.INTERNAL", "web02.example.internal"],
      ["example.internal", "", "web02.example.internal"],
      ["not-a-domain", "EXAMPLE.INTERNAL", "web02.example.internal"],
      ["example.internal", "EXAMPLE.INTERNAL", "Web02.Example.Internal"],
      ["example.internal", "EXAMPLE.INTERNAL", "web02.localhost"],
    ];
    for (const [domain, realm, hostname] of cases) {
      const order = enrollOrder(domain, realm, "", hostname);
      expect(order.problems, `${domain}/${realm}/${hostname}`).not.toEqual([]);
      expect(order.problems).toEqual(entry?.validate({
        ...emptyForm(entry), domain, realm: realm.trim().toUpperCase(), server: "", hostname,
      }));
    }
  });
});
