import { describe, expect, it } from "vitest";
import { destroyable, filterSecrets, reasonGiven, secretReference, storeCounts } from "./Secrets";

/* The helpers decide what the store pages offer and refuse before the
   server is asked; they are tested on their own, without a screen. */

describe("reasonGiven", () => {
  it("opens the button at eight characters of reason, blanks aside", () => {
    expect(reasonGiven("")).toBe(false);
    expect(reasonGiven("short")).toBe(false);
    expect(reasonGiven("       8")).toBe(false);
    expect(reasonGiven("rotation")).toBe(true);
    expect(reasonGiven("  quarterly rotation  ")).toBe(true);
  });
});

describe("secretReference", () => {
  it("names the secret the way a payload does, pinned only when a version is given", () => {
    expect(secretReference("repo.token")).toBe('{"name":"repo.token"}');
    expect(secretReference("repo.token", 3)).toBe('{"name":"repo.token","version":3}');
  });

  it("treats version zero as the current one, which a payload does not pin", () => {
    expect(secretReference("repo.token", 0)).toBe('{"name":"repo.token"}');
  });
});

describe("filterSecrets", () => {
  const secrets = [
    { name: "repo.token", description: "package repository token" },
    { name: "backup.password", description: "restic store" },
    { name: "tls.key" },
  ];

  it("matches the name or the description, case aside", () => {
    expect(filterSecrets(secrets, "REPO").map((secret) => secret.name)).toEqual(["repo.token"]);
    expect(filterSecrets(secrets, "re").map((secret) => secret.name)).toEqual(["repo.token", "backup.password"]);
    expect(filterSecrets(secrets, "tls").map((secret) => secret.name)).toEqual(["tls.key"]);
  });

  it("keeps the whole list for a blank search and finds nothing for a stranger", () => {
    expect(filterSecrets(secrets, "   ")).toBe(secrets);
    expect(filterSecrets(secrets, "vault")).toEqual([]);
  });
});

describe("storeCounts", () => {
  it("counts the issuable, the retired and the never rotated, without overlap", () => {
    const counts = storeCounts([
      { current_version: 1 },
      { current_version: 3 },
      { current_version: 1, retired_at: "2026-09-15T10:00:00Z" },
    ]);
    expect(counts).toEqual({ issuable: 2, retired: 1, neverRotated: 1 });
  });

  it("counts nothing in an empty store rather than guessing", () => {
    expect(storeCounts([])).toEqual({ issuable: 0, retired: 0, neverRotated: 0 });
  });
});

describe("destroyable", () => {
  const issuable = { current_version: 3 };
  const retired = { current_version: 3, retired_at: "2026-09-15T10:00:00Z" };

  it("offers the destruction of an earlier version, never of the one the next job gets", () => {
    expect(destroyable(issuable, { version: 2 })).toBe(true);
    expect(destroyable(issuable, { version: 3 })).toBe(false);
  });

  it("offers every version of a retired secret, which issues nothing any more", () => {
    expect(destroyable(retired, { version: 3 })).toBe(true);
  });

  it("does not destroy twice", () => {
    expect(destroyable(issuable, { version: 2, destroyed_at: "2026-09-15T10:00:00Z" })).toBe(false);
    expect(destroyable(retired, { version: 3, destroyed_at: "2026-09-15T10:00:00Z" })).toBe(false);
  });
});
