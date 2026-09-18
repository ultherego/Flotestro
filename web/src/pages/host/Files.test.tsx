import { describe, expect, it } from "vitest";
import { hostRollbackPayload, hostVersionRefusal } from "./Files";

/* The host keeps copies of a file the panel never had: the content from
   before the panel managed it, and whatever somebody changed outside the
   panel. The page offers those copies, so the order names a checksum the
   operator has actually seen. */

describe("hostVersionRefusal", () => {
  it("lets a version with a checksum be ordered back", () => {
    expect(hostVersionRefusal({ sha256: "a".repeat(64), size_bytes: 12, kept_at: "2026-09-18T10:00:00Z" })).toBe("");
  });

  it("refuses a version from the secret store, which the host keeps but does not name", () => {
    expect(hostVersionRefusal({ size_bytes: 12, kept_at: "2026-09-18T10:00:00Z", from_secret: true })).toBe("from_secret");
  });

  it("refuses a version the host reports without a checksum", () => {
    expect(hostVersionRefusal({ size_bytes: 12, kept_at: "2026-09-18T10:00:00Z" })).toBe("no_checksum");
  });
});

/* A return names one content and carries the permissions of that copy: the
   file comes back as the inode it was, not as the bytes under whatever
   mode the newer file happened to have. */

describe("hostRollbackPayload", () => {
  const file = {
    path: "/etc/app.conf",
    updated_by: "operator",
    updated_at: "2026-09-18T10:00:00Z",
    observed_sha256: "b".repeat(64),
    mode: "0600",
    exists: true,
    drift: false,
  };

  it("names the version by its checksum and binds the write to what the host has now", () => {
    const payload = hostRollbackPayload(file, {
      sha256: "a".repeat(64), size_bytes: 12, mode: "0640", kept_at: "2026-09-18T09:00:00Z",
    });
    expect(payload).toEqual({
      file: {
        path: "/etc/app.conf",
        version_sha256: "a".repeat(64),
        expected_sha256: "b".repeat(64),
        mode: "0640",
      },
    });
  });

  it("leaves the mode to the host when the copy was kept without one", () => {
    const payload = hostRollbackPayload(file, {
      sha256: "a".repeat(64), size_bytes: 12, kept_at: "2026-09-18T09:00:00Z",
    });
    expect(payload.file.mode).toBe("");
  });
});
