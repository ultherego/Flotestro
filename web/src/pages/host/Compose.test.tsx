import { describe, expect, it } from "vitest";
import { digestSourceWords, planImageDigests } from "./Compose";

/* The plan names the digest every service will run and where the host
   learned it; the words are the operator's, the code is the host's. */

describe("digestSourceWords", () => {
  it("names the three sources of a digest", () => {
    expect(digestSourceWords("reference")).toBe("pinned in manifest");
    expect(digestSourceWords("registry")).toBe("from registry");
    expect(digestSourceWords("local")).toBe("from host image");
  });

  it("passes a source it does not know through unchanged", () => {
    expect(digestSourceWords("mirror")).toBe("mirror");
  });
});

describe("planImageDigests", () => {
  it("maps every resolved service to its digest and skips an unresolved one", () => {
    expect(planImageDigests({
      project: "shop", digest: "abc",
      services: [
        { name: "web", image: "nginx:alpine", image_digest: "sha256:aaa" },
        { name: "db", image: "postgres:16" },
      ],
    })).toEqual({ web: "sha256:aaa" });
  });
});
