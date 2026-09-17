import { describe, expect, it } from "vitest";
import { bootLogsPath, dashedBootID } from "./Power";

/* The journal and the kernel spell the same boot identifier differently;
   the table shows the kernel's form so the current boot is recognised. */

describe("dashedBootID", () => {
  it("dashes the journal's bare form into the kernel's", () => {
    expect(dashedBootID("2cd1131243654fe6b49ee4d704ea2c5a")).toBe("2cd11312-4365-4fe6-b49e-e4d704ea2c5a");
  });

  it("leaves an identifier that is already dashed, or not an identifier at all, as it came", () => {
    expect(dashedBootID("2cd11312-4365-4fe6-b49e-e4d704ea2c5a")).toBe("2cd11312-4365-4fe6-b49e-e4d704ea2c5a");
    expect(dashedBootID("not-a-boot-id")).toBe("not-a-boot-id");
  });
});

/* A boot on the Power tab opens the Logs tab narrowed to it; the address
   carries the journal's bare form, whichever form the row showed. */

describe("bootLogsPath", () => {
  it("links to the host's logs with the bare boot identifier", () => {
    expect(bootLogsPath("h1", "2cd11312-4365-4fe6-b49e-e4d704ea2c5a")).toBe("/hosts/h1/logs?boot=2cd1131243654fe6b49ee4d704ea2c5a");
    expect(bootLogsPath("h1", "2cd1131243654fe6b49ee4d704ea2c5a")).toBe("/hosts/h1/logs?boot=2cd1131243654fe6b49ee4d704ea2c5a");
  });
});
