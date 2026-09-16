import { describe, expect, it } from "vitest";
import { campaignLabel } from "./Jobs";

/* The chip beside a campaign's job names the campaign the way the
   operator knows it; the rule is a pure function, so it is tested alone. */

describe("campaignLabel", () => {
  it("takes the campaign's name from the author of the job", () => {
    expect(campaignLabel({ campaign_id: "b9aa09ed-534f-48d5-89fb-12750d0560b6", created_by: "campaign:Test" })).toBe("Test");
    expect(campaignLabel({ campaign_id: "b9aa09ed-534f", created_by: "campaign:certificate on the fleet" })).toBe("certificate on the fleet");
  });

  it("falls back to the first letters of the identifier when the author is not the campaign", () => {
    expect(campaignLabel({ campaign_id: "b9aa09ed-534f-48d5-89fb-12750d0560b6", created_by: "bootstrap-admin" })).toBe("b9aa09ed");
    expect(campaignLabel({ campaign_id: "b9aa09ed-534f", created_by: "campaign:" })).toBe("b9aa09ed");
    expect(campaignLabel({ created_by: "campaign:" })).toBe("");
  });
});
