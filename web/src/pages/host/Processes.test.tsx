import { describe, expect, it } from "vitest";
import { stateWords } from "./Processes";

/* procfs prints the scheduler state as one letter; the table says it in
   words and keeps the letter on hover. */

describe("stateWords", () => {
  it("names the states an operator asks about", () => {
    expect(stateWords("S")).toBe("sleeping");
    expect(stateWords("D")).toBe("waiting on disk");
    expect(stateWords("Z")).toBe("zombie");
    expect(stateWords("I")).toBe("idle");
  });

  it("reads the first letter only and passes an unknown state through", () => {
    expect(stateWords("R+")).toBe("running");
    expect(stateWords("Ss")).toBe("sleeping");
    expect(stateWords("?")).toBe("?");
  });
});
