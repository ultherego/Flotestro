import { describe, expect, it } from "vitest";
import { kernelThread, processColumns, stateWords } from "./Processes";

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

/* A kernel thread is kthreadd or one of its children; it has no memory of
   its own and takes no signal, so the table treats it apart. */

describe("kernelThread", () => {
  it("recognises kthreadd and its children", () => {
    expect(kernelThread({ pid: 2, ppid: 0 })).toBe(true);
    expect(kernelThread({ pid: 15, ppid: 2 })).toBe(true);
  });

  it("leaves ordinary processes alone, including init", () => {
    expect(kernelThread({ pid: 1, ppid: 0 })).toBe(false);
    expect(kernelThread({ pid: 1160, ppid: 1 })).toBe(false);
  });
});

/* The PID and the command identify a process; a preference that hides
   every other column still leaves both on the screen. */

describe("processColumns", () => {
  it("fixes the PID and the command, and names the rest for the chooser", () => {
    const columns = processColumns((text) => text);
    const fixed = columns.filter((column) => column.fixed).map((column) => column.key);
    expect(fixed).toEqual(["pid", "command"]);
    expect(columns.map((column) => column.key)).toEqual([
      "pid", "user", "memory", "cpu", "threads", "state", "managed_by", "command", "actions",
    ]);
  });
});
