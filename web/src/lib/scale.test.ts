import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import { SCALES, useScale } from "./scale";

const KEY = "flotestro.scale";

beforeEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.scale;
});

afterEach(cleanup);

describe("useScale", () => {
  it("starts at the normal size when nothing is remembered", () => {
    const { result } = renderHook(() => useScale());
    expect(result.current.scale).toBe("normal");
    expect(document.documentElement.dataset.scale).toBe("normal");
  });

  it("remembers the choice in localStorage and stamps it on the root element", () => {
    const { result } = renderHook(() => useScale());
    act(() => result.current.setScale("large"));
    expect(result.current.scale).toBe("large");
    expect(window.localStorage.getItem(KEY)).toBe("large");
    expect(document.documentElement.dataset.scale).toBe("large");
  });

  it("reads the remembered choice back on the next start", () => {
    window.localStorage.setItem(KEY, "larger");
    const { result } = renderHook(() => useScale());
    expect(result.current.scale).toBe("larger");
    expect(document.documentElement.dataset.scale).toBe("larger");
  });

  it("ignores a remembered value it does not know", () => {
    window.localStorage.setItem(KEY, "gigantic");
    const { result } = renderHook(() => useScale());
    expect(result.current.scale).toBe("normal");
  });

  it("stores the value as a bare string the inline script can read", () => {
    const { result } = renderHook(() => useScale());
    act(() => result.current.setScale("small"));
    // Not JSON: index.html compares the raw value before React mounts.
    expect(window.localStorage.getItem(KEY)).toBe("small");
    expect(window.localStorage.getItem(KEY)).not.toBe(JSON.stringify("small"));
  });

  it("offers every size the stylesheet knows, in growing order", () => {
    const factors = SCALES.map((entry) => entry.factor);
    expect([...factors].sort((a, b) => a - b)).toEqual(factors);
    expect(SCALES.map((entry) => entry.code)).toEqual(["small", "normal", "large", "larger"]);
  });
});
