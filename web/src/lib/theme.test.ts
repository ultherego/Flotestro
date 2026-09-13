import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import { THEMES, useTheme } from "./theme";

const KEY = "flotestro.theme";

type Listener = (event: MediaQueryListEvent) => void;

/**
 * jsdom has no matchMedia. This stand-in answers the light-scheme query
 * with a chosen value and lets a test flip it, as an operating system
 * switching between day and night would.
 */
function installMatchMedia(light: boolean) {
  const listeners = new Set<Listener>();
  const state = { light };
  const query = {
    get matches() { return state.light; },
    media: "(prefers-color-scheme: light)",
    onchange: null,
    addEventListener: (_type: string, listener: Listener) => { listeners.add(listener); },
    removeEventListener: (_type: string, listener: Listener) => { listeners.delete(listener); },
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => true,
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn().mockImplementation(() => query),
  });
  return {
    flip(nextLight: boolean) {
      state.light = nextLight;
      for (const listener of listeners) listener({ matches: nextLight } as MediaQueryListEvent);
    },
    listeners,
  };
}

beforeEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
});

afterEach(() => {
  cleanup();
  delete (window as { matchMedia?: unknown }).matchMedia;
});

describe("useTheme", () => {
  it("follows the operating system when nothing is remembered", () => {
    installMatchMedia(true);
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("latte");
    expect(document.documentElement.dataset.theme).toBe("latte");
  });

  it("falls back to the dark theme where matchMedia does not exist", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("mocha-peach");
  });

  it("remembers the choice in localStorage and stamps it on the root element", () => {
    installMatchMedia(false);
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("latte"));
    expect(result.current.theme).toBe("latte");
    expect(window.localStorage.getItem(KEY)).toBe("latte");
    expect(document.documentElement.dataset.theme).toBe("latte");
  });

  it("reads the remembered choice back on the next start, whatever the system says", () => {
    installMatchMedia(true);
    window.localStorage.setItem(KEY, "mocha-green");
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("mocha-green");
    expect(document.documentElement.dataset.theme).toBe("mocha-green");
  });

  it("ignores a remembered value it does not know", () => {
    installMatchMedia(false);
    window.localStorage.setItem(KEY, "solarized");
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("mocha-peach");
  });

  it("follows a system switch only while nobody has chosen", () => {
    const media = installMatchMedia(false);
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("mocha-peach");
    act(() => media.flip(true));
    expect(result.current.theme).toBe("latte");

    act(() => result.current.setTheme("mocha-green"));
    act(() => media.flip(false));
    expect(result.current.theme).toBe("mocha-green");
  });

  it("stops listening to the system when it unmounts", () => {
    const media = installMatchMedia(false);
    const { unmount } = renderHook(() => useTheme());
    expect(media.listeners.size).toBe(1);
    unmount();
    expect(media.listeners.size).toBe(0);
  });

  it("stores the value as a bare string the inline script can read", () => {
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("latte"));
    expect(window.localStorage.getItem(KEY)).toBe("latte");
  });

  it("offers exactly the themes the inline script accepts", () => {
    expect(THEMES.map((entry) => entry.code)).toEqual(["mocha-peach", "mocha-green", "latte"]);
  });
});
