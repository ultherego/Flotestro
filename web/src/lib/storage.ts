import { useCallback, useState } from "react";

/**
 * A piece of interface state remembered in the browser: the theme, the
 * sidebar width, which navigation groups are folded.
 */
export function readStored<T>(key: string, fallback: T, valid: (value: unknown) => value is T): T {
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return fallback;
    const parsed: unknown = JSON.parse(raw);
    return valid(parsed) ? parsed : fallback;
  } catch {
    // Storage may be unavailable (private mode, blocked site data) or hold
    // something unreadable from an older version; the default applies then.
    return fallback;
  }
}

export function writeStored(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // A preference that cannot be remembered still applies to this session.
  }
}

/** useState whose value is read from and written back to localStorage. */
export function useStoredState<T>(
  key: string,
  fallback: T,
  valid: (value: unknown) => value is T,
): [T, (next: T | ((current: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => readStored(key, fallback, valid));
  const set = useCallback((next: T | ((current: T) => T)) => {
    setValue((current) => {
      const resolved = typeof next === "function" ? (next as (current: T) => T)(current) : next;
      writeStored(key, resolved);
      return resolved;
    });
  }, [key]);
  return [value, set];
}

export const isBoolean = (value: unknown): value is boolean => typeof value === "boolean";

export const isStringList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");
