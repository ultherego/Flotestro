import { useCallback, useEffect, useState } from "react";

/**
 * The colour theme of the panel.
 *
 * The themes are defined in styles.css as sets of custom properties under
 * [data-theme]; this hook only decides which name stands on the root
 * element. Nothing here paints anything, so a page never needs to know
 * which theme is on.
 */
export type Theme = "mocha-peach" | "mocha-green" | "latte";

export const THEMES: { code: Theme; label: string; description: string }[] = [
  { code: "mocha-peach", label: "Peach", description: "Dark theme with a peach accent" },
  { code: "mocha-green", label: "Green", description: "Dark theme with a green accent" },
  { code: "latte", label: "Latte", description: "Light theme" },
];

// The value is kept as a bare string, not JSON, because the inline script
// in index.html reads the same key before React mounts and must not parse
// anything to avoid a flash of the wrong theme.
const STORAGE_KEY = "flotestro.theme";

function isTheme(value: unknown): value is Theme {
  return THEMES.some((entry) => entry.code === value);
}

function storedTheme(): Theme | null {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isTheme(stored) ? stored : null;
  } catch {
    // Storage may be unavailable (private mode, blocked site data); the
    // system preference decides then.
    return null;
  }
}

function systemTheme(): Theme {
  const light = typeof window.matchMedia === "function"
    && window.matchMedia("(prefers-color-scheme: light)").matches;
  return light ? "latte" : "mocha-peach";
}

export function useTheme(): { theme: Theme; setTheme: (theme: Theme) => void } {
  const [theme, setThemeState] = useState<Theme>(() => storedTheme() ?? systemTheme());

  const setTheme = useCallback((next: Theme) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // A theme that cannot be remembered still applies to this session.
    }
    setThemeState(next);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // Somebody who never chose a theme follows the operating system, also
  // when it switches between day and night while the panel stays open. An
  // explicit choice is never overridden by the system.
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const follow = () => {
      if (storedTheme() === null) setThemeState(systemTheme());
    };
    query.addEventListener("change", follow);
    return () => query.removeEventListener("change", follow);
  }, []);

  return { theme, setTheme };
}
