import { useCallback, useEffect, useState } from "react";

/**
 * The text size of the panel, chosen by the person at the screen the way
 * the theme is: a 4K monitor at arm's length and a laptop on a lap want
 * different sizes of the same interface. The choice scales everything -
 * text, spacing, controls - so the composition stays the same.
 */
export type Scale = "small" | "normal" | "large" | "larger";

export const SCALES: { code: Scale; label: string; description: string; factor: number }[] = [
  { code: "small", label: "A-", description: "Smaller text and denser layout", factor: 0.9 },
  { code: "normal", label: "A", description: "Default text size", factor: 1 },
  { code: "large", label: "A+", description: "Larger text", factor: 1.12 },
  { code: "larger", label: "A++", description: "Largest text", factor: 1.25 },
];

// A bare string, like the theme: the inline script in index.html reads the
// same key before React mounts, so the page does not jump when it starts.
const STORAGE_KEY = "flotestro.scale";

function isScale(value: unknown): value is Scale {
  return SCALES.some((entry) => entry.code === value);
}

function storedScale(): Scale {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isScale(stored) ? stored : "normal";
  } catch {
    return "normal";
  }
}

export function useScale(): { scale: Scale; setScale: (scale: Scale) => void } {
  const [scale, setScaleState] = useState<Scale>(storedScale);
  const setScale = useCallback((next: Scale) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // A size that cannot be remembered still applies to this session.
    }
    setScaleState(next);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.scale = scale;
  }, [scale]);
  return { scale, setScale };
}
