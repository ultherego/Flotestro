import { createContext, useContext, type ReactNode } from "react";
import { SCALES, type Scale } from "../lib/scale";
import { THEMES, type Theme } from "../lib/theme";

/**
 * The look of the panel as the person at the screen set it, from the one
 * place that holds it.
 *
 * `useTheme` and `useScale` each keep their own state, so a second call
 * of either is a second answer: on 16.10 the menu under the avatar had
 * one and the application had another, and choosing a theme wrote it to
 * the browser and to the server while the page went on wearing the one
 * the other instance had applied. Everything in the new panel reads the
 * application's own instance through here.
 */
export type Look = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  scale: Scale;
  setScale: (scale: Scale) => void;
};

const LookContext = createContext<Look | null>(null);

export function LookProvider({ look, children }: { look: Look; children: ReactNode }) {
  return <LookContext.Provider value={look}>{children}</LookContext.Provider>;
}

/**
 * What the panel looks like and how to change it. Outside the provider -
 * a screen drawn on its own, as a test draws it - the choices are still
 * offered and simply go nowhere, rather than the screen failing to draw.
 */
export function useLook(): Look {
  const held = useContext(LookContext);
  return held ?? {
    theme: THEMES[0].code,
    setTheme: () => undefined,
    scale: SCALES[1].code,
    setScale: () => undefined,
  };
}
