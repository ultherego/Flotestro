import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { pl } from "./pl";

/**
 * The interface language.
 *
 * English is the source: the texts in the components are the English
 * strings themselves, and a translation is a catalogue keyed by that text.
 * A string missing from the catalogue falls back to English, so an
 * untranslated screen is still readable instead of showing bare keys.
 */
export type Locale = "en" | "pl";

export const LOCALES: { code: Locale; label: string }[] = [
  { code: "en", label: "English" },
  { code: "pl", label: "Polski" },
];

const STORAGE_KEY = "flotestro.locale";

const catalogues: Record<Locale, Record<string, string>> = { en: {}, pl };

type Params = Record<string, string | number>;

// The current locale is also kept outside React, so that helpers used
// outside components (formatting, notifications) translate the same way as
// the screens. The provider keeps both in step.
let currentLocale: Locale = initialLocale();

function initialLocale(): Locale {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "en" || stored === "pl") return stored;
  } catch {
    // Storage may be unavailable (private mode, blocked site data); the
    // browser language decides then.
  }
  const language = typeof navigator !== "undefined" ? navigator.language : "en";
  return language.toLowerCase().startsWith("pl") ? "pl" : "en";
}

function interpolate(text: string, params?: Params): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match);
}

/** Translates a source string into the current locale. */
export function t(text: string, params?: Params): string {
  const translated = catalogues[currentLocale][text] ?? text;
  return interpolate(translated, params);
}

export function currentLanguage(): Locale {
  return currentLocale;
}

type Context = { locale: Locale; setLocale: (locale: Locale) => void };

const LocaleContext = createContext<Context>({ locale: currentLocale, setLocale: () => {} });

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(currentLocale);
  const setLocale = useCallback((next: Locale) => {
    currentLocale = next;
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // A locale that cannot be remembered still applies to this session.
    }
    setLocaleState(next);
  }, []);
  const value = useMemo(() => ({ locale, setLocale }), [locale, setLocale]);
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

/**
 * The translation function bound to the locale of the provider, so that a
 * language switch re-renders every screen that uses it.
 */
export function useT(): (text: string, params?: Params) => string {
  const { locale } = useContext(LocaleContext);
  return useCallback((text: string, params?: Params) => {
    const translated = catalogues[locale][text] ?? text;
    return interpolate(translated, params);
  }, [locale]);
}

export function useLocale(): Context {
  return useContext(LocaleContext);
}
