import { createContext, useCallback, useContext, useEffect, useMemo, useRef, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import { LOCALES, useLocale, type Locale } from "../i18n";
import { setPreferredTimeZone } from "./format";
import { THEMES, type Theme } from "./theme";

/**
 * The preferences of the person at the screen, kept on the server under
 * their identity.
 *
 * The theme and the language have lived in the browser's storage since
 * the first screens, and still do: the inline script reads them before
 * React mounts so the page does not flash. The server copy is what makes
 * them follow the person to the next browser - and it carries what the
 * browser never held: the zone the times are read in, the size of a
 * page, the page the panel opens on. The browser copy is a cache of the
 * server's; a switch in the top bar writes both.
 */
export type Preferences = {
  /** An IANA zone name the times are read in; empty for the browser's own zone. */
  time_zone: string;
  /** Rows per page of the lists; zero for the panel's default. */
  page_size: number;
  /** The path the panel opens on after signing in; empty for the dashboard. */
  landing_page: string;
  /** The interface language by its code; empty leaves the choice to the browser. */
  language: string;
  /** The colour theme by its code; empty leaves the choice to the browser. */
  theme: string;
  updated_at?: string;
};

export const DEFAULT_PREFERENCES: Preferences = {
  time_zone: "", page_size: 0, landing_page: "", language: "", theme: "",
};

export const PREFERENCES_PATH = "/api/v1/me/preferences";

/**
 * The zones offered by the profile screen. Any IANA name is accepted by
 * the API; the list only saves the typing for the zones a fleet is
 * likely to stand in, and the browser's own zone always heads it.
 */
export const COMMON_TIME_ZONES = [
  "UTC", "Europe/Warsaw", "Europe/Berlin", "Europe/London", "Europe/Paris", "Europe/Madrid", "Europe/Kyiv",
  "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "America/Sao_Paulo",
  "Asia/Tokyo", "Asia/Singapore", "Asia/Kolkata", "Asia/Dubai", "Australia/Sydney",
];

/** Says whether the browser can format times in the named zone. */
export function validTimeZone(zone: string): boolean {
  if (!zone) return true;
  try {
    new Intl.DateTimeFormat("en-GB", { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

type Context = {
  preferences: Preferences;
  /** True once the server has answered; until then the defaults stand in. */
  loaded: boolean;
  /** True once the read has ended, with an answer or with an error: what the landing page waits for. */
  settled: boolean;
  /** Writes the preferences whole; a field left out keeps its current value. */
  save: (patch: Partial<Preferences>) => Promise<Preferences>;
  saving: boolean;
};

const PreferencesContext = createContext<Context>({
  preferences: DEFAULT_PREFERENCES,
  loaded: false,
  settled: true,
  save: async () => DEFAULT_PREFERENCES,
  saving: false,
});

function isLocale(value: string): value is Locale {
  return LOCALES.some((entry) => entry.code === value);
}

function isTheme(value: string): value is Theme {
  return THEMES.some((entry) => entry.code === value);
}

/**
 * Mounts once around the signed-in application. It reads the server's
 * copy and, on the first answer, applies the language and the theme it
 * names over the browser's: the person who chose them on another
 * workstation chose them here too. A later change made at this screen
 * goes to the server through save() and never fights the answer.
 */
export function PreferencesProvider({ children, applyTheme }: {
  children: ReactNode;
  /** Puts a theme the server names on the root element; the App owns the theme hook. */
  applyTheme?: (theme: Theme) => void;
}) {
  const queryClient = useQueryClient();
  const { locale, setLocale } = useLocale();
  const query = useQuery({
    queryKey: ["preferences"],
    queryFn: () => api.get<Preferences>(PREFERENCES_PATH),
    staleTime: Infinity,
    refetchInterval: false,
    retry: false,
  });
  const preferences = useMemo(
    () => ({ ...DEFAULT_PREFERENCES, ...(query.data ?? {}) }),
    [query.data],
  );

  // The formatting helpers outside React are told the zone as soon as the
  // answer is in, before the screens re-render with it; a zone this
  // browser cannot format in leaves them on the browser's own.
  setPreferredTimeZone(validTimeZone(preferences.time_zone) ? preferences.time_zone : "");

  const applied = useRef(false);
  useEffect(() => {
    if (!query.data || applied.current) return;
    applied.current = true;
    if (isLocale(query.data.language) && query.data.language !== locale) setLocale(query.data.language);
    if (isTheme(query.data.theme) && applyTheme) applyTheme(query.data.theme);
  }, [query.data, locale, setLocale, applyTheme]);

  const mutation = useMutation({
    mutationFn: (next: Preferences) => api.put<Preferences>(PREFERENCES_PATH, next),
    onSuccess: (saved) => {
      queryClient.setQueryData(["preferences"], saved);
    },
  });

  const { mutateAsync } = mutation;
  const save = useCallback(
    (patch: Partial<Preferences>) => mutateAsync({ ...preferences, ...patch }),
    [mutateAsync, preferences],
  );

  const value = useMemo<Context>(
    () => ({
      preferences, loaded: query.data !== undefined, settled: query.isFetched, save, saving: mutation.isPending,
    }),
    [preferences, query.data, query.isFetched, save, mutation.isPending],
  );
  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

export function usePreferences(): Context {
  return useContext(PreferencesContext);
}
