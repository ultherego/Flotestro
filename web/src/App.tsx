import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import { Door } from "./next/Door";
import type { Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { useTheme } from "./lib/theme";
import { useScale } from "./lib/scale";
import { useT } from "./i18n";
import { NextPanel } from "./next/Panel";
import { ToastProvider } from "./components/Toast";
import { ModalProvider } from "./components/Modal";
import { PreferencesProvider } from "./lib/preferences";

/**
 * Everything before the panel: who is asking, and whether they may ask.
 *
 * The panel itself is one shell under `src/next`. It stood at /next while
 * it was written and took the root on 16.10, when the one it replaces was
 * removed; what is left here is the gate in front of it - the session, the
 * way in, and the one answer a sign-in with no role deserves.
 */
export function App() {
  const t = useT();
  const capabilities = useCapabilities();
  // The theme is owned here so that it applies to every screen, the way in
  // included; the switch in the user menu only changes it.
  const { theme, setTheme } = useTheme();
  const { scale, setScale } = useScale();

  const { data, isLoading, error } = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    retry: false,
    refetchInterval: false,
  });

  if (isLoading) return <div className="fl-app" />;

  // A missing session leads to the way in. The panel collects no passwords
  // of its own where there is an identity provider: those go to it alone.
  if (error instanceof ApiError && error.unauthenticated) {
    return <Door provider={capabilities.identity_provider} />;
  }
  if (error) {
    return (
      <div className="fl-app">
        <p className="fl-problem" role="alert">{t("Error: {message}", { message: String(error) })}</p>
      </div>
    );
  }

  // A sign-in that carries no permission at all. Every section is hidden for
  // want of one, so the panel would draw its shell around nothing and say
  // nothing - which is what somebody met after the first sign-in through an
  // identity provider whose groups nobody had mapped yet. The checklist
  // knew; the person who had just signed in was not told.
  const permissions = new Set(data?.permissions ?? []);
  if (permissions.size === 0) {
    return (
      <div className="fl-app">
        <section className="fl-card">
          <h1>{t("Signed in, with nothing granted")}</h1>
          <p>
            {t("You are signed in as {name}, and this sign-in carries no role. The panel shows only what a role allows, so there is nothing here to show - this is not an error and nothing is broken.", {
              name: data?.display_name || data?.subject || t("an unnamed principal"),
            })}
          </p>
          <p>
            {t("Whoever administers this installation grants it: under Settings, a group of the identity provider is mapped to a role, or a role is bound to this principal directly. Until then every page refuses, which is the panel working as intended.")}
          </p>
        </section>
      </div>
    );
  }

  return (
    <ToastProvider>
      <ModalProvider>
        <PreferencesProvider applyTheme={setTheme}>
          <NextPanel look={{ theme, setTheme, scale, setScale }} />
        </PreferencesProvider>
      </ModalProvider>
    </ToastProvider>
  );
}
