import { afterEach, describe, expect, it } from "vitest";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { I18nProvider, loadCatalogue, useLocale, useT } from "./index";

/**
 * The Polish catalogue is most of a megabyte, so it is fetched when Polish is
 * chosen and not with the panel. What is held here is that choosing it still
 * ends in Polish, and that nothing is switched until the catalogue is there -
 * a switch that applied first drew the English sentence for a moment.
 */

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

const wrapper = ({ children }: { children: ReactNode }) => <I18nProvider>{children}</I18nProvider>;

describe("the Polish catalogue", () => {
  it("is not needed to read English", () => {
    const { result } = renderHook(() => useT(), { wrapper });
    expect(result.current("Hosts")).toBe("Hosts");
  });

  it("is fetched when Polish is chosen, and the language switches only then", async () => {
    const { result } = renderHook(() => ({ t: useT(), locale: useLocale() }), { wrapper });
    expect(result.current.locale.locale).toBe("en");

    act(() => result.current.locale.setLocale("pl"));
    await waitFor(() => expect(result.current.locale.locale).toBe("pl"));
    expect(result.current.t("Hosts")).toBe("Hosty");

    // Back to English: no catalogue to fetch, and the sentence is the source.
    await loadCatalogue("en");
    act(() => result.current.locale.setLocale("en"));
    await waitFor(() => expect(result.current.locale.locale).toBe("en"));
    expect(result.current.t("Hosts")).toBe("Hosts");
  });
});
