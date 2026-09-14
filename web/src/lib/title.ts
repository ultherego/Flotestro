import { useEffect } from "react";

/** The name every tab ends with, so a row of Flotestro tabs reads as one. */
export const APP_NAME = "Flotestro";

/**
 * The tab title of a fleet page: "Hosts — Flotestro". The page name comes
 * first, because a browser shows the first characters of a title and the
 * operator is looking for the page, not for the product.
 */
export function pageTitle(title: string): string {
  return `${title.trim()} — ${APP_NAME}`;
}

/**
 * The tab title of a host page: "web01 · 10.0.0.5 · Packages — Flotestro".
 * An operator with a dozen tabs open recognises the machine by the name
 * and the address before looking at the page; an address the panel does
 * not know is left out rather than shown as anything else.
 */
export function hostTitle(host: { hostname: string; management_address?: string }, module: string): string {
  const parts = [host.hostname, host.management_address, module.trim()].filter((part): part is string => Boolean(part));
  return `${parts.join(" · ")} — ${APP_NAME}`;
}

/**
 * Sets the document title while the component is mounted and hands the
 * bare product name back when it leaves, so a page that sets no title of
 * its own does not inherit the previous one. An empty title changes
 * nothing: a page still loading keeps whatever stands there.
 */
export function useDocumentTitle(title: string | undefined): void {
  useEffect(() => {
    if (!title) return;
    document.title = title;
    return () => {
      document.title = APP_NAME;
    };
  }, [title]);
}
