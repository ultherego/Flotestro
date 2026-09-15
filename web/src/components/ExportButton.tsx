import { useState } from "react";
import { useToast } from "./Toast";
import { useT } from "../i18n";

/**
 * The export of a list screen as a CSV file.
 *
 * The button asks the list's own address with format=csv and the filter
 * the screen is showing, so the file holds what the operator is looking
 * at - every page of it, because the server ignores the page for a file.
 * The browser carries the session; the file is saved through a link the
 * page makes for it and removes again, and a refusal is announced rather
 * than written into the screen: the list itself is untouched by a failed
 * export.
 */
export function ExportButton({ path, params, disabled = false, label }: {
  /** The address of the list, without a query: /api/v1/hosts. */
  path: string;
  /** The filter of the screen as the server reads it; the page keys are dropped. */
  params?: URLSearchParams;
  disabled?: boolean;
  /** The text of the button; "Export CSV" by default. */
  label?: string;
}) {
  const t = useT();
  const toast = useToast();
  const [exporting, setExporting] = useState(false);

  const download = async () => {
    setExporting(true);
    try {
      const response = await fetch(exportAddress(path, params), { credentials: "same-origin" });
      if (!response.ok) {
        let detail = response.statusText;
        try { detail = ((await response.json()) as { detail?: string }).detail ?? detail; } catch { /* a proxy's page, not the API's answer */ }
        throw new Error(detail);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = exportFileName(response.headers.get("Content-Disposition"));
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      toast.error(t("The export failed: {message}", { message: error instanceof Error ? error.message : String(error) }));
    } finally {
      setExporting(false);
    }
  };

  return (
    <button type="button" className="secondary" onClick={download} disabled={disabled || exporting} data-testid="export-csv">
      {exporting ? t("Exporting…") : (label ?? t("Export CSV"))}
    </button>
  );
}

/** The keys of a page, which a file has no use for. */
const PAGE_KEYS = ["limit", "cursor", "offset", "format"];

/**
 * The address of the export: the list's path with the screen's filter and
 * format=csv, without the page keys.
 */
export function exportAddress(path: string, params?: URLSearchParams): string {
  const query = new URLSearchParams(params);
  for (const key of PAGE_KEYS) query.delete(key);
  query.set("format", "csv");
  return `${path}?${query}`;
}

/**
 * The file name the server gave the export, read off the disposition
 * header; the server names the file after the list and the day, and the
 * saved file is to carry that name. Without a header the file is a plain
 * export.
 */
export function exportFileName(disposition?: string | null): string {
  const match = /filename="([^"]+)"/.exec(disposition ?? "");
  return match?.[1] ?? "flotestro-export.csv";
}
