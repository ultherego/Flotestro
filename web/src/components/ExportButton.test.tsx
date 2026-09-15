import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { ExportButton, exportAddress, exportFileName } from "./ExportButton";

/* The browser's download machinery, replaced: the object URL is a fixed
   token, and the link the button clicks is watched rather than followed. */
const fetchMock = vi.fn();
const clicks: string[] = [];

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  URL.createObjectURL = vi.fn(() => "blob:export");
  URL.revokeObjectURL = vi.fn();
  clicks.length = 0;
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    clicks.push(`${this.download}<-${this.href}`);
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("exportAddress", () => {
  it("keeps the filter and drops the page", () => {
    const params = new URLSearchParams({ site: "krk", limit: "100", cursor: "abc", offset: "50" });
    params.append("tag", "role=db");
    expect(exportAddress("/api/v1/hosts", params)).toBe("/api/v1/hosts?site=krk&tag=role%3Ddb&format=csv");
  });

  it("asks for a file without a filter too", () => {
    expect(exportAddress("/api/v1/backups")).toBe("/api/v1/backups?format=csv");
  });
});

describe("exportFileName", () => {
  it("takes the name the server gave", () => {
    expect(exportFileName('attachment; filename="flotestro-hosts-2026-09-15.csv"')).toBe("flotestro-hosts-2026-09-15.csv");
  });

  it("names a file the server did not", () => {
    expect(exportFileName(null)).toBe("flotestro-export.csv");
  });
});

describe("ExportButton", () => {
  it("fetches the list as CSV with the session and saves it under the server's name", async () => {
    fetchMock.mockResolvedValue(new Response("hostname,id\r\n", {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="flotestro-jobs-2026-09-15.csv"',
      },
    }));
    render(<ExportButton path="/api/v1/jobs" params={new URLSearchParams({ state: "failed", limit: "100" })} />);
    await act(async () => { fireEvent.click(screen.getByTestId("export-csv")); });

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/jobs?state=failed&format=csv", { credentials: "same-origin" });
    await waitFor(() => expect(clicks).toEqual(["flotestro-jobs-2026-09-15.csv<-blob:export"]));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:export");
    expect(screen.getByTestId("export-csv")).toBeEnabled();
  });

  it("saves nothing when the server refuses", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ code: "forbidden", detail: "no right to read the fleet" }), {
      status: 403, headers: { "Content-Type": "application/problem+json" },
    }));
    render(<ExportButton path="/api/v1/hosts" />);
    await act(async () => { fireEvent.click(screen.getByTestId("export-csv")); });

    await waitFor(() => expect(screen.getByTestId("export-csv")).toBeEnabled());
    expect(clicks).toEqual([]);
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
