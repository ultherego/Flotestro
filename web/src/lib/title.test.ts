import { afterEach, describe, expect, it } from "vitest";
import { cleanup, renderHook } from "@testing-library/react";
import { APP_NAME, hostTitle, pageTitle, useDocumentTitle } from "./title";

afterEach(() => {
  cleanup();
  document.title = "";
});

describe("the title formats", () => {
  it("names a fleet page before the product", () => {
    expect(pageTitle("Hosts")).toBe("Hosts — Flotestro");
    expect(pageTitle("  Campaigns ")).toBe("Campaigns — Flotestro");
  });

  it("names the host, its address and the module", () => {
    expect(hostTitle({ hostname: "web01", management_address: "10.0.0.5" }, "Packages"))
      .toBe("web01 · 10.0.0.5 · Packages — Flotestro");
  });

  it("leaves an unknown address out rather than inventing one", () => {
    expect(hostTitle({ hostname: "web01" }, "Overview")).toBe("web01 · Overview — Flotestro");
    expect(hostTitle({ hostname: "web01", management_address: "" }, "Overview")).toBe("web01 · Overview — Flotestro");
  });
});

describe("useDocumentTitle", () => {
  it("sets the title while mounted and hands the product name back on unmount", () => {
    const { unmount } = renderHook(() => useDocumentTitle("Hosts — Flotestro"));
    expect(document.title).toBe("Hosts — Flotestro");
    unmount();
    expect(document.title).toBe(APP_NAME);
  });

  it("follows the title as it changes", () => {
    const { rerender } = renderHook(({ title }) => useDocumentTitle(title), {
      initialProps: { title: "web01 · Overview — Flotestro" as string | undefined },
    });
    expect(document.title).toBe("web01 · Overview — Flotestro");
    rerender({ title: "web01 · Packages — Flotestro" });
    expect(document.title).toBe("web01 · Packages — Flotestro");
  });

  it("changes nothing for an empty title", () => {
    document.title = "kept";
    renderHook(() => useDocumentTitle(undefined));
    expect(document.title).toBe("kept");
  });
});
