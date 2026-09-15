import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { TOAST_LIFETIME, ToastProvider, useToast, type ToastOptions } from "./Toast";

/* A screen with one button per kind of notification, the way a page
   announces a mutation's outcome. */
function Announcer({ options }: { options?: ToastOptions }) {
  const toast = useToast();
  return (
    <>
      <button onClick={() => toast.success("Rule cpu-high is deleted.", options)}>success</button>
      <button onClick={() => toast.error("E_CONFLICT: the rule changed under you.")}>error</button>
      <button onClick={() => toast.info("The repository is being read.")}>info</button>
    </>
  );
}

function draw(options?: ToastOptions) {
  render(
    <MemoryRouter>
      <ToastProvider>
        <Announcer options={options} />
      </ToastProvider>
    </MemoryRouter>,
  );
  return {
    fire: (kind: "success" | "error" | "info") => act(() => { fireEvent.click(screen.getByText(kind)); }),
    toasts: () => screen.queryAllByTestId("toast"),
    region: () => screen.getByRole("region", { name: "Notifications" }),
  };
}

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("ToastProvider", () => {
  it("keeps an empty live region ready, then fills it", () => {
    const { fire, region, toasts } = draw();
    expect(region()).toHaveAttribute("aria-live", "polite");
    expect(toasts()).toHaveLength(0);
    fire("success");
    expect(toasts()).toHaveLength(1);
    expect(toasts()[0]).toHaveClass("toast", "success");
    expect(region()).toHaveTextContent("Rule cpu-high is deleted.");
  });

  it("dismisses a success and a note on its own, but never an error", () => {
    const { fire, toasts } = draw();
    fire("success");
    fire("info");
    fire("error");
    expect(toasts()).toHaveLength(3);
    act(() => { vi.advanceTimersByTime(TOAST_LIFETIME - 1); });
    expect(toasts()).toHaveLength(3);
    act(() => { vi.advanceTimersByTime(1); });
    expect(toasts()).toHaveLength(1);
    expect(toasts()[0]).toHaveClass("error");
    act(() => { vi.advanceTimersByTime(10 * TOAST_LIFETIME); });
    expect(toasts()).toHaveLength(1);
  });

  it("stacks in order of arrival", () => {
    const { fire, toasts } = draw();
    fire("info");
    fire("success");
    const texts = toasts().map((toast) => toast.textContent);
    expect(texts[0]).toContain("The repository is being read.");
    expect(texts[1]).toContain("Rule cpu-high is deleted.");
  });

  it("is dismissed by its button and by Escape", () => {
    const { fire, toasts } = draw();
    fire("error");
    fire("error");
    expect(toasts()).toHaveLength(2);
    act(() => { fireEvent.click(screen.getAllByRole("button", { name: "Dismiss" })[0]); });
    expect(toasts()).toHaveLength(1);
    act(() => { fireEvent.keyDown(toasts()[0], { key: "Escape" }); });
    expect(toasts()).toHaveLength(0);
  });

  it("waits while the pointer rests on it", () => {
    const { fire, toasts } = draw();
    fire("success");
    act(() => { fireEvent.mouseEnter(toasts()[0]); });
    act(() => { vi.advanceTimersByTime(2 * TOAST_LIFETIME); });
    expect(toasts()).toHaveLength(1);
    act(() => { fireEvent.mouseLeave(toasts()[0]); });
    act(() => { vi.advanceTimersByTime(TOAST_LIFETIME); });
    expect(toasts()).toHaveLength(0);
  });

  it("carries a link to the record it names", () => {
    const { fire, toasts } = draw({ link: { to: "/hosts/h1/jobs", label: "Jobs" } });
    fire("success");
    const link = screen.getByRole("link", { name: "Jobs" });
    expect(link).toHaveAttribute("href", "/hosts/h1/jobs");
    act(() => { fireEvent.click(link); });
    expect(toasts()).toHaveLength(0);
  });
});
