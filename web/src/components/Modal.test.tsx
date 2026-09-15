import { afterEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { ModalProvider, useConfirm, type ConfirmRequest, type ConfirmResult } from "./Modal";

/* A screen that asks one question through the hook and keeps the answer
   where the test can read it, the way a page keeps a mutation's outcome. */
function Asker({ request, onAnswer }: { request: ConfirmRequest; onAnswer: (result: ConfirmResult) => void }) {
  const confirm = useConfirm();
  return <button onClick={() => { void confirm(request).then(onAnswer); }}>ask</button>;
}

function draw(request: ConfirmRequest) {
  const answers: ConfirmResult[] = [];
  render(
    <ModalProvider>
      <Asker request={request} onAnswer={(result) => answers.push(result)} />
    </ModalProvider>,
  );
  return { answers, ask: () => act(() => { fireEvent.click(screen.getByText("ask")); }) };
}

/* The promise settles on a microtask after the click; one turn of the
   event loop under act() lets the answer land. */
const settle = () => act(() => Promise.resolve());

afterEach(cleanup);

describe("ModalProvider", () => {
  it("renders nothing until asked, then a labelled dialog", () => {
    const { ask } = draw({ title: "Delete the policy", body: "Its campaigns stay." });
    expect(screen.queryByRole("dialog")).toBeNull();
    ask();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName("Delete the policy");
    expect(dialog).toHaveAccessibleDescription("Its campaigns stay.");
  });

  it("resolves true on confirm and closes", async () => {
    const { answers, ask } = draw({ title: "Delete the rule", confirmLabel: "Delete" });
    ask();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await settle();
    expect(answers).toEqual([{ ok: true }]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("resolves false on cancel and on Escape", async () => {
    const { answers, ask } = draw({ title: "Delete the rule" });
    ask();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await settle();
    ask();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await settle();
    expect(answers).toEqual([{ ok: false }, { ok: false }]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("holds the confirm back until the reason has eight characters, then returns it trimmed", async () => {
    const { answers, ask } = draw({ title: "Remove from trust set", confirmLabel: "Remove", danger: true, reason: { required: true, min: 8 } });
    ask();
    const confirm = screen.getByRole("button", { name: "Remove" });
    const reason = screen.getByLabelText("Reason");
    expect(confirm).toBeDisabled();
    expect(confirm).toHaveClass("danger");
    expect(screen.getByText(/At least 8 characters/)).toBeInTheDocument();
    fireEvent.change(reason, { target: { value: "short  " } });
    expect(confirm).toBeDisabled();
    expect(reason).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText(/3 more to go/)).toBeInTheDocument();
    // Enter in the field does not get past the rule either.
    fireEvent.keyDown(reason, { key: "Enter" });
    await settle();
    expect(answers).toEqual([]);
    fireEvent.change(reason, { target: { value: "  expired and unused  " } });
    expect(confirm).toBeEnabled();
    expect(reason).toHaveAttribute("aria-invalid", "false");
    fireEvent.click(confirm);
    await settle();
    expect(answers).toEqual([{ ok: true, reason: "expired and unused" }]);
  });

  it("returns a plain input under its own name, prefilled", async () => {
    const { answers, ask } = draw({
      title: "Restore copy",
      input: { label: "Target directory", initial: "/srv/flotestro-restore", required: true },
    });
    ask();
    const field = screen.getByLabelText("Target directory");
    expect(field).toHaveValue("/srv/flotestro-restore");
    expect(field).toHaveFocus();
    fireEvent.change(field, { target: { value: "   " } });
    expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();
    fireEvent.change(field, { target: { value: "/srv/restore-2026" } });
    fireEvent.keyDown(field, { key: "Enter" });
    await settle();
    expect(answers).toEqual([{ ok: true, value: "/srv/restore-2026" }]);
  });

  it("moves the focus into the dialog and back to the opener", async () => {
    const { ask } = draw({ title: "Delete the rule", danger: true });
    const opener = screen.getByText("ask");
    opener.focus();
    ask();
    // A dangerous question starts on the cancel, so a stray Enter deletes nothing.
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await settle();
    expect(opener).toHaveFocus();
  });

  it("keeps Tab inside the dialog", () => {
    const { ask } = draw({ title: "Delete the rule" });
    ask();
    const dialog = screen.getByRole("dialog");
    const confirm = screen.getByRole("button", { name: "Confirm" });
    const cancel = screen.getByRole("button", { name: "Cancel" });
    expect(confirm).toHaveFocus();
    cancel.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(confirm).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(cancel).toHaveFocus();
  });

  it("asks the questions one at a time", async () => {
    const answers: ConfirmResult[] = [];
    function Twice() {
      const confirm = useConfirm();
      return (
        <button onClick={() => {
          void confirm({ title: "First" }).then((result) => answers.push(result));
          void confirm({ title: "Second" }).then((result) => answers.push(result));
        }}>ask</button>
      );
    }
    render(<ModalProvider><Twice /></ModalProvider>);
    act(() => { fireEvent.click(screen.getByText("ask")); });
    expect(screen.getByRole("dialog")).toHaveAccessibleName("First");
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await settle();
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Second");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await settle();
    expect(answers).toEqual([{ ok: true }, { ok: false }]);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
