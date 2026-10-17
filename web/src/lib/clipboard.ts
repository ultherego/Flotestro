/**
 * Copying to the clipboard, and saying whether it happened.
 *
 * navigator.clipboard exists only in a secure context, so on a panel reached
 * over plain HTTP - which a laboratory and a first installation both are - it
 * is undefined. Four places wrote `navigator.clipboard?.writeText(text)` and
 * then set "copied" unconditionally: the optional call evaluated to undefined,
 * the promise was dropped where it existed, and the operator was told the
 * identifier was on their clipboard when nothing was. A diagnostic bundle or a
 * token "copied" that way is pasted as whatever was there before.
 *
 * So the answer is awaited, and a refusal is an answer: the caller shows what
 * actually happened. The text is handed back on failure, so the interface can
 * offer it to be selected by hand instead of claiming success.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  const api = navigator.clipboard;
  if (api && typeof api.writeText === "function") {
    try {
      await api.writeText(text);
      return true;
    } catch {
      // A denied permission, a document without focus: fall through to the
      // older way rather than give up while one is left.
    }
  }
  return copyThroughTheSelection(text);
}

/**
 * The way that works without a secure context.
 *
 * A text is put in a box that is not on the page's flow, selected, and the
 * browser is told to copy the selection. Every browser still has it and it
 * needs no HTTPS, which a laboratory and a first installation do not have -
 * so "copy" did nothing at all on the panel the owner was looking at, and
 * said "copy by hand" while it did. The answer is still the browser's own:
 * `execCommand` returns whether it happened, and that is what is reported.
 */
function copyThroughTheSelection(text: string): boolean {
  if (typeof document === "undefined" || typeof document.execCommand !== "function") return false;
  const box = document.createElement("textarea");
  box.value = text;
  // Read-only so a phone does not raise its keyboard, and off the screen so
  // nothing flashes; not display:none, which cannot be selected.
  box.setAttribute("readonly", "");
  box.style.position = "fixed";
  box.style.top = "0";
  box.style.left = "-9999px";
  box.style.opacity = "0";
  const holder = document.activeElement as HTMLElement | null;
  document.body.appendChild(box);
  try {
    box.select();
    box.setSelectionRange(0, text.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    document.body.removeChild(box);
    // The page keeps the focus it had; a copy is not a navigation.
    holder?.focus?.();
  }
}
