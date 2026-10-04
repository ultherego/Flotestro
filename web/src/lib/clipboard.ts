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
  if (!api || typeof api.writeText !== "function") {
    return false;
  }
  try {
    await api.writeText(text);
    return true;
  } catch {
    // A denied permission, a document without focus, a browser that refuses
    // the write: all of them mean the text is not on the clipboard.
    return false;
  }
}
