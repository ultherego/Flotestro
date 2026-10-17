/**
 * The payload of a read, as the operator types it.
 *
 * A payload is an object grouped by name. Text that parses but is not an
 * object - a list, a number, a string - is not broken JSON, and saying so
 * sends the operator hunting for a missing quote in text that has none.
 */

/** The payload text as an object, or the reason it is not one. */
export function parsePayload(text: string): { value?: Record<string, unknown>; error?: string; shape?: boolean } {
  if (!text.trim()) return { value: {} };
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return { value: parsed as Record<string, unknown> };
    // Valid JSON that is not an object. Calling that "not valid JSON" sends the
    // operator looking for a missing quote in text that has none; the panel
    // answered that way until 08.10, as the API did.
    return { error: "not an object", shape: true };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * What to say about the payload field. A shape that is not an object is not
 * broken JSON, and saying so is the difference between the operator fixing the
 * wrapping and hunting for a typo.
 */
export function payloadHint(t: (text: string) => string, payload: { error?: string; shape?: boolean }): string {
  if (!payload.error) return t("The same payload the host page sends for this read.");
  if (payload.shape) return t("A payload is an object grouped by name, like {\"journal\": {\"lines\": 100}}.");
  return t("The payload is not valid JSON.");
}
