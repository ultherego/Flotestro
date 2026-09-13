import { useEffect, useState } from "react";

/**
 * A value that follows its source after a pause in typing.
 *
 * A search box asks the server, and the server must not get a request per
 * keystroke: the operator typing "web-0" would fire five queries to learn
 * the answer to the last one. The screen keeps the typed text for the
 * input and hands the settled text to the query.
 */
export function useDebounced<T>(value: T, delay = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return settled;
}
