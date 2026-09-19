import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
  type KeyboardEvent, type ReactNode,
} from "react";
import { Link } from "react-router-dom";
import { useT } from "../i18n";

/**
 * The notifications of the panel.
 */

export type ToastKind = "success" | "error" | "info";

export type ToastLink = { to: string; label: string };

export type ToastOptions = {
  /** A place to go next: the job that was queued, the record that was made. */
  link?: ToastLink;
};

export type Toast = {
  success: (text: string, options?: ToastOptions) => number;
  error: (text: string, options?: ToastOptions) => number;
  info: (text: string, options?: ToastOptions) => number;
  dismiss: (id: number) => void;
};

type Item = { id: number; kind: ToastKind; text: string; link?: ToastLink };

/** How long a self-dismissing toast stays, in milliseconds. */
export const TOAST_LIFETIME = 6000;

/** More than this and the stack hides the page; the oldest goes first. */
const STACK_LIMIT = 6;

/* Without a provider the calls do nothing: the inline text the screens
   keep is the record, and a missing announcement loses nothing that the
   record does not say. A screen under test is not asked to mount one. */
const silent: Toast = { success: () => 0, error: () => 0, info: () => 0, dismiss: () => {} };

const ToastContext = createContext<Toast>(silent);

export function useToast(): Toast {
  return useContext(ToastContext);
}

/**
 * Mounts once around the application. It owns the stack and the region
 * that announces it; the screens only add to it.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const t = useT();
  const [items, setItems] = useState<Item[]>([]);
  const sequence = useRef(0);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer !== undefined) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const schedule = useCallback((id: number) => {
    timers.current.set(id, setTimeout(() => dismiss(id), TOAST_LIFETIME));
  }, [dismiss]);

  const pause = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer === undefined) return;
    clearTimeout(timer);
    timers.current.delete(id);
  }, []);

  const push = useCallback((kind: ToastKind, text: string, options?: ToastOptions): number => {
    sequence.current += 1;
    const id = sequence.current;
    setItems((current) => {
      const next = [...current, { id, kind, text, link: options?.link }];
      // The stack is trimmed from the top, but an error is never trimmed
      // for a note: it stays until it is read.
      while (next.length > STACK_LIMIT) {
        const index = next.findIndex((item) => item.kind !== "error");
        if (index === -1) break;
        next.splice(index, 1);
      }
      return next;
    });
    if (kind !== "error") schedule(id);
    return id;
  }, [schedule]);

  const toast = useMemo<Toast>(() => ({
    success: (text, options) => push("success", text, options),
    error: (text, options) => push("error", text, options),
    info: (text, options) => push("info", text, options),
    dismiss,
  }), [push, dismiss]);

  // Timers do not outlive the provider.
  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const timer of pending.values()) clearTimeout(timer);
      pending.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {/* The region exists even while empty, so a screen reader has it in
          hand when the first toast lands: a live region that appears with
          its first content is often not announced. The cards carry no
          live role of their own: a region inside a region is read twice. */}
      <div className="toasts" role="region" aria-live="polite" aria-label={t("Notifications")}>
        {items.map((item) => (
          <ToastCard
            key={item.id}
            item={item}
            onDismiss={() => dismiss(item.id)}
            onHold={() => pause(item.id)}
            onRelease={() => { if (item.kind !== "error") schedule(item.id); }}
          />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function ToastCard({ item, onDismiss, onHold, onRelease }: {
  item: Item;
  onDismiss: () => void;
  onHold: () => void;
  onRelease: () => void;
}) {
  const t = useT();
  // Escape on the toast dismisses it, wherever inside the focus is. The
  // dismiss button is a real button, so Tab reaches it and Enter works.
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onDismiss();
    }
  };
  // A toast the pointer or the focus rests on does not go away under the
  // operator's hand; it resumes when they leave.
  return (
    <div
      className={`toast ${item.kind}`}
      data-testid="toast"
      onKeyDown={onKeyDown}
      onMouseEnter={onHold}
      onMouseLeave={onRelease}
      onFocus={onHold}
      onBlur={onRelease}
    >
      <div className="toast-text">
        {item.text}
        {item.link && (
          <>
            {" "}
            <Link className="toast-link" to={item.link.to} onClick={onDismiss}>{item.link.label}</Link>
          </>
        )}
      </div>
      <button type="button" className="toast-dismiss" onClick={onDismiss} aria-label={t("Dismiss")} title={t("Dismiss")}>
        ×
      </button>
    </div>
  );
}
