import {
  createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState,
  type KeyboardEvent, type ReactNode,
} from "react";
import { useT } from "../i18n";

/**
 * The confirmation dialog of the panel.
 *
 * The browser's own confirm() and prompt() served the first screens, but
 * they cannot be styled, cannot say which button is the dangerous one,
 * cannot validate a reason before the request leaves, and a prompt shows
 * the rule "at least 8 characters" only as text the operator has to read.
 * This dialog does all of that and is asked the same way: one awaited
 * call that resolves when the operator decides, so a call site reads as a
 * question and its answer rather than as a state machine.
 */

/** A reason the API records: the audit trail wants at least eight characters. */
export type ReasonRule = {
  required: true;
  /** The least number of characters after trimming; the API's rule is 8. */
  min?: number;
  label?: string;
  placeholder?: string;
};

/**
 * A value the operation needs that is not a reason: a target directory of
 * a restore, say. It is validated like a reason, but travels under its own
 * name so a call site does not send a path where a reason is expected.
 */
export type InputRule = {
  label: string;
  initial?: string;
  placeholder?: string;
  hint?: string;
  /** An empty value keeps the confirm button disabled. */
  required?: boolean;
  /** The least number of characters after trimming, when a bare non-empty value is not enough. */
  min?: number;
  /** Paths and identifiers read better in the monospace face. */
  mono?: boolean;
};

export type ConfirmRequest = {
  title: string;
  body?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Marks an operation that destroys or overwrites: the confirm button turns red. */
  danger?: boolean;
  reason?: ReasonRule;
  input?: InputRule;
};

export type ConfirmResult = {
  ok: boolean;
  /** The trimmed reason, present only when one was asked and the operator confirmed. */
  reason?: string;
  /** The trimmed input value, present only when one was asked and the operator confirmed. */
  value?: string;
};

export type Confirm = (request: ConfirmRequest) => Promise<ConfirmResult>;

const REASON_MIN = 8;

const ModalContext = createContext<Confirm | null>(null);

/**
 * The question a screen asks, as a function that resolves with the answer.
 *
 * The function is stable across renders, so it can sit in an effect or a
 * memoised callback without re-running them. Outside a ModalProvider it
 * throws when called: a dialog that cannot open would otherwise look like
 * an operator who never confirms.
 */
export function useConfirm(): Confirm {
  const confirm = useContext(ModalContext);
  return useMemo<Confirm>(() => {
    if (confirm) return confirm;
    return () => {
      throw new Error("useConfirm() needs a ModalProvider above the component that calls it");
    };
  }, [confirm]);
}

type Pending = { id: number; request: ConfirmRequest; resolve: (result: ConfirmResult) => void };

/**
 * Mounts once around the application and draws the dialog when a screen
 * asks. One question at a time: a second call while a dialog is open
 * waits for the first to close, so two dialogs never stack.
 */
export function ModalProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<Pending | null>(null);
  // The open question and the waiting ones live in refs: the promise
  // callbacks read them outside a render, and a state updater must not
  // shift a queue, because React may run it twice.
  const open = useRef<Pending | null>(null);
  const queue = useRef<Pending[]>([]);
  const sequence = useRef(0);

  const show = useCallback((next: Pending | null) => {
    open.current = next;
    setCurrent(next);
  }, []);

  const confirm = useCallback<Confirm>((request) => new Promise<ConfirmResult>((resolve) => {
    sequence.current += 1;
    const pending = { id: sequence.current, request, resolve };
    if (open.current) queue.current.push(pending);
    else show(pending);
  }), [show]);

  const settle = useCallback((result: ConfirmResult) => {
    const answered = open.current;
    show(queue.current.shift() ?? null);
    answered?.resolve(result);
  }, [show]);

  return (
    <ModalContext.Provider value={confirm}>
      {children}
      {/* Each question gets a fresh dialog with empty fields: a reason
          typed for one operation must not linger into the next. */}
      {current && <ConfirmDialog key={current.id} request={current.request} onSettle={settle} />}
    </ModalContext.Provider>
  );
}

const FOCUSABLE = 'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])';

function ConfirmDialog({ request, onSettle }: { request: ConfirmRequest; onSettle: (result: ConfirmResult) => void }) {
  const t = useT();
  const titleId = useId();
  const bodyId = useId();
  const reasonId = useId();
  const inputId = useId();
  const dialog = useRef<HTMLDivElement>(null);
  const [reason, setReason] = useState("");
  const [value, setValue] = useState(request.input?.initial ?? "");

  const reasonMin = request.reason?.min ?? REASON_MIN;
  const reasonReady = !request.reason || reason.trim().length >= reasonMin;
  const inputMin = request.input?.min ?? (request.input?.required ? 1 : 0);
  const inputReady = !request.input || value.trim().length >= inputMin;
  const ready = reasonReady && inputReady;

  const cancel = useCallback(() => onSettle({ ok: false }), [onSettle]);
  const accept = useCallback(() => {
    if (!ready) return;
    const result: ConfirmResult = { ok: true };
    if (request.reason) result.reason = reason.trim();
    if (request.input) result.value = value.trim();
    onSettle(result);
  }, [ready, request.reason, request.input, reason, value, onSettle]);

  // Focus moves into the dialog when it opens and back to the control
  // that opened it when it closes: a keyboard operator must not be left
  // on a page whose dialog just vanished. The page behind does not
  // scroll while the dialog is up.
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const root = dialog.current;
    if (root) {
      const preferred = root.querySelector<HTMLElement>("[data-autofocus]");
      const first = preferred ?? root.querySelector<HTMLElement>(FOCUSABLE);
      (first ?? root).focus();
    }
    return () => {
      document.body.style.overflow = previousOverflow;
      opener?.focus();
    };
  }, []);

  // Escape is the cancel; Tab stays inside the dialog and wraps at the
  // ends, so the page behind cannot be reached until the question is
  // answered. Enter in a field is the confirm, when the fields allow it.
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      cancel();
      return;
    }
    if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      accept();
      return;
    }
    if (event.key !== "Tab" || !dialog.current) return;
    const focusable = Array.from(dialog.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === dialog.current)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  };

  // With a field the field takes the initial focus. Without one the
  // routine confirm does, so a plain question is answered with one key;
  // the dangerous confirm does not, because a stray Enter must not
  // delete anything - the cancel takes it instead.
  const hasField = Boolean(request.reason || request.input);
  const initialFocus = hasField ? "field" : request.danger ? "cancel" : "confirm";
  const describedBy = [request.body ? bodyId : "", request.reason ? `${reasonId}-hint` : ""].filter(Boolean).join(" ") || undefined;

  return (
    <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) cancel(); }}>
      <div
        ref={dialog}
        className={request.danger ? "modal danger" : "modal"}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={describedBy}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <h2 id={titleId} className="modal-title">{request.title}</h2>
        {request.body && (
          typeof request.body === "string"
            ? <p id={bodyId} className="modal-body">{request.body}</p>
            : <div id={bodyId} className="modal-body">{request.body}</div>
        )}
        {request.input && (
          <div className="field modal-field">
            <label htmlFor={inputId} className="field-label">{request.input.label}</label>
            <input
              id={inputId}
              className={request.input.mono ? "mono" : undefined}
              value={value}
              placeholder={request.input.placeholder}
              onChange={(event) => setValue(event.target.value)}
              aria-invalid={!inputReady}
              aria-describedby={request.input.hint ? `${inputId}-hint` : undefined}
              data-autofocus=""
            />
            {request.input.hint && <span id={`${inputId}-hint`} className="field-hint">{request.input.hint}</span>}
          </div>
        )}
        {request.reason && (
          <div className="field modal-field">
            <label htmlFor={reasonId} className="field-label">{request.reason.label ?? t("Reason")}</label>
            <input
              id={reasonId}
              value={reason}
              placeholder={request.reason.placeholder}
              onChange={(event) => setReason(event.target.value)}
              aria-invalid={!reasonReady}
              aria-describedby={`${reasonId}-hint`}
              data-autofocus={request.input ? undefined : ""}
            />
            <span id={`${reasonId}-hint`} className={reasonReady ? "field-hint" : "field-hint modal-rule"}>
              {t("At least {n} characters, kept in the audit trail.", { n: reasonMin })}
              {!reasonReady && reason.trim().length > 0 && ` ${t("{n} more to go.", { n: reasonMin - reason.trim().length })}`}
            </span>
          </div>
        )}
        <div className="actions modal-actions">
          <button
            type="button"
            className={request.danger ? "danger" : undefined}
            disabled={!ready}
            onClick={accept}
            data-autofocus={initialFocus === "confirm" ? "" : undefined}
          >
            {request.confirmLabel ?? t("Confirm")}
          </button>
          <button type="button" className="secondary" onClick={cancel} data-autofocus={initialFocus === "cancel" ? "" : undefined}>
            {request.cancelLabel ?? t("Cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}
