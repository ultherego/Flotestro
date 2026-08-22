import type { ReactNode } from "react";
import { ApiError } from "../lib/api";
import { optional, relativeTime, absoluteTime } from "../lib/format";

/** Znacznik stanu polaczenia. Stan nieznany ma wlasny wyglad. */
export function StanPolaczenia({ stan }: { stan: string }) {
  const klasa =
    stan === "online" ? "ok" : stan === "offline" ? "blad" : stan === "stale" ? "uwaga" : "unknown";
  return <span className={`znacznik ${klasa}`}>{stan}</span>;
}

/** Wynik operacji albo stan zadania. */
export function StanZadania({ stan }: { stan: string }) {
  const udane = ["succeeded", "completed", "active"].includes(stan);
  const nieudane = ["failed", "timed_out", "expired", "partially_applied"].includes(stan);
  const czeka = ["awaiting_approval", "queued", "planned", "paused"].includes(stan);
  const klasa = udane ? "ok" : nieudane ? "blad" : czeka ? "uwaga" : "";
  return <span className={`znacznik ${klasa}`}>{stan}</span>;
}

/**
 * Liczba, ktora moze byc nieustalona. Zero i brak wiedzy to rozne rzeczy,
 * wiec maja rozny wyglad.
 */
export function LiczbaOpcjonalna({
  wartosc,
  ostrzegajOd = 1,
}: {
  wartosc: number | null | undefined;
  ostrzegajOd?: number;
}) {
  if (wartosc === null || wartosc === undefined) {
    return <span className="znacznik nieznany">unknown</span>;
  }
  if (wartosc >= ostrzegajOd) {
    return <span className="znacznik uwaga">{wartosc}</span>;
  }
  return <span>{wartosc}</span>;
}

export function FlagaOpcjonalna({ wartosc }: { wartosc: boolean | null | undefined }) {
  if (wartosc === null || wartosc === undefined) {
    return <span className="znacznik nieznany">unknown</span>;
  }
  return wartosc ? <span className="znacznik uwaga">tak</span> : <span>nie</span>;
}

/** Czas z zrodlem obserwacji: kazda wartosc ma czas, kiedy byla prawdziwa. */
export function Czas({ wartosc }: { wartosc?: string | null }) {
  if (!wartosc) return <span className="znacznik nieznany">never</span>;
  return <span title={absoluteTime(wartosc)}>{relativeTime(wartosc)}</span>;
}

export function Pusto({ children }: { children: ReactNode }) {
  return <div className="pusto">{children}</div>;
}

/**
 * Odmowa nie jest awaria panelu, tylko odpowiedzia serwera na uprawnienia
 * uzytkownika. Czerwony komunikat o bledzie sugerowalby usterke tam, gdzie
 * system dziala poprawnie.
 */
export function Blad({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.forbidden) {
    return <Pusto>You do not have permission to view this.</Pusto>;
  }
  const message = error instanceof Error ? error.message : String(error);
  return <div className="blad-strony">Blad: {message}</div>;
}

export function Pary({ children }: { children: ReactNode }) {
  return <dl className="pary">{children}</dl>;
}

export function Para({ etykieta, children }: { etykieta: string; children: ReactNode }) {
  return (
    <>
      <dt>{etykieta}</dt>
      <dd>{children}</dd>
    </>
  );
}

export { optional };
