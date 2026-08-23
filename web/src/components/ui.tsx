import type { ReactNode } from "react";
import { ApiError } from "../lib/api";
import { optional, relativeTime, absoluteTime } from "../lib/format";

/** Znacznik stanu polaczenia. Stan nieznany ma wlasny wyglad. */
export function StanPolaczenia({ stan }: { stan: string }) {
  const klasa =
    stan === "online" ? "ok" : stan === "offline" ? "blad" : stan === "stale" ? "uwaga" : "unknown";
  return <span className={`znacznik ${klasa}`}>{nazwaStanu(stan)}</span>;
}

/** Wynik operacji albo stan zadania. */
export function StanZadania({ stan }: { stan: string }) {
  const udane = ["succeeded", "completed", "active"].includes(stan);
  const nieudane = ["failed", "timed_out", "expired", "partially_applied"].includes(stan);
  const czeka = ["awaiting_approval", "queued", "planned", "paused"].includes(stan);
  const klasa = udane ? "ok" : nieudane ? "blad" : czeka ? "uwaga" : "";
  return <span className={`znacznik ${klasa}`}>{nazwaStanu(stan)}</span>;
}

/**
 * Stany przychodza z bazy jako identyfikatory kontraktu i tak wygladaly
 * w interfejsie: "awaiting_approval" albo "partially_applied". Nazwa czytelna
 * dla operatora nie moze byc jedynym zapisem stanu - identyfikator zostaje
 * w API i w audycie - ale to operator patrzy na ekran.
 *
 * Stan spoza listy pokazujemy tak, jak przyszedl. Zgadywanie tlumaczenia
 * ukryloby fakt, ze panel zobaczyl cos, czego nie zna.
 */
function nazwaStanu(stan: string): string {
  const nazwy: Record<string, string> = {
    online: "online", offline: "offline", stale: "stale", unknown: "unknown",
    queued: "queued", planned: "planned", leased: "assigned",
    dispatched: "dispatched", running: "running",
    awaiting_approval: "awaiting approval",
    succeeded: "succeeded", failed: "failed", timed_out: "timed out",
    canceled: "canceled", cancelled: "canceled", expired: "expired",
    rejected: "rejected", replayed: "replayed",
    active: "active", paused: "paused", completed: "completed",
    partially_applied: "partially applied",
    denied: "denied", success: "success", failure: "failure",
  };
  return nazwy[stan] ?? stan;
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

/**
 * Pasek postepu operacji w toku.
 *
 * Postep nieustalony nie jest rysowany jako zero - pasek przy zerze wyglada
 * jak praca, ktora stoi. Bez procentu i bez krokow zostaje sam opis tego,
 * co sie akurat dzieje.
 */
export function PasekPostepu({
  procent, krok, krokow, opis,
}: { procent?: number; krok?: number; krokow?: number; opis?: string }) {
  const zProcentu = typeof procent === "number" ? procent : undefined;
  const zKrokow = krok && krokow ? Math.round((krok / krokow) * 100) : undefined;
  const wypelnienie = zProcentu ?? zKrokow;

  return (
    <div className="postep">
      <div className="postep-tor">
        {wypelnienie === undefined ? (
          <span className="postep-nieznany" />
        ) : (
          <span className="postep-wypelnienie" style={{ width: `${Math.min(100, wypelnienie)}%` }} />
        )}
      </div>
      <span className="postep-opis">
        {krok && krokow ? `${krok}/${krokow}` : wypelnienie !== undefined ? `${wypelnienie}%` : "in progress"}
        {opis ? ` · ${opis}` : ""}
      </span>
    </div>
  );
}
