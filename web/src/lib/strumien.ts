import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

/** Postep operacji w toku. Wartosci nieustalone sa pominiete, nie wyzerowane. */
export type Postep = {
  job_id: string;
  step?: number;
  total?: number;
  percent?: number;
  message?: string;
};

/**
 * Strumien postepu operacji.
 *
 * Strumien niesie wylacznie sygnal "cos sie zmienilo"; trescia jest zawsze
 * odpowiedz API. Gdyby stan jechal strumieniem, ekran po zerwaniu polaczenia
 * pokazywalby cos innego niz zapisano - a operator nie mialby jak tego
 * zauwazyc.
 *
 * Przegladarka sama wznawia zerwany EventSource, wiec chwilowa utrata
 * polaczenia nie zatrzymuje podgladu na stale.
 */
export function useStrumienPostepu(sciezka: string | null, klucze: unknown[][]) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!sciezka) return;
    const zrodlo = new EventSource(sciezka, { withCredentials: true });

    const odswiez = () => {
      for (const klucz of klucze) {
        queryClient.invalidateQueries({ queryKey: klucz });
      }
    };
    zrodlo.addEventListener("job", odswiez);
    // Podlaczenie tez odswieza: ekran mogl przegapic zmiany, zanim strumien
    // sie otworzyl.
    zrodlo.addEventListener("ready", odswiez);

    return () => zrodlo.close();
    // Klucze zapytan sa stale w obrebie ekranu; zaleznoscia jest sciezka.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sciezka, queryClient]);
}

/**
 * Odstep odpytywania dla widokow zbiorczych, ktore nie maja wlasnego
 * strumienia. Lista floty i pulpit zmieniaja sie same z siebie - przez
 * heartbeaty hostow - a nie tylko przez operacje operatora.
 */
export const ODSTEP_ODSWIEZANIA = 5000;

/** Krotszy odstep dla list operacji, gdzie liczy sie postep na oczach. */
export const ODSTEP_OPERACJI = 2000;

/**
 * Postep operacji w toku, prosto ze strumienia.
 *
 * Postep jest ulotny: nie ma go w API i nie da sie go odczytac po fakcie.
 * Ekran podlaczony w polowie transakcji zobaczy dopiero nastepny meldunek -
 * i to wystarczy, bo wynik i tak jest trwaly w bazie.
 */
export function usePostep(sciezka: string | null): Map<string, Postep> {
  const [postepy, setPostepy] = useState<Map<string, Postep>>(new Map());
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!sciezka) {
      setPostepy(new Map());
      return;
    }
    const zrodlo = new EventSource(sciezka, { withCredentials: true });

    zrodlo.addEventListener("progress", (zdarzenie) => {
      try {
        const dane = JSON.parse((zdarzenie as MessageEvent).data);
        const postep: Postep = { job_id: dane.job_id, ...(dane.progress ?? {}) };
        setPostepy((poprzednie) => new Map(poprzednie).set(postep.job_id, postep));
      } catch {
        // Nieczytelny meldunek pomijamy: podglad nie moze wywrocic ekranu.
      }
    });
    // Koniec operacji konczy jej pasek - inaczej zostalby na ekranie
    // i sugerowal, ze cos jeszcze trwa.
    zrodlo.addEventListener("job", (zdarzenie) => {
      try {
        const dane = JSON.parse((zdarzenie as MessageEvent).data);
        if (["succeeded", "failed", "canceled", "expired", "rejected"].includes(dane.state)) {
          setPostepy((poprzednie) => {
            const kopia = new Map(poprzednie);
            kopia.delete(dane.job_id);
            return kopia;
          });
        }
      } catch {
        // jak wyzej
      }
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    });

    return () => zrodlo.close();
  }, [sciezka, queryClient]);

  return postepy;
}
