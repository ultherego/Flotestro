import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

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
