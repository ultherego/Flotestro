import { useEffect } from "react";
import { NavLink, Outlet, useLocation, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host } from "../../lib/types";
import { Blad, Pusto } from "../../components/ui";
import { useCapabilities } from "../../lib/capabilities";
import { PasekKontekstu } from "./PasekKontekstu";
import { moduly, MODUL_DOMYSLNY } from "./moduly";
import { ODSTEP_ODSWIEZANIA } from "../../lib/strumien";

/**
 * Host workspace. Aktywny modul jest segmentem adresu, a nie stanem
 * komponentu: dzieki temu dzialaja odswiezenie, historia przegladarki,
 * odnosnik bezposredni i otwarcie w nowej karcie.
 */
export function UkladHosta() {
  const { id = "" } = useParams();
  const location = useLocation();
  const instalacja = useCapabilities();

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    // Pasek kontekstu niesie stan polaczenia i swiezosc danych, wiec musi
    // sam sie odswiezac: nieaktualny stan celu jest gorszy niz jego brak.
    refetchInterval: ODSTEP_ODSWIEZANIA,
  });

  const dane = host.data;
  const segment = location.pathname.split("/")[3] || MODUL_DOMYSLNY;

  // Tytul karty niesie cel operacji. Operator z kilkoma otwartymi kartami
  // rozpoznaje maszyne po tytule, zanim na nia spojrzy.
  useEffect(() => {
    if (!dane) return;
    const adres = dane.management_address ? ` ${dane.management_address}` : "";
    document.title = `${dane.hostname}${adres} · ${segment} · Flotestro`;
    return () => {
      document.title = "Flotestro";
    };
  }, [dane, segment]);

  if (host.error) return <Blad error={host.error} />;
  if (!dane) return <Pusto>Loading…</Pusto>;

  const lista = moduly(dane, instalacja);
  const aktywny = lista.find((pozycja) => pozycja.segment === segment);
  const odrzucony = location.state as { odrzucony?: string; powod?: string } | null;

  return (
    <>
      <PasekKontekstu host={dane} segment={segment} instalacja={instalacja} />

      <div className="zakladki">
        {lista.map((pozycja) => (
          <NavLink
            key={pozycja.segment}
            to={`/hosts/${dane.id}/${pozycja.segment}`}
            className={({ isActive }) =>
              [isActive ? "aktywna" : "", pozycja.dostepny ? "" : "niedostepna"].join(" ").trim()
            }
            title={pozycja.dostepny ? undefined : pozycja.powod_braku}
          >
            {pozycja.nazwa}
          </NavLink>
        ))}
      </div>

      {/* Przelaczenie hosta, ktore zmienilo modul, mowi dlaczego. Bez tego
          operator widzi inny ekran, niz otwieral, i nie wie, co sie stalo. */}
      {odrzucony?.odrzucony && (
        <p className="ostrzezenie">
          <span>
            {odrzucony.odrzucony} is not available on {dane.hostname}: {odrzucony.powod}
          </span>
        </p>
      )}

      {/* Adres spoza rejestru modulow nie moze skonczyc sie pusta trescia:
          operator ma zobaczyc, ze taki modul nie istnieje. */}
      {!aktywny ? (
        <Pusto>
          There is no module named "{segment}". Pick one of the tabs above.
        </Pusto>
      ) : /* Modul bez pokrycia na tym hoscie zachowuje trase i podaje powod.
             Zniknieta zakladka wygladalaby jak brak funkcji w produkcie. */
      !aktywny.dostepny ? (
        <Pusto>
          {aktywny.nazwa} is not available on this host: {aktywny.powod_braku}.
        </Pusto>
      ) : (
        <Outlet context={{ host: dane }} />
      )}
    </>
  );
}
