import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { GroupMapping, Principal } from "../lib/types";
import { Blad, Czas, Pusto } from "../components/ui";

const ROLE = [
  "viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin",
];

/**
 * Zarzadzanie dostepem do panelu.
 *
 * Te operacje przestawiaja same reguly dostepu, wiec panel wymaga swiezego
 * uwierzytelnienia i podania powodu. Powod trafia do sladu audytowego razem
 * z opisem zmiany.
 */
export function Dostep() {
  const [zakladka, setZakladka] = useState<"mapowania" | "tozsamosci">("mapowania");

  return (
    <>
      <h1>Dostep</h1>
      <p className="podtytul">
        Mapowanie grup dostawcy tozsamosci na role oraz tozsamosci lokalne.
        Grupa z tokenu sama w sobie niczego nie nadaje - rola wynika z mapowania.
      </p>

      <div className="zakladki">
        <button className={zakladka === "mapowania" ? "aktywna" : ""} onClick={() => setZakladka("mapowania")}>
          Mapowania grup
        </button>
        <button className={zakladka === "tozsamosci" ? "aktywna" : ""} onClick={() => setZakladka("tozsamosci")}>
          Tozsamosci
        </button>
      </div>

      {zakladka === "mapowania" ? <Mapowania /> : <Tozsamosci />}
    </>
  );
}

function Mapowania() {
  const queryClient = useQueryClient();
  const [ostrzezenie, setOstrzezenie] = useState<ApiError | null>(null);
  const [formularz, setFormularz] = useState(false);
  const [grupa, setGrupa] = useState("");
  const [rola, setRola] = useState("viewer");
  const [site, setSite] = useState("");
  const [srodowisko, setSrodowisko] = useState("");
  const [powod, setPowod] = useState("");

  const lista = useQuery({
    queryKey: ["group-mappings"],
    queryFn: () => api.get<Collection<GroupMapping>>("/api/v1/group-mappings"),
    retry: false,
  });

  const odswiez = () => queryClient.invalidateQueries({ queryKey: ["group-mappings"] });

  const dodaj = useMutation({
    mutationFn: () =>
      api.post<GroupMapping>("/api/v1/group-mappings", {
        group_name: grupa.trim(), role: rola,
        site: site.trim(), environment: srodowisko.trim(), reason: powod.trim(),
      }),
    onSuccess: () => { setFormularz(false); setGrupa(""); setPowod(""); odswiez(); },
    onError: (blad) => setOstrzezenie(blad instanceof ApiError ? blad : null),
  });

  const usun = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/group-mappings/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: odswiez,
    onError: (blad) => setOstrzezenie(blad instanceof ApiError ? blad : null),
  });

  if (lista.error instanceof ApiError && lista.error.forbidden) {
    return <Pusto>Brak uprawnienia do zarzadzania dostepem.</Pusto>;
  }
  if (lista.error) return <Blad error={lista.error} />;

  return (
    <>
      <Ostrzezenie blad={ostrzezenie} zamknij={() => setOstrzezenie(null)} />

      {lista.data?.items.length ? (
        <table>
          <thead>
            <tr><th>Grupa</th><th>Rola</th><th>Zakres</th><th>Dodal</th><th>Kiedy</th><th /></tr>
          </thead>
          <tbody>
            {lista.data.items.map((mapowanie) => (
              <tr key={mapowanie.id}>
                <td>{mapowanie.group_name}</td>
                <td>{mapowanie.role}</td>
                <td className="zrodlo">
                  {mapowanie.site || "*"} / {mapowanie.environment || "*"}
                </td>
                <td className="zrodlo">{mapowanie.created_by}</td>
                <td><Czas wartosc={mapowanie.created_at} /></td>
                <td>
                  <button
                    onClick={() => {
                      const reason = window.prompt(
                        `Powod usuniecia mapowania grupy ${mapowanie.group_name} (min. 8 znakow):`,
                      );
                      if (reason) usun.mutate({ id: mapowanie.id, reason });
                    }}
                  >
                    Usun
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Pusto>Brak mapowan. Bez nich nikt nie dostanie roli przez dostawce tozsamosci.</Pusto>
      )}

      {formularz ? (
        <div className="formularz" style={{ marginTop: 24 }}>
          <h2>Nowe mapowanie</h2>
          <label>Grupa u dostawcy tozsamosci
            <input value={grupa} onChange={(z) => setGrupa(z.target.value)} placeholder="flotestro-operators" />
          </label>
          <label>Rola
            <select value={rola} onChange={(z) => setRola(z.target.value)}>
              {ROLE.map((nazwa) => <option key={nazwa} value={nazwa}>{nazwa}</option>)}
            </select>
          </label>
          <label>Lokalizacja (puste = wszystkie)
            <input value={site} onChange={(z) => setSite(z.target.value)} placeholder="lab" />
          </label>
          <label>Srodowisko (puste = wszystkie)
            <input value={srodowisko} onChange={(z) => setSrodowisko(z.target.value)} placeholder="test" />
          </label>
          <label>Powod zmiany
            <input value={powod} onChange={(z) => setPowod(z.target.value)} placeholder="np. nowy zespol dyzurny" />
          </label>
          <div className="operacje">
            <button disabled={!grupa.trim() || powod.trim().length < 8 || dodaj.isPending}
                    onClick={() => dodaj.mutate()}>
              Dodaj mapowanie
            </button>
            <button onClick={() => setFormularz(false)}>Anuluj</button>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 24 }}>
          <button onClick={() => setFormularz(true)}>Dodaj mapowanie</button>
        </div>
      )}
    </>
  );
}

function Tozsamosci() {
  const { data, error } = useQuery({
    queryKey: ["principals"],
    queryFn: () => api.get<Collection<Principal>>("/api/v1/principals"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Pusto>Brak uprawnienia do zarzadzania dostepem.</Pusto>;
  }
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>Brak tozsamosci.</Pusto>;

  return (
    <table>
      <thead><tr><th>Podmiot</th><th>Nazwa</th><th>Rodzaj</th><th>Role i zakresy</th></tr></thead>
      <tbody>
        {data.items.map((tozsamosc) => (
          <tr key={tozsamosc.id}>
            <td>{tozsamosc.subject}</td>
            <td>{tozsamosc.display_name || "—"}</td>
            <td className="zrodlo">{tozsamosc.kind}</td>
            <td>
              {tozsamosc.bindings.length === 0
                ? <span className="zrodlo">brak przypisan</span>
                : tozsamosc.bindings.map((wiazanie, indeks) => (
                    <div key={indeks}>
                      {wiazanie.role}
                      <span className="zrodlo">
                        {" "}{wiazanie.scope.site || "*"} / {wiazanie.scope.environment || "*"}
                      </span>
                    </div>
                  ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Odmowa z powodu nieswiezego uwierzytelnienia nie jest bledem aplikacji:
 * panel ma zaproponowac ponowne logowanie i wrocic w to samo miejsce.
 */
function Ostrzezenie({ blad, zamknij }: { blad: ApiError | null; zamknij: () => void }) {
  if (!blad) return null;

  if (blad.code === "reauthentication_required") {
    return (
      <div className="ostrzezenie">
        <div>
          <strong>Wymagane ponowne uwierzytelnienie.</strong> {blad.message}
        </div>
        <div className="operacje">
          <button
            onClick={() => {
              const cel = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${cel}`;
            }}
          >
            Zaloguj ponownie
          </button>
          <button onClick={zamknij}>Zamknij</button>
        </div>
      </div>
    );
  }
  return (
    <div className="ostrzezenie">
      <div>{blad.message}</div>
      <div className="operacje"><button onClick={zamknij}>Zamknij</button></div>
    </div>
  );
}
