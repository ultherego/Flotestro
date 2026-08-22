import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import type { Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { Pulpit } from "./pages/Pulpit";
import { Hosty } from "./pages/Hosty";
import { Host } from "./pages/Host";
import { Zadania } from "./pages/Zadania";
import { Kampanie } from "./pages/Kampanie";
import { Kampania } from "./pages/Kampania";
import { Katalog } from "./pages/Katalog";
import { Dostep } from "./pages/Dostep";
import { Audyt } from "./pages/Audyt";

export function App() {
  const zdolnosci = useCapabilities();
  const { data, isLoading, error } = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    retry: false,
    refetchInterval: false,
  });

  if (isLoading) return <div className="pusto" style={{ padding: 40 }}>Wczytywanie…</div>;

  // Brak sesji kieruje do logowania u dostawcy tozsamosci. Panel nie zbiera
  // hasel: poswiadczenia trafiaja wylacznie do Keycloaka.
  if (error instanceof ApiError && error.unauthenticated) {
    return <EkranLogowania dostawca={zdolnosci.identity_provider} />;
  }
  if (error) return <div className="pusto" style={{ padding: 40 }}>Blad: {String(error)}</div>;

  // Sekcje bez pokrycia w uprawnieniach sa ukrywane: pozycja w nawigacji,
  // ktora prowadzi wylacznie do odmowy, jest bledem interfejsu, a nie
  // zabezpieczeniem. O tym, co wolno zrobic, i tak decyduje serwer.
  const uprawnienia = new Set(data?.permissions ?? []);
  const zarzadzaDostepem = uprawnienia.has("principal.manage");
  const widziAudyt = uprawnienia.has("audit.read");
  const widziKampanie = uprawnienia.has("campaign.read");

  return (
    <div className="uklad">
      <nav className="nawigacja">
        <div className="marka">Flotestro</div>
        <Link do="/pulpit">Pulpit</Link>
        <Link do="/hosty">Hosty</Link>
        <Link do="/zadania">Zadania</Link>
        {widziKampanie && <Link do="/kampanie">Kampanie</Link>}
        {zdolnosci.directory && <Link do="/katalog">Katalog</Link>}
        {/* Zarzadzanie dostepem widzi tylko ten, kto moze cokolwiek w nim
            zmienic; pozostalym pozycja prowadzilaby do samej odmowy. */}
        {zarzadzaDostepem && <Link do="/dostep">Dostep</Link>}
        {widziAudyt && <Link do="/audyt">Audyt</Link>}
        <div className="stopka">
          <div>{data?.display_name || data?.subject}</div>
          <div>{data?.roles.join(", ") || "brak rol"}</div>
          <a href="#" onClick={wyloguj}>Wyloguj</a>
        </div>
      </nav>
      <main className="tresc">
        <Routes>
          <Route path="/" element={<Navigate to="/pulpit" replace />} />
          <Route path="/pulpit" element={<Pulpit />} />
          <Route path="/hosty" element={<Hosty />} />
          <Route path="/hosty/:id" element={<Host />} />
          <Route path="/zadania" element={<Zadania />} />
          {widziKampanie && <Route path="/kampanie" element={<Kampanie />} />}
          {widziKampanie && <Route path="/kampanie/:id" element={<Kampania />} />}
          {zdolnosci.directory && <Route path="/katalog" element={<Katalog />} />}
          {zarzadzaDostepem && <Route path="/dostep" element={<Dostep />} />}
          {widziAudyt && <Route path="/audyt" element={<Audyt />} />}
          <Route path="*" element={<div className="pusto">Nie ma takiej strony.</div>} />
        </Routes>
      </main>
    </div>
  );
}

function Link({ do: cel, children }: { do: string; children: string }) {
  return (
    <NavLink to={cel} className={({ isActive }) => (isActive ? "aktywny" : "")}>
      {children}
    </NavLink>
  );
}

async function wyloguj(event: React.MouseEvent) {
  event.preventDefault();
  // Uniewaznienie sesji panelu nie wystarcza: bez wylogowania u dostawcy
  // kolejne wejscie zalogowaloby uzytkownika bez pytania.
  const wynik = await api.post<{ logout_url: string }>("/auth/logout");
  window.location.href = wynik.logout_url || "/";
}

function EkranLogowania({ dostawca }: { dostawca: boolean }) {
  return (
    <div className="ekran-logowania">
      <div>
        <h1>Flotestro</h1>
        <p className="podtytul">Panel zarzadzania flota Linux</p>
        {dostawca ? (
          <button onClick={() => (window.location.href = "/auth/login?redirect=/pulpit")}>
            Zaloguj przez dostawce tozsamosci
          </button>
        ) : (
          // Bez skonfigurowanego dostawcy przycisk logowania prowadzilby do
          // bledu. Panel dziala wtedy na tokenach API i trzeba to powiedziec
          // wprost, zamiast pokazywac martwa akcje.
          <p className="podtytul">
            W tej instalacji nie skonfigurowano dostawcy tozsamosci. Dostep do
            panelu odbywa sie tokenem API przekazanym w naglowku Authorization.
          </p>
        )}
      </div>
    </div>
  );
}
