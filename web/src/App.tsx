import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import type { Whoami } from "./lib/types";
import { Pulpit } from "./pages/Pulpit";
import { Hosty } from "./pages/Hosty";
import { Host } from "./pages/Host";
import { Zadania } from "./pages/Zadania";
import { Kampanie } from "./pages/Kampanie";
import { Kampania } from "./pages/Kampania";
import { Katalog } from "./pages/Katalog";
import { Audyt } from "./pages/Audyt";

export function App() {
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
    return <EkranLogowania />;
  }
  if (error) return <div className="pusto" style={{ padding: 40 }}>Blad: {String(error)}</div>;

  return (
    <div className="uklad">
      <nav className="nawigacja">
        <div className="marka">Flotestro</div>
        <Link do="/pulpit">Pulpit</Link>
        <Link do="/hosty">Hosty</Link>
        <Link do="/zadania">Zadania</Link>
        <Link do="/kampanie">Kampanie</Link>
        <Link do="/katalog">Katalog</Link>
        <Link do="/audyt">Audyt</Link>
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
          <Route path="/kampanie" element={<Kampanie />} />
          <Route path="/kampanie/:id" element={<Kampania />} />
          <Route path="/katalog" element={<Katalog />} />
          <Route path="/audyt" element={<Audyt />} />
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

function EkranLogowania() {
  return (
    <div className="ekran-logowania">
      <div>
        <h1>Flotestro</h1>
        <p className="podtytul">Panel zarzadzania flota Linux</p>
        <button onClick={() => (window.location.href = "/auth/login?redirect=/pulpit")}>
          Zaloguj przez dostawce tozsamosci
        </button>
      </div>
    </div>
  );
}
