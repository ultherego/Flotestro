import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import type { Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { Pulpit } from "./pages/Pulpit";
import { Hosty } from "./pages/Hosty";
import { UkladHosta } from "./pages/host/Uklad";
import { Przeglad } from "./pages/host/Przeglad";
import { Pakiety } from "./pages/host/Pakiety";
import { Uslugi } from "./pages/host/Uslugi";
import { Kontenery } from "./pages/host/Kontenery";
import { Procesy } from "./pages/host/Procesy";
import { Harmonogramy } from "./pages/host/Harmonogramy";
import { Siec } from "./pages/host/Siec";
import { Resolver } from "./pages/host/Resolver";
import { Zapora } from "./pages/host/Zapora";
import { Przestrzen } from "./pages/host/Przestrzen";
import { SerwerSSH } from "./pages/host/SerwerSSH";
import { Jadro } from "./pages/host/Jadro";
import { Zegar } from "./pages/host/Zegar";
import { Zasilanie } from "./pages/host/Zasilanie";
import { Bezpieczenstwo } from "./pages/host/Bezpieczenstwo";
import { Bezpieczenstwo as BezpieczenstwoFloty } from "./pages/Bezpieczenstwo";
import { Sekrety } from "./pages/Sekrety";
import { CertyfikatyFloty } from "./pages/Certyfikaty";
import { Certyfikaty } from "./pages/host/Certyfikaty";
import { Pliki } from "./pages/host/Pliki";
import { Compose } from "./pages/host/Compose";
import { Logi } from "./pages/host/Logi";
import { KontaHosta } from "./pages/host/Konta";
import { Tozsamosc } from "./pages/host/Tozsamosc";
import { ZadaniaHosta } from "./pages/host/Zadania";
import { AudytHosta } from "./pages/host/Audyt";
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

  if (isLoading) return <div className="pusto" style={{ padding: 40 }}>Loading…</div>;

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
  const widziBezpieczenstwo = uprawnienia.has("security.read");
  const widziSekrety = uprawnienia.has("secret.read");
  const widziCertyfikaty = uprawnienia.has("certificate.read");

  return (
    <div className="uklad">
      <nav className="nawigacja">
        <div className="marka">Flotestro</div>
        <Link do="/dashboard">Dashboard</Link>
        <Link do="/hosts">Hosts</Link>
        <Link do="/jobs">Jobs</Link>
        {widziKampanie && <Link do="/campaigns">Campaigns</Link>}
        {widziBezpieczenstwo && <Link do="/security">Security</Link>}
        {widziCertyfikaty && <Link do="/certificates">Certificates</Link>}
        {widziSekrety && <Link do="/secrets">Secrets</Link>}
        {zdolnosci.directory && <Link do="/directory">Directory</Link>}
        {/* Zarzadzanie dostepem widzi tylko ten, kto moze cokolwiek w nim
            zmienic; pozostalym pozycja prowadzilaby do samej odmowy. */}
        {zarzadzaDostepem && <Link do="/access">Access</Link>}
        {widziAudyt && <Link do="/audit">Audit</Link>}
        <div className="stopka">
          <div>{data?.display_name || data?.subject}</div>
          <div>{data?.roles.join(", ") || "no roles"}</div>
          {/* Dostawca tozsamosci moze miec aktywna sesje innego uzytkownika
              i logowac nia po cichu. Bez tego odnosnika nie ma z tego wyjscia
              inaczej niz przez czyszczenie ciasteczek przegladarki. */}
          <a href={`/auth/login?force=1&redirect=${encodeURIComponent(window.location.pathname)}`}>
            Switch account
          </a>
          <a href="#" onClick={wyloguj}>Sign out</a>
        </div>
      </nav>
      <main className="tresc">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Pulpit />} />
          <Route path="/hosts" element={<Hosty />} />
          <Route path="/security" element={<BezpieczenstwoFloty />} />
          <Route path="/certificates" element={<CertyfikatyFloty />} />
          <Route path="/secrets" element={<Sekrety />} />
          {/* Modul hosta jest segmentem adresu, wiec odswiezenie, historia
              przegladarki i odnosnik bezposredni prowadza tam, gdzie operator
              faktycznie byl. */}
          <Route path="/hosts/:id" element={<UkladHosta />}>
            <Route index element={<Navigate to="overview" replace />} />
            <Route path="overview" element={<Przeglad />} />
            <Route path="packages" element={<Pakiety />} />
            <Route path="services" element={<Uslugi />} />
            <Route path="processes" element={<Procesy />} />
            <Route path="schedules" element={<Harmonogramy />} />
            <Route path="network" element={<Siec />} />
            <Route path="dns" element={<Resolver />} />
            <Route path="firewall" element={<Zapora />} />
            <Route path="storage" element={<Przestrzen />} />
            <Route path="ssh" element={<SerwerSSH />} />
            <Route path="kernel" element={<Jadro />} />
            <Route path="time" element={<Zegar />} />
            <Route path="power" element={<Zasilanie />} />
            <Route path="security" element={<Bezpieczenstwo />} />
            <Route path="certificates" element={<Certyfikaty />} />
            <Route path="files" element={<Pliki />} />
            <Route path="containers" element={<Kontenery />} />
            <Route path="compose" element={<Compose />} />
            <Route path="logs" element={<Logi />} />
            <Route path="accounts" element={<KontaHosta />} />
            <Route path="identity" element={<Tozsamosc />} />
            <Route path="jobs" element={<ZadaniaHosta />} />
            <Route path="audit" element={<AudytHosta />} />
          </Route>
          <Route path="/jobs" element={<Zadania />} />
          {widziKampanie && <Route path="/campaigns" element={<Kampanie />} />}
          {widziKampanie && <Route path="/campaigns/:id" element={<Kampania />} />}
          {zdolnosci.directory && <Route path="/directory" element={<Katalog />} />}
          {zarzadzaDostepem && <Route path="/access" element={<Dostep />} />}
          {widziAudyt && <Route path="/audit" element={<Audyt />} />}
          <Route path="*" element={<div className="pusto">Page not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}

function Link({ do: cel, children }: { do: string; children: string }) {
  return (
    <NavLink to={cel} className={({ isActive }) => (isActive ? "active" : "")}>
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
        <p className="podtytul">Linux fleet management</p>
        {dostawca ? (
          <>
            <button onClick={() => (window.location.href = "/auth/login?redirect=/dashboard")}>
              Sign in with identity provider
            </button>
            <p className="podtytul" style={{ marginTop: 14 }}>
              Your identity provider may sign you in with an account you already
              have an open session for.{" "}
              <a href="/auth/login?force=1&redirect=/dashboard">Sign in as a different user</a>
            </p>
          </>
        ) : (
          // Bez skonfigurowanego dostawcy przycisk logowania prowadzilby do
          // bledu. Panel dziala wtedy na tokenach API i trzeba to powiedziec
          // wprost, zamiast pokazywac martwa akcje.
          <p className="podtytul">
            No identity provider is configured in this installation. Access to
            the panel uses an API token passed in the Authorization header.
          </p>
        )}
      </div>
    </div>
  );
}
