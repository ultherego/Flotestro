import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { DirectoryGroup, DirectoryUser, HBACRule, SudoRule } from "../lib/types";
import { Blad, Pusto } from "../components/ui";

type Zakladka = "uzytkownicy" | "grupy" | "hbac" | "sudo";

/**
 * Widok katalogu tozsamosci. Reguly HBAC i sudo maja osobne uprawnienie:
 * opisuja, kto moze wejsc na host i podniesc uprawnienia.
 */
export function Katalog() {
  const [zakladka, setZakladka] = useState<Zakladka>("uzytkownicy");

  const stan = useQuery({
    queryKey: ["identity-status"],
    queryFn: () => api.get<{ configured: boolean; reachable?: boolean; principal?: string; summary?: string; error?: string }>("/api/v1/identity/status"),
  });

  return (
    <>
      <h1>Katalog tozsamosci</h1>
      <p className="podtytul">
        {stan.data?.configured === false
          ? "Connector katalogu nie jest skonfigurowany."
          : stan.data?.reachable
            ? `${stan.data.summary} · connector: ${stan.data.principal}`
            : stan.data?.error
              ? `Katalog niedostepny: ${stan.data.error}`
              : "Sprawdzanie…"}
      </p>

      <div className="zakladki">
        {(["uzytkownicy", "grupy", "hbac", "sudo"] as Zakladka[]).map((klucz) => (
          <button key={klucz} className={zakladka === klucz ? "aktywna" : ""} onClick={() => setZakladka(klucz)}>
            {klucz}
          </button>
        ))}
      </div>

      {zakladka === "uzytkownicy" && <Uzytkownicy />}
      {zakladka === "grupy" && <Grupy />}
      {zakladka === "hbac" && <RegulyHBAC />}
      {zakladka === "sudo" && <RegulySudo />}
    </>
  );
}

function BrakUprawnien() {
  return <Pusto>Brak uprawnienia do odczytu tego zasobu.</Pusto>;
}

function Uzytkownicy() {
  const { data, error } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <BrakUprawnien />;
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>Brak kont.</Pusto>;

  return (
    <table>
      <thead><tr><th>Konto</th><th>Imie i nazwisko</th><th>UID</th><th>Grupy</th><th>Klucze SSH</th><th>Stan</th></tr></thead>
      <tbody>
        {data.items.map((uzytkownik) => (
          <tr key={uzytkownik.uid}>
            <td>{uzytkownik.uid}</td>
            <td>{[uzytkownik.first_name, uzytkownik.last_name].filter(Boolean).join(" ")}</td>
            <td>{uzytkownik.uid_number || "—"}</td>
            <td>{(uzytkownik.groups ?? []).join(", ") || "—"}</td>
            <td>{uzytkownik.ssh_key_fingerprints?.length ?? 0}</td>
            <td>{uzytkownik.disabled ? <span className="znacznik blad">zablokowane</span> : <span className="znacznik ok">aktywne</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Grupy() {
  const { data, error } = useQuery({
    queryKey: ["identity-groups"],
    queryFn: () => api.get<Collection<DirectoryGroup>>("/api/v1/identity/groups"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <BrakUprawnien />;
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>Brak grup.</Pusto>;

  return (
    <table>
      <thead><tr><th>Grupa</th><th>GID</th><th>Opis</th><th>Czlonkowie</th></tr></thead>
      <tbody>
        {data.items.map((grupa) => (
          <tr key={grupa.name}>
            <td>{grupa.name}</td>
            <td>{grupa.gid_number || "—"}</td>
            <td>{grupa.description || "—"}</td>
            <td>{(grupa.members ?? []).join(", ") || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RegulyHBAC() {
  const { data, error } = useQuery({
    queryKey: ["identity-hbac"],
    queryFn: () => api.get<Collection<HBACRule>>("/api/v1/identity/hbac-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <BrakUprawnien />;
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>Brak regul.</Pusto>;

  return (
    <table>
      <thead><tr><th>Regula</th><th>Wlaczona</th><th>Grupy</th><th>Hosty</th><th>Ryzyko</th></tr></thead>
      <tbody>
        {data.items.map((regula) => (
          <tr key={regula.name}>
            <td>{regula.name}</td>
            <td>{regula.enabled ? "tak" : "nie"}</td>
            <td>{(regula.user_groups ?? []).join(", ") || "—"}</td>
            <td>{[...(regula.hosts ?? []), ...(regula.host_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {regula.allows_everything
                ? <span className="znacznik blad">obejmuje cala flote</span>
                : <span className="znacznik">zawezona</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RegulySudo() {
  const { data, error } = useQuery({
    queryKey: ["identity-sudo"],
    queryFn: () => api.get<Collection<SudoRule>>("/api/v1/identity/sudo-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <BrakUprawnien />;
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>Brak regul sudo.</Pusto>;

  return (
    <table>
      <thead><tr><th>Regula</th><th>Wlaczona</th><th>Kogo dotyczy</th><th>Ryzyko</th></tr></thead>
      <tbody>
        {data.items.map((regula) => (
          <tr key={regula.name}>
            <td>{regula.name}</td>
            <td>{regula.enabled ? "tak" : "nie"}</td>
            <td>{[...(regula.users ?? []), ...(regula.user_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {regula.critical
                ? <span className="znacznik blad" title={(regula.critical_reasons ?? []).join("; ")}>krytyczna</span>
                : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
