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
      <h1>Identity directory</h1>
      <p className="podtytul">
        {stan.data?.configured === false
          ? "No directory connector is configured."
          : stan.data?.reachable
            ? `${stan.data.summary} · connector: ${stan.data.principal}`
            : stan.data?.error
              ? `Directory unavailable: ${stan.data.error}`
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
  return <Pusto>You do not have permission to read this resource.</Pusto>;
}

function Uzytkownicy() {
  const { data, error } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <BrakUprawnien />;
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No accounts.</Pusto>;

  return (
    <table>
      <thead><tr><th>Account</th><th>Full name</th><th>UID</th><th>Groups</th><th>SSH keys</th><th>State</th></tr></thead>
      <tbody>
        {data.items.map((uzytkownik) => (
          <tr key={uzytkownik.uid}>
            <td>{uzytkownik.uid}</td>
            <td>{[uzytkownik.first_name, uzytkownik.last_name].filter(Boolean).join(" ")}</td>
            <td>{uzytkownik.uid_number || "—"}</td>
            <td>{(uzytkownik.groups ?? []).join(", ") || "—"}</td>
            <td>{uzytkownik.ssh_key_fingerprints?.length ?? 0}</td>
            <td>{uzytkownik.disabled ? <span className="znacznik blad">locked</span> : <span className="znacznik ok">aktywne</span>}</td>
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
  if (!data?.items.length) return <Pusto>No groups.</Pusto>;

  return (
    <table>
      <thead><tr><th>Group</th><th>GID</th><th>Description</th><th>Members</th></tr></thead>
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
  if (!data?.items.length) return <Pusto>No rules.</Pusto>;

  return (
    <table>
      <thead><tr><th>Rule</th><th>Enabled</th><th>Groups</th><th>Hosts</th><th>Risk</th></tr></thead>
      <tbody>
        {data.items.map((regula) => (
          <tr key={regula.name}>
            <td>{regula.name}</td>
            <td>{regula.enabled ? "tak" : "nie"}</td>
            <td>{(regula.user_groups ?? []).join(", ") || "—"}</td>
            <td>{[...(regula.hosts ?? []), ...(regula.host_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {regula.allows_everything
                ? <span className="znacznik blad">covers the whole fleet</span>
                : <span className="znacznik">narrowed</span>}
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
  if (!data?.items.length) return <Pusto>No sudo rules.</Pusto>;

  return (
    <table>
      <thead><tr><th>Rule</th><th>Enabled</th><th>Applies to</th><th>Risk</th></tr></thead>
      <tbody>
        {data.items.map((regula) => (
          <tr key={regula.name}>
            <td>{regula.name}</td>
            <td>{regula.enabled ? "tak" : "nie"}</td>
            <td>{[...(regula.users ?? []), ...(regula.user_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {regula.critical
                ? <span className="znacznik blad" title={(regula.critical_reasons ?? []).join("; ")}>critical</span>
                : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
