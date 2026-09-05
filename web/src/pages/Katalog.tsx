import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { DirectoryGroup, DirectoryUser, HBACRule, SudoRule } from "../lib/types";
import { Blad, Pusto } from "../components/ui";

type Zakladka = "uzytkownicy" | "grupy" | "hbac" | "sudo" | "dns";

// Klucz zakladki jest identyfikatorem w kodzie, a nie napisem dla operatora.
// Wyswietlanie go wprost dawalo w interfejsie angielskim polskie nazwy.
const nazwaZakladki: Record<Zakladka, string> = {
  uzytkownicy: "Users",
  grupy: "Groups",
  hbac: "HBAC rules",
  sudo: "sudo rules",
  dns: "DNS",
};

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
              : "Checking…"}
      </p>

      <div className="zakladki">
        {(["uzytkownicy", "grupy", "hbac", "sudo", "dns"] as Zakladka[]).map((klucz) => (
          <button key={klucz} className={zakladka === klucz ? "aktywna" : ""} onClick={() => setZakladka(klucz)}>
            {nazwaZakladki[klucz]}
          </button>
        ))}
      </div>

      {zakladka === "uzytkownicy" && <Uzytkownicy />}
      {zakladka === "grupy" && <Grupy />}
      {zakladka === "hbac" && <RegulyHBAC />}
      {zakladka === "sudo" && <RegulySudo />}
      {zakladka === "dns" && <DNSKatalogowy />}
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

type Strefa = { name: string; reverse: boolean };

type RekordDNS = { zone: string; name: string; type: string; values: string[]; ttl?: number };

type ZmianaKatalogu = { id: string; state: string; plan?: { summary?: string; steps?: string[]; conflicts?: string[] } };

/**
 * DNS katalogowy.
 *
 * To jest inny zakres niz resolver hosta: tam panel mowi jednemu hostowi,
 * kogo ma pytac, a tutaj - co katalog odpowie calej sieci. Dlatego rekord
 * idzie ta sama droga co zmiana konta: plan, zatwierdzenie, wykonanie faza
 * po fazie - a nie jako zadanie dla agenta.
 */
function DNSKatalogowy() {
  const queryClient = useQueryClient();
  const [strefa, setStrefa] = useState("");
  const [nazwa, setNazwa] = useState("");
  const [typ, setTyp] = useState("A");
  const [wartosc, setWartosc] = useState("");
  const [ttl, setTtl] = useState("");
  const [odwrotny, setOdwrotny] = useState(true);
  const [komunikat, setKomunikat] = useState("");

  const strefy = useQuery({
    queryKey: ["dns-zones"],
    queryFn: () => api.get<Collection<Strefa>>("/api/v1/identity/dns/zones"),
    retry: false,
  });
  const wybrana = strefa || strefy.data?.items?.[0]?.name || "";

  const rekordy = useQuery({
    queryKey: ["dns-records", wybrana],
    queryFn: () =>
      api.get<Collection<RekordDNS>>(`/api/v1/identity/dns/records?zone=${encodeURIComponent(wybrana)}`),
    enabled: wybrana !== "",
    retry: false,
  });

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<ZmianaKatalogu>("/api/v1/identity/changes", tresc),
    onSuccess: (zmiana) => {
      const konflikty = zmiana.plan?.conflicts ?? [];
      setKomunikat(
        konflikty.length
          ? `Change ${zmiana.id.slice(0, 8)} planned with conflicts: ${konflikty.join("; ")}`
          : `Change ${zmiana.id.slice(0, 8)} is ${zmiana.state.replace("_", " ")}.`,
      );
      queryClient.invalidateQueries({ queryKey: ["dns-records", wybrana] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (strefy.error instanceof ApiError && strefy.error.forbidden) return <BrakUprawnien />;
  if (strefy.error) return <Blad error={strefy.error} />;

  const rekord = (dopisanie: boolean) => ({
    action: dopisanie ? "dns.record.ensure" : "dns.record.remove",
    payload: {
      dns: {
        zone: wybrana, name: nazwa, type: typ, value: wartosc,
        ttl: Number(ttl) || 0,
        reverse: odwrotny && (typ === "A" || typ === "AAAA"),
      },
    },
  });

  return (
    <>
      <p className="podtytul">
        Zones and records live in the directory, not in anyone's /etc/hosts. A
        record here answers for the whole network, so it goes the same way as a
        directory account: plan first, then approval, then execution — and the
        reverse record is a separate, visible step of that plan.
      </p>

      <div className="filtry">
        <select value={wybrana} onChange={(e) => setStrefa(e.target.value)}>
          {(strefy.data?.items ?? []).map((pozycja) => (
            <option key={pozycja.name} value={pozycja.name}>
              {pozycja.name}{pozycja.reverse ? " (reverse)" : ""}
            </option>
          ))}
        </select>
        <span className="zrodlo">{(rekordy.data?.items ?? []).length} records</span>
      </div>

      <div className="formularz" style={{ marginBottom: 16 }}>
        <div className="filtry">
          <input value={nazwa} onChange={(e) => setNazwa(e.target.value)}
                 placeholder="name (web, @, _ldap._tcp)" style={{ minWidth: 200 }} />
          <select value={typ} onChange={(e) => setTyp(e.target.value)}>
            {["A", "AAAA", "CNAME", "TXT", "SRV", "PTR"].map((pozycja) => (
              <option key={pozycja} value={pozycja}>{pozycja}</option>
            ))}
          </select>
          <input value={wartosc} onChange={(e) => setWartosc(e.target.value)}
                 placeholder="value (10.0.0.5)" style={{ minWidth: 240 }} />
          <input value={ttl} onChange={(e) => setTtl(e.target.value)}
                 placeholder="TTL" style={{ width: 90 }} />
        </div>
        {(typ === "A" || typ === "AAAA") && (
          <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={odwrotny} onChange={(e) => setOdwrotny(e.target.checked)} />
            Also write the reverse (PTR) record — forgetting it is the usual mistake
          </label>
        )}
        <div className="operacje">
          <button disabled={!wybrana || !nazwa || !wartosc} onClick={() => zlec.mutate(rekord(true))}>
            Plan record
          </button>
          <button className="wtorny" disabled={!wybrana || !nazwa || !wartosc}
                  onClick={() => zlec.mutate(rekord(false))}>
            Plan removal
          </button>
        </div>
        {komunikat && <p className="zrodlo" style={{ margin: 0 }}>{komunikat}</p>}
      </div>

      {rekordy.error ? (
        <Blad error={rekordy.error} />
      ) : !(rekordy.data?.items ?? []).length ? (
        <Pusto>This zone has no records the panel can read.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th></tr></thead>
          <tbody>
            {(rekordy.data?.items ?? []).map((pozycja, indeks) => (
              <tr key={`${pozycja.name}-${pozycja.type}-${indeks}`}>
                <td>{pozycja.name}</td>
                <td>{pozycja.type}</td>
                <td className="zrodlo">{pozycja.values.join(", ")}</td>
                <td>{pozycja.ttl || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
