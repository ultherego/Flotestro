import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { api, ApiError, type Collection } from "../lib/api";
import type { AuditEvent, Host as HostType, InventoryRevision, Job } from "../lib/types";
import { Blad, Czas, FlagaOpcjonalna, LiczbaOpcjonalna, Para, Pary, Pusto, StanPolaczenia, StanZadania } from "../components/ui";
import { bytes } from "../lib/format";
import { useCapabilities } from "../lib/capabilities";
import { KontaHosta } from "./KontaHosta";

type Zakladka = "przeglad" | "pakiety" | "uslugi" | "konta" | "tozsamosc" | "zadania" | "audyt";

/**
 * Widok hosta. Zakladki nieobslugiwane przez dany host sa wylaczone na
 * podstawie jego zdolnosci, a nie ukrywane bez wyjasnienia.
 */
export function Host() {
  const { id = "" } = useParams();
  const [zakladka, setZakladka] = useState<Zakladka>("przeglad");
  const zdolnosci = useCapabilities();

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<HostType>(`/api/v1/hosts/${id}`),
  });

  if (host.error) return <Blad error={host.error} />;
  if (!host.data) return <Pusto>Loading…</Pusto>;
  const dane = host.data;

  const zakladki: { klucz: Zakladka; nazwa: string; dostepna: boolean; powod?: string }[] = [
    { klucz: "przeglad", nazwa: "Overview", dostepna: true },
    { klucz: "pakiety", nazwa: "Packages", dostepna: dane.capabilities.apt || dane.capabilities.dnf, powod: "host has no supported package manager" },
    { klucz: "uslugi", nazwa: "Services", dostepna: dane.capabilities.systemd, powod: "host does not use systemd" },
    { klucz: "konta", nazwa: "Accounts", dostepna: zdolnosci.local_users, powod: "the local accounts module is disabled in this installation" },
    { klucz: "tozsamosc", nazwa: "Identity", dostepna: true },
    { klucz: "zadania", nazwa: "Jobs", dostepna: true },
    { klucz: "audyt", nazwa: "Audit", dostepna: true },
  ];

  return (
    <>
      <h1>{dane.hostname}</h1>
      <p className="podtytul">
        <StanPolaczenia stan={dane.connection_state} /> · {dane.site} / {dane.environment} ·
        agent {dane.agent_version || "?"} · ostatnio widziany <Czas wartosc={dane.last_seen_at} />
      </p>

      <div className="zakladki">
        {zakladki.map((pozycja) => (
          <button
            key={pozycja.klucz}
            className={zakladka === pozycja.klucz ? "aktywna" : ""}
            disabled={!pozycja.dostepna}
            title={pozycja.dostepna ? undefined : pozycja.powod}
            onClick={() => setZakladka(pozycja.klucz)}
          >
            {pozycja.nazwa}
          </button>
        ))}
      </div>

      {zakladka === "przeglad" && <Przeglad host={dane} />}
      {zakladka === "pakiety" && <Pakiety host={dane} />}
      {zakladka === "uslugi" && <Uslugi host={dane} />}
      {zakladka === "konta" && <KontaHosta host={dane} />}
      {zakladka === "tozsamosc" && <Tozsamosc host={dane} />}
      {zakladka === "zadania" && <ZadaniaHosta host={dane} />}
      {zakladka === "audyt" && <AudytHosta host={dane} />}
    </>
  );
}

function Przeglad({ host }: { host: HostType }) {
  const inventory = useQuery({
    queryKey: ["inventory", host.id],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${host.id}/inventory`),
    retry: false,
  });
  const sprzet = inventory.data?.payload?.hardware;

  return (
    <>
      <Pary>
        <Para etykieta="System">{host.os_distribution} {host.os_version} ({host.os_family})</Para>
        <Para etykieta="Architecture">{host.architecture || "—"}</Para>
        <Para etykieta="Machine ID">{host.machine_id}</Para>
        <Para etykieta="Boot ID">{host.boot_id || "—"}</Para>
        <Para etykieta="Lifecycle state">{host.lifecycle_state}</Para>
        <Para etykieta="Reboot required"><FlagaOpcjonalna wartosc={host.reboot_required} /></Para>
        <Para etykieta="Failed units"><LiczbaOpcjonalna wartosc={host.failed_units} /></Para>
        <Para etykieta="Package database">
          {host.package_database_broken ? <span className="znacznik blad">needs repair</span> : "w porzadku"}
        </Para>
        <Para etykieta="Enrolled"><Czas wartosc={host.enrolled_at} /></Para>
      </Pary>

      {sprzet && (
        <>
          <h2>Hardware</h2>
          <Pary>
            <Para etykieta="CPU cores">{sprzet.cpu_cores}</Para>
            <Para etykieta="Memory">{bytes(sprzet.memory_bytes)}</Para>
            <Para etykieta="Root filesystem">
              {bytes(sprzet.root_fs_free_bytes)} wolne z {bytes(sprzet.root_fs_bytes)}
            </Para>
            <Para etykieta="Virtualization">{sprzet.virtualization || "—"}</Para>
          </Pary>
        </>
      )}

      {inventory.data && (
        <p className="zrodlo" style={{ marginTop: 16 }}>
          Zrodlo: inventory, rewizja {inventory.data.revision.slice(0, 12)}, zaobserwowane{" "}
          <Czas wartosc={inventory.data.observed_at} />
        </p>
      )}
    </>
  );
}

function Pakiety({ host }: { host: HostType }) {
  const inventory = useQuery({
    queryKey: ["inventory", host.id],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${host.id}/inventory`),
    retry: false,
  });
  const pakiety = inventory.data?.payload?.packages;

  return (
    <>
      <Pary>
        <Para etykieta="Manager">{pakiety?.manager || "—"}</Para>
        <Para etykieta="Installed">{pakiety?.installed ?? <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="Upgradable"><LiczbaOpcjonalna wartosc={host.pending_updates} /></Para>
        <Para etykieta="Security updates"><LiczbaOpcjonalna wartosc={host.pending_security_updates} /></Para>
      </Pary>
      {pakiety?.unavailable_reason && (
        <p className="zrodlo" style={{ marginTop: 12 }}>
          Stanu nie udalo sie ustalic: {pakiety.unavailable_reason}
        </p>
      )}
      <ZlecOperacje
        host={host}
        opis="Count available updates without changing host state."
        akcja="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        etykieta="Plan updates"
      />
    </>
  );
}

function Uslugi({ host }: { host: HostType }) {
  const inventory = useQuery({
    queryKey: ["inventory", host.id],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${host.id}/inventory`),
    retry: false,
  });
  const wBledzie: string[] = inventory.data?.payload?.failed_units ?? [];
  const znane: boolean = inventory.data?.payload?.failed_units_known ?? false;

  return (
    <>
      <h2>Failed units</h2>
      {!znane ? (
        <Pusto>Unit states could not be determined.</Pusto>
      ) : wBledzie.length === 0 ? (
        <Pusto>No unit is in a failed state.</Pusto>
      ) : (
        <table>
          <thead><tr><th>Unit</th></tr></thead>
          <tbody>{wBledzie.map((jednostka) => <tr key={jednostka}><td>{jednostka}</td></tr>)}</tbody>
        </table>
      )}
    </>
  );
}

function Tozsamosc({ host }: { host: HostType }) {
  const inventory = useQuery({
    queryKey: ["inventory", host.id],
    queryFn: () => api.get<InventoryRevision>(`/api/v1/hosts/${host.id}/inventory`),
    retry: false,
  });
  const tozsamosc = inventory.data?.payload?.identity ?? {};

  return (
    <>
      <Pary>
        <Para etykieta="In domain">
          {host.identity.enrolled ? <span className="znacznik ok">tak</span> : <span className="znacznik">nie</span>}
        </Para>
        <Para etykieta="Domain">{host.identity.domain || "—"}</Para>
        <Para etykieta="Realm">{host.identity.realm || "—"}</Para>
        <Para etykieta="Servers">{(tozsamosc.servers ?? []).join(", ") || "—"}</Para>
        <Para etykieta="SSSD running">{tozsamosc.sssd_running ? "tak" : "nie"}</Para>
        <Para etykieta="SSSD online"><FlagaOpcjonalna wartosc={host.identity.sssd_online} /></Para>
        <Para etykieta="Cache age">
          {tozsamosc.cache_age_seconds !== undefined
            ? `${tozsamosc.cache_age_seconds} s`
            : <span className="znacznik nieznany">unknown</span>}
        </Para>
        <Para etykieta="Host principal">{tozsamosc.host_principal || <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="KVNO keytab">{tozsamosc.keytab_kvno ?? <span className="znacznik nieznany">unknown</span>}</Para>
        <Para etykieta="Clock synchronized">{tozsamosc.time_synchronized ? "tak" : "nie"}</Para>
        <Para etykieta="Checked"><Czas wartosc={host.identity.checked_at} /></Para>
      </Pary>
      {tozsamosc.unavailable_reason && (
        <p className="zrodlo" style={{ marginTop: 12 }}>Braki: {tozsamosc.unavailable_reason}</p>
      )}
    </>
  );
}

function ZadaniaHosta({ host }: { host: HostType }) {
  const { data, error } = useQuery({
    queryKey: ["jobs", host.id],
    queryFn: () => api.get<Collection<Job>>(`/api/v1/jobs?host_id=${host.id}&limit=50`),
  });
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No jobs for this host.</Pusto>;

  return (
    <table>
      <thead><tr><th>Operation</th><th>State</th><th>Requested by</th><th>Approved by</th><th>Result</th><th>Created</th></tr></thead>
      <tbody>
        {data.items.map((zadanie) => (
          <tr key={zadanie.id}>
            <td>{zadanie.action_type}</td>
            <td><StanZadania stan={zadanie.state} /></td>
            <td>{zadanie.created_by}</td>
            <td>{zadanie.approved_by || "—"}</td>
            <td>{zadanie.result_error_code || zadanie.result_status || "—"}</td>
            <td><Czas wartosc={zadanie.created_at} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function AudytHosta({ host }: { host: HostType }) {
  const { data, error } = useQuery({
    queryKey: ["audit", host.id],
    queryFn: () => api.get<Collection<AuditEvent>>(`/api/v1/hosts/${host.id}/audit?limit=50`),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Pusto>You do not have permission to read this host's audit trail.</Pusto>;
  }
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No events.</Pusto>;

  return (
    <table>
      <thead><tr><th>Time</th><th>Actor</th><th>Operation</th><th>Result</th></tr></thead>
      <tbody>
        {data.items.map((zdarzenie) => (
          <tr key={zdarzenie.id}>
            <td><Czas wartosc={zdarzenie.occurred_at} /></td>
            <td>{zdarzenie.actor_id}</td>
            <td>{zdarzenie.action}</td>
            <td><StanZadania stan={zdarzenie.outcome} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Zlecenie operacji prowadzi do planu, a nie do natychmiastowej zmiany.
 * Operacja mutujaca trafia do stanu oczekiwania na zatwierdzenie.
 */
function ZlecOperacje({
  host, opis, akcja, payload, etykieta,
}: { host: HostType; opis: string; akcja: string; payload: unknown; etykieta: string }) {
  const queryClient = useQueryClient();
  const [wynik, setWynik] = useState<string>("");

  const mutacja = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action: akcja, payload }),
    onSuccess: (zadanie) => {
      setWynik(
        zadanie.requires_approval
          ? `Zadanie ${zadanie.id.slice(0, 8)} czeka na zatwierdzenie.`
          : `Zadanie ${zadanie.id.slice(0, 8)} trafilo do kolejki.`,
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setWynik(error instanceof Error ? error.message : String(error)),
  });

  return (
    <div style={{ marginTop: 24 }}>
      <h2>Request an operation</h2>
      <p className="podtytul">{opis}</p>
      <button onClick={() => mutacja.mutate()} disabled={mutacja.isPending}>
        {mutacja.isPending ? "Requesting…" : etykieta}
      </button>
      {wynik && <p className="zrodlo" style={{ marginTop: 10 }}>{wynik}</p>}
      <p style={{ marginTop: 12 }}>
        <Link to="/jobs">See all jobs</Link>
      </p>
    </div>
  );
}
