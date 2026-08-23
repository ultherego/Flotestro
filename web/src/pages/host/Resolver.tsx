import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Czas, Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";
import { PotwierdzenieCelu } from "./PotwierdzenieCelu";

type Link = {
  name: string;
  index?: number;
  servers?: string[];
  domains?: string[];
  default_route?: boolean;
  dnssec?: string;
  dns_over_tls?: string;
};

type Zapytanie = {
  name: string;
  addresses?: string[];
  server?: string;
  error?: string;
  took_millis: number;
};

type WynikDNS = { kind?: string; queries?: { queries?: Zapytanie[] } };


type Snapshot = {
  owner?: string;
  mode?: string;
  resolv_conf?: string;
  resolv_conf_target?: string;
  servers?: string[];
  search_domains?: string[];
  links?: Link[];
  dnssec?: string;
  dns_over_tls?: string;
  writable?: boolean;
  write_adapter?: string;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/**
 * Resolver hosta.
 *
 * Panel pokazuje stan faktyczny wraz z jego wlascicielem: plik resolvera
 * nalezacy do uslugi zostanie nadpisany przy nastepnym zdarzeniu sieci, wiec
 * to wlasciciel rozstrzyga, czy panel moze tu cokolwiek zmienic.
 */
export function Resolver() {
  const host = useHost();
  const queryClient = useQueryClient();
  const modul = useModul<Snapshot>(host.id, "dns");
  const [nazwy, setNazwy] = useState("ipa.flotestro.test");
  const [zamiar, setZamiar] = useState<{ opis: string; payload: Record<string, unknown> } | null>(null);
  const [komunikat, setKomunikat] = useState("");
  const [formularz, setFormularz] = useState(false);
  // Wynik testu nalezy do zadania, wiec czekamy na to konkretne zadanie,
  // zamiast odswiezac cala liste.
  const [zadanieTestu, setZadanieTestu] = useState("");

  // Wynik zadania mieszka przy probie, a nie przy zadaniu: to proba wie,
  // co odpowiedzial host i kiedy.
  const test = useQuery({
    queryKey: ["job-attempts", zadanieTestu],
    queryFn: () =>
      api.get<{ items: { status?: string; detail?: WynikDNS }[] }>(
        `/api/v1/jobs/${zadanieTestu}/attempts`,
      ),
    enabled: zadanieTestu !== "",
    refetchInterval: (zapytanie) => {
      const proby = (zapytanie.state.data as { items?: { status?: string }[] } | undefined)?.items;
      const ostatnia = proby?.[proby.length - 1];
      return ostatnia?.status ? false : 2000;
    },
  });

  const proby = test.data?.items ?? [];
  const ostatniaProba = proby[proby.length - 1];
  const odpowiedzi = ostatniaProba?.detail?.queries?.queries ?? [];

  const zlec = useMutation({
    mutationFn: (tresc: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, tresc),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Job ${zadanie.id.slice(0, 8)} is waiting for approval.`
          : `Job ${zadanie.id.slice(0, 8)} has been queued.`,
      );
      if (!zadanie.requires_approval) setZadanieTestu(zadanie.id);
      setZamiar(null);
      setFormularz(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = modul.data?.payload;
  if (!modul.data) return <Pusto>This host has not reported its resolver yet.</Pusto>;

  const listaNazw = nazwy.split(",").map((nazwa) => nazwa.trim()).filter(Boolean);
  const interfejsZarzadzania = snapshot?.links?.find((link) => (link.servers ?? []).length > 0);

  return (
    <>
      <p className="podtytul">
        What the host resolves with, and who writes that configuration. A file
        owned by a service is rewritten on the next network event, so ownership
        decides whether the panel can change anything here.
      </p>

      {snapshot?.unavailable_reason && (
        <p className="ostrzezenie">
          <span>Resolver state could not be read: {snapshot.unavailable_reason}</span>
        </p>
      )}
      {snapshot?.read_only_reason && (
        <p className="ostrzezenie">
          <span>{snapshot.read_only_reason}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>Owner</th><td>{snapshot?.owner || <span className="znacznik nieznany">unknown</span>}</td></tr>
          <tr><th>Mode</th><td>{snapshot?.mode || "—"}</td></tr>
          <tr>
            <th>resolv.conf</th>
            <td>
              {snapshot?.resolv_conf}
              {snapshot?.resolv_conf_target && ` → ${snapshot.resolv_conf_target}`}
            </td>
          </tr>
          <tr><th>Servers</th><td>{(snapshot?.servers ?? []).join(", ") || "—"}</td></tr>
          <tr><th>Search domains</th><td>{(snapshot?.search_domains ?? []).join(", ") || "—"}</td></tr>
          {/* "unsupported" i "wylaczone" to dwie rozne odpowiedzi, wiec
              pokazujemy to, co powiedzial host, a nie yes/no. */}
          <tr><th>DNSSEC</th><td>{snapshot?.dnssec || <span className="znacznik nieznany">unknown</span>}</td></tr>
          <tr><th>DNS over TLS</th><td>{snapshot?.dns_over_tls || <span className="znacznik nieznany">unknown</span>}</td></tr>
        </tbody>
      </table>

      <h2>Per-link resolvers</h2>
      {!snapshot?.links?.length ? (
        <Pusto>This host does not report per-link resolvers; it has one global list.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Link</th><th>Servers</th><th>Domains</th><th>Answers other names</th><th>DNSSEC</th><th>DoT</th></tr>
          </thead>
          <tbody>
            {snapshot.links.map((link) => (
              <tr key={link.name}>
                <td>{link.name}</td>
                <td>{(link.servers ?? []).join(", ") || "—"}</td>
                <td>{(link.domains ?? []).join(", ") || "—"}</td>
                {/* Trasa domyslna rozstrzyga, ktory link odpowie na nazwe
                    spoza swoich domen - i to jest pytanie operatora. */}
                <td>
                  {link.default_route === undefined ? (
                    <span className="znacznik nieznany">unknown</span>
                  ) : link.default_route ? (
                    "yes"
                  ) : (
                    "no"
                  )}
                </td>
                <td>{link.dnssec || "—"}</td>
                <td>{link.dns_over_tls || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>Test resolution from the host</h2>
      <p className="podtytul">
        The panel sits in a different network, so its own answer says nothing
        about what this host sees. The query runs on the host.
      </p>
      <div className="filtry">
        <input
          value={nazwy}
          onChange={(e) => setNazwy(e.target.value)}
          placeholder="Names, comma separated"
          style={{ minWidth: 320 }}
        />
        <button
          onClick={() => zlec.mutate({ action: "dns.resolve.test", payload: { dns: { names: listaNazw } } })}
          disabled={!listaNazw.length || zlec.isPending}
        >
          Resolve
        </button>
        <button
          className="wtorny"
          onClick={() => setFormularz((otwarty) => !otwarty)}
          disabled={!snapshot?.writable}
          title={snapshot?.writable ? "" : snapshot?.read_only_reason}
        >
          {formularz ? "Cancel" : "Change resolver"}
        </button>
      </div>

      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {/* Odpowiedzi przychodza razem z wynikiem zadania: to fakt z hosta
          w konkretnej chwili, a nie stan, ktory da sie odswiezyc. */}
      {zadanieTestu && (
        <table>
          <thead><tr><th>Name</th><th>Addresses</th><th>Answered by</th><th>Took</th></tr></thead>
          <tbody>
            {odpowiedzi.map((zapytanie) => (
              <tr key={zapytanie.name}>
                <td>{zapytanie.name}</td>
                <td>
                  {zapytanie.addresses?.length
                    ? zapytanie.addresses.join(", ")
                    : <span className="znacznik nieznany">{zapytanie.error || "no answer"}</span>}
                </td>
                <td>{zapytanie.server || "—"}</td>
                <td>{zapytanie.took_millis} ms</td>
              </tr>
            ))}
            {!odpowiedzi.length && (
              <tr><td colSpan={4}>{ostatniaProba?.status ? "No answers." : "Running…"}</td></tr>
            )}
          </tbody>
        </table>
      )}

      {formularz && (
        <ZmianaResolvera
          domyslnyInterfejs={interfejsZarzadzania?.name ?? ""}
          domyslneSerwery={(snapshot?.servers ?? []).join(", ")}
          domyslneDomeny={(snapshot?.search_domains ?? []).map((d) => d.replace(/^~/, "")).join(", ")}
          onZamiar={setZamiar}
        />
      )}

      <SwiezoscModulu fragment={modul.data} />
      {snapshot?.observed_at && (
        <p className="zrodlo">
          Resolver read <Czas wartosc={snapshot.observed_at} />
        </p>
      )}

      {zamiar && (
        <PotwierdzenieCelu
          host={host}
          etykieta="Change resolver"
          opis={zamiar.opis}
          pracuje={zlec.isPending}
          onPotwierdz={(powod) =>
            zlec.mutate({ action: "dns.host.apply", reason: powod, payload: zamiar.payload })
          }
          onAnuluj={() => setZamiar(null)}
        />
      )}
    </>
  );
}

/**
 * Formularz zmiany resolvera. Zmiana idzie przez profil polaczenia, wiec
 * pyta o interfejs: resolver nalezy do interfejsu, a plik jest tylko tym,
 * co usluga z tego wyliczyla.
 */
function ZmianaResolvera({
  domyslnyInterfejs, domyslneSerwery, domyslneDomeny, onZamiar,
}: {
  domyslnyInterfejs: string;
  domyslneSerwery: string;
  domyslneDomeny: string;
  onZamiar: (zamiar: { opis: string; payload: Record<string, unknown> }) => void;
}) {
  const [interfejs, setInterfejs] = useState(domyslnyInterfejs);
  const [serwery, setSerwery] = useState(domyslneSerwery);
  const [domeny, setDomeny] = useState(domyslneDomeny);
  const [pomijajDHCP, setPomijajDHCP] = useState(true);
  const [okno, setOkno] = useState("120");

  const lista = (wartosc: string) =>
    wartosc.split(",").map((element) => element.trim()).filter(Boolean);

  return (
    <div className="formularz" style={{ marginBottom: 16 }}>
      <h2>Change resolver</h2>
      <p className="podtytul" style={{ margin: 0 }}>
        A host that cannot resolve names loses the directory, Kerberos and with
        them logins — so this change is armed with the same rollback timer as an
        address change.
      </p>
      <div className="filtry">
        <input value={interfejs} onChange={(e) => setInterfejs(e.target.value)} placeholder="Interface" />
        <input
          value={serwery}
          onChange={(e) => setSerwery(e.target.value)}
          placeholder="DNS servers, comma separated"
          style={{ minWidth: 260 }}
        />
        <input value={domeny} onChange={(e) => setDomeny(e.target.value)} placeholder="Search domains" />
      </div>
      <div className="filtry">
        <label className="przelacznik">
          <input type="checkbox" checked={pomijajDHCP} onChange={(e) => setPomijajDHCP(e.target.checked)} />
          Ignore DNS servers offered by DHCP
        </label>
        <input value={okno} onChange={(e) => setOkno(e.target.value)} placeholder="Rollback seconds" />
        <button
          onClick={() =>
            onZamiar({
              opis: `${interfejs} will resolve through ${lista(serwery).join(", ")}${
                lista(domeny).length ? `, searching ${lista(domeny).join(", ")}` : ""
              }. The host rolls back after ${Number(okno) || 0}s unless the agent confirms it still reaches the panel.`,
              payload: {
                dns: {
                  interface: interfejs,
                  servers: lista(serwery),
                  search_domains: lista(domeny),
                  ignore_auto_dns: pomijajDHCP,
                  rollback_seconds: Number(okno) || 0,
                },
              },
            })
          }
          disabled={!interfejs || lista(serwery).length === 0}
        >
          Apply resolver
        </button>
      </div>
    </div>
  );
}
