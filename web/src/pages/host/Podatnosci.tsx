import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Blad, Czas, Pusto } from "../../components/ui";
import { useHost } from "./wspolne";

type Ustalenie = {
  provider: string;
  advisory_id: string;
  cve_ids?: string[];
  source_package?: string;
  binary_package?: string;
  architecture?: string;
  installed_version?: string;
  fixed_version?: string;
  state: string;
  reason_code?: string;
  remediation: string;
  vendor_severity?: string;
  comparator_version?: string;
  evaluated_at: string;
};

type StanOceny = {
  distribution?: string;
  release?: string;
  provider?: string;
  snapshot_digest?: string;
  inventory_digest?: string;
  packages_total: number;
  packages_covered: number;
  affected: number;
  affected_fixable: number;
  affected_no_fix: number;
  unknown: number;
  coverage_reason?: string;
  evaluated_at?: string;
};

type StanListy = {
  digest?: string;
  package_count: number;
  collected_at?: string;
  unavailable_reason?: string;
};

type Snapshot = {
  provider: string;
  digest: string;
  advisory_count: number;
  releases?: string[];
  fetched_at: string;
  error?: string;
};

type Raport = {
  host_id: string;
  state: StanOceny;
  findings: Ustalenie[];
  package_state: StanListy;
  snapshot?: Snapshot;
  snapshot_stale: boolean;
  coverage_percent: number;
};

/** Powody, dla ktorych ocena jest niepelna - w jezyku operatora, nie kodow. */
const powody: Record<string, string> = {
  feed_missing: "no security feed for this distribution",
  feed_stale: "the feed is older than the policy allows",
  release_unsupported: "this release is not covered by the feed",
  package_origin_unknown: "the package does not come from the distribution",
  source_package_unknown: "the source package is unknown",
  vendor_investigating: "the vendor has not decided yet",
  version_unparseable: "the version cannot be compared",
  distribution_eol: "this release is past end of life",
  package_list_missing: "the panel has not collected the package list yet",
  package_list_stale: "the package list is older than what the host reports",
};

function opisPowodu(kod?: string) {
  if (!kod) return "";
  return powody[kod] ?? kod;
}

function ZnacznikWagi({ waga }: { waga?: string }) {
  const klasa =
    waga === "critical" ? "blad" : waga === "high" ? "blad"
      : waga === "medium" ? "uwaga" : waga === "low" || waga === "unimportant" ? "" : "nieznany";
  return <span className={`znacznik ${klasa}`}>{waga || "unrated"}</span>;
}

/**
 * Podatnosci hosta.
 *
 * Rozstrzyga tracker producenta dystrybucji: to on wie, ktora wersja zawiera
 * poprawke, bo poprawki sa backportowane i wedlug numeracji upstream wygladaja
 * na podatne. Panel niczego nie zgaduje - liczba znalezisk stoi tu obok
 * pokrycia, bo bez niego nie znaczy nic: host, ktorego feed nie obejmuje,
 * i host bez podatnosci maja tak samo zero na liczniku.
 */
export function Podatnosci() {
  const host = useHost();
  const queryClient = useQueryClient();
  const [filtr, setFiltr] = useState<"do-zalatania" | "bez-poprawki" | "nieznane">("do-zalatania");
  const [komunikat, setKomunikat] = useState("");

  const raport = useQuery({
    queryKey: ["vulnerabilities", host.id],
    queryFn: () => api.get<Raport>(`/api/v1/hosts/${host.id}/vulnerabilities`),
    retry: false,
  });

  const odswiez = useMutation({
    mutationFn: () =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.list", payload: {},
      }),
    onSuccess: (zadanie) => {
      setKomunikat(`Job ${zadanie.id.slice(0, 8)} reads the package list; the assessment follows.`);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (raport.error) return <Blad error={raport.error} />;
  const dane = raport.data;
  const stan = dane?.state;
  const ustalenia = dane?.findings ?? [];

  const widoczne = ustalenia.filter((pozycja) => {
    if (filtr === "nieznane") return pozycja.state === "unknown";
    if (filtr === "bez-poprawki") return pozycja.state === "affected" && !pozycja.fixed_version;
    return pozycja.state === "affected" && !!pozycja.fixed_version;
  });

  return (
    <>
      <p className="podtytul">
        What the distribution's own security tracker says about the packages on
        this host. Fixes are backported, so upstream version ranges cannot
        answer this question — only the vendor can. Where the vendor says
        nothing, the panel says "not known", never "clean".
      </p>

      <div className="filtry">
        <span className="znacznik blad">{stan?.affected_fixable ?? 0} fixable</span>
        <span className="znacznik uwaga">{stan?.affected_no_fix ?? 0} no fix from vendor</span>
        <span className="znacznik nieznany">{stan?.unknown ?? 0} not established</span>
        <span className={`znacznik ${(dane?.coverage_percent ?? 0) >= 99 ? "ok" : "uwaga"}`}>
          {Math.round(dane?.coverage_percent ?? 0)}% of packages covered
        </span>
        <button className="wtorny" disabled={odswiez.isPending || host.connection_state !== "online"}
                onClick={() => odswiez.mutate()}>
          Re-read packages
        </button>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {stan?.coverage_reason && (
        <p className="ostrzezenie">
          <span>
            This assessment is incomplete: {opisPowodu(stan.coverage_reason)}. Zero
            findings here does not mean the host is clean.
          </span>
        </p>
      )}
      {dane?.snapshot_stale && dane.snapshot && (
        <p className="ostrzezenie">
          <span>
            The security data was last fetched <Czas wartosc={dane.snapshot.fetched_at} /> —
            older than the policy allows. The assessment still uses it, because
            yesterday's data beats none.
          </span>
        </p>
      )}

      <div className="filtry">
        {(["do-zalatania", "bez-poprawki", "nieznane"] as const).map((klucz) => (
          <button key={klucz} className={filtr === klucz ? "" : "wtorny"} onClick={() => setFiltr(klucz)}>
            {klucz === "do-zalatania" ? "Fixable" : klucz === "bez-poprawki" ? "No fix" : "Not established"}
          </button>
        ))}
      </div>

      {!widoczne.length ? (
        <Pusto>
          {filtr === "do-zalatania"
            ? "Nothing here can be closed by installing an update."
            : filtr === "bez-poprawki"
              ? "The vendor has published a fix for everything it knows about here."
              : "Everything on this host could be decided one way or the other."}
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Severity</th><th>Advisory</th><th>Package</th>
              <th>Installed</th><th>Fixed in</th><th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {widoczne.slice(0, 300).map((pozycja, indeks) => (
              <tr key={`${pozycja.advisory_id}-${pozycja.binary_package}-${pozycja.installed_version}-${indeks}`}>
                <td><ZnacznikWagi waga={pozycja.vendor_severity} /></td>
                <td>
                  {pozycja.advisory_id}
                  {pozycja.cve_ids?.length ? (
                    <div className="zrodlo">{pozycja.cve_ids.join(", ")}</div>
                  ) : null}
                </td>
                <td>
                  {pozycja.binary_package}
                  {pozycja.source_package && pozycja.source_package !== pozycja.binary_package && (
                    <div className="zrodlo">source: {pozycja.source_package}</div>
                  )}
                </td>
                <td className="zrodlo">{pozycja.installed_version}</td>
                <td className="zrodlo">
                  {pozycja.fixed_version || <span className="znacznik uwaga">no fix</span>}
                </td>
                <td>
                  {pozycja.state === "unknown" ? (
                    <span className="znacznik nieznany">{opisPowodu(pozycja.reason_code)}</span>
                  ) : pozycja.remediation === "available" ? (
                    <span className="znacznik ok">in this host's repositories</span>
                  ) : pozycja.remediation === "unavailable" ? (
                    <span className="znacznik uwaga">vendor has no fix</span>
                  ) : (
                    <span className="znacznik">plan an update to find out</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {widoczne.length > 300 && (
        <p className="zrodlo">
          Showing the first 300 of {widoczne.length}. The counts above cover all of them.
        </p>
      )}

      <h2>What decided this</h2>
      <table>
        <tbody>
          <tr>
            <td>Distribution</td>
            <td>{stan?.distribution} {stan?.release}</td>
          </tr>
          <tr>
            <td>Security data</td>
            <td>
              {dane?.snapshot
                ? <>
                    {dane.snapshot.provider} · {dane.snapshot.advisory_count} advisories ·
                    fetched <Czas wartosc={dane.snapshot.fetched_at} />
                    <div className="zrodlo">{dane.snapshot.digest.slice(0, 16)}</div>
                  </>
                : <span className="znacznik nieznany">none</span>}
            </td>
          </tr>
          <tr>
            <td>Package list</td>
            <td>
              {dane?.package_state.package_count ?? 0} packages,
              read <Czas wartosc={dane?.package_state.collected_at} />
              {dane?.package_state.unavailable_reason && (
                <div className="zrodlo">{dane.package_state.unavailable_reason}</div>
              )}
            </td>
          </tr>
          <tr>
            <td>Assessed</td>
            <td>
              <Czas wartosc={stan?.evaluated_at} />
              {ustalenia[0]?.comparator_version && (
                <div className="zrodlo">version rules: {ustalenia[0].comparator_version}</div>
              )}
            </td>
          </tr>
        </tbody>
      </table>
    </>
  );
}
