import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign, CampaignTarget } from "../lib/types";
import { Blad, Pusto, StanZadania } from "../components/ui";
import { ODSTEP_OPERACJI } from "../lib/strumien";
import { useCapabilities } from "../lib/capabilities";

/**
 * Bulk Workspace: druga rownorzedna sciezka pracy obok zakladek hosta.
 *
 * Host Workspace sluzy do dokladnej pracy na jednej maszynie. Tutaj wybiera
 * sie cel, oglada odmowy i prowadzi zmiane na calej flocie. Kampania nie moze
 * byc jednym przyciskiem schowanym na liscie hostow: to jest glowny mechanizm
 * zmiany, a nie skrot.
 */
export function Bulk() {
  const [krok, setKrok] = useState(0);
  // Kampania powstaje w polowie drogi. Do tej chwili pracujemy na zamowieniu,
  // potem - na kampanii, ktora sama liczy plany i czeka na zgode.
  const [kampaniaID, setKampaniaID] = useState("");
  const [zamowienie, setZamowienie] = useState<Zamowienie>({
    nazwa: "",
    akcja: "",
    jednostka: "",
    tylkoBezpieczenstwo: true,
    site: "",
    environment: "",
    osFamily: "",
    canary: 1,
    fala: 10,
    rownolegle: 5,
    progProcent: 20,
    progLiczba: 0,
    politykaRestartu: "never",
  });

  const zmien = (zmiana: Partial<Zamowienie>) =>
    setZamowienie((poprzednie) => ({ ...poprzednie, ...zmiana }));

  const zdolnosci = useCapabilities();
  const operacje = useQuery({
    queryKey: ["actions"],
    // Katalog operacji stoi pod /api/v1/actions. Kreator pytal o adres,
    // ktorego nie ma, wiec lista operacji byla pusta od poczatku.
    queryFn: () => api.get<Collection<Operacja>>("/api/v1/actions"),
  });
  const masowe = (operacje.data?.items ?? []).filter((pozycja) => pozycja.campaign_ready);
  // Odmowy pokazujemy razem z powodem. Operacja, ktorej nie ma na liscie bez
  // slowa wyjasnienia, wyglada jak brak funkcji - a bywa granica postawiona
  // swiadomie, na przyklad odtworzenie kopii.
  const odmowy = (operacje.data?.items ?? []).filter(
    (pozycja) => pozycja.mutating && !pozycja.campaign_ready && pozycja.campaign_refusal,
  );

  const parametry = new URLSearchParams();
  if (zamowienie.site) parametry.set("site", zamowienie.site);
  if (zamowienie.environment) parametry.set("environment", zamowienie.environment);
  if (zamowienie.osFamily) parametry.set("os_family", zamowienie.osFamily);
  if (zamowienie.akcja) parametry.set("action", zamowienie.akcja);
  const podglad = useQuery({
    queryKey: ["campaign-preview", parametry.toString()],
    queryFn: () => api.get<Podglad>(`/api/v1/campaigns/preview?${parametry}`),
    enabled: Boolean(zamowienie.akcja),
  });

  const kampania = useQuery({
    queryKey: ["campaign", kampaniaID],
    queryFn: () => api.get<Campaign>(`/api/v1/campaigns/${kampaniaID}`),
    enabled: Boolean(kampaniaID),
    refetchInterval: ODSTEP_OPERACJI,
  });

  const gotowy = podglad.data?.eligible ?? 0;
  const bramki = bramkiKrokow(zamowienie, podglad.data, kampania.data);

  // Backend bez fazy planowania nie poprowadzi zadnej z tych zmian. Kreator,
  // ktory konczy sie bledem po wypelnieniu formularza, jest gorszy niz jego
  // brak razem z powodem.
  if (!zdolnosci.campaign_v2) {
    return (
      <>
        <h1>Bulk Workspace</h1>
        <Pusto>
          This installation runs operations host by host: the backend has no campaign engine,
          so there is no set of per-host plans to approve.
        </Pusto>
      </>
    );
  }

  return (
    <>
      <h1>Bulk Workspace</h1>
      <p className="podtytul">
        Choose the target, read the refusals, run the change. One host at a time lives in the
        host workspace; this is where the fleet is changed.
      </p>

      <PasekZakresu
        zamowienie={zamowienie}
        podglad={podglad.data}
        kampania={kampania.data}
      />

      <ol className="kroki-bulk">
        {KROKI.map((tytul, indeks) => (
          <li key={tytul}>
            <button
              className={indeks === krok ? "krok aktywny" : "krok"}
              onClick={() => setKrok(indeks)}
              disabled={indeks > 0 && !bramki[indeks - 1].otwarta}
            >
              <span className="numer">{indeks + 1}</span>
              <span className="tytul">{tytul}</span>
              {/* Zamknieta bramka mowi, czego brakuje. Krok wygaszony bez
                  powodu wyglada jak usterka interfejsu. */}
              {indeks > 0 && !bramki[indeks - 1].otwarta && (
                <span className="powod">{bramki[indeks - 1].powod}</span>
              )}
            </button>
          </li>
        ))}
      </ol>

      {krok === 0 && (
        <KrokZakresu
          zamowienie={zamowienie}
          zmien={zmien}
          masowe={masowe}
          odmowy={odmowy}
          podglad={podglad.data}
        />
      )}
      {krok === 1 && <KrokCelow zamowienie={zamowienie} zmien={zmien} podglad={podglad.data} />}
      {krok === 2 && <KrokKwalifikacji podglad={podglad.data} pytanie={podglad.isLoading} />}
      {krok === 3 && <KrokRozwijania zamowienie={zamowienie} zmien={zmien} celow={gotowy} />}
      {krok === 4 && (
        <KrokUtworzenia
          zamowienie={zamowienie}
          celow={gotowy}
          kampaniaID={kampaniaID}
          onUtworzona={(id) => {
            setKampaniaID(id);
            setKrok(5);
          }}
        />
      )}
      {krok === 5 && <KrokPlanow kampaniaID={kampaniaID} kampania={kampania.data} />}
      {krok === 6 && <KrokZgody kampaniaID={kampaniaID} kampania={kampania.data} />}
    </>
  );
}

type Zamowienie = {
  nazwa: string;
  akcja: string;
  jednostka: string;
  tylkoBezpieczenstwo: boolean;
  site: string;
  environment: string;
  osFamily: string;
  canary: number;
  fala: number;
  rownolegle: number;
  progProcent: number;
  progLiczba: number;
  politykaRestartu: string;
};

type Operacja = {
  action: string;
  campaign_refusal?: string;
  mutating: boolean;
  campaign_mode: string;
  campaign_ready: boolean;
};

type Grupa = { reason: string; count: number; sample: string[] };

type Podglad = {
  count: number;
  limit: number;
  eligible?: number;
  sample?: string[];
  excluded?: Grupa[];
  notes?: Grupa[];
  campaign_mode?: string;
  requires_plan?: boolean;
};

/**
 * Kroki ida w kolejnosci, w ktorej system naprawde pracuje.
 *
 * Dokument stawia plany przed polityka rozwijania. U nas plan powstaje jako
 * pierwsza faza kampanii - a kampania musi juz znac swoja polityke, bo ta
 * wchodzi do odcisku zgody. Kolejnosc jest wiec inna, i lepiej ja pokazac
 * wprost niz udawac, ze plan da sie policzyc przed zamowieniem.
 */
const KROKI = [
  "Scope",
  "Targets",
  "Eligibility",
  "Rollout",
  "Create",
  "Plans",
  "Approval & run",
];

/** Bramka przejscia: krok nastepny otwiera sie dopiero, gdy jest po co. */
type Bramka = { otwarta: boolean; powod: string };

function bramkiKrokow(
  zamowienie: Zamowienie,
  podglad?: Podglad,
  kampania?: Campaign,
): Bramka[] {
  const maAkcje = Boolean(zamowienie.akcja && zamowienie.nazwa);
  const maCele = (podglad?.count ?? 0) > 0;
  const maGotowe = (podglad?.eligible ?? 0) > 0;
  return [
    { otwarta: maAkcje, powod: "pick an operation and name the campaign" },
    { otwarta: maAkcje && maCele, powod: "the selector matches no host" },
    { otwarta: maGotowe, powod: "no matched host can run this operation" },
    { otwarta: maGotowe, powod: "no matched host can run this operation" },
    { otwarta: Boolean(kampania), powod: "the campaign does not exist yet" },
    { otwarta: Boolean(kampania && kampania.state !== "planning"), powod: "hosts are still planning" },
  ];
}

/**
 * ScopeBar: nazwa, operacja, liczba celow i odcisk migawki, przyklejone na
 * czas calego kreatora.
 *
 * Operator ma przez caly czas widziec, czego dotyczy to, co wlasnie ustawia.
 * Liczba hostow schowana dwa kroki wczesniej znaczy tyle co jej brak.
 */
function PasekZakresu({
  zamowienie,
  podglad,
  kampania,
}: {
  zamowienie: Zamowienie;
  podglad?: Podglad;
  kampania?: Campaign;
}) {
  return (
    <div className="pasek-zakresu">
      <div className="tozsamosc">
        <span className="nazwa">{zamowienie.nazwa || "unnamed campaign"}</span>
        <span className="akcja">{zamowienie.akcja || "no operation"}</span>
      </div>
      <div className="fakty">
        <span>
          targets: <strong>{podglad?.eligible ?? podglad?.count ?? 0}</strong>
          {podglad && podglad.eligible !== undefined && podglad.eligible !== podglad.count && (
            <> of {podglad.count} matched</>
          )}
        </span>
        {podglad?.campaign_mode && <span>mode: {podglad.campaign_mode}</span>}
        {kampania && (
          <>
            <span>
              state: <StanZadania stan={kampania.state} />
            </span>
            {/* Odcisk jest tym, czego dotyczy zgoda. Bez niego "zatwierdzone"
                nie mowi, co zostalo zatwierdzone. */}
            <span className="zrodlo">
              fingerprint {kampania.approval_fingerprint.slice(0, 12)}
            </span>
          </>
        )}
      </div>
    </div>
  );
}

/** Operacje, dla ktorych kreator umie zbudowac payload. */
const OPERACJE_JEDNOSTKI = ["unit.start", "unit.stop", "unit.restart", "unit.reload"];
const OPERACJE_KREATORA = [...OPERACJE_JEDNOSTKI, "packages.upgrade"];

function KrokZakresu({
  zamowienie,
  zmien,
  masowe,
  odmowy,
  podglad,
}: {
  zamowienie: Zamowienie;
  zmien: (zmiana: Partial<Zamowienie>) => void;
  masowe: Operacja[];
  odmowy: Operacja[];
  podglad?: Podglad;
}) {
  const wymagaJednostki = OPERACJE_JEDNOSTKI.includes(zamowienie.akcja);
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>1. Scope</h2>
      <p className="podtytul">
        The registry decides what may run on many hosts at once. An operation with no bulk mode is
        a deliberate refusal, not a missing screen.
      </p>
      <div className="filtry">
        <input
          placeholder="campaign name"
          value={zamowienie.nazwa}
          onChange={(e) => zmien({ nazwa: e.target.value })}
          style={{ minWidth: 240 }}
        />
        <select value={zamowienie.akcja} onChange={(e) => zmien({ akcja: e.target.value })}>
          <option value="">pick an operation…</option>
          {masowe.map((pozycja) => (
            <option
              key={pozycja.action}
              value={pozycja.action}
              disabled={!OPERACJE_KREATORA.includes(pozycja.action)}
            >
              {pozycja.action}
              {OPERACJE_KREATORA.includes(pozycja.action) ? "" : " — no bulk form yet"}
            </option>
          ))}
        </select>
        {wymagaJednostki && (
          <input
            placeholder="unit, e.g. cron.service"
            value={zamowienie.jednostka}
            onChange={(e) => zmien({ jednostka: e.target.value })}
          />
        )}
        {zamowienie.akcja === "packages.upgrade" && (
          <label>
            <input
              type="checkbox"
              checked={zamowienie.tylkoBezpieczenstwo}
              onChange={(e) => zmien({ tylkoBezpieczenstwo: e.target.checked })}
            />{" "}
            security updates only
          </label>
        )}
      </div>
      {podglad?.requires_plan && (
        <p className="podtytul">
          Every host computes its own plan first. You approve the set of plans, not one payload,
          and a host whose plan changed in the meantime refuses the change.
        </p>
      )}
      {odmowy.length > 0 && (
        <details style={{ marginTop: 12 }}>
          <summary className="podtytul">
            {odmowy.length} operations change hosts but cannot run as a campaign — with reasons
          </summary>
          <table>
            <thead><tr><th>Operation</th><th>Why not</th></tr></thead>
            <tbody>
              {odmowy.map((pozycja) => (
                <tr key={pozycja.action}>
                  <td>{pozycja.action}</td>
                  <td className="zrodlo">{pozycja.campaign_refusal}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  );
}

function KrokCelow({
  zamowienie,
  zmien,
  podglad,
}: {
  zamowienie: Zamowienie;
  zmien: (zmiana: Partial<Zamowienie>) => void;
  podglad?: Podglad;
}) {
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>2. Targets</h2>
      <p className="podtytul">
        The count comes from the database, not from the first page of a list. The snapshot is
        frozen when the campaign is created; hosts added later do not join it.
      </p>
      <div className="filtry">
        <input
          placeholder="site"
          value={zamowienie.site}
          onChange={(e) => zmien({ site: e.target.value })}
        />
        <input
          placeholder="environment"
          value={zamowienie.environment}
          onChange={(e) => zmien({ environment: e.target.value })}
        />
        <input
          placeholder="os family"
          value={zamowienie.osFamily}
          onChange={(e) => zmien({ osFamily: e.target.value })}
        />
      </div>
      <p>
        The selector matches <strong>{podglad?.count ?? 0}</strong> hosts
        {podglad && podglad.count > podglad.limit && (
          <> — more than the {podglad.limit} one campaign may carry</>
        )}
        .
      </p>
      <div className="zrodlo">{(podglad?.sample ?? []).join(", ")}</div>
    </section>
  );
}

function KrokKwalifikacji({ podglad, pytanie }: { podglad?: Podglad; pytanie: boolean }) {
  if (pytanie) return <Pusto>Checking every matched host…</Pusto>;
  const wykluczone = podglad?.excluded ?? [];
  const uwagi = podglad?.notes ?? [];
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>3. Eligibility</h2>
      <p className="podtytul">
        A host that cannot run this operation stays in the snapshot with its reason. Dropping it
        quietly would hide a decision nobody made.
      </p>
      <table>
        <thead>
          <tr><th>Bucket</th><th>Hosts</th><th>Which</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><span className="znacznik ok">eligible</span></td>
            <td>{podglad?.eligible ?? 0}</td>
            <td className="zrodlo">{(podglad?.sample ?? []).join(", ")}</td>
          </tr>
          {wykluczone.map((grupa) => (
            <tr key={grupa.reason}>
              <td><span className="znacznik blad">{nazwaPowodu(grupa.reason)}</span></td>
              <td>{grupa.count}</td>
              <td className="zrodlo">{grupa.sample.join(", ")}</td>
            </tr>
          ))}
          {/* Uwaga nie wyklucza hosta. Host offline wroci i wykona swoja
              czesc; host w kolizji poczeka na cudza blokade. */}
          {uwagi.map((grupa) => (
            <tr key={grupa.reason}>
              <td><span className="znacznik uwaga">{nazwaPowodu(grupa.reason)}</span></td>
              <td>{grupa.count}</td>
              <td className="zrodlo">{grupa.sample.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!wykluczone.length && !uwagi.length && (
        <p className="podtytul">Every matched host can run this operation.</p>
      )}
    </section>
  );
}

function nazwaPowodu(powod: string): string {
  const nazwy: Record<string, string> = {
    capability_missing: "no adapter",
    capability_unknown: "adapter unknown",
    maintenance: "in maintenance",
    quarantined: "quarantined",
    out_of_scope: "out of your scope",
    conflict: "in another campaign",
    offline: "offline",
  };
  return nazwy[powod] ?? powod;
}

function KrokRozwijania({
  zamowienie,
  zmien,
  celow,
}: {
  zamowienie: Zamowienie;
  zmien: (zmiana: Partial<Zamowienie>) => void;
  celow: number;
}) {
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>4. Rollout</h2>
      <p className="podtytul">
        Canary is wave zero. The concurrency limit says how many hosts move at once in this
        change; fleet and site budgets say how much the system carries in total, and a host
        waiting for capacity says so instead of standing still.
      </p>
      <div className="filtry">
        <label>
          canary{" "}
          <input type="number" min={0} value={zamowienie.canary}
            onChange={(e) => zmien({ canary: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          wave{" "}
          <input type="number" min={1} value={zamowienie.fala}
            onChange={(e) => zmien({ fala: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          concurrent{" "}
          <input type="number" min={1} value={zamowienie.rownolegle}
            onChange={(e) => zmien({ rownolegle: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          threshold %{" "}
          <input type="number" min={0} max={100} value={zamowienie.progProcent}
            onChange={(e) => zmien({ progProcent: +e.target.value })} style={{ width: 70 }} />
        </label>
        <label>
          threshold count{" "}
          <input type="number" min={0} value={zamowienie.progLiczba}
            onChange={(e) => zmien({ progLiczba: +e.target.value })} style={{ width: 70 }} />
        </label>
        <select value={zamowienie.politykaRestartu}
          onChange={(e) => zmien({ politykaRestartu: e.target.value })}>
          <option value="never">reboot: never</option>
          <option value="if_required">reboot: when required</option>
          <option value="always">reboot: always</option>
        </select>
      </div>
      <p className="podtytul">
        {celow} hosts, canary {zamowienie.canary}, then waves of {zamowienie.fala} with at most{" "}
        {zamowienie.rownolegle} at a time.
      </p>
    </section>
  );
}

function KrokUtworzenia({
  zamowienie,
  celow,
  kampaniaID,
  onUtworzona,
}: {
  zamowienie: Zamowienie;
  celow: number;
  kampaniaID: string;
  onUtworzona: (id: string) => void;
}) {
  const [blad, setBlad] = useState("");
  const queryClient = useQueryClient();

  const utworz = useMutation({
    mutationFn: () =>
      api.post<Campaign>("/api/v1/campaigns", {
        name: zamowienie.nazwa,
        action: zamowienie.akcja,
        reason: `bulk workspace: ${zamowienie.akcja}`,
        payload: OPERACJE_JEDNOSTKI.includes(zamowienie.akcja)
          ? { unit: { unit: zamowienie.jednostka } }
          : { package_upgrade: { security_only: zamowienie.tylkoBezpieczenstwo } },
        selector: {
          site: zamowienie.site || undefined,
          environment: zamowienie.environment || undefined,
          os_family: zamowienie.osFamily || undefined,
        },
        canary_size: zamowienie.canary,
        wave_size: zamowienie.fala,
        max_concurrent: zamowienie.rownolegle,
        failure_threshold_percent: zamowienie.progProcent,
        failure_threshold_absolute: zamowienie.progLiczba,
        reboot_policy: zamowienie.politykaRestartu,
      }),
    onSuccess: (campaign) => {
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onUtworzona(campaign.id);
    },
    onError: (error) => setBlad(error instanceof Error ? error.message : String(error)),
  });

  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>5. Create</h2>
      <p className="podtytul">
        Creating the campaign freezes the snapshot. Nothing changes on any host yet.
      </p>
      {blad && <p className="blad-strony">{blad}</p>}
      <button onClick={() => utworz.mutate()} disabled={utworz.isPending || Boolean(kampaniaID)}>
        {utworz.isPending ? "Creating…" : `Create campaign on ${celow} hosts`}
      </button>
    </section>
  );
}

function KrokPlanow({ kampaniaID, kampania }: { kampaniaID: string; kampania?: Campaign }) {
  const cele = useQuery({
    queryKey: ["campaign-targets", kampaniaID],
    queryFn: () => api.get<Collection<CampaignTarget>>(`/api/v1/campaigns/${kampaniaID}/targets`),
    enabled: Boolean(kampaniaID),
    refetchInterval: ODSTEP_OPERACJI,
  });
  if (cele.error) return <Blad error={cele.error} />;

  const planuje = kampania?.state === "planning";
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>6. Plans</h2>
      <p className="podtytul">
        {planuje
          ? "Each host is computing its own diff. Nothing is applied while this runs."
          : "Every host has its plan. The fingerprint below covers the whole set: a host whose plan changed refuses the change."}
      </p>
      <TabelaCelow cele={cele.data?.items ?? []} />
    </section>
  );
}

function KrokZgody({ kampaniaID, kampania }: { kampaniaID: string; kampania?: Campaign }) {
  const [blad, setBlad] = useState("");
  const queryClient = useQueryClient();
  const cele = useQuery({
    queryKey: ["campaign-targets", kampaniaID],
    queryFn: () => api.get<Collection<CampaignTarget>>(`/api/v1/campaigns/${kampaniaID}/targets`),
    enabled: Boolean(kampaniaID),
    refetchInterval: ODSTEP_OPERACJI,
  });
  const zatwierdz = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/campaigns/${kampaniaID}/approve`, {
        reason: "bulk workspace",
        // Zgoda niesie odcisk tego, co widac na ekranie. Kampania zmieniona
        // od jej wczytania konczy sie odmowa, a nie przeniesieniem zgody.
        approval_fingerprint: kampania?.approval_fingerprint,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["campaign", kampaniaID] }),
    onError: (error) => setBlad(error instanceof Error ? error.message : String(error)),
  });

  if (!kampania) return <Pusto>No campaign yet.</Pusto>;
  return (
    <section className="kafelek">
      <h2 style={{ marginTop: 0 }}>7. Approval and run</h2>
      <p className="podtytul">
        You are approving this operation, this payload, this list of hosts, this rollout policy
        and this set of plans - together, as one fingerprint.
      </p>
      <p className="zrodlo">fingerprint {kampania.approval_fingerprint}</p>
      {blad && <p className="blad-strony">{blad}</p>}
      {kampania.state === "awaiting_approval" ? (
        <button onClick={() => zatwierdz.mutate()} disabled={zatwierdz.isPending}>
          {zatwierdz.isPending ? "Approving..." : "Approve and start"}
        </button>
      ) : (
        <p>
          This campaign is <StanZadania stan={kampania.state} />.{" "}
          {/* Pauza i anulowanie nalezy do ekranu kampanii: tam sa opisane
              skutki, ktorych ten kreator nie powtarza. */}
          <Link to={`/campaigns/${kampania.id}`}>Pause, cancel or read the report</Link>.
        </p>
      )}
      <TabelaCelow cele={cele.data?.items ?? []} />
    </section>
  );
}

/**
 * Tabela celow z blokada. Host, ktory stoi, ma powiedziec, na co czeka:
 * na budzet, na cudza blokade zasobu, czy na powrot do sieci.
 */
function TabelaCelow({ cele }: { cele: CampaignTarget[] }) {
  if (!cele.length) return <Pusto>No targets.</Pusto>;
  return (
    <table>
      <thead>
        <tr><th>Host</th><th>Wave</th><th>State</th><th>Blocker</th><th>Message</th></tr>
      </thead>
      <tbody>
        {cele.map((cel) => (
          <tr key={cel.host_id}>
            <td>
              <Link to={`/hosts/${cel.host_id}/overview`}>
                {cel.hostname || cel.host_id.slice(0, 8)}
              </Link>
            </td>
            <td>{cel.wave}{cel.wave === 0 && " (canary)"}</td>
            <td><StanZadania stan={cel.state} /></td>
            <td>{opisBlokady(cel)}</td>
            <td>{cel.message || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** opisBlokady nazywa rodzaj przeszkody, a nie sam kod bledu. */
function opisBlokady(cel: CampaignTarget): string {
  if (!cel.error_code) return "—";
  if (cel.error_code.startsWith("budget_")) return "budget";
  if (cel.error_code === "resource_busy") return "resource lock";
  if (cel.error_code === "capability_missing") return "capability";
  if (cel.error_code === "maintenance") return "maintenance";
  return cel.error_code;
}
