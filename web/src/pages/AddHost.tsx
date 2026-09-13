import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type StanKroku = "waiting" | "done" | "failed";

type KrokInstalacji = {
  key: "token" | "certificate" | "connected" | "inventory";
  state: StanKroku;
};

type Zamowienie = {
  id: string;
  description?: string;
  site: string;
  environment: string;
  kind: "agent" | "relay";
  purpose: "new" | "replace_identity" | "relay";
  max_uses: number;
  uses: number;
  status: "pending" | "enrolled" | "expired" | "revoked" | "failed";
  enrolled_host_id?: string;
  expires_at: string;
  created_by: string;
  created_at: string;
  steps?: KrokInstalacji[];
};

/** Zamowienie zaraz po utworzeniu - jedyny moment, w ktorym token istnieje. */
type NoweZamowienie = Zamowienie & { token: string };

/** Opis kroku instalacji w jezyku operatora, a nie kodu. */
const opisyKrokow: Record<KrokInstalacji["key"], string> = {
  token: "token accepted",
  certificate: "certificate issued",
  connected: "agent online",
  inventory: "inventory received",
};

/** Znak stanu kroku. Sam kolor nie wystarczy: stan musi dac sie przeczytac. */
function znakKroku(stan: StanKroku): string {
  if (stan === "done") return "✓";
  if (stan === "failed") return "✕";
  return "…";
}

/**
 * Dodanie hosta do floty.
 *
 * Ekran prowadzi przez jedna decyzje naraz i pokazuje na zywo, co host juz
 * zrobil. Token pojawia sie wylacznie po utworzeniu zamowienia i nie wraca po
 * odswiezeniu strony: jest sekretem jednorazowym, a nie polem do odczytania.
 * Panel nie sklada za operatora polecenia powloki z tokenem w srodku - token
 * wkleja sie w ukrytym pytaniu narzedzia na hoscie.
 */
export function DodajHost() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [opis, setOpis] = useState("");
  const [site, setSite] = useState("default");
  const [srodowisko, setSrodowisko] = useState("unassigned");
  const [minuty, setMinuty] = useState(15);
  const [rodzina, setRodzina] = useState<"debian" | "rpm">("debian");
  const [utworzone, setUtworzone] = useState<NoweZamowienie | null>(null);
  const [skopiowane, setSkopiowane] = useState(false);
  const [komunikat, setKomunikat] = useState("");

  const lista = useQuery({
    queryKey: ["enrollment-requests"],
    queryFn: () => api.get<{ items: Zamowienie[] }>("/api/v1/enrollment-requests"),
  });

  // Postep instalacji odswieza sie sam, dopoki cos jeszcze moze sie zmienic.
  const postep = useQuery({
    queryKey: ["enrollment-request", utworzone?.id],
    queryFn: () => api.get<Zamowienie>(`/api/v1/enrollment-requests/${utworzone?.id}`),
    enabled: !!utworzone,
    refetchInterval: (zapytanie) =>
      zapytanie.state.data?.status === "pending" ? 3000 : false,
  });

  const zamow = useMutation({
    mutationFn: () =>
      api.post<NoweZamowienie>("/api/v1/enrollment-requests", {
        description: opis,
        site,
        environment: srodowisko,
        ttl_minutes: minuty,
      }),
    onSuccess: (zamowienie) => {
      setUtworzone(zamowienie);
      setSkopiowane(false);
      setKomunikat("");
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const cofnij = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/enrollment-requests/${id}/revoke`, {}),
    onSuccess: (_wynik, id) => {
      if (utworzone?.id === id) setUtworzone(null);
      setKomunikat("Enrollment request revoked; the token no longer works.");
      queryClient.invalidateQueries({ queryKey: ["enrollment-requests"] });
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (lista.error) return <Blad error={lista.error} />;

  const stan = postep.data ?? utworzone;
  const kroki = stan?.steps ?? [];
  const hostGotowy = stan?.enrolled_host_id;
  const oczekujace = (lista.data?.items ?? []).filter((wpis) => wpis.status === "pending");

  return (
    <>
      <h1>Add host</h1>
      <p className="podtytul">
        A host joins the fleet by proving it holds a one-time token, then
        keeping the certificate the panel issues for it. The token is shown
        once, here, and never again — it is not stored in this browser and
        cannot be read back from the panel.
      </p>

      {!utworzone ? (
        <div className="formularz">
          <h2>1. What is being installed</h2>
          <label>
            What this host is for
            <input
              value={opis}
              onChange={(e) => setOpis(e.target.value)}
              placeholder="web-042, Warsaw production"
            />
          </label>
          <div className="siatka-dwie">
            <label>
              Site
              <input value={site} onChange={(e) => setSite(e.target.value)} />
            </label>
            <label>
              Environment
              <input value={srodowisko} onChange={(e) => setSrodowisko(e.target.value)} />
            </label>
          </div>
          <label>
            {/* Krotki termin jest zabezpieczeniem, a nie niewygoda: token,
                ktory lezy godzinami, jest sekretem czekajacym na wyciek. */}
            Token valid for (minutes, at most 24 h)
            <input
              type="number"
              min={1}
              max={1440}
              value={minuty}
              onChange={(e) => setMinuty(Number(e.target.value))}
            />
          </label>
          <div className="operacje">
            <button onClick={() => zamow.mutate()} disabled={zamow.isPending}>
              Create enrollment token
            </button>
          </div>
        </div>
      ) : (
        <div className="formularz">
          <h2>2. Install on the host</h2>
          <p className="zrodlo">
            Site {utworzone.site} · environment {utworzone.environment} · token expires{" "}
            <Czas wartosc={utworzone.expires_at} />
          </p>

          <div className="operacje" style={{ marginBottom: 12 }}>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(utworzone.token);
                setSkopiowane(true);
              }}
            >
              {skopiowane ? "Token copied" : "Copy token"}
            </button>
            <span className="zrodlo">
              Shown once. Paste it into the hidden prompt on the host; do not put
              it in a shell command — the command line is visible to every user
              of that machine.
            </span>
          </div>

          <div className="operacje" style={{ marginBottom: 12 }}>
            <button
              className={rodzina === "debian" ? "" : "drugorzedny"}
              onClick={() => setRodzina("debian")}
            >
              Debian / Ubuntu
            </button>
            <button
              className={rodzina === "rpm" ? "" : "drugorzedny"}
              onClick={() => setRodzina("rpm")}
            >
              Fedora / RHEL
            </button>
          </div>
          <ol className="kroki">
            <li>
              Install the agent package
              <pre>
                {rodzina === "debian"
                  ? "sudo apt-get install flotestro-agent"
                  : "sudo dnf install flotestro-agent"}
              </pre>
            </li>
            <li>
              Point it at this panel in <code>/etc/flotestro/agent.yaml</code>
              <pre>
                {`connection:\n  enrollment_url: "${window.location.origin.replace(/:\d+$/, ":8444")}"\n  gateway_urls: ["${window.location.origin.replace(/:\d+$/, ":8443")}"]`}
              </pre>
            </li>
            <li>
              Register the host and paste the token when asked
              <pre>sudo -u flotestro-agent flotestro-agentctl enroll</pre>
            </li>
            <li>
              Start the agent
              <pre>sudo systemctl start flotestro-agent.service</pre>
            </li>
          </ol>

          <h2>3. Enrollment status</h2>
          <ul className="kroki" aria-live="polite">
            {kroki.map((krok) => (
              <li key={krok.key}>
                <span className={`znacznik ${krok.state === "done" ? "ok" : krok.state === "failed" ? "uwaga" : "nieznany"}`}>
                  {znakKroku(krok.state)}
                </span>{" "}
                {opisyKrokow[krok.key]}
              </li>
            ))}
            {!kroki.length && <li className="zrodlo">waiting for the host…</li>}
          </ul>

          <div className="operacje">
            {hostGotowy && (
              <button onClick={() => navigate(`/hosts/${hostGotowy}/overview`)}>
                Open host
              </button>
            )}
            <button className="drugorzedny" onClick={() => cofnij.mutate(utworzone.id)}>
              Revoke token
            </button>
            <button className="drugorzedny" onClick={() => setUtworzone(null)}>
              Add another host
            </button>
          </div>
        </div>
      )}

      {komunikat && <p className="zrodlo" style={{ margin: "12px 0" }}>{komunikat}</p>}

      <h2>Pending installations</h2>
      {!oczekujace.length ? (
        <Pusto>No installation is waiting for a host right now.</Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>What for</th><th>Scope</th><th>Uses</th><th>Expires</th><th>Requested by</th><th></th>
            </tr>
          </thead>
          <tbody>
            {oczekujace.map((wpis) => (
              <tr key={wpis.id}>
                <td>
                  {wpis.description || "—"}
                  <div className="zrodlo">{wpis.purpose}</div>
                </td>
                <td className="zrodlo">{wpis.site} / {wpis.environment}</td>
                <td className="zrodlo">{wpis.uses} / {wpis.max_uses}</td>
                <td className="zrodlo"><Czas wartosc={wpis.expires_at} /></td>
                <td className="zrodlo">{wpis.created_by}</td>
                <td>
                  <button className="drugorzedny" onClick={() => cofnij.mutate(wpis.id)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
