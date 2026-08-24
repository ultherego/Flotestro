import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Blad, Czas, Pusto } from "../components/ui";

type WersjaSekretu = {
  version: number;
  size_bytes: number;
  created_by: string;
  created_at: string;
  destroyed_at?: string;
};

type Sekret = {
  id: string;
  name: string;
  description?: string;
  current_version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  retired_at?: string;
  versions?: WersjaSekretu[];
};

/**
 * Magazyn sekretow.
 *
 * Wartosc wchodzi i nie wychodzi: przez API nie da sie jej odczytac, a jedyna
 * droga wyjscia prowadzi przez krotka dzierzawe wystawiona hostowi na czas
 * jednego zadania. Ten ekran pokazuje metadane - co istnieje, kto zalozyl,
 * kiedy obrocono - i nigdy tresci.
 */
export function Sekrety() {
  const queryClient = useQueryClient();
  const [nazwa, setNazwa] = useState("");
  const [opis, setOpis] = useState("");
  const [wartosc, setWartosc] = useState("");
  const [rozwiniety, setRozwiniety] = useState("");
  const [obrot, setObrot] = useState("");
  const [komunikat, setKomunikat] = useState("");

  const lista = useQuery({
    queryKey: ["secrets"],
    queryFn: () => api.get<{ items: Sekret[] }>("/api/v1/secrets"),
  });

  function poZmianie(tekst: string) {
    setKomunikat(tekst);
    setWartosc("");
    setObrot("");
    queryClient.invalidateQueries({ queryKey: ["secrets"] });
  }

  const zaloz = useMutation({
    mutationFn: () =>
      api.post<Sekret>("/api/v1/secrets", { name: nazwa, description: opis, value: wartosc }),
    onSuccess: (sekret) => {
      setNazwa("");
      setOpis("");
      poZmianie(`Secret ${sekret.name} created at version ${sekret.current_version}.`);
    },
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const obroc = useMutation({
    mutationFn: (cel: string) => api.post<Sekret>(`/api/v1/secrets/${cel}/rotate`, { value: obrot }),
    onSuccess: (sekret) => poZmianie(`Secret ${sekret.name} rotated to version ${sekret.current_version}.`),
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  const wycofaj = useMutation({
    mutationFn: (cel: string) => api.post<Sekret>(`/api/v1/secrets/${cel}/retire`, {}),
    onSuccess: (sekret) => poZmianie(`Secret ${sekret.name} retired; no host can be issued its value now.`),
    onError: (error) => setKomunikat(error instanceof Error ? error.message : String(error)),
  });

  if (lista.error) return <Blad error={lista.error} />;

  const sekrety = lista.data?.items ?? [];

  return (
    <>
      <h1>Secrets</h1>
      <p className="podtytul">
        Values go in and do not come out. Nothing here can read a secret back:
        the only way out is a short lease issued to one host for one job, and
        the value never appears in a job payload, in the audit trail or in
        inventory. The store is encrypted with a key kept outside the database.
      </p>

      <div className="formularz" style={{ marginBottom: 16 }}>
        <h2>New secret</h2>
        <label>
          Name (lowercase, digits, dot, dash, underscore)
          <input value={nazwa} onChange={(e) => setNazwa(e.target.value)} placeholder="repo.token" />
        </label>
        <label>
          What it is for
          <input value={opis} onChange={(e) => setOpis(e.target.value)} placeholder="token repozytorium pakietow" />
        </label>
        <label>
          Value
          <textarea
            value={wartosc}
            onChange={(e) => setWartosc(e.target.value)}
            rows={4}
            placeholder="wartosc sekretu"
          />
        </label>
        <div className="operacje">
          <button onClick={() => zaloz.mutate()} disabled={!nazwa || !wartosc || zaloz.isPending}>
            Create
          </button>
        </div>
      </div>
      {komunikat && <p className="zrodlo" style={{ marginBottom: 12 }}>{komunikat}</p>}

      {!sekrety.length ? (
        <Pusto>No secrets are stored in this installation.</Pusto>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>Version</th><th>What for</th><th>Created</th><th>State</th><th></th></tr>
          </thead>
          <tbody>
            {sekrety.map((sekret) => (
              <tr key={sekret.id}>
                <td>
                  <button
                    className="wtorny"
                    onClick={() => setRozwiniety((obecny) => (obecny === sekret.name ? "" : sekret.name))}
                  >
                    {rozwiniety === sekret.name ? "▾" : "▸"}
                  </button>{" "}
                  {sekret.name}
                  {rozwiniety === sekret.name && (
                    <div className="zrodlo">
                      {(sekret.versions ?? []).map((wersja) => (
                        <div key={wersja.version}>
                          v{wersja.version} · {wersja.size_bytes} B · {wersja.created_by} ·{" "}
                          <Czas wartosc={wersja.created_at} />
                          {wersja.destroyed_at && " · destroyed"}
                        </div>
                      ))}
                    </div>
                  )}
                </td>
                <td>{sekret.current_version}</td>
                <td>{sekret.description || "—"}</td>
                <td>
                  {sekret.created_by} · <Czas wartosc={sekret.created_at} />
                </td>
                <td>
                  {sekret.retired_at ? (
                    <span className="znacznik blad">retired</span>
                  ) : (
                    <span className="znacznik ok">issuable</span>
                  )}
                </td>
                <td>
                  {!sekret.retired_at && (
                    <div className="filtry">
                      <input
                        value={obrot}
                        onChange={(e) => setObrot(e.target.value)}
                        placeholder="new value"
                        style={{ width: 160 }}
                      />
                      <button onClick={() => obroc.mutate(sekret.name)} disabled={!obrot || obroc.isPending}>
                        Rotate
                      </button>
                      {/* Wycofanie nie kasuje historii: slad po tym, ze sekret
                          istnial, jest czescia audytu. */}
                      <button
                        className="wtorny"
                        onClick={() => wycofaj.mutate(sekret.name)}
                        disabled={wycofaj.isPending}
                      >
                        Retire
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
