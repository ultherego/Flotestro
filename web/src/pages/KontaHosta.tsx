import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Host, Job, LocalAccount } from "../lib/types";
import { Blad, Czas, Pusto } from "../components/ui";

/**
 * Konta lokalne hosta.
 *
 * Modul jest przeznaczony dla instalacji bez katalogu tozsamosci. Tam, gdzie
 * dziala FreeIPA albo inny katalog, konta ludzi pochodza z katalogu i panel
 * ich nie duplikuje - widok pokazuje wtedy, ze konto jest z katalogu, i nie
 * proponuje zmian, ktore nalezy zrobic w katalogu.
 *
 * Dane pochodza z ostatniego raportu agenta, a nie z odpytania hosta na
 * zadanie; stad znacznik obserwacji przy tabeli.
 */
export function KontaHosta({ host }: { host: Host }) {
  const [pokazSystemowe, setPokazSystemowe] = useState(false);
  const zapytanie = useQuery({
    queryKey: ["local-accounts", host.id, pokazSystemowe],
    queryFn: () =>
      api.get<{ accounts: LocalAccount[] }>(
        `/api/v1/hosts/${host.id}/local-accounts${pokazSystemowe ? "?source=system" : ""}`,
      ),
    retry: false,
  });

  if (zapytanie.error instanceof ApiError && zapytanie.error.forbidden) {
    return <Pusto>Brak uprawnienia do odczytu kont tego hosta.</Pusto>;
  }
  if (zapytanie.error) return <Blad error={zapytanie.error} />;

  const konta = zapytanie.data?.accounts ?? [];

  return (
    <>
      <p className="podtytul">
        Konta widziane na hoscie przy ostatnim raporcie agenta.{" "}
        {konta.length > 0 && <>Obserwacja: <Czas wartosc={konta[0].observed_at} />.</>}
      </p>

      <label className="przelacznik">
        <input
          type="checkbox"
          checked={pokazSystemowe}
          onChange={(zdarzenie) => setPokazSystemowe(zdarzenie.target.checked)}
        />
        Pokaz konta systemowe
      </label>

      {konta.length === 0 ? (
        <Pusto>
          {pokazSystemowe
            ? "Host nie zgłosil kont systemowych."
            : "Host nie zgłosil jeszcze kont uzytkownikow."}
        </Pusto>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Konto</th><th>UID</th><th>Zrodlo</th><th>Dostep</th>
              <th>Klucze SSH</th><th>Grupy</th><th>Operacje</th>
            </tr>
          </thead>
          <tbody>
            {konta.map((konto) => (
              <Wiersz key={konto.name} host={host} konto={konto} />
            ))}
          </tbody>
        </table>
      )}

      <NoweKonto host={host} />
    </>
  );
}

function Wiersz({ host, konto }: { host: Host; konto: LocalAccount }) {
  const [klucze, setKlucze] = useState<string | null>(null);
  const zlec = useZlecenie(host);
  const zKatalogu = konto.source === "directory";

  return (
    <>
      <tr>
        <td>
          {konto.name}
          {konto.gecos && <div className="zrodlo">{konto.gecos}</div>}
        </td>
        <td>{konto.uid}</td>
        <td>{nazwaZrodla(konto.source)}</td>
        <td><Dostep konto={konto} /></td>
        <td>
          {konto.ssh_keys.length === 0 ? (
            <span className="zrodlo">brak</span>
          ) : (
            konto.ssh_keys.map((klucz) => (
              <div key={klucz.fingerprint} title={klucz.fingerprint}>
                {klucz.type || "?"} · {klucz.fingerprint.replace(/^SHA256:/, "").slice(0, 12)}…
                {klucz.comment && <span className="zrodlo"> {klucz.comment}</span>}
              </div>
            ))
          )}
        </td>
        <td className="zrodlo">{konto.groups.join(", ") || "—"}</td>
        <td>
          {zKatalogu ? (
            // Zmiana konta z katalogu nalezy do katalogu. Lokalna zmiana
            // rozjechalaby stan miedzy hostami przy najblizszej synchronizacji.
            <span className="zrodlo">zarzadzane przez katalog</span>
          ) : (
            <div className="operacje">
              {konto.locked === true ? (
                <button onClick={() => zlec.mutate({ akcja: "localuser.unlock", nazwa: konto.name })}>
                  Odblokuj
                </button>
              ) : (
                <button onClick={() => zlec.mutate({ akcja: "localuser.lock", nazwa: konto.name })}>
                  Zablokuj
                </button>
              )}
              <button onClick={() => setKlucze(klucze === null ? "" : null)}>Klucze SSH</button>
            </div>
          )}
        </td>
      </tr>

      {klucze !== null && (
        <tr>
          <td colSpan={7}>
            <div className="formularz">
              <p className="podtytul">
                Pelna lista kluczy konta {konto.name}, po jednym w wierszu. Zapisanie pustej
                listy odbiera dostep kluczem SSH.
              </p>
              <textarea
                rows={4}
                value={klucze}
                placeholder="ssh-ed25519 AAAA… jan@stacja"
                onChange={(zdarzenie) => setKlucze(zdarzenie.target.value)}
              />
              <div className="operacje">
                <button
                  onClick={() =>
                    zlec.mutate({
                      akcja: "localuser.sshkeys.set",
                      nazwa: konto.name,
                      ssh_keys: klucze.split("\n").map((linia) => linia.trim()).filter(Boolean),
                    })
                  }
                >
                  Zapisz klucze
                </button>
                <button onClick={() => setKlucze(null)}>Anuluj</button>
              </div>
            </div>
          </td>
        </tr>
      )}

      {zlec.komunikat && (
        <tr>
          <td colSpan={7} className="zrodlo">{zlec.komunikat}</td>
        </tr>
      )}
    </>
  );
}

/**
 * Dostep laczy trzy niezalezne fakty: blokade, haslo i klucze. Zaden z nich
 * osobno nie odpowiada na pytanie, czy ktos moze wejsc na host.
 */
function Dostep({ konto }: { konto: LocalAccount }) {
  if (konto.locked === null) {
    return <span className="znacznik nieznany">nieustalone</span>;
  }
  if (konto.locked) return <span className="znacznik blad">zablokowane</span>;
  if (konto.ssh_keys.length > 0) {
    return <span className="znacznik">klucz SSH</span>;
  }
  if (konto.password_set === true) return <span className="znacznik">haslo</span>;
  if (konto.password_set === false) {
    // Konto bez hasla i bez klucza jest niedostepne dla nikogo. To zwykle
    // slad po polowicznym odebraniu dostepu i warto to widziec.
    return <span className="znacznik blad">brak dostepu</span>;
  }
  return <span className="znacznik nieznany">nieustalone</span>;
}

function NoweKonto({ host }: { host: Host }) {
  const [otwarty, setOtwarty] = useState(false);
  const [nazwa, setNazwa] = useState("");
  const [opis, setOpis] = useState("");
  const [grupy, setGrupy] = useState("");
  const [klucze, setKlucze] = useState("");
  const zlec = useZlecenie(host);

  if (!otwarty) {
    return (
      <div style={{ marginTop: 24 }}>
        <button onClick={() => setOtwarty(true)}>Zaloz konto lokalne</button>
        {zlec.komunikat && <p className="zrodlo" style={{ marginTop: 10 }}>{zlec.komunikat}</p>}
      </div>
    );
  }

  return (
    <div className="formularz" style={{ marginTop: 24 }}>
      <h2>Nowe konto lokalne</h2>
      <p className="podtytul">
        Konto powstaje bez hasla; dostep daje wylacznie klucz SSH. Panel nie
        przechowuje ani nie przesyla hasel.
      </p>
      <label>Nazwa
        <input value={nazwa} onChange={(z) => setNazwa(z.target.value)} placeholder="kowalski" />
      </label>
      <label>Opis
        <input value={opis} onChange={(z) => setOpis(z.target.value)} placeholder="Jan Kowalski" />
      </label>
      <label>Grupy dodatkowe
        <input value={grupy} onChange={(z) => setGrupy(z.target.value)} placeholder="sudo, adm" />
      </label>
      <label>Klucze publiczne SSH, po jednym w wierszu
        <textarea rows={3} value={klucze} onChange={(z) => setKlucze(z.target.value)} />
      </label>
      <div className="operacje">
        <button
          disabled={!nazwa.trim()}
          onClick={() =>
            zlec.mutate({
              akcja: "localuser.create",
              nazwa: nazwa.trim(),
              gecos: opis.trim(),
              groups: grupy.split(",").map((g) => g.trim()).filter(Boolean),
              ssh_keys: klucze.split("\n").map((k) => k.trim()).filter(Boolean),
              create_home: true,
            })
          }
        >
          Zlec zalozenie konta
        </button>
        <button onClick={() => setOtwarty(false)}>Anuluj</button>
      </div>
      {zlec.komunikat && <p className="zrodlo">{zlec.komunikat}</p>}
    </div>
  );
}

type Zlecenie = {
  akcja: string;
  nazwa: string;
  gecos?: string;
  groups?: string[];
  ssh_keys?: string[];
  create_home?: boolean;
};

/**
 * Zlecenie operacji tworzy plan, a nie natychmiastowa zmiane: operacja
 * mutujaca domyslnie czeka na zatwierdzenie.
 */
function useZlecenie(host: Host) {
  const queryClient = useQueryClient();
  const [komunikat, setKomunikat] = useState("");

  const mutacja = useMutation({
    mutationFn: ({ akcja, ...reszta }: Zlecenie) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: akcja,
        payload: {
          local_user: {
            name: reszta.nazwa,
            gecos: reszta.gecos || undefined,
            groups: reszta.groups,
            ssh_keys: reszta.ssh_keys,
            create_home: reszta.create_home,
          },
        },
      }),
    onSuccess: (zadanie) => {
      setKomunikat(
        zadanie.requires_approval
          ? `Zadanie ${zadanie.id.slice(0, 8)} czeka na zatwierdzenie.`
          : `Zadanie ${zadanie.id.slice(0, 8)} trafilo do kolejki. Lista odswiezy sie po nastepnym raporcie agenta.`,
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (blad) => setKomunikat(blad instanceof Error ? blad.message : String(blad)),
  });

  return { mutate: mutacja.mutate, komunikat };
}

function nazwaZrodla(zrodlo: LocalAccount["source"]) {
  switch (zrodlo) {
    case "local": return "lokalne";
    case "directory": return "katalog";
    case "system": return "systemowe";
    default: return "nieustalone";
  }
}
