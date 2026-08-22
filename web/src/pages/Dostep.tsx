import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { GroupMapping, Principal } from "../lib/types";
import { Blad, Czas, Pusto } from "../components/ui";
import { CentrumCA } from "./CentrumCA";

const ROLE = [
  "viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin",
];

/**
 * Zarzadzanie dostepem do panelu.
 *
 * Te operacje przestawiaja same reguly dostepu, wiec panel wymaga swiezego
 * uwierzytelnienia i podania powodu. Powod trafia do sladu audytowego razem
 * z opisem zmiany.
 */
export function Dostep() {
  const [zakladka, setZakladka] = useState<"mapowania" | "tozsamosci" | "ca">("mapowania");
  const [ostrzezenie, setOstrzezenie] = useState<ApiError | null>(null);

  return (
    <>
      <h1>Access</h1>
      <p className="podtytul">
        Mapping of identity provider groups to roles, plus local identities.
        A group in the token grants nothing by itself - the role comes from the mapping.
      </p>

      <div className="zakladki">
        <button className={zakladka === "mapowania" ? "aktywna" : ""} onClick={() => setZakladka("mapowania")}>
          Group mappings
        </button>
        <button className={zakladka === "tozsamosci" ? "aktywna" : ""} onClick={() => setZakladka("tozsamosci")}>
          Identities
        </button>
        <button className={zakladka === "ca" ? "aktywna" : ""} onClick={() => setZakladka("ca")}>
          Fleet CA
        </button>
      </div>

      {zakladka === "ca" && <Ostrzezenie blad={ostrzezenie} zamknij={() => setOstrzezenie(null)} />}
      {zakladka === "mapowania" && <Mapowania />}
      {zakladka === "tozsamosci" && <Tozsamosci />}
      {zakladka === "ca" && <CentrumCA zglosBlad={setOstrzezenie} />}
    </>
  );
}

function Mapowania() {
  const queryClient = useQueryClient();
  const [ostrzezenie, setOstrzezenie] = useState<ApiError | null>(null);
  const [formularz, setFormularz] = useState(false);
  const [grupa, setGrupa] = useState("");
  const [rola, setRola] = useState("viewer");
  const [site, setSite] = useState("");
  const [srodowisko, setSrodowisko] = useState("");
  const [powod, setPowod] = useState("");

  const lista = useQuery({
    queryKey: ["group-mappings"],
    queryFn: () => api.get<Collection<GroupMapping>>("/api/v1/group-mappings"),
    retry: false,
  });

  const odswiez = () => queryClient.invalidateQueries({ queryKey: ["group-mappings"] });

  const dodaj = useMutation({
    mutationFn: () =>
      api.post<GroupMapping>("/api/v1/group-mappings", {
        group_name: grupa.trim(), role: rola,
        site: site.trim(), environment: srodowisko.trim(), reason: powod.trim(),
      }),
    onSuccess: () => { setFormularz(false); setGrupa(""); setPowod(""); odswiez(); },
    onError: (blad) => setOstrzezenie(blad instanceof ApiError ? blad : null),
  });

  const usun = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/group-mappings/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: odswiez,
    onError: (blad) => setOstrzezenie(blad instanceof ApiError ? blad : null),
  });

  if (lista.error instanceof ApiError && lista.error.forbidden) {
    return <Pusto>You do not have permission to manage access.</Pusto>;
  }
  if (lista.error) return <Blad error={lista.error} />;

  return (
    <>
      <Ostrzezenie blad={ostrzezenie} zamknij={() => setOstrzezenie(null)} />

      {lista.data?.items.length ? (
        <table>
          <thead>
            <tr><th>Group</th><th>Role</th><th>Scope</th><th>Added by</th><th>When</th><th /></tr>
          </thead>
          <tbody>
            {lista.data.items.map((mapowanie) => (
              <tr key={mapowanie.id}>
                <td>{mapowanie.group_name}</td>
                <td>{mapowanie.role}</td>
                <td className="zrodlo">
                  {mapowanie.site || "*"} / {mapowanie.environment || "*"}
                </td>
                <td className="zrodlo">{mapowanie.created_by}</td>
                <td><Czas wartosc={mapowanie.created_at} /></td>
                <td>
                  <button
                    onClick={() => {
                      const reason = window.prompt(
                        `Reason for removing the group mapping ${mapowanie.group_name} (min. 8 characters):`,
                      );
                      if (reason) usun.mutate({ id: mapowanie.id, reason });
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Pusto>No mappings. Without them nobody gets a role from the identity provider.</Pusto>
      )}

      {formularz ? (
        <div className="formularz" style={{ marginTop: 24 }}>
          <h2>New mapping</h2>
          <label>Identity provider group
            <input value={grupa} onChange={(z) => setGrupa(z.target.value)} placeholder="flotestro-operators" />
          </label>
          <label>Role
            <select value={rola} onChange={(z) => setRola(z.target.value)}>
              {ROLE.map((nazwa) => <option key={nazwa} value={nazwa}>{nazwa}</option>)}
            </select>
          </label>
          <label>Site (empty = all)
            <input value={site} onChange={(z) => setSite(z.target.value)} placeholder="lab" />
          </label>
          <label>Environment (empty = all)
            <input value={srodowisko} onChange={(z) => setSrodowisko(z.target.value)} placeholder="test" />
          </label>
          <label>Reason for the change
            <input value={powod} onChange={(z) => setPowod(z.target.value)} placeholder="e.g. new on-call team" />
          </label>
          <div className="operacje">
            <button disabled={!grupa.trim() || powod.trim().length < 8 || dodaj.isPending}
                    onClick={() => dodaj.mutate()}>
              Dodaj mapowanie
            </button>
            <button onClick={() => setFormularz(false)}>Cancel</button>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: 24 }}>
          <button onClick={() => setFormularz(true)}>Add mapping</button>
        </div>
      )}
    </>
  );
}

function Tozsamosci() {
  const { data, error } = useQuery({
    queryKey: ["principals"],
    queryFn: () => api.get<Collection<Principal>>("/api/v1/principals"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Pusto>You do not have permission to manage access.</Pusto>;
  }
  if (error) return <Blad error={error} />;
  if (!data?.items.length) return <Pusto>No identities.</Pusto>;

  return (
    <table>
      <thead><tr><th>Subject</th><th>Name</th><th>Kind</th><th>Roles and scopes</th></tr></thead>
      <tbody>
        {data.items.map((tozsamosc) => (
          <tr key={tozsamosc.id}>
            <td>{tozsamosc.subject}</td>
            <td>{tozsamosc.display_name || "—"}</td>
            <td className="zrodlo">{tozsamosc.kind}</td>
            <td>
              {tozsamosc.bindings.length === 0
                ? <span className="zrodlo">brak przypisan</span>
                : tozsamosc.bindings.map((wiazanie, indeks) => (
                    <div key={indeks}>
                      {wiazanie.role}
                      <span className="zrodlo">
                        {" "}{wiazanie.scope.site || "*"} / {wiazanie.scope.environment || "*"}
                      </span>
                    </div>
                  ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Odmowa z powodu nieswiezego uwierzytelnienia nie jest bledem aplikacji:
 * panel ma zaproponowac ponowne logowanie i wrocic w to samo miejsce.
 */
function Ostrzezenie({ blad, zamknij }: { blad: ApiError | null; zamknij: () => void }) {
  if (!blad) return null;

  if (blad.code === "reauthentication_required") {
    return (
      <div className="ostrzezenie">
        <div>
          <strong>Re-authentication required.</strong> {blad.message}
        </div>
        <div className="operacje">
          <button
            onClick={() => {
              const cel = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${cel}`;
            }}
          >
            Sign in again
          </button>
          <button onClick={zamknij}>Close</button>
        </div>
      </div>
    );
  }
  return (
    <div className="ostrzezenie">
      <div>{blad.message}</div>
      <div className="operacje"><button onClick={zamknij}>Close</button></div>
    </div>
  );
}
