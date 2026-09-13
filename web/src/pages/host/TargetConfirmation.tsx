import { useState } from "react";
import type { Host } from "../../lib/types";

/**
 * Potwierdzenie operacji nieodwracalnej.
 *
 * Klikniecie nie jest wystarczajaca decyzja przy zmianie, ktorej nie da sie
 * cofnac: lista hostow bywa dluga i podobna, a okno potwierdzenia otwarte na
 * niewlasciwym wierszu wyglada tak samo jak na wlasciwym. Dlatego operator
 * przepisuje nazwe hosta i podaje powod - jedno chroni przed pomylka celu,
 * drugie zostaje w audycie.
 */
export function PotwierdzenieCelu({
  host, opis, etykieta, onPotwierdz, onAnuluj, pracuje,
}: {
  host: Host;
  opis: string;
  etykieta: string;
  onPotwierdz: (powod: string, potwierdzenie: string) => void;
  onAnuluj: () => void;
  pracuje: boolean;
}) {
  const [powod, setPowod] = useState("");
  const [potwierdzenie, setPotwierdzenie] = useState("");
  const gotowe = powod.trim().length >= 8 && potwierdzenie === host.hostname;

  return (
    <div className="formularz" style={{ marginTop: 16 }}>
      <h2>{etykieta}</h2>
      <p className="podtytul" style={{ margin: 0 }}>{opis}</p>
      {/* Cel powtorzony w oknie: operator zatwierdza konkretna maszyne. */}
      <p className="zrodlo" style={{ margin: 0 }}>
        Target: {host.hostname}
        {host.management_address ? ` · ${host.management_address}` : " · address unknown"}
        {` · ${host.site} / ${host.environment}`}
      </p>
      <label>
        Reason (at least 8 characters, kept in the audit trail)
        <input value={powod} onChange={(e) => setPowod(e.target.value)} />
      </label>
      <label>
        Type the hostname to confirm: <code>{host.hostname}</code>
        <input value={potwierdzenie} onChange={(e) => setPotwierdzenie(e.target.value)} />
      </label>
      <div className="operacje">
        <button disabled={!gotowe || pracuje} onClick={() => onPotwierdz(powod, potwierdzenie)}>
          {pracuje ? "Requesting…" : etykieta}
        </button>
        <button className="wtorny" onClick={onAnuluj} disabled={pracuje}>Cancel</button>
      </div>
    </div>
  );
}
