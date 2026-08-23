import { Pusto } from "../../components/ui";
import { SwiezoscModulu, useHost, useModul } from "./wspolne";

type StanUslug = {
  failed_units: string[] | null;
  failed_units_known: boolean;
};

export function Uslugi() {
  const host = useHost();
  const modul = useModul<StanUslug>(host.id, "services");
  const wBledzie = modul.data?.payload?.failed_units ?? [];
  const znane = modul.data?.payload?.failed_units_known ?? false;

  return (
    <>
      <h2>Failed units</h2>
      {/* Nieodczytany stan nie moze wygladac jak brak jednostek w bledzie. */}
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
      <SwiezoscModulu fragment={modul.data} />
    </>
  );
}
