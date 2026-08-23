import { Pusto } from "../../components/ui";
import { useHost, useInventory } from "./wspolne";

export function Uslugi() {
  const host = useHost();
  const inventory = useInventory(host.id);
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
