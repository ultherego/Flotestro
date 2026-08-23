import { KontaHosta as Konta } from "../KontaHosta";
import { useHost } from "./wspolne";

/** Modul kont lokalnych pobiera hosta z kontekstu trasy. */
export function KontaHosta() {
  return <Konta host={useHost()} />;
}
