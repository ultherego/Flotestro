import type { Facet } from "../lib/types";

/**
 * The values a target field may take, offered under an input that still
 * takes free text: the sites the fleet really has are a hint, not a boundary
 * - a site with no host yet is a valid selector that matches nobody, and
 *
 * It sits here rather than in lib because it is a rendered thing with an
 * appearance of its own - a datalist the browser draws under the input -
 * and six screens hang one under a target field.
 */
export function FacetList({ id, facets }: { id: string; facets?: Facet[] }) {
  return (
    <datalist id={id}>
      {(facets ?? []).map((facet) => (
        <option key={facet.key} value={facet.key} label={`${facet.count}`} />
      ))}
    </datalist>
  );
}
