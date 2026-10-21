
/**
 * A screen the installation arranges for itself: which widgets it draws, in
 * what order and how wide each one is.
 *
 * The arrangement belongs to the installation rather than to each person. An
 * operations screen people talk to each other over ("look at the second
 * tile") stops working when everyone sees a different second tile, and a
 * per-person layout would have to be taught to every new account.
 */

export type BoardWidget = {
  key: string;
  /** Of the twelve columns. */
  width: number;
  /** In rows of the board; absent means the one row every tile starts with. */
  height?: number;
  /**
   * Taken off the screen on purpose. It stays in the arrangement so that
   * "somebody removed this" and "this did not exist when the arrangement
   * was made" remain two different answers - which is what lets a panel
   * added by an upgrade appear without undoing anybody's decision.
   */
  hidden?: boolean;
  /**
   * Where it stands, when somebody has placed it: the column it starts at
   * (0..11) and the row (0 upwards). Absent for an arrangement made by
   * ordering alone, which flows left to right and wraps - the two ways
   * coexist, so an installation that never touched the grid keeps the
   * arrangement it has.
   */
  x?: number;
  y?: number;
};

/** The columns of the grid, which is also the widest a widget may be. */
export const BOARD_COLUMNS = 12;
/** A row of the free grid, in pixels. The step a height moves by. */

/** True when this arrangement was placed on the grid rather than ordered. */
export function isPlaced(widgets: BoardWidget[]): boolean {
  return widgets.some((one) => one.x !== undefined && one.y !== undefined);
}

/**
 * Every widget given a place, so an arrangement made by ordering can be
 * picked up and moved. The flow is what the browser would have drawn:
 * left to right, wrapping when the row is full, each row as tall as the
 * tallest widget that started in it.
 */
export function placeAll(widgets: BoardWidget[]): BoardWidget[] {
  if (isPlaced(widgets)) {
    return widgets.map((one) => ({ ...one, x: one.x ?? 0, y: one.y ?? 0 }));
  }
  let x = 0;
  let y = 0;
  let tallest = 1;
  return widgets.map((one) => {
    const width = Math.min(Math.max(one.width, 1), BOARD_COLUMNS);
    const height = Math.max(one.height ?? 2, 1);
    if (x + width > BOARD_COLUMNS) {
      x = 0;
      y += tallest;
      tallest = 1;
    }
    const placed = { ...one, x, y, width, height };
    x += width;
    tallest = Math.max(tallest, height);
    return placed;
  });
}

export type StoredBoard = {
  widgets: BoardWidget[];
  present: boolean;
  updated_at?: string;
  updated_by?: string;
  revision?: number;
  reason?: string;
};

/**
 * One widget the screen can draw: how it is named when picked, and the
 * shape it ships with. The height is optional, because a screen arranged
 * by ordering alone never had one; a screen laid out on the grid says
 * what each container is worth in rows.
 */
/** `x` and `y` give a container its place on a fixed board; without them the shapes are packed into rows. */
export type BoardEntry = { key: string; title: string; width: number; height?: number; x?: number; y?: number };

/** How many rows of the board a tile may take. Its content scrolls inside. */
export const BOARD_HEIGHTS = { min: 1, max: 16 };



/**
 * What is drawn: the stored arrangement, with the widgets this panel cannot
 * draw left out, and the panel's own order when nothing is stored.
 *
 * A key the panel does not know is skipped rather than refused - that is what
 * lets a record written by a newer panel still draw on an older one - and a
 * widget the record does not carry is simply not on the screen.
 */
export function boardToDraw(
  stored: StoredBoard | undefined, catalogue: BoardEntry[], known: Set<string>,
): BoardWidget[] {
  if (!stored || !stored.present || stored.widgets.length === 0) {
    return catalogue.filter((one) => known.has(one.key)).map((one) => ({ key: one.key, width: one.width, height: one.height, x: one.x, y: one.y }));
  }
  const placed = stored.widgets.filter((one) => known.has(one.key) && !one.hidden);
  const decided = new Set(stored.widgets.map((one) => one.key));

  // A panel the stored arrangement says nothing about did not exist when
  // somebody arranged this screen: it arrived with an upgrade. Leaving it
  // out would make every panel this product ever adds invisible to every
  // installation that has arranged that screen once, and nobody would know
  // to go looking. A panel somebody removed carries hidden and stays away:
  // the two are deliberately not the same record.
  //
  // Where it goes matters as much as that it appears. At the end it would
  // be buried: a row of headline tiles added above six existing panels
  // would arrive under the tables at the bottom. So it lands beside the
  // catalogue neighbour it shipped next to - after the nearest earlier
  // panel that is on the screen, or at the front when there is none - and
  // an arrangement somebody made keeps its own order around it.
  const result = [...placed];
  for (let i = 0; i < catalogue.length; i += 1) {
    const entry = catalogue[i];
    if (!known.has(entry.key) || decided.has(entry.key)) continue;
    // After everything that ships before it and is on the screen - not
    // merely after the nearest one. With the nearest, a newcomer jumped
    // over a panel somebody had deliberately moved earlier.
    let at = 0;
    for (let before = 0; before < i; before += 1) {
      const neighbour = result.findIndex((one) => one.key === catalogue[before].key);
      if (neighbour !== -1 && neighbour + 1 > at) at = neighbour + 1;
    }
    result.splice(at, 0, { key: entry.key, width: entry.width, height: entry.height });
  }
  return result;
}
