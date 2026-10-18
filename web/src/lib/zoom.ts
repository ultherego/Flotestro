/**
 * How much the browser is enlarging an element: the width it is drawn at
 * over the width it is laid out at.
 *
 * On a very large screen the panel is zoomed as a whole, and a pointer's
 * position is in drawn pixels while a gap in the stylesheet is in laid-out
 * ones. Anything that divides one by the other has to know the ratio.
 */
export function zoomOf(element: Element | null | undefined): number {
  if (!element) return 1;
  const laidOut = (element as HTMLElement).offsetWidth;
  const drawn = element.getBoundingClientRect().width;
  return laidOut > 0 && drawn > 0 ? drawn / laidOut : 1;
}
