// Wspolne formatowanie. Kazda wartosc pokazana operatorowi ma czas
// obserwacji, a stan nieustalony nigdy nie jest rysowany jako zero.

export function relativeTime(value?: string | null): string {
  if (!value) return "never";
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 0) return "in a moment";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Czas bezwzgledny w formacie ISO ze strefa lokalna przegladarki.
 *
 * Format zalezny od jezyka przegladarki rozjezdzalby sie miedzy operatorami
 * ogladajacymi ten sam incydent, a kolejnosc dnia i miesiaca bywa w nim
 * odwrotna. Slad operacyjny musi czytac sie tak samo u wszystkich.
 */
export function absoluteTime(value?: string | null): string {
  if (!value) return "";
  const date = new Date(value);
  const pad = (liczba: number) => String(liczba).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * Wartosc nieustalona ma wlasna reprezentacje. Rysowanie jej jako zera
 * bylo by falszywym sygnalem, ze host jest w porzadku.
 */
export function optional(value: number | boolean | null | undefined): string {
  if (value === null || value === undefined) return "unknown";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

export function bytes(value?: number): string {
  if (!value) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}
