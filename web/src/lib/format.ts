// Wspolne formatowanie. Kazda wartosc pokazana operatorowi ma czas
// obserwacji, a stan nieustalony nigdy nie jest rysowany jako zero.

export function relativeTime(value?: string | null): string {
  if (!value) return "nigdy";
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 0) return "za chwile";
  if (seconds < 60) return `${seconds} s temu`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min temu`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} godz. temu`;
  return `${Math.floor(seconds / 86400)} dni temu`;
}

export function absoluteTime(value?: string | null): string {
  if (!value) return "";
  return new Date(value).toLocaleString("pl-PL");
}

/**
 * Wartosc nieustalona ma wlasna reprezentacje. Rysowanie jej jako zera
 * bylo by falszywym sygnalem, ze host jest w porzadku.
 */
export function optional(value: number | boolean | null | undefined): string {
  if (value === null || value === undefined) return "nieustalone";
  if (typeof value === "boolean") return value ? "tak" : "nie";
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
