import type { Host } from "../../lib/types";
import type { Capabilities as ZdolnosciInstalacji } from "../../lib/capabilities";

/**
 * Rejestr modulow hosta. Jedno zrodlo prawdy dla zakladek, tras i przelacznika
 * hostow: gdyby kazde z nich liczylo dostepnosc osobno, zakladka mogłaby
 * prowadzic do trasy, ktorej nie ma, albo odwrotnie.
 */
export type Modul = {
  /** Segment sciezki: /hosts/:id/<segment>. Czesc kontraktu adresu. */
  segment: string;
  nazwa: string;
  /** Powod niedostepnosci albo pusty, gdy modul dziala na tym hoscie. */
  powod: (host: Host, instalacja: ZdolnosciInstalacji) => string;
};

/** Modul wylaczony w calej instalacji nie zostawia martwej trasy. */
export type ModulWidoczny = Modul & { dostepny: boolean; powod_braku: string };

const MODULY: Modul[] = [
  { segment: "overview", nazwa: "Overview", powod: () => "" },
  {
    segment: "packages",
    nazwa: "Packages",
    powod: (host) =>
      host.capabilities.apt || host.capabilities.dnf
        ? ""
        : "this host has no supported package manager",
  },
  {
    segment: "services",
    nazwa: "Services",
    powod: (host) => (host.capabilities.systemd ? "" : "this host does not use systemd"),
  },
  {
    segment: "accounts",
    nazwa: "Accounts",
    powod: (_host, instalacja) =>
      instalacja.local_users ? "" : "the local accounts module is disabled in this installation",
  },
  { segment: "identity", nazwa: "Identity", powod: () => "" },
  { segment: "jobs", nazwa: "Jobs", powod: () => "" },
  { segment: "audit", nazwa: "Audit", powod: () => "" },
];

export const MODUL_DOMYSLNY = "overview";

export function moduly(host: Host, instalacja: ZdolnosciInstalacji): ModulWidoczny[] {
  return MODULY.map((modul) => {
    const powod = modul.powod(host, instalacja);
    return { ...modul, dostepny: powod === "", powod_braku: powod };
  });
}

export function modul(segment: string): Modul | undefined {
  return MODULY.find((pozycja) => pozycja.segment === segment);
}
