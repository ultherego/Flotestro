import type { Capability, Host } from "../../lib/types";
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
  /**
   * Modul inwentarza, z ktorego zakladka zyje. Brak znaczy, ze zakladka nie
   * czyta inwentarza (Jobs, Audit) albo czyta go w calosci (Overview) - i ze
   * odswiezenie z tej zakladki obejmuje caly host.
   */
  inwentarz?: string;
};

/** Modul wylaczony w calej instalacji nie zostawia martwej trasy. */
export type ModulWidoczny = Modul & { dostepny: boolean; powod_braku: string };

export function zdolnosc(host: Host, nazwa: string): Capability | undefined {
  return (host.capabilities ?? []).find((pozycja) => pozycja.name === nazwa);
}

/**
 * Modul dziala, gdy dziala ktorykolwiek z adapterow, ktore go obsluguja.
 * Gdy nie dziala zaden, operator dostaje powody wszystkich - bo kazdy z nich
 * jest osobna odpowiedzia na pytanie "dlaczego tego tu nie ma".
 */
function wymaga(...nazwy: string[]) {
  return (host: Host): string => {
    const adaptery = nazwy.map((nazwa) => zdolnosc(host, nazwa));
    if (adaptery.some((adapter) => adapter?.available)) return "";
    const powody = adaptery
      .map((adapter, i) => adapter?.reason || `the host does not report ${nazwy[i]}`)
      .filter((powod, i, lista) => lista.indexOf(powod) === i);
    return powody.join("; ");
  };
}

const MODULY: Modul[] = [
  { segment: "overview", nazwa: "Overview", powod: () => "" },
  { segment: "packages", nazwa: "Packages", powod: wymaga("packages.apt", "packages.dnf"), inwentarz: "packages" },
  { segment: "services", nazwa: "Services", powod: wymaga("systemd"), inwentarz: "services" },
  { segment: "processes", nazwa: "Processes", powod: () => "" },
  { segment: "containers", nazwa: "Containers", powod: wymaga("docker"), inwentarz: "containers" },
  { segment: "compose", nazwa: "Compose", powod: wymaga("docker.compose"), inwentarz: "containers" },
  { segment: "logs", nazwa: "Logs", powod: wymaga("journald") },
  { segment: "schedules", nazwa: "Schedules", powod: wymaga("schedules"), inwentarz: "schedules" },
  { segment: "network", nazwa: "Network", powod: wymaga("network"), inwentarz: "network" },
  { segment: "dns", nazwa: "DNS", powod: wymaga("dns"), inwentarz: "dns" },
  { segment: "firewall", nazwa: "Firewall", powod: wymaga("firewall"), inwentarz: "firewall" },
  { segment: "storage", nazwa: "Storage", powod: wymaga("storage"), inwentarz: "storage" },
  { segment: "ssh", nazwa: "SSH", powod: wymaga("sshd"), inwentarz: "ssh" },
  { segment: "kernel", nazwa: "Kernel", powod: wymaga("kernel"), inwentarz: "kernel" },
  { segment: "time", nazwa: "Time", powod: wymaga("time"), inwentarz: "time" },
  { segment: "power", nazwa: "Power", powod: wymaga("systemd"), inwentarz: "power" },
  { segment: "security", nazwa: "Security", powod: wymaga("security"), inwentarz: "security" },
  { segment: "certificates", nazwa: "Certificates", powod: wymaga("certificates"), inwentarz: "certificates" },
  { segment: "backups", nazwa: "Backups", powod: wymaga("backup"), inwentarz: "backups" },
  { segment: "monitoring", nazwa: "Monitoring", powod: wymaga("monitoring") },
  {
    segment: "vulnerabilities",
    nazwa: "Vulnerabilities",
    powod: wymaga("packages.apt", "packages.dnf"),
    // Podatnosci panel liczy z listy pakietow, wiec swiezosc bierze sie stad.
    inwentarz: "packages",
  },
  { segment: "files", nazwa: "Files", powod: wymaga("files.managed"), inwentarz: "files" },
  {
    segment: "accounts",
    nazwa: "Accounts",
    // Konta lokalne wylacza sie w calej instalacji, a nie na hoscie.
    powod: (_host, instalacja) =>
      instalacja.local_users ? "" : "the local accounts module is disabled in this installation",
    inwentarz: "accounts",
  },
  { segment: "identity", nazwa: "Identity", powod: () => "", inwentarz: "identity" },
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
