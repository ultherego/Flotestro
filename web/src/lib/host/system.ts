/**
 * What the machine is, said in words: the reason a fact is missing, an
 * uptime, a processor layout, and the page an adapter's name leads to.
 *
 * All four are read off what the host reported and nothing else, so the
 * host's system tab and its overview say the same thing about the same
 * machine whichever panel draws them.
 */

/**
 * The reason a fact is missing, or nothing when the fact was read. A fact
 * inherits the reason of its parent: "dmi.
 */
export function factReason(missing: Record<string, string> | undefined, fact: string): string | undefined {
  if (!missing) return undefined;
  let key = fact;
  for (;;) {
    if (missing[key]) return missing[key];
    const dot = key.lastIndexOf(".");
    if (dot < 0) return undefined;
    key = key.slice(0, dot);
  }
}

/** Days, hours and minutes from a count of seconds: "3 d 4 h 5 min". */
export function uptimeText(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days} d`);
  if (days > 0 || hours > 0) parts.push(`${hours} h`);
  parts.push(`${minutes} min`);
  return parts.join(" ");
}

/**
 * The processor layout in one phrase: "2 sockets × 4 cores, 16 threads".
 */
export function layoutText(cpu: { sockets?: number; cores?: number; threads?: number } | undefined): string {
  if (!cpu) return "";
  const parts: string[] = [];
  if (cpu.sockets !== undefined && cpu.cores !== undefined && cpu.sockets > 0) {
    const perSocket = Math.round(cpu.cores / cpu.sockets);
    parts.push(`${cpu.sockets} ${cpu.sockets === 1 ? "socket" : "sockets"} × ${perSocket} ${perSocket === 1 ? "core" : "cores"}`);
  } else if (cpu.cores !== undefined) {
    parts.push(`${cpu.cores} ${cpu.cores === 1 ? "core" : "cores"}`);
  }
  if (cpu.threads !== undefined) parts.push(`${cpu.threads} ${cpu.threads === 1 ? "thread" : "threads"}`);
  return parts.join(", ");
}

/**
 * The page an adapter serves, by the adapter's name: the row of the registry
 * links there, so "packages.
 */
export function adapterSegment(name: string): string | undefined {
  const bySegment: Record<string, string> = {
    backup: "backups", certificates: "certificates", "certificates.renew": "certificates",
    dns: "dns", docker: "containers", "docker.compose": "compose", "files.managed": "files",
    firewall: "firewall", journald: "logs", kernel: "kernel", monitoring: "monitoring",
    network: "network", schedules: "schedules", security: "security", sshd: "ssh",
    storage: "storage", systemd: "services", time: "time",
  };
  if (bySegment[name]) return bySegment[name];
  if (name.startsWith("packages.")) return "packages";
  return undefined;
}
