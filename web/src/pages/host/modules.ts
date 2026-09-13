import type { Capability, Host } from "../../lib/types";
import type { Capabilities as InstallationCapabilities } from "../../lib/capabilities";

/**
 * The host module registry. One source of truth for the tabs, the routes
 * and the host switch: if each of them computed availability separately, a
 * tab could lead to a route that does not exist, or the other way round.
 */
export type Module = {
  /** The path segment: /hosts/:id/<segment>. Part of the address contract. */
  segment: string;
  /** The English tab name; it goes through the translation catalogue. */
  name: string;
  /** The unavailability reason, or empty when the module works on this host. */
  reason: (host: Host, installation: InstallationCapabilities) => string;
  /**
   * The inventory module the tab lives off. None means the tab does not read
   * the inventory (Jobs, Audit) or reads it whole (Overview) - and that a
   * refresh from that tab covers the whole host.
   */
  inventory?: string;
};

/** A module disabled in the whole installation leaves no dead route. */
export type VisibleModule = Module & { available: boolean; missingReason: string };

export function capability(host: Host, name: string): Capability | undefined {
  return (host.capabilities ?? []).find((item) => item.name === name);
}

/**
 * A module works when any of the adapters serving it works. When none does,
 * the operator gets the reasons of all of them - because each is a separate
 * answer to the question "why is this not here".
 */
function requires(...names: string[]) {
  return (host: Host): string => {
    const adapters = names.map((name) => capability(host, name));
    if (adapters.some((adapter) => adapter?.available)) return "";
    const reasons = adapters
      .map((adapter, i) => adapter?.reason || `the host does not report ${names[i]}`)
      .filter((reason, i, list) => list.indexOf(reason) === i);
    return reasons.join("; ");
  };
}

const MODULES: Module[] = [
  { segment: "overview", name: "Overview", reason: () => "" },
  { segment: "packages", name: "Packages", reason: requires("packages.apt", "packages.dnf"), inventory: "packages" },
  { segment: "services", name: "Services", reason: requires("systemd"), inventory: "services" },
  { segment: "processes", name: "Processes", reason: () => "" },
  { segment: "containers", name: "Containers", reason: requires("docker"), inventory: "containers" },
  { segment: "compose", name: "Compose", reason: requires("docker.compose"), inventory: "containers" },
  { segment: "logs", name: "Logs", reason: requires("journald") },
  { segment: "schedules", name: "Schedules", reason: requires("schedules"), inventory: "schedules" },
  { segment: "network", name: "Network", reason: requires("network"), inventory: "network" },
  { segment: "dns", name: "DNS", reason: requires("dns"), inventory: "dns" },
  { segment: "firewall", name: "Firewall", reason: requires("firewall"), inventory: "firewall" },
  { segment: "storage", name: "Storage", reason: requires("storage"), inventory: "storage" },
  { segment: "ssh", name: "SSH", reason: requires("sshd"), inventory: "ssh" },
  { segment: "kernel", name: "Kernel", reason: requires("kernel"), inventory: "kernel" },
  { segment: "time", name: "Time", reason: requires("time"), inventory: "time" },
  { segment: "power", name: "Power", reason: requires("systemd"), inventory: "power" },
  { segment: "security", name: "Security", reason: requires("security"), inventory: "security" },
  { segment: "certificates", name: "Certificates", reason: requires("certificates"), inventory: "certificates" },
  { segment: "backups", name: "Backups", reason: requires("backup"), inventory: "backups" },
  { segment: "monitoring", name: "Monitoring", reason: requires("monitoring") },
  {
    segment: "vulnerabilities",
    name: "Vulnerabilities",
    reason: requires("packages.apt", "packages.dnf"),
    // The panel computes vulnerabilities from the package list, so the
    // freshness comes from there.
    inventory: "packages",
  },
  { segment: "files", name: "Files", reason: requires("files.managed"), inventory: "files" },
  {
    segment: "accounts",
    name: "Accounts",
    // Local accounts are disabled in the whole installation, not on a host.
    reason: (_host, installation) =>
      installation.local_users ? "" : "the local accounts module is disabled in this installation",
    inventory: "accounts",
  },
  { segment: "identity", name: "Identity", reason: () => "", inventory: "identity" },
  { segment: "jobs", name: "Jobs", reason: () => "" },
  { segment: "audit", name: "Audit", reason: () => "" },
];

export const DEFAULT_MODULE = "overview";

export function modules(host: Host, installation: InstallationCapabilities): VisibleModule[] {
  return MODULES.map((module) => {
    const reason = module.reason(host, installation);
    return { ...module, available: reason === "", missingReason: reason };
  });
}

export function module(segment: string): Module | undefined {
  return MODULES.find((item) => item.segment === segment);
}

/**
 * The module an operation belongs to, by the prefix of its type. A campaign
 * links its hosts to that module, so the operator lands where the change
 * shows rather than on the overview.
 */
export function moduleForAction(action: string): string {
  const prefix = action.split(".")[0];
  const bySecond: Record<string, string> = {
    "docker.compose": "compose", "system.reboot": "power", "system.shutdown": "power",
    "packages.repository": "packages",
  };
  const twoParts = action.split(".").slice(0, 2).join(".");
  if (bySecond[twoParts]) return bySecond[twoParts];
  const byPrefix: Record<string, string> = {
    packages: "packages", package: "packages", unit: "services", process: "processes",
    docker: "containers", journal: "logs", logfile: "logs", schedule: "schedules",
    network: "network", dns: "dns", firewall: "firewall", storage: "storage", mount: "storage",
    filesystem: "storage", lvm: "storage", disk: "storage", ssh: "ssh", sysctl: "kernel",
    kernel: "kernel", time: "time", security: "security", selinux: "security",
    certificate: "certificates", backup: "backups", monitoring: "monitoring",
    localuser: "accounts", file: "files", inventory: "overview", agent: "packages",
  };
  return byPrefix[prefix] ?? DEFAULT_MODULE;
}
