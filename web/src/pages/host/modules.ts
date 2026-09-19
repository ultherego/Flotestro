import type { Capability, Host } from "../../lib/types";
import type { Capabilities as InstallationCapabilities } from "../../lib/capabilities";
import type { IconName } from "../../components/icons";

/**
 * The host module registry.
 */
export type Module = {
  /** The path segment: /hosts/:id/<segment>. Part of the address contract. */
  segment: string;
  /** The English tab name; it goes through the translation catalogue. */
  name: string;
  /**
   * The heading the module sits under in the host navigation.
   */
  group: ModuleGroup;
  /** The icon beside the name in the host navigation. */
  icon: IconName;
  /** The unavailability reason, or empty when the module works on this host. */
  reason: (host: Host, installation: InstallationCapabilities) => string;
  /**
   * The inventory module the tab lives off.
   */
  inventory?: string;
};

/** A module disabled in the whole installation leaves no dead route. */
export type VisibleModule = Module & { available: boolean; missingReason: string };

export type ModuleGroup =
  | "system" | "network" | "storage" | "containers" | "security" | "identity" | "observability" | "records";

/**
 * The groups in the order the navigation shows them: the machine itself
 * first, what it talks to next, what it keeps, what it runs, and the records
 * last.
 */
export const MODULE_GROUPS: { key: ModuleGroup; title: string }[] = [
  { key: "system", title: "System" },
  { key: "network", title: "Network" },
  { key: "storage", title: "Storage and files" },
  { key: "containers", title: "Containers" },
  { key: "security", title: "Security" },
  { key: "identity", title: "Identity" },
  { key: "observability", title: "Observability" },
  { key: "records", title: "Records" },
];

export function capability(host: Host, name: string): Capability | undefined {
  return (host.capabilities ?? []).find((item) => item.name === name);
}

/**
 * A module works when any of the adapters serving it works.
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

// The registry is written in the order of the groups, so the flat list
// and the grouped navigation agree on where a module stands.
const MODULES: Module[] = [
  { segment: "overview", name: "Overview", group: "system", icon: "overview", reason: () => "" },
  // The platform picture travels in the system fragment every agent sends,
  // so the tab is never unavailable; an old agent shows the basic facts.
  { segment: "system", name: "System", group: "system", icon: "server", reason: () => "", inventory: "system" },
  { segment: "packages", name: "Packages", group: "system", icon: "packages", reason: requires("packages.apt", "packages.dnf", "packages.pacman"), inventory: "packages" },
  { segment: "services", name: "Services", group: "system", icon: "services", reason: requires("systemd"), inventory: "services" },
  { segment: "processes", name: "Processes", group: "system", icon: "processes", reason: () => "" },
  { segment: "schedules", name: "Schedules", group: "system", icon: "schedules", reason: requires("schedules"), inventory: "schedules" },
  { segment: "kernel", name: "Kernel", group: "system", icon: "kernel", reason: requires("kernel"), inventory: "kernel" },
  { segment: "time", name: "Time", group: "system", icon: "time", reason: requires("time"), inventory: "time" },
  { segment: "power", name: "Power", group: "system", icon: "power", reason: requires("systemd"), inventory: "power" },
  // The verdicts of the desired-state policies that select the host.
  { segment: "policies", name: "Policies", group: "system", icon: "security", reason: () => "" },

  { segment: "network", name: "Network", group: "network", icon: "network", reason: requires("network"), inventory: "network" },
  { segment: "dns", name: "DNS", group: "network", icon: "dns", reason: requires("dns"), inventory: "dns" },
  { segment: "firewall", name: "Firewall", group: "network", icon: "firewall", reason: requires("firewall"), inventory: "firewall" },
  { segment: "ssh", name: "SSH", group: "network", icon: "ssh", reason: requires("sshd"), inventory: "ssh" },

  { segment: "storage", name: "Storage", group: "storage", icon: "storage", reason: requires("storage"), inventory: "storage" },
  { segment: "files", name: "Files", group: "storage", icon: "files", reason: requires("files.managed"), inventory: "files" },
  { segment: "backups", name: "Backups", group: "storage", icon: "backups", reason: requires("backup"), inventory: "backups" },

  { segment: "containers", name: "Containers", group: "containers", icon: "containers", reason: requires("docker"), inventory: "containers" },
  { segment: "compose", name: "Compose", group: "containers", icon: "compose", reason: requires("docker.compose"), inventory: "containers" },

  { segment: "security", name: "Security", group: "security", icon: "security", reason: requires("security"), inventory: "security" },
  {
    segment: "vulnerabilities",
    name: "Vulnerabilities",
    group: "security",
    icon: "vulnerabilities",
    reason: requires("packages.apt", "packages.dnf", "packages.pacman"),
    // The panel computes vulnerabilities from the package list, so the
    // freshness comes from there.
    inventory: "packages",
  },
  { segment: "certificates", name: "Certificates", group: "security", icon: "certificates", reason: requires("certificates"), inventory: "certificates" },

  {
    segment: "accounts",
    name: "Accounts",
    group: "identity",
    icon: "accounts",
    // Local accounts are disabled in the whole installation, not on a host.
    reason: (_host, installation) =>
      installation.local_users ? "" : "the local accounts module is disabled in this installation",
    inventory: "accounts",
  },
  { segment: "identity", name: "Identity", group: "identity", icon: "identity", reason: () => "", inventory: "identity" },

  { segment: "logs", name: "Logs", group: "observability", icon: "logs", reason: requires("journald") },
  { segment: "monitoring", name: "Monitoring", group: "observability", icon: "monitoring", reason: requires("monitoring") },

  { segment: "jobs", name: "Jobs", group: "records", icon: "jobs", reason: () => "" },
  { segment: "audit", name: "Audit", group: "records", icon: "audit", reason: () => "" },
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
 * The visible modules under their group headings, in the group order.
 */
export function groupedModules(list: VisibleModule[]): { key: ModuleGroup; title: string; items: VisibleModule[] }[] {
  return MODULE_GROUPS.map((group) => ({
    ...group,
    items: list.filter((item) => item.group === group.key),
  })).filter((group) => group.items.length > 0);
}

/**
 * The module an operation belongs to, by the prefix of its type.
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
