/**
 * The navigation icons: hand-drawn 16px strokes on a 24-unit grid, drawn
 * in currentColor so they take the colour of the text next to them. They
 * are decorative - every icon stands beside a label or a title - so they
 * are hidden from assistive technology.
 */
export type IconName =
  | "dashboard" | "hosts" | "add-host" | "jobs" | "bulk" | "campaigns"
  | "security" | "vulnerabilities" | "certificates" | "secrets"
  | "backups" | "monitoring" | "directory" | "access" | "audit"
  | "chevron" | "menu" | "collapse" | "expand" | "search" | "sign-out" | "server" | "user" | "back" | "star"
  // The host modules.
  | "overview" | "packages" | "services" | "processes" | "schedules" | "kernel" | "time" | "power"
  | "network" | "dns" | "firewall" | "ssh" | "storage" | "files" | "containers" | "compose"
  | "accounts" | "identity" | "logs";

const PATHS: Record<IconName, string> = {
  dashboard: "M3 3h8v8H3zM13 3h8v5h-8zM13 11h8v10h-8zM3 14h8v7H3z",
  hosts: "M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01",
  "add-host": "M3 5h18v6H3zM3 13h10v6H3zM7 8h.01M7 16h.01M18 15v6M15 18h6",
  jobs: "M9 5h6M9 3h6v4H9zM5 6h2v15h10V6h2M9 12l2 2 4-4",
  bulk: "M4 6h16M4 12h16M4 18h10M18 16l2 2 2-4",
  campaigns: "M4 20V4M4 4h13l-2 4 2 4H4",
  security: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  vulnerabilities: "M12 3l9 16H3zM12 10v4M12 17.5h.01",
  certificates: "M12 3l2.5 2.5H18v3.5L20.5 12 18 15v3.5h-3.5L12 21l-2.5-2.5H6V15L3.5 12 6 9V5.5h3.5zM9 12l2 2 4-4",
  secrets: "M8 11V7a4 4 0 0 1 8 0v4M5 11h14v10H5zM12 15v3",
  backups: "M12 3a9 9 0 1 0 9 9M21 3v6h-6M12 7v5l3 3",
  monitoring: "M3 12h4l3-7 4 14 3-7h4",
  directory: "M4 5h6l2 2h8v12H4zM8 13h8",
  access: "M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM3 20a5 5 0 0 1 10 0M14 9h7M17 9v3M20 9v2",
  audit: "M6 3h9l4 4v14H6zM9 12h6M9 16h6M9 8h3",
  chevron: "M9 6l6 6-6 6",
  menu: "M4 7h16M4 12h16M4 17h16",
  collapse: "M4 4v16M20 12H9M13 8l-4 4 4 4",
  expand: "M4 4v16M9 12h11M16 8l4 4-4 4",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4",
  "sign-out": "M10 4H5v16h5M14 8l5 4-5 4M19 12H9",
  server: "M4 4h16v7H4zM4 13h16v7H4zM8 7.5h.01M8 16.5h.01",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  // The host modules. Each is the object the module manages, not an
  // abstract sign, so an operator who knows the machine knows the icon.
  overview: "M4 17a8 8 0 1 1 16 0M12 17l4-6M12 17h.01",
  packages: "M12 3l9 4.5v9L12 21l-9-4.5v-9zM3 7.5l9 4.5 9-4.5M12 12v9",
  services: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1",
  processes: "M3 6h12M3 12h8M3 18h10M16 10l5 3-5 3z",
  schedules: "M4 5h16v15H4zM4 10h16M8 3v4M16 3v4M8 14h.01M12 14h.01M16 14h.01",
  kernel: "M7 7h10v10H7zM10 10h4v4h-4zM9 3v4M15 3v4M9 17v4M15 17v4M3 9h4M3 15h4M17 9h4M17 15h4",
  time: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  power: "M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0",
  network: "M9 3h6v6H9zM3 15h6v6H3zM15 15h6v6h-6zM12 9v3M6 15v-3h12v3",
  dns: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18",
  firewall: "M3 5h18v14H3zM3 9.7h18M3 14.3h18M9 5v4.7M15 9.7v4.6M9 14.3V19",
  ssh: "M4 5h16v14H4zM8 9l3 3-3 3M13 15h4",
  storage: "M12 3c5 0 8 1.3 8 3s-3 3-8 3-8-1.3-8-3 3-3 8-3zM4 6v12c0 1.7 3 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3 3 8 3s8-1.3 8-3",
  files: "M6 3h8l4 4v14H6zM14 3v4h4",
  containers: "M4 11h4v4H4zM10 11h4v4h-4zM16 11h4v4h-4zM7 5h4v4H7zM13 5h4v4h-4zM2 19h20",
  compose: "M12 3l9 5-9 5-9-5zM3 12.5l9 5 9-5M3 16.5l9 5 9-5",
  accounts: "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM3 20a6 6 0 0 1 12 0M16 4.5a3.5 3.5 0 0 1 0 6.5M21 20a6 6 0 0 0-4-5.6",
  identity: "M3 5h18v14H3zM7 15a3 3 0 0 1 6 0M10 8a2 2 0 1 0 0 4 2 2 0 0 0 0-4M15 10h4M15 14h4",
  logs: "M4 6h16M4 10h12M4 14h16M4 18h8",
  back: "M19 12H5M11 6l-6 6 6 6",
  star: "M12 3.5l2.6 5.4 5.9.8-4.3 4.1 1.1 5.9-5.3-2.8-5.3 2.8 1.1-5.9-4.3-4.1 5.9-.8z",
};

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
