import type { IconName } from "../components/icons";
import type { Capabilities } from "./capabilities";

/**
 * Where the panel can be gone to, grouped by what the operator is doing
 * rather than by backend module.
 *
 * It lives apart from any shell because there are two of them while the
 * panel is being written again: the one being replaced and the one under
 * /next. A navigation copied into both is a navigation that drifts between
 * them inside a week.
 */

export type NavItem = {
  to: string;
  /** The English label; it goes through the translation catalogue. */
  label: string;
  icon: IconName;
  /** Overrides the router's prefix match where two items share a prefix. */
  active?: (pathname: string) => boolean;
  /** The reason the item has no backing here; it stays listed, dimmed. */
  unavailable?: string;
};

export type NavGroup = {
  /** The storage key of the fold state; it must not change between versions. */
  key: string;
  /** The English heading; a group without one is a single top-level item. */
  label?: string;
  /** The mark beside the heading, so a group is found by shape as well as by word. */
  icon?: IconName;
  items: NavItem[];
};

/**
 * The navigation has two faces, never both at once: the fleet, and one host.
 */
export type NavFace = {
  groups: NavGroup[];
  /** Set on a host page: the address of the fleet view the modules replace. */
  back?: { to: string; label: string };
};

/**
 * What this sign-in may see at all. The navigation leaves out what it
 * cannot reach, and the router refuses the same addresses, so the two
 * answers are taken once here rather than written twice.
 */
export function visibility(permissions: Set<string>, capabilities: Capabilities) {
  const managesAccess = permissions.has("principal.manage");
  const seesAudit = permissions.has("audit.read");
  const seesCampaigns = permissions.has("campaign.read");
  const seesSecurity = permissions.has("security.read");
  const seesSecrets = permissions.has("secret.read");
  const seesCertificates = permissions.has("certificate.read");
  const seesBackups = permissions.has("backup.read");
  const seesMonitoring = permissions.has("monitoring.read");
  const seesNotifications = permissions.has("notification.read");
  const seesVulnerabilities = permissions.has("vulnerability.read");
  const addsHosts = permissions.has("host.enroll.create");
  // The settings screen is read by whoever administers the panel: the
  // permission of its own, or the one to decide who may do what.
  const seesSettings = permissions.has("settings.read") || managesAccess;
  // A support bundle reads the whole panel, so the section shows only for
  // whoever may ask for one.
  const seesSupport = permissions.has("support.bundle.read");
  // The relays are read with the right that reads the installations: the
  // list is the same one the add-host wizard picks a route from.
  const seesRelays = permissions.has("host.enroll.read");
  // The budgets are the reason a job or a campaign stands in the queue, so
  // they stand with the operations they hold back.
  const seesBudgets = permissions.has("budget.read");
  // The declared state stands with the operations: a policy is the third
  // model of change, next to the job and the campaign.
  const seesPolicies = permissions.has("policy.read");


  return { managesAccess, seesAudit, seesCampaigns, seesSecurity, seesSecrets, seesCertificates, seesBackups, seesMonitoring, seesNotifications, seesVulnerabilities, addsHosts, seesSettings, seesSupport, seesRelays, seesBudgets, seesPolicies, directory: capabilities.directory };
}

/**
 * Sections without backing in the permissions are left out: an item that
 * leads only to a refusal is an interface defect, not a safeguard.
 */
export function fleetNavigation(permissions: Set<string>, capabilities: Capabilities): NavGroup[] {
  const v = visibility(permissions, capabilities);
  return [
    {
      key: "fleet",
      icon: "hosts",
      label: "Fleet",
      items: [
        { to: "/dashboard", label: "Dashboard", icon: "dashboard" },
        // The host list stays lit on a host page, but not on the enrolment
        // screen, which has an item of its own under the same prefix.
        { to: "/hosts", label: "Hosts", icon: "hosts", active: (path) => path.startsWith("/hosts") && !path.startsWith("/hosts/new") },
        ...(v.addsHosts ? [{ to: "/hosts/new", label: "Add host", icon: "add-host" as const }] : []),
        // A group is a saved answer to "which hosts"; it lives with the
        // fleet, because that is what it describes, not with the campaigns
        // that use it.
        { to: "/groups", label: "Groups", icon: "groups" },
        { to: "/tags", label: "Tags", icon: "groups" },
        // A relay is a piece of the fleet's plumbing rather than a host: it
        // stands with the fleet, because a silent one is a site cut off.
        ...(v.seesRelays ? [{ to: "/relays", label: "Relays", icon: "relays" as const }] : []),
        { to: "/reports", label: "Reports", icon: "audit" as const },
      ],
    },
    {
      key: "operations",
      icon: "jobs",
      label: "Operations",
      items: [
        { to: "/jobs", label: "Jobs", icon: "jobs" },
        // What the fleet could not confirm. Beside the jobs because that is
        // what these are, and before the rest of the operations because an
        // operator who has unconfirmed changes should read them before
        // ordering more.
        { to: "/unresolved", label: "Needs confirmation", icon: "jobs" },
        // What the fleet cannot be asked to do, and why. It stands at the head
        // of the operations because it is the question before any of them:
        // ordering work a host cannot carry out is refused, and this is where
        // that is read once rather than one refusal at a time.
        { to: "/readiness", label: "Readiness", icon: "overview" },
        // A read on a handful of hosts at once: a diagnostic, not a change,
        // so it stands next to the jobs it is made of rather than with the
        // campaigns.
        { to: "/reads", label: "Reads", icon: "reads" },
        // A campaign is the main mechanism of change, not a shortcut on the
        // host list: it has its own place in the navigation, next to the
        // work on a single host.
        ...(v.seesCampaigns ? [
          { to: "/bulk", label: "Bulk Workspace", icon: "bulk" as const },
          { to: "/campaigns", label: "Campaigns", icon: "campaigns" as const },
        ] : []),
        // A policy declares what is to be true and orders campaigns for
        // the rest, so it stands after the campaigns it orders.
        // The capacity the jobs and the campaigns draw on: the gauge stands
        // last in the group, after the work it meters.
      ],
    },
    {
      key: "security",
      icon: "security",
      label: "Security",
      items: [
        ...(v.seesSecurity ? [{ to: "/security", label: "Security", icon: "security" as const }] : []),
        ...(v.seesVulnerabilities ? [{ to: "/vulnerabilities", label: "Vulnerabilities", icon: "vulnerabilities" as const }] : []),
        ...(v.seesCertificates ? [{ to: "/certificates", label: "Certificates", icon: "certificates" as const }] : []),
        ...(v.seesSecrets ? [{ to: "/secrets", label: "Secrets", icon: "secrets" as const }] : []),
      ],
    },
    {
      key: "continuity",
      icon: "backups",
      label: "Continuity",
      items: [
        ...(v.seesBackups ? [{ to: "/backups", label: "Backups", icon: "backups" as const }] : []),
        ...(v.seesMonitoring ? [{ to: "/monitoring", label: "Monitoring", icon: "monitoring" as const }] : []),
      ],
    },
    {
      key: "identity",
      icon: "identity",
      label: "Identity",
      items: [
        ...(v.directory ? [{ to: "/directory", label: "Directory", icon: "directory" as const }] : []),
        // Access management is seen only by whoever can change anything in
        // it; for the rest the item would lead to a bare refusal.
        // A team is a boundary of authority rather than a label, so it
        // stands with the access rules and not with the groups and the tags,
        // which only choose hosts inside what somebody may touch.
        { to: "/teams", label: "Teams", icon: "accounts" as const },
      ],
    },
    {
      key: "audit",
      items: v.seesAudit ? [{ to: "/audit", label: "Audit", icon: "audit" as const }] : [],
    },
    // The settings stand last: they describe the panel itself rather than
    // the fleet, and they are read rarely.
    {
      key: "settings",
      items: v.seesSettings
        ? [{ to: "/status", label: "Status", icon: "settings" as const },
           { to: "/settings", label: "Settings", icon: "settings" as const },
           ...(v.seesSupport ? [{ to: "/support", label: "Support bundle", icon: "logs" as const }] : [])]
        : [],
    },
  ];
}
