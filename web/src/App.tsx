import { useEffect, useState, type MouseEvent } from "react";
import { Navigate, Route, Routes, useLocation, useMatch } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import type { Host, Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { useTheme } from "./lib/theme";
import { useScale } from "./lib/scale";
import { isBoolean, useStoredState } from "./lib/storage";
import { useT } from "./i18n";
import { Sidebar, type NavFace, type NavGroup } from "./components/Sidebar";
import { Topbar, type Trail } from "./components/Topbar";
import { Logo } from "./components/Logo";
import { Dashboard } from "./pages/Dashboard";
import { Hosts } from "./pages/Hosts";
import { AddHost } from "./pages/AddHost";
import { HostLayout } from "./pages/host/Layout";
import { DEFAULT_MODULE, groupedModules, modules } from "./pages/host/modules";
import { REFRESH_INTERVAL } from "./lib/stream";
import { Overview } from "./pages/host/Overview";
import { Packages } from "./pages/host/Packages";
import { Services } from "./pages/host/Services";
import { Containers } from "./pages/host/Containers";
import { Processes } from "./pages/host/Processes";
import { Schedules } from "./pages/host/Schedules";
import { Network } from "./pages/host/Network";
import { Resolver } from "./pages/host/Resolver";
import { Firewall } from "./pages/host/Firewall";
import { Storage } from "./pages/host/Storage";
import { SshServer } from "./pages/host/SshServer";
import { Kernel } from "./pages/host/Kernel";
import { Time } from "./pages/host/Time";
import { Power } from "./pages/host/Power";
import { Security } from "./pages/host/Security";
import { FleetSecurity } from "./pages/Security";
import { Secrets } from "./pages/Secrets";
import { FleetCertificates } from "./pages/Certificates";
import { FleetBackups } from "./pages/Backups";
import { FleetMonitoring } from "./pages/Monitoring";
import { FleetVulnerabilities } from "./pages/Vulnerabilities";
import { Vulnerabilities } from "./pages/host/Vulnerabilities";
import { Monitoring } from "./pages/host/Monitoring";
import { Backups } from "./pages/host/Backups";
import { Certificates } from "./pages/host/Certificates";
import { Files } from "./pages/host/Files";
import { Compose } from "./pages/host/Compose";
import { Logs } from "./pages/host/Logs";
import { HostAccounts } from "./pages/host/Accounts";
import { Identity } from "./pages/host/Identity";
import { HostJobs } from "./pages/host/Jobs";
import { HostAudit } from "./pages/host/Audit";
import { Jobs } from "./pages/Jobs";
import { Bulk } from "./pages/Bulk";
import { Campaigns } from "./pages/Campaigns";
import { Campaign } from "./pages/Campaign";
import { Directory } from "./pages/Directory";
import { Access } from "./pages/Access";
import { Audit } from "./pages/Audit";

const SIDEBAR_KEY = "flotestro.sidebar";

export function App() {
  const t = useT();
  const capabilities = useCapabilities();
  const location = useLocation();
  // The theme is owned here so that it applies to every screen, the login
  // included; the switch in the user menu only changes it.
  const { theme, setTheme } = useTheme();
  const { scale, setScale } = useScale();
  const [collapsed, setCollapsed] = useStoredState<boolean>(SIDEBAR_KEY, false, isBoolean);
  // The drawer on a narrow screen; it closes on every navigation, because
  // the operator opened it to go somewhere, not to keep it.
  const [drawer, setDrawer] = useState(false);
  useEffect(() => {
    setDrawer(false);
  }, [location.pathname]);

  const onHost = useHostContext(capabilities);

  const { data, isLoading, error } = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    retry: false,
    refetchInterval: false,
  });

  if (isLoading) return <div className="empty" style={{ padding: 40 }}>{t("Loading…")}</div>;

  // A missing session leads to the login at the identity provider. The
  // panel collects no passwords: the credentials go only to Keycloak.
  if (error instanceof ApiError && error.unauthenticated) {
    return <LoginScreen provider={capabilities.identity_provider} />;
  }
  if (error) return <div className="empty" style={{ padding: 40 }}>{t("Error: {message}", { message: String(error) })}</div>;

  // Sections without backing in the permissions are hidden: a navigation
  // item that leads only to a refusal is an interface defect, not a
  // safeguard. The server decides what is allowed anyway.
  const permissions = new Set(data?.permissions ?? []);
  const managesAccess = permissions.has("principal.manage");
  const seesAudit = permissions.has("audit.read");
  const seesCampaigns = permissions.has("campaign.read");
  const seesSecurity = permissions.has("security.read");
  const seesSecrets = permissions.has("secret.read");
  const seesCertificates = permissions.has("certificate.read");
  const seesBackups = permissions.has("backup.read");
  const seesMonitoring = permissions.has("monitoring.read");
  const seesVulnerabilities = permissions.has("vulnerability.read");
  const addsHosts = permissions.has("host.enroll.create");

  // The navigation, grouped by what the operator is doing rather than by
  // backend module. An item that is not allowed is left out of its group;
  // a group left empty is not drawn.
  const groups: NavGroup[] = [
    {
      key: "fleet",
      label: "Fleet",
      items: [
        { to: "/dashboard", label: "Dashboard", icon: "dashboard" },
        // The host list stays lit on a host page, but not on the enrolment
        // screen, which has an item of its own under the same prefix.
        { to: "/hosts", label: "Hosts", icon: "hosts", active: (path) => path.startsWith("/hosts") && !path.startsWith("/hosts/new") },
        ...(addsHosts ? [{ to: "/hosts/new", label: "Add host", icon: "add-host" as const }] : []),
      ],
    },
    {
      key: "operations",
      label: "Operations",
      items: [
        { to: "/jobs", label: "Jobs", icon: "jobs" },
        // A campaign is the main mechanism of change, not a shortcut on the
        // host list: it has its own place in the navigation, next to the
        // work on a single host.
        ...(seesCampaigns ? [
          { to: "/bulk", label: "Bulk Workspace", icon: "bulk" as const },
          { to: "/campaigns", label: "Campaigns", icon: "campaigns" as const },
        ] : []),
      ],
    },
    {
      key: "security",
      label: "Security",
      items: [
        ...(seesSecurity ? [{ to: "/security", label: "Security", icon: "security" as const }] : []),
        ...(seesVulnerabilities ? [{ to: "/vulnerabilities", label: "Vulnerabilities", icon: "vulnerabilities" as const }] : []),
        ...(seesCertificates ? [{ to: "/certificates", label: "Certificates", icon: "certificates" as const }] : []),
        ...(seesSecrets ? [{ to: "/secrets", label: "Secrets", icon: "secrets" as const }] : []),
      ],
    },
    {
      key: "continuity",
      label: "Continuity",
      items: [
        ...(seesBackups ? [{ to: "/backups", label: "Backups", icon: "backups" as const }] : []),
        ...(seesMonitoring ? [{ to: "/monitoring", label: "Monitoring", icon: "monitoring" as const }] : []),
      ],
    },
    {
      key: "identity",
      label: "Identity",
      items: [
        ...(capabilities.directory ? [{ to: "/directory", label: "Directory", icon: "directory" as const }] : []),
        // Access management is seen only by whoever can change anything in
        // it; for the rest the item would lead to a bare refusal.
        ...(managesAccess ? [{ to: "/access", label: "Access", icon: "access" as const }] : []),
      ],
    },
    {
      key: "audit",
      items: seesAudit ? [{ to: "/audit", label: "Audit", icon: "audit" as const }] : [],
    },
  ];

  const face: NavFace = onHost?.face ?? { groups };
  const trail: Trail = { ...sectionOf(groups, location.pathname), host: onHost?.host, module: onHost?.module };

  return (
    <div className={collapsed ? "layout sidebar-collapsed" : "layout"}>
      {/* The shell is two panels: the sidebar down the left edge with the
          places to go, and the top bar across the rest with where the
          operator is and who they are. On a narrow screen the sidebar
          becomes a drawer behind the bar's menu button. */}
      <Sidebar
        face={face}
        collapsed={collapsed}
        open={drawer}
        onClose={() => setDrawer(false)}
      />
      {drawer && <div className="sidebar-backdrop" onClick={() => setDrawer(false)} />}
      <Topbar
        trail={trail}
        user={data}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((current) => !current)}
        onOpenDrawer={() => setDrawer(true)}
        onSignOut={signOut}
        theme={theme}
        setTheme={setTheme}
        scale={scale}
        setScale={setScale}
      />
      <main className="content">
        {/* The page keeps a reading width and sits in the middle of the
            content area: on a wide screen a full-width page hugs the left
            edge and leaves the rest empty. */}
        <div className="page">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/hosts" element={<Hosts />} />
          {/* The path is before the host route, because "new" is not an identifier. */}
          <Route path="/hosts/new" element={<AddHost />} />
          <Route path="/security" element={<FleetSecurity />} />
          <Route path="/certificates" element={<FleetCertificates />} />
          <Route path="/backups" element={<FleetBackups />} />
          <Route path="/monitoring" element={<FleetMonitoring />} />
          <Route path="/vulnerabilities" element={<FleetVulnerabilities />} />
          <Route path="/secrets" element={<Secrets />} />
          {/* The host module is a segment of the address, so a refresh, the
              browser history and a direct link lead where the operator
              actually was. */}
          <Route path="/hosts/:id" element={<HostLayout />}>
            <Route index element={<Navigate to="overview" replace />} />
            <Route path="overview" element={<Overview />} />
            <Route path="packages" element={<Packages />} />
            <Route path="services" element={<Services />} />
            <Route path="processes" element={<Processes />} />
            <Route path="schedules" element={<Schedules />} />
            <Route path="network" element={<Network />} />
            <Route path="dns" element={<Resolver />} />
            <Route path="firewall" element={<Firewall />} />
            <Route path="storage" element={<Storage />} />
            <Route path="ssh" element={<SshServer />} />
            <Route path="kernel" element={<Kernel />} />
            <Route path="time" element={<Time />} />
            <Route path="power" element={<Power />} />
            <Route path="security" element={<Security />} />
            <Route path="certificates" element={<Certificates />} />
            <Route path="backups" element={<Backups />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="files" element={<Files />} />
            <Route path="containers" element={<Containers />} />
            <Route path="compose" element={<Compose />} />
            <Route path="logs" element={<Logs />} />
            <Route path="accounts" element={<HostAccounts />} />
            <Route path="identity" element={<Identity />} />
            <Route path="jobs" element={<HostJobs />} />
            <Route path="audit" element={<HostAudit />} />
          </Route>
          <Route path="/jobs" element={<Jobs />} />
          {seesCampaigns && <Route path="/bulk" element={<Bulk />} />}
          {seesCampaigns && <Route path="/campaigns" element={<Campaigns />} />}
          {seesCampaigns && <Route path="/campaigns/:id" element={<Campaign />} />}
          {capabilities.directory && <Route path="/directory" element={<Directory />} />}
          {managesAccess && <Route path="/access" element={<Access />} />}
          {seesAudit && <Route path="/audit" element={<Audit />} />}
          <Route path="*" element={<div className="empty">{t("Page not found.")}</div>} />
        </Routes>
        </div>
      </main>
    </div>
  );
}

async function signOut(event: MouseEvent) {
  event.preventDefault();
  // Invalidating the panel session is not enough: without signing out at
  // the provider the next visit would sign the user in without asking.
  const result = await api.post<{ logout_url: string }>("/auth/logout");
  window.location.href = result.logout_url || "/";
}

function LoginScreen({ provider }: { provider: boolean }) {
  const t = useT();
  return (
    <div className="login-screen">
      <div>
        <h1 className="login-brand"><Logo size={40} /></h1>
        <p className="subtitle">{t("Linux fleet management")}</p>
        {provider ? (
          <>
            <button onClick={() => (window.location.href = "/auth/login?redirect=/dashboard")}>
              {t("Sign in with identity provider")}
            </button>
            <p className="subtitle" style={{ marginTop: 14 }}>
              {t("Your identity provider may sign you in with an account you already have an open session for.")}{" "}
              <a href="/auth/login?force=1&redirect=/dashboard">{t("Sign in as a different user")}</a>
            </p>
          </>
        ) : (
          // Without a configured provider the login button would lead to an
          // error. The panel then works on API tokens and that has to be
          // said outright instead of showing a dead action.
          <p className="subtitle">
            {t("No identity provider is configured in this installation. Access to the panel uses an API token passed in the Authorization header.")}
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * The section the address belongs to, for the trail in the top bar. It is
 * found in the navigation itself, so the bar names a page exactly as the
 * sidebar does; a page deeper than its item (a campaign, a host) gets the
 * item as a link back. An address outside the navigation is named by the
 * product, because a bar with an empty title would look broken.
 */
function sectionOf(groups: NavGroup[], pathname: string): Pick<Trail, "section" | "to"> {
  for (const group of groups) {
    for (const item of group.items) {
      const on = item.active
        ? item.active(pathname)
        : pathname === item.to || pathname.startsWith(`${item.to}/`);
      if (!on) continue;
      return pathname === item.to ? { section: item.label } : { section: item.label, to: item.to };
    }
  }
  return { section: "Flotestro" };
}

/**
 * The host context of the shell: on a host page the fleet groups of the
 * sidebar give way to the modules of that host, under the same headings
 * the registry knows, with the way back to the list above them; the top
 * bar names the host and the open module. The host is read with the same
 * query the page uses, so it costs no second request.
 */
function useHostContext(installation: ReturnType<typeof useCapabilities>): { face: NavFace; host?: Host; module?: string } | undefined {
  const match = useMatch("/hosts/:id/*");
  const location = useLocation();
  const id = match?.params.id;
  const onHost = id !== undefined && id !== "new";
  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    refetchInterval: REFRESH_INTERVAL,
    enabled: onHost,
  });
  if (!onHost) return undefined;
  const back = { to: "/hosts", label: "All hosts" };
  if (!host.data) return { face: { groups: [], back } };
  const list = modules(host.data, installation);
  // The search keeps the way back to a campaign across module switches.
  const groups: NavGroup[] = groupedModules(list).map((group) => ({
    key: `host:${group.key}`,
    label: group.title,
    items: group.items.map((item) => ({
      to: `/hosts/${id}/${item.segment}${location.search}`,
      label: item.name,
      icon: item.icon,
      unavailable: item.available ? undefined : item.missingReason,
    })),
  }));
  // The module is the third segment of the address, as the host layout
  // reads it; the default is what the index route redirects to.
  const segment = location.pathname.split("/")[3] || DEFAULT_MODULE;
  const open = list.find((item) => item.segment === segment);
  return { face: { groups, back }, host: host.data, module: open?.name };
}
