import { useEffect, useState, type MouseEvent } from "react";
import { Navigate, Route, Routes, useLocation, useMatch } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, BEARER_TOKEN_KEY, ApiError } from "./lib/api";
import { PasswordSignIn } from "./pages/SignIn";
import type { Host, Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { useTheme } from "./lib/theme";
import { useScale } from "./lib/scale";
import { isBoolean, useStoredState } from "./lib/storage";
import { useT } from "./i18n";
import { Sidebar } from "./components/Sidebar";
import { NextPanel } from "./next/Panel";
import { fleetNavigation, visibility, type NavFace, type NavGroup } from "./lib/navigation";
import { Topbar, type Trail } from "./components/Topbar";
import { Logo } from "./components/Logo";
import { Dashboard } from "./pages/Dashboard";
import { Hosts } from "./pages/Hosts";
import { AddHost } from "./pages/AddHost";
import { Groups } from "./pages/Groups";
import { Relays, RelayPage } from "./pages/Relays";
import { HostLayout } from "./pages/host/Layout";
import { DEFAULT_MODULE, groupedModules, modules } from "./lib/modules";
import { REFRESH_INTERVAL } from "./lib/stream";
import { Overview } from "./pages/host/Overview";
import { System } from "./pages/host/System";
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
import Readiness from "./pages/Readiness";
import { FleetSecurity } from "./pages/Security";
import { Secrets } from "./pages/Secrets";
import { SecretPage } from "./pages/Secret";
import { ModalProvider } from "./components/Modal";
import { ToastProvider } from "./components/Toast";
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
import Unresolved from "./pages/Unresolved";
import { JobPage } from "./pages/Job";
import { Vulnerability } from "./pages/Vulnerability";
import { Schedules as CampaignSchedules } from "./pages/Schedules";
import { Setup } from "./pages/Setup";
import { Status } from "./pages/Status";
import { Reports } from "./pages/Reports";
import { Support } from "./pages/Support";
import { Profile } from "./pages/Profile";
import { Tags } from "./pages/Tags";
import { Teams } from "./pages/Teams";
import { PreferencesProvider, usePreferences } from "./lib/preferences";
import { Bulk } from "./pages/Bulk";
import { Campaigns } from "./pages/Campaigns";
import { Campaign } from "./pages/Campaign";
import { Reads } from "./pages/Reads";
import { PolicyPage } from "./pages/Policy";
import { HostPolicies } from "./pages/host/Policies";
import { Directory } from "./pages/Directory";
import { AccessRedirect } from "./pages/Access";
import { Audit } from "./pages/Audit";
import { Settings } from "./pages/Settings";

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

  if (isLoading) return <div className="ui-empty" style={{ padding: 40 }}>{t("Loading…")}</div>;

  // A missing session leads to the login at the identity provider. The
  // panel collects no passwords: the credentials go only to Keycloak.
  if (error instanceof ApiError && error.unauthenticated) {
    return <LoginScreen provider={capabilities.identity_provider} />;
  }
  if (error) return <div className="ui-empty" style={{ padding: 40 }}>{t("Error: {message}", { message: String(error) })}</div>;

  // Sections without backing in the permissions are hidden: a navigation
  // item that leads only to a refusal is an interface defect, not a
  // safeguard.
  const permissions = new Set(data?.permissions ?? []);
  // A sign-in that carries no permission at all. Every section below is hidden
  // for want of one, so the panel would render its shell around nothing and say
  // nothing - which is what an operator met after the first sign-in through an
  // identity provider whose groups nobody had mapped yet. The checklist knew;
  // the person who had just signed in was not told.
  if (!isLoading && !error && permissions.size === 0) {
    return (
      <div className="ui-empty" style={{ padding: 40, maxWidth: 760 }}>
        <h1>{t("Signed in, with nothing granted")}</h1>
        <p className="ui-prose">
          {t("You are signed in as {name}, and this sign-in carries no role. The panel shows only what a role allows, so there is nothing here to show - this is not an error and nothing is broken.", {
            name: data?.display_name || data?.subject || t("an unnamed principal"),
          })}
        </p>
        <p className="ui-prose">
          {t("Whoever administers this installation grants it: under Settings, a group of the identity provider is mapped to a role, or a role is bound to this principal directly. Until then every page refuses, which is the panel working as intended.")}
        </p>
      </div>
    );
  }
  // The panel being written again lives under /next until it is finished;
  // the shell below is the one it replaces, and the two share nothing but
  // the navigation model and the API.
  if (location.pathname.startsWith("/next")) {
    return (
      <ToastProvider>
        <ModalProvider>
          <PreferencesProvider applyTheme={setTheme}>
            <NextPanel look={{ theme, setTheme, scale, setScale }} />
          </PreferencesProvider>
        </ModalProvider>
      </ToastProvider>
    );
  }

  const v = visibility(permissions, capabilities);
  const groups = fleetNavigation(permissions, capabilities);

  const face: NavFace = onHost?.face ?? { groups };
  const trail: Trail = { ...sectionOf(groups, location.pathname), host: onHost?.host, module: onHost?.module };

  return (
    <ToastProvider>
      <ModalProvider>
        <PreferencesProvider applyTheme={setTheme}>
        <div className={collapsed ? "ui-shell ui-folded" : "ui-shell"}>
          <a href="#main-content" className="ui-skip">{t("Skip to content")}</a>
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
          {drawer && <div className="ui-sidebar-backdrop" onClick={() => setDrawer(false)} />}
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
          <main className="ui-content" id="main-content" tabIndex={-1}>
            {/* The page keeps a reading width and sits in the middle of the
                content area: on a wide screen a full-width page hugs the left
                edge and leaves the rest empty. */}
            <div className="ui-page">
            <Routes>
              <Route path="/" element={<Landing />} />
              <Route path="/profile" element={<Profile theme={theme} setTheme={setTheme} />} />
              <Route path="/tags" element={<Tags />} />
              <Route path="/teams" element={<Teams />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/setup" element={<Setup />} />
              <Route path="/hosts" element={<Hosts />} />
              {/* The path is before the host route, because "new" is not an identifier. */}
              <Route path="/hosts/new" element={<AddHost />} />
              <Route path="/groups" element={<Groups />} />
              <Route path="/groups/:id" element={<Groups />} />
              {v.seesRelays && <Route path="/relays" element={<Relays />} />}
              {v.seesRelays && <Route path="/relays/:id" element={<RelayPage />} />}
              <Route path="/readiness" element={<Readiness />} />
              <Route path="/security" element={<FleetSecurity />} />
              {/* The six screens of an installation's configuration live in
                  the settings area since 15.10. Their old addresses are kept
                  and send the reader there: they are in bookmarks, in the
                  manual and in the panel's own links. */}
              {v.seesPolicies && <Route path="/policies" element={<Navigate to="/settings?tab=policies" replace />} />}
              {v.seesPolicies && <Route path="/policies/:id" element={<PolicyPage />} />}
              <Route path="/certificates" element={<FleetCertificates />} />
              <Route path="/backups" element={<FleetBackups />} />
              <Route path="/monitoring" element={<FleetMonitoring />} />
              {v.seesNotifications && <Route path="/notifications" element={<Navigate to="/settings?tab=channels" replace />} />}
              <Route path="/vulnerabilities" element={<FleetVulnerabilities />} />
              <Route path="/vulnerabilities/:cve" element={<Vulnerability />} />
              <Route path="/secrets" element={<Secrets />} />
              <Route path="/secrets/:name" element={<SecretPage />} />
              {/* The host module is a segment of the address, so a refresh, the
                  browser history and a direct link lead where the operator
                  actually was. */}
              <Route path="/hosts/:id" element={<HostLayout />}>
                <Route index element={<Navigate to="overview" replace />} />
                <Route path="overview" element={<Overview />} />
                <Route path="system" element={<System />} />
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
                <Route path="policies" element={<HostPolicies />} />
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
              <Route path="/jobs/:id" element={<JobPage />} />
              <Route path="/unresolved" element={<Unresolved />} />
              <Route path="/reads" element={<Reads />} />
              <Route path="/reads/:id" element={<Reads />} />
              {v.seesCampaigns && <Route path="/bulk" element={<Bulk />} />}
              {v.seesCampaigns && <Route path="/campaigns" element={<Campaigns />} />}
              {v.seesCampaigns && <Route path="/campaigns/schedules" element={<CampaignSchedules />} />}
              {v.seesCampaigns && <Route path="/campaigns/:id" element={<Campaign />} />}
              {v.seesBudgets && <Route path="/budgets" element={<Navigate to="/settings?tab=budgets" replace />} />}
              {capabilities.directory && <Route path="/directory" element={<Directory />} />}
              {/* The access screen became four tabs of the settings area on
                  15.10, where the roles and the mappings had already gone.
                  The address answers and leads to the right one. */}
              {v.managesAccess && <Route path="/access" element={<AccessRedirect />} />}
              {v.seesAudit && <Route path="/audit" element={<Audit />} />}
              {v.seesSettings && <Route path="/settings" element={<Settings />} />}
              {v.seesSupport && <Route path="/support" element={<Support />} />}
              {v.seesSettings && <Route path="/status" element={<Status />} />}
              <Route path="*" element={<div className="ui-empty">{t("Page not found.")}</div>} />
            </Routes>
            </div>
          </main>
        </div>
        </PreferencesProvider>
      </ModalProvider>
    </ToastProvider>
  );
}

async function signOut(event: MouseEvent) {
  event.preventDefault();
  // Invalidating the panel session is not enough: without signing out at
  // the provider the next visit would sign the user in without asking.
  try { sessionStorage.removeItem(BEARER_TOKEN_KEY); } catch { /* nothing kept */ }
  const result = await api.post<{ logout_url: string }>("/auth/logout");
  window.location.href = result.logout_url || "/";
}

export function LoginScreen({ provider }: { provider: boolean }) {
  const t = useT();
  return (
    <div className="ui-login">
      <div>
        <h1 className="ui-login-brand"><Logo size={40} /></h1>
        <p className="ui-note">{t("Linux fleet management")}</p>

        {/* The password door. An installation with no identity provider had
            none until 16.10: the panel had roles and tokens and no way for a
            person to sign in. It stands first because where there is no
            provider it is the only way in, and where there is one an
            administrator still keeps a local account for the day the
            provider is the thing that is down. */}
        <PasswordSignIn />

        {provider && (
          <>
            <div className="ui-login-or"><span>{t("or")}</span></div>
            <button className="ui-btn-secondary" onClick={() => (window.location.href = "/auth/login?redirect=/dashboard")}>
              {t("Sign in with identity provider")}
            </button>
            <p className="ui-note">
              {t("Your identity provider may sign you in with an account you already have an open session for.")}{" "}
              <a href="/auth/login?force=1&redirect=/dashboard">{t("Sign in as a different user")}</a>
            </p>
          </>
        )}
        <BootstrapTokenEntry />
      </div>
    </div>
  );
}

/** The first page: the one the operator chose, the dashboard until then. */
function Landing() {
  const { preferences, settled } = usePreferences();
  if (!settled) return null;
  return <Navigate to={preferences.landing_page || "/dashboard"} replace />;
}

/**
 * The way in before the identity provider lets anybody in: the bootstrap
 * token from the state directory.
 */
function BootstrapTokenEntry() {
  const t = useT();
  const [token, setToken] = useState("");
  return (
    <details style={{ marginTop: 18, textAlign: "left" }}>
      <summary className="ui-note" style={{ cursor: "pointer" }}>{t("Sign in with a bootstrap token")}</summary>
      <p className="ui-note">
        {t("The bootstrap token is printed at the first start and lies in the state directory. It is for the first group mapping only: the first-run checklist warns while it still works.")}
      </p>
      <input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="flta…" autoComplete="off"
             data-testid="bootstrap-token" style={{ width: "100%", marginBottom: 8 }} />
      <button className="ui-btn-secondary" disabled={token.trim() === ""} onClick={() => {
        try { sessionStorage.setItem(BEARER_TOKEN_KEY, token.trim()); } catch { /* a window without storage: the token is simply not kept */ }
        window.location.href = "/setup";
      }}>
        {t("Continue to the first run")}
      </button>
    </details>
  );
}

/**
 * The section the address belongs to, for the trail in the top bar.
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
  // Pages reached from the user menu rather than the sidebar are named by
  // the page, not by the product, so the bar does not look broken there.
  const unlisted: Record<string, string> = { "/profile": "Profile", "/setup": "First run" };
  if (unlisted[pathname]) return { section: unlisted[pathname] };
  return { section: "Flotestro" };
}

/**
 * The host context of the shell: on a host page the fleet groups of the
 * sidebar give way to the modules of that host, under the same headings the
 * registry knows, with the way back to the list above them; the top bar.
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
