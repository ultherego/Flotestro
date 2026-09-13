import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "./lib/api";
import type { Whoami } from "./lib/types";
import { useCapabilities } from "./lib/capabilities";
import { LOCALES, useLocale, useT } from "./i18n";
import { Dashboard } from "./pages/Dashboard";
import { Hosts } from "./pages/Hosts";
import { AddHost } from "./pages/AddHost";
import { HostLayout } from "./pages/host/Layout";
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

export function App() {
  const t = useT();
  const capabilities = useCapabilities();
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

  return (
    <div className="layout">
      <nav className="navigation">
        <div className="brand">Flotestro</div>
        <Link to="/dashboard">{t("Dashboard")}</Link>
        <Link to="/hosts">{t("Hosts")}</Link>
        <Link to="/jobs">{t("Jobs")}</Link>
        {/* A campaign is the main mechanism of change, not a shortcut on the
            host list: it has its own place in the navigation, next to the
            work on a single host. */}
        {seesCampaigns && <Link to="/bulk">{t("Bulk")}</Link>}
        {seesCampaigns && <Link to="/campaigns">{t("Campaigns")}</Link>}
        {seesSecurity && <Link to="/security">{t("Security")}</Link>}
        {seesCertificates && <Link to="/certificates">{t("Certificates")}</Link>}
        {seesBackups && <Link to="/backups">{t("Backups")}</Link>}
        {seesMonitoring && <Link to="/monitoring">{t("Monitoring")}</Link>}
        {seesVulnerabilities && <Link to="/vulnerabilities">{t("Vulnerabilities")}</Link>}
        {seesSecrets && <Link to="/secrets">{t("Secrets")}</Link>}
        {capabilities.directory && <Link to="/directory">{t("Directory")}</Link>}
        {/* Access management is seen only by whoever can change anything in
            it; for the rest the item would lead to a bare refusal. */}
        {managesAccess && <Link to="/access">{t("Access")}</Link>}
        {seesAudit && <Link to="/audit">{t("Audit")}</Link>}
        <div className="footer">
          <div>{data?.display_name || data?.subject}</div>
          <div>{data?.roles.join(", ") || t("no roles")}</div>
          <LanguageSwitch />
          {/* The identity provider may have an active session of another
              user and sign in with it quietly. Without this link there is no
              way out of that other than clearing the browser cookies. */}
          <a href={`/auth/login?force=1&redirect=${encodeURIComponent(window.location.pathname)}`}>
            {t("Switch account")}
          </a>
          <a href="#" onClick={signOut}>{t("Sign out")}</a>
        </div>
      </nav>
      <main className="content">
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
      </main>
    </div>
  );
}

function Link({ to, children }: { to: string; children: string }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? "active" : "")}>
      {children}
    </NavLink>
  );
}

/** The interface language; the choice is remembered in the browser. */
function LanguageSwitch() {
  const { locale, setLocale } = useLocale();
  return (
    <div className="language-switch">
      {LOCALES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === locale ? "active" : ""}
          onClick={() => setLocale(entry.code)}
        >
          {entry.label}
        </button>
      ))}
    </div>
  );
}

async function signOut(event: React.MouseEvent) {
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
        <h1>Flotestro</h1>
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
