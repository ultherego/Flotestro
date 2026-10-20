import { lazy, Suspense, type ComponentType } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { usePreferences } from "../lib/preferences";
import { Shell } from "./Shell";
import { Empty, Head, HeadSlot, Screen, ShellHead } from "./kit";
import { ABOUT } from "./screens/about";
import { LookProvider, type Look } from "./look";
import { useT } from "../i18n";

/**
 * A screen is fetched when it is first opened, not with the shell: the whole
 * panel in one file was 2.5 MB, most of it screens nobody opens on a given day.
 */
function screen<K extends string>(load: () => Promise<Record<K, ComponentType>>, name: K) {
  return lazy(() => load().then((module) => ({ default: module[name] })));
}

const Dashboard = screen(() => import("./screens/Dashboard"), "Dashboard");
const Hosts = screen(() => import("./screens/Hosts"), "Hosts");
const Access = screen(() => import("./screens/Access"), "Access");
const Teams = screen(() => import("./screens/Teams"), "Teams");
const Tags = screen(() => import("./screens/Tags"), "Tags");
const Groups = screen(() => import("./screens/Groups"), "Groups");
const Relays = screen(() => import("./screens/Relays"), "Relays");
const Audit = screen(() => import("./screens/Audit"), "Audit");
const Profile = screen(() => import("./screens/Profile"), "Profile");
const Reads = screen(() => import("./screens/Reads"), "Reads");
const Readiness = screen(() => import("./screens/Readiness"), "Readiness");
const Monitoring = screen(() => import("./screens/Monitoring"), "Monitoring");
const Backups = screen(() => import("./screens/Backups"), "Backups");
const Certificates = screen(() => import("./screens/Certificates"), "Certificates");
const Vulnerabilities = screen(() => import("./screens/Vulnerabilities"), "Vulnerabilities");
const Unresolved = screen(() => import("./screens/Unresolved"), "Unresolved");
const Jobs = screen(() => import("./screens/Jobs"), "Jobs");
const HostWorkspace = screen(() => import("./screens/host/Workspace"), "HostWorkspace");
const Campaigns = screen(() => import("./screens/Campaigns"), "Campaigns");
const Security = screen(() => import("./screens/Security"), "Security");
const Notifications = screen(() => import("./screens/Notifications"), "Notifications");
const Budgets = screen(() => import("./screens/Budgets"), "Budgets");
const Policies = screen(() => import("./screens/Policies"), "Policies");
const Schedules = screen(() => import("./screens/Schedules"), "Schedules");
const Setup = screen(() => import("./screens/Setup"), "Setup");
const AddHost = screen(() => import("./screens/AddHost"), "AddHost");
const Bulk = screen(() => import("./screens/Bulk"), "Bulk");
const Campaign = screen(() => import("./screens/Campaign"), "Campaign");
const Directory = screen(() => import("./screens/Directory"), "Directory");
const Job = screen(() => import("./screens/Job"), "Job");
const Reports = screen(() => import("./screens/Reports"), "Reports");
const Secrets = screen(() => import("./screens/Secrets"), "Secrets");
const Settings = screen(() => import("./screens/Settings"), "Settings");
const Status = screen(() => import("./screens/Status"), "Status");
const Support = screen(() => import("./screens/Support"), "Support");

/**
 * The panel.
 *
 * It stands beside the one it replaces rather than over it: the
 * laboratory goes on running the panel the owner uses while the screens
 * move across one at a time, and the swap is one commit at the end -
 * these routes become the panel's own and /next goes.
 *
 * A place that has not been written yet says so rather than refusing: the
 * navigation lists the whole fleet's worth of places from the first day,
 * and a reader who follows one is told where it is up to.
 */

const TITLES: Record<string, string> = {
  "": "Fleet dashboard",
  dashboard: "Fleet dashboard",
  hosts: "Hosts",
  profile: "My settings",
  campaigns: "Campaigns",
  security: "Security",
};

export function NextPanel({ look }: { look: Look }) {
  const t = useT();
  const location = useLocation();
  const section = location.pathname.replace(/^\//, "").split("/")[0] ?? "";
  const title = TITLES[section] ?? section.charAt(0).toUpperCase() + section.slice(1);

  // One machine brings its own shell, because its rail is its modules and
  // not the fleet's places. Wrapped in the fleet's shell as well it drew
  // two of everything - two rails, two bars, two brands.
  if (/^\/hosts\/(?!new$)[^/]+/.test(location.pathname)) {
    return (
      <LookProvider look={look}>
      <Suspense fallback={<Waiting />}>
      <Routes>
        <Route path="/hosts/:id" element={<HostWorkspace />} />
        <Route path="/hosts/:id/:module" element={<HostWorkspace />} />
      </Routes>
      </Suspense>
      </LookProvider>
    );
  }

  /*
   * The heading is the shell's, out of one table, so no screen can write
   * its own shape of one and none can leave it out.
   *
   * Except where the screen names a thing rather than a section. One job
   * is not "Jobs"; one campaign is not "Campaigns"; the wizard that adds
   * a machine is not "Hosts". Those carry their own frame, so the shell
   * draws none and the screen's own name stands. The test beside the
   * screens holds every one of them to a title and an explanation.
   */
  const ownHeading = [
    /^\/jobs\/[^/]+$/, /^\/hosts\/new$/, /^\/setup$/,
    // One campaign names itself; the schedules screen is given its frame
    // where it is routed, so the shell draws neither.
    /^\/campaigns\/[^/]+$/,
    /^\/(bulk|reports|settings|secrets|directory|status|support)$/,
  ].some((one) => one.test(location.pathname));
  const about = ownHeading ? undefined : ABOUT[section === "" ? "dashboard" : section];

  return (
    <LookProvider look={look}>
    <Shell trail={{ section: about ? about.title : title }}>
      <ShellHead.Provider value={about !== undefined}>
      {about && (
        <Head
          title={t(about.title)}
          lead={t(about.lead)}
          icon={about.icon}
          help={typeof about.help === "string" ? <p>{t(about.help)}</p> : about.help}
          actions={<HeadSlot />}
        />
      )}
      <Suspense fallback={<Waiting />}>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/new" element={<AddHost />} />
        <Route path="/bulk" element={<Bulk />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/directory" element={<Directory />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/secrets" element={<Secrets />} />
        <Route path="/status" element={<Status />} />
        <Route path="/support" element={<Support />} />
        <Route path="/jobs/:id" element={<Job />} />
        <Route path="/campaigns/:id" element={<Campaign />} />
        <Route path="/campaigns" element={<Campaigns />} />
        {/* Before the one campaign: "schedules" is a word, not an id. */}
        <Route
          path="/campaigns/schedules"
          element={
            <Screen
              title={t("Scheduled campaigns")}
              lead={t("The campaigns that run on a clock, and what each is waiting for.")}
              icon="schedules"
              help={
                <p>{t("A schedule is an order the panel keeps until its moment: at that moment it places the campaign, and the campaign then waits for its approval like any other. It places that order under the rights of whoever last wrote the schedule, read again at every moment - so a schedule can be refused long after it was written, and the refusal is kept on it rather than thrown away.")}</p>
              }
            >
              <Schedules />
            </Screen>
          }
        />
        <Route path="/security" element={<Security />} />
        <Route path="/jobs" element={<Jobs />} />
        <Route path="/unresolved" element={<Unresolved />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/backups" element={<Backups />} />
        <Route path="/monitoring" element={<Monitoring />} />
        <Route path="/reads/:id" element={<Reads />} />
        <Route path="/readiness" element={<Readiness />} />
        <Route path="/reads" element={<Reads />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/notifications" element={<Notifications />} />
        <Route path="/budgets" element={<Budgets />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/policies/:id" element={<Policies />} />
        <Route path="/setup" element={<Setup />} />
        <Route path="/groups/:id" element={<Groups />} />
        <Route path="/relays/:id" element={<Relays />} />
        <Route path="/secrets/:name" element={<Secrets />} />
        <Route path="/vulnerabilities/:cve" element={<Vulnerabilities />} />
        <Route path="/relays" element={<Relays />} />
        <Route path="/groups" element={<Groups />} />
        <Route path="/tags" element={<Tags />} />
        <Route path="/teams" element={<Teams />} />
        <Route path="/access" element={<Access />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
      </Suspense>
      </ShellHead.Provider>
    </Shell>
    </LookProvider>
  );
}

/**
 * An address this panel does not serve.
 *
 * It used to offer the panel being replaced, because every screen not yet
 * rewritten was still there. There is no second panel now, so it says
 * plainly that the address leads nowhere and offers the board.
 */
function NotFound() {
  const t = useT();
  const location = useLocation();
  return (
    <>
      <Head title={t("Page not found.")} lead={location.pathname} />
      <Empty icon="search" action={<Link className="fl-btn fl-quiet" to="/dashboard">{t("Go to the dashboard")}</Link>}>
        {t("No screen of this panel answers to that address.")}
      </Empty>
    </>
  );
}

/**
 * The first page: the one the reader chose, the dashboard until then.
 *
 * A person who lives on the host list should not pass through the board
 * every morning, so the panel asks what they set and goes there. It waits
 * for the answer rather than guessing: a redirect to the dashboard and a
 * second one to the real choice is a flicker nobody asked for.
 */
function Landing() {
  const { preferences, settled } = usePreferences();
  if (!settled) return null;
  return <Navigate to={preferences.landing_page || "/dashboard"} replace />;
}

/** What stands where a screen is still being fetched: a bone, never a word. */
function Waiting() {
  return <div className="fl-bone" style={{ height: 160 }} aria-hidden="true" />;
}
