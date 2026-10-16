import { Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./Shell";
import { Dashboard } from "./screens/Dashboard";
import { Hosts } from "./screens/Hosts";
import { Access } from "./screens/Access";
import { Teams } from "./screens/Teams";
import { Tags } from "./screens/Tags";
import { Groups } from "./screens/Groups";
import { Relays } from "./screens/Relays";
import { Audit } from "./screens/Audit";
import { Profile } from "./screens/Profile";
import { Reads } from "./screens/Reads";
import { Readiness } from "./screens/Readiness";
import { Monitoring } from "./screens/Monitoring";
import { Backups } from "./screens/Backups";
import { Certificates } from "./screens/Certificates";
import { Vulnerabilities } from "./screens/Vulnerabilities";
import { Unresolved } from "./screens/Unresolved";
import { Jobs } from "./screens/Jobs";
import { HostWorkspace } from "./screens/host/Workspace";
import { Campaigns } from "./screens/Campaigns";
import { Security } from "./screens/Security";
import { Notifications } from "./screens/Notifications";
import { Budgets } from "./screens/Budgets";
import { Policies } from "./screens/Policies";
import { Schedules } from "./screens/Schedules";
import { Setup } from "./screens/Setup";
import { AddHost } from "./screens/AddHost";
import { Bulk } from "./screens/Bulk";
import { Campaign } from "./screens/Campaign";
import { Directory } from "./screens/Directory";
import { Job } from "./screens/Job";
import { Reports } from "./screens/Reports";
import { Secrets } from "./screens/Secrets";
import { Settings } from "./screens/Settings";
import { Status } from "./screens/Status";
import { Support } from "./screens/Support";
import { Empty, Head, HeadSlot, Screen, ShellHead } from "./kit";
import { ABOUT } from "./screens/about";
import { LookProvider, type Look } from "./look";
import { useT } from "../i18n";

/**
 * The panel being written again, under /next.
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
  const section = location.pathname.replace(/^\/next\/?/, "").split("/")[0] ?? "";
  const title = TITLES[section] ?? section.charAt(0).toUpperCase() + section.slice(1);

  // One machine brings its own shell, because its rail is its modules and
  // not the fleet's places. Wrapped in the fleet's shell as well it drew
  // two of everything - two rails, two bars, two brands.
  if (/^\/next\/hosts\/(?!new$)[^/]+/.test(location.pathname)) {
    return (
      <LookProvider look={look}>
      <Routes>
        <Route path="/next/hosts/:id" element={<HostWorkspace />} />
        <Route path="/next/hosts/:id/:module" element={<HostWorkspace />} />
      </Routes>
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
    /^\/next\/jobs\/[^/]+$/, /^\/next\/hosts\/new$/, /^\/next\/setup$/,
    // One campaign names itself; the schedules screen is given its frame
    // where it is routed, so the shell draws neither.
    /^\/next\/campaigns\/[^/]+$/,
    /^\/next\/(bulk|reports|settings|secrets|directory|status|support)$/,
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
      <Routes>
        <Route path="/next" element={<Dashboard />} />
        <Route path="/next/dashboard" element={<Dashboard />} />
        <Route path="/next/hosts" element={<Hosts />} />
        <Route path="/next/hosts/new" element={<AddHost />} />
        <Route path="/next/bulk" element={<Bulk />} />
        <Route path="/next/reports" element={<Reports />} />
        <Route path="/next/directory" element={<Directory />} />
        <Route path="/next/settings" element={<Settings />} />
        <Route path="/next/secrets" element={<Secrets />} />
        <Route path="/next/status" element={<Status />} />
        <Route path="/next/support" element={<Support />} />
        <Route path="/next/jobs/:id" element={<Job />} />
        <Route path="/next/campaigns/:id" element={<Campaign />} />
        <Route path="/next/campaigns" element={<Campaigns />} />
        {/* Before the one campaign: "schedules" is a word, not an id. */}
        <Route
          path="/next/campaigns/schedules"
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
        <Route path="/next/security" element={<Security />} />
        <Route path="/next/jobs" element={<Jobs />} />
        <Route path="/next/unresolved" element={<Unresolved />} />
        <Route path="/next/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/next/certificates" element={<Certificates />} />
        <Route path="/next/backups" element={<Backups />} />
        <Route path="/next/monitoring" element={<Monitoring />} />
        <Route path="/next/reads/:id" element={<Reads />} />
        <Route path="/next/readiness" element={<Readiness />} />
        <Route path="/next/reads" element={<Reads />} />
        <Route path="/next/profile" element={<Profile />} />
        <Route path="/next/audit" element={<Audit />} />
        <Route path="/next/notifications" element={<Notifications />} />
        <Route path="/next/budgets" element={<Budgets />} />
        <Route path="/next/policies" element={<Policies />} />
        <Route path="/next/policies/:id" element={<Policies />} />
        <Route path="/next/setup" element={<Setup />} />
        <Route path="/next/groups/:id" element={<Groups />} />
        <Route path="/next/relays/:id" element={<Relays />} />
        <Route path="/next/secrets/:name" element={<Secrets />} />
        <Route path="/next/vulnerabilities/:cve" element={<Vulnerabilities />} />
        <Route path="/next/relays" element={<Relays />} />
        <Route path="/next/groups" element={<Groups />} />
        <Route path="/next/tags" element={<Tags />} />
        <Route path="/next/teams" element={<Teams />} />
        <Route path="/next/access" element={<Access />} />
        <Route path="*" element={<NotYet />} />
      </Routes>
      </ShellHead.Provider>
    </Shell>
    </LookProvider>
  );
}

/** A place the rewrite has not reached. It says so, and where to go. */
function NotYet() {
  const t = useT();
  const location = useLocation();
  const where = location.pathname.replace(/^\/next/, "") || "/";
  return (
    <>
      <Head title={t("Not written yet")} lead={t("This screen is still being rewritten.")} />
      <Empty action={<a className="fl-btn fl-quiet" href={where}>{t("Open it in the panel as it is")}</a>}>
        {t("The new panel is being written screen by screen; this one has not been reached yet.")}
      </Empty>
    </>
  );
}
