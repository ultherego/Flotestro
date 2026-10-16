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
import { Empty, Head } from "./kit";
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

export function NextPanel() {
  const location = useLocation();
  const section = location.pathname.replace(/^\/next\/?/, "").split("/")[0] ?? "";
  const title = TITLES[section] ?? section.charAt(0).toUpperCase() + section.slice(1);

  // One machine brings its own shell, because its rail is its modules and
  // not the fleet's places. Wrapped in the fleet's shell as well it drew
  // two of everything - two rails, two bars, two brands.
  if (/^\/next\/hosts\/[^/]+/.test(location.pathname)) {
    return (
      <Routes>
        <Route path="/next/hosts/:id" element={<HostWorkspace />} />
        <Route path="/next/hosts/:id/:module" element={<HostWorkspace />} />
      </Routes>
    );
  }

  return (
    <Shell trail={{ section: title }}>
      <Routes>
        <Route path="/next" element={<Dashboard />} />
        <Route path="/next/dashboard" element={<Dashboard />} />
        <Route path="/next/hosts" element={<Hosts />} />
        <Route path="/next/campaigns" element={<Campaigns />} />
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
        <Route path="/next/relays" element={<Relays />} />
        <Route path="/next/groups" element={<Groups />} />
        <Route path="/next/tags" element={<Tags />} />
        <Route path="/next/teams" element={<Teams />} />
        <Route path="/next/access" element={<Access />} />
        <Route path="*" element={<NotYet />} />
      </Routes>
    </Shell>
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
