import { Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./Shell";
import { Dashboard } from "./screens/Dashboard";
import { Hosts } from "./screens/Hosts";
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
  campaigns: "Campaigns",
  security: "Security",
};

export function NextPanel() {
  const location = useLocation();
  const section = location.pathname.replace(/^\/next\/?/, "").split("/")[0] ?? "";
  const title = TITLES[section] ?? section.charAt(0).toUpperCase() + section.slice(1);
  return (
    <Shell trail={{ section: title }}>
      <Routes>
        <Route path="/next" element={<Dashboard />} />
        <Route path="/next/dashboard" element={<Dashboard />} />
        <Route path="/next/hosts" element={<Hosts />} />
        {/* One machine: the rail becomes its modules, and the workspace
            draws the one named in the address. */}
        <Route path="/next/hosts/:id" element={<HostWorkspace />} />
        <Route path="/next/hosts/:id/:module" element={<HostWorkspace />} />
        <Route path="/next/campaigns" element={<Campaigns />} />
        <Route path="/next/security" element={<Security />} />
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
